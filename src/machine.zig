//! Guest machine: the Runner owns the CPU context and guest memory, and drives
//! the execution loop.
//!
//! Unlike runupc (which sniffs the trap opcode via Musashi's instruction hook),
//! musashi88k reports traps directly: `decode.step()` returns
//! `StepResult.trapped` with the vector number in `cpu.last_exception`. So the
//! run loop steps the core and, on a trap, dispatches on `last_exception`:
//!   - the active personality's syscall vector => service a syscall
//!     (SysV/88 = 451; BSD = 128), or
//!   - anything else => a real fault (illegal opcode, bounds, divide, ...) that
//!     stops the guest with a diagnostic.
//!
//! This milestone (0/1) has no personality/syscall layer yet; it proves the
//! core integration end to end: build a Cpu, wire memory, run a program that
//! executes the SysV/88 syscall trap `tb0 0, r0, 451`, and observe a trap with
//! `last_exception == 451`, the syscall number readable in r9.

const std = @import("std");
const m88k = @import("m88k");
const mem = @import("mem.zig");

const Cpu = m88k.Cpu;
const StepResult = m88k.cpu.StepResult;

/// Register indices we care about at this layer (SysV/88 ABI).
pub const Reg = struct {
    pub const sp: u5 = 31; // r31 = stack pointer
    pub const syscall_num: u5 = 9; // r9 holds the SysV/88 syscall number
    pub const ret: u5 = 2; // r2 holds the return value
    pub const arg0: u5 = 2; // args begin at r2
    pub const link: u5 = 1; // r1 = return address
};

/// Why the run loop stopped.
pub const StopReason = enum {
    exited, // guest requested exit
    fault, // a real CPU fault (unexpected trap / memory fault)
    halted, // core halted
    timed_out, // cycle budget exhausted (runaway guest)
    trap, // stopped ON a trap for the caller to inspect (no handler installed)
};

/// Syscall handler signature. Installed by the syscall layer to avoid an
/// import cycle (dispatch imports machine). Returns true to continue the
/// guest, false to stop (exit or fatal). The handler reads the number/args
/// from `runner.cpu`, services the call, writes the result, and adjusts PC.
pub const SyscallFn = *const fn (runner: *Runner) bool;

/// A tracked file-backed mmap region. `host_fd` is a dup of the guest's file
/// descriptor kept open for the mapping's lifetime so write-back on munmap
/// works even after the guest closes its own fd. -1 host_fd = free slot.
pub const FileMap = struct {
    base: u32 = 0,
    len: u32 = 0,
    file_off: u32 = 0,
    host_fd: i32 = -1,
    shared: bool = false,
};

pub const Runner = struct {
    cpu: Cpu = .{},
    memory: *mem.Memory,

    /// The active personality's syscall trap vector (SysV/88 = 451). A trap
    /// with this vector is dispatched to `handler`; any other trap is a fault.
    syscall_vector: u32 = 0xffff_ffff,
    /// Installed syscall handler. If null, a syscall trap stops the loop.
    handler: ?SyscallFn = null,
    /// Guest filesystem (mount table + fd table). Type-erased to avoid an
    /// import cycle (fs is imported by the dispatcher, not by machine). The
    /// dispatcher casts it back to *fs.Fs.
    fs: ?*anyopaque = null,
    /// Process model (fork/exec/wait/pipe). Type-erased, same reasoning.
    procmodel: ?*anyopaque = null,

    /// Set when the guest exits; holds the process exit status.
    exit_status: ?u32 = null,
    /// True once a fatal fault / unimplemented syscall aborted the run.
    aborted: bool = false,
    /// The last trap vector observed. NO_TRAP when none.
    last_trap: u32 = NO_TRAP,
    /// Program break (top of heap); brk syscall grows it. Set by the loader.
    brk: u32 = 0,
    /// Lowest legal break (initial brk); brk cannot go below this.
    brk_base: u32 = 0,
    /// mmap bump pointer for anonymous allocations (grows down from a high
    /// region, kept clear of the stack).
    mmap_next: u32 = 0x0800_0000,
    /// Active file-backed mmap regions (for MAP_SHARED write-back on munmap).
    /// Tools like `as`/`ld` build their ELF output in a MAP_SHARED mapping of
    /// the output file and rely on munmap flushing it back.
    file_maps: [16]FileMap = @splat(.{}),
    /// umask (tracked; applied host-side).
    umask: u32 = 0,
    /// Thread control block pointer (OpenBSD __set_tcb/__get_tcb). Holds the
    /// TLS/stack-guard base the guest libc installs at startup.
    tcb: u32 = 0,
    /// Set by a successful execve: the run loop must NOT advance PC past the
    /// trap (the handler already set PC to the new image's entry). Cleared by
    /// the run loop after honoring it.
    exec_pending: bool = false,
    /// Ring buffer of recent PCs (diagnostics for runaway/timeout).
    pc_ring: [32]u32 = @splat(0),
    pc_ring_i: usize = 0,
    /// Instruction budget guard against a runaway guest.
    steps_run: u64 = 0,

    pub const NO_TRAP: u32 = 0xffff_ffff;

    /// Default instruction budget for a single run() call. Generous; exists
    /// only to stop a truly wedged guest.
    pub const default_max_steps: u64 = 200_000_000;

    pub fn init(memory: *mem.Memory) Runner {
        return .{ .memory = memory };
    }

    /// Wire memory into the CPU and reset. Call once before setting PC/regs.
    pub fn attachBus(self: *Runner) void {
        self.cpu.bus = self.memory.bus();
        self.cpu.reset();
    }

    /// Set the program counter (and the delay-slot shadow) to `addr`.
    pub fn setPc(self: *Runner, addr: u32) void {
        self.cpu.pc = addr;
        self.cpu.npc = addr +% 4;
    }

    pub fn getReg(self: *const Runner, index: u5) u32 {
        return self.cpu.getReg(index);
    }
    pub fn setReg(self: *Runner, index: u5, value: u32) void {
        self.cpu.setReg(index, value);
    }

    /// Run until the guest exits, faults, halts, or exhausts the step budget.
    /// Returns the reason it stopped.
    ///
    /// A trap whose vector equals `syscall_vector` and for which a `handler`
    /// is installed is serviced as a syscall (the handler advances PC). Any
    /// other trap, or a syscall trap with no handler, stops the loop
    /// (`.fault` / `.trap`).
    pub fn run(self: *Runner, max_steps: u64) StopReason {
        // Guard: the bus must resolve to this memory, or every fetch reads 0
        // and the CPU spins. mem.active is set by memory.bus() in attachBus.
        if (mem.active == null or mem.active.? != self.memory) {
            return .fault;
        }

        var budget = max_steps;
        while (budget > 0) : (budget -= 1) {
            self.pc_ring[self.pc_ring_i % self.pc_ring.len] = self.cpu.pc;
            self.pc_ring_i +%= 1;
            const result = m88k.step(&self.cpu);
            self.steps_run += 1;

            // A memory fault during the step is fatal.
            if (self.memory.fault.kind != .none) {
                self.memory.fault.pc = self.cpu.ppc;
                return .fault;
            }

            switch (result) {
                .normal => {},
                .halted => return .halted,
                .trapped => {
                    self.last_trap = self.cpu.last_exception;
                    if (self.cpu.last_exception == self.syscall_vector) {
                        if (self.handler) |h| {
                            if (!h(self)) {
                                // Handler asked to stop: exit or abort.
                                return if (self.aborted) .fault else .exited;
                            }
                            // Serviced; the handler set PC. Continue.
                            continue;
                        }
                    }
                    // No handler, or a non-syscall trap: a real fault.
                    return .trap;
                },
            }
        }
        return .timed_out;
    }
};

// ---------------------------------------------------------------------------
// Tests: core integration (Milestone 0/1)
// ---------------------------------------------------------------------------

// m88k instruction encodings used by the tests, assembled by hand and verified
// against musashi88k's decoder / the recovered SysV/88 stubs:
//   addu r9, r0, N   => op1=0x18, d=9, s1=0 : 0x61200000 | (N & 0xffff)
//   tb0  0, r0, 451  => 0xf000d1c3  (op1=0x3c, op7=1101000 tb0, always fires,
//                        vector = 451 = 0x1c3)
const OP_TB0_SYSCALL: u32 = 0xf000_d1c3;
fn opAdduImm(d: u5, s1: u5, imm: u16) u32 {
    return (@as(u32, 0x18) << 26) | (@as(u32, d) << 21) | (@as(u32, s1) << 16) | imm;
}

test "SysV/88 syscall trap: tb0 0,r0,451 traps with vector 451 and number in r9" {
    var memory = try mem.Memory.init(std.testing.allocator);
    defer memory.deinit();
    defer mem.setActive(null);
    memory.enforce = false;

    // Program at 0x10000:
    //   addu r9, r0, 4      ; syscall number 4 (write) into r9
    //   tb0  0, r0, 451     ; the SysV/88 syscall trap
    const entry: u32 = 0x0001_0000;
    memory.write32(entry + 0, opAdduImm(Reg.syscall_num, 0, 4));
    memory.write32(entry + 4, OP_TB0_SYSCALL);

    var runner = Runner.init(&memory);
    runner.attachBus();
    runner.setPc(entry);

    const reason = runner.run(100);

    try std.testing.expectEqual(StopReason.trap, reason);
    try std.testing.expectEqual(@as(u32, 451), runner.last_trap);
    // The syscall number is readable in r9, matching the recovered ABI.
    try std.testing.expectEqual(@as(u32, 4), runner.getReg(Reg.syscall_num));
}

test "addu immediate computes into r9 before the trap" {
    var memory = try mem.Memory.init(std.testing.allocator);
    defer memory.deinit();
    defer mem.setActive(null);
    memory.enforce = false;

    const entry: u32 = 0x0001_0000;
    // addu r9, r0, 0x1234 ; then loop-safe: tb0 syscall so we stop deterministically
    memory.write32(entry + 0, opAdduImm(Reg.syscall_num, 0, 0x1234));
    memory.write32(entry + 4, OP_TB0_SYSCALL);

    var runner = Runner.init(&memory);
    runner.attachBus();
    runner.setPc(entry);

    _ = runner.run(100);
    try std.testing.expectEqual(@as(u32, 0x1234), runner.getReg(Reg.syscall_num));
}
