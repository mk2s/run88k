//! Data General DG/UX (m88k) personality: the ABI-specific glue between the
//! CPU core and the syscall dispatcher.
//!
//! Recovered convention (from /usr/dglib/libc.so.1 stubs + the shared error
//! trampoline at libc 0x455b0, verified in Ghidra — see docs/abi-dgux.md):
//!   - syscall number: r9   (loaded via `or r9,r0,<N>` == 0x5920_00NN)
//!   - TWO trap gates, and the number in r9 is interpreted RELATIVE to the
//!     gate (the two tables overlap numerically with different meanings):
//!       * `tb0 0, r0, 0x1c2` (vector 450) -> STANDARD table (table_dgux.Std)
//!       * `tb0 0, r0, 0x080` (vector 128) -> DG-EXTENDED table (table_dgux.Ext)
//!   - arguments: r2..r9 (SVR4 m88k C calling convention), passed through the
//!     libc stub UNMODIFIED (the stub only sets r9 and traps).
//!   - return value: r2 (second word r3 for dual-return calls).
//!   - error signalling / return PC: "skip-on-success". The libc stub is
//!         or r9,r0,<N> ; tb0 0,r0,<gate> ; br 0x455b0 ; jmp r1
//!     On SUCCESS the kernel advances past `br 0x455b0` so control reaches
//!     `jmp r1`. On ERROR it leaves control on `br 0x455b0` (the shared error
//!     trampoline), with the errno value in r2; the trampoline stores it into
//!     the global `errno` and forces the return value to -1. The PSR carry bit
//!     (bit 28) mirrors success/error.
//!
//! DG/UX is SVR4-derived (ELF32-BE, dynamically linked, interpreter
//! /usr/dglib/libc.so.1). Compared to the other m88k personalities:
//!   - SysV/88 (abi/sysv88.zig): SAME number register (r9), single gate 451.
//!   - UTek (abi/utek.zig): SAME number register (r9), gates 450/449, but the
//!     449 gate is only a small multiplexor, not an overlapping full table.
//!   - OpenBSD (abi/openbsd.zig): number register r13, single gate 450, auxv
//!     stack startup.
//! DG/UX is the only personality with two FULL overlapping syscall tables, so
//! the dispatcher routes on `cpu.last_exception` (the gate) first.
//!
//! PC handling detail (identical to the other personalities, verified against
//! the core): after a trapped step the core has redirected pc/npc to the
//! exception vector and left `ppc` pointing at the `tb0`. This personality
//! RECOMPUTES pc from `ppc`: success -> ppc+8 (the `jmp r1`), error -> ppc+4
//! (the `br 0x455b0`).

const m88k = @import("m88k");

const Cpu = m88k.Cpu;

/// Standard syscall gate: `tb0 0, r0, 0x1c2` -> exception vector 450.
pub const syscall_vector: u32 = 450;

/// DG-extended syscall gate: `tb0 0, r0, 0x080` -> exception vector 128.
pub const syscall_vector_ext: u32 = 128;

/// Register indices (DG/UX = m88k SVR4).
pub const R_NUM: u5 = 9; // syscall number (same as SysV/88, UTek)
pub const R_RET: u5 = 2; // return value (and first arg)
pub const R_ARG0: u5 = 2; // args r2..r9
pub const R_ARG_LAST: u5 = 9;
pub const PSR_CARRY_BIT: u5 = 28;

/// Which trap gate a given exception vector represents.
pub const Gate = enum { std, ext };

/// Classify the trapping exception vector into a gate. Returns null if the
/// vector is not a DG/UX syscall gate.
pub fn gateOf(vector: u32) ?Gate {
    return switch (vector) {
        syscall_vector => .std,
        syscall_vector_ext => .ext,
        else => null,
    };
}

/// Read the syscall number (r9).
pub fn syscallNumber(cpu: *const Cpu) u32 {
    return cpu.getReg(R_NUM);
}

/// Read the Nth syscall argument (0-based): arg0=r2, arg1=r3, ... arg7=r9.
pub fn arg(cpu: *const Cpu, n: u5) u32 {
    return cpu.getReg(R_ARG0 + n);
}

/// Overwrite a syscall argument register. Used to re-shape one syscall's args
/// into another's convention before delegating.
pub fn setArg(cpu: *Cpu, n: u5, value: u32) void {
    cpu.setReg(R_ARG0 + n, value);
}

/// Write a success return value into r2 and clear the carry (success), then
/// advance PC past the error branch to the `jmp r1`.
pub fn returnSuccess(cpu: *Cpu, value: u32) void {
    cpu.setReg(R_RET, value);
    setCarry(cpu, false);
    advance(cpu, false);
}

/// Write a 64-bit / dual success return (r2:r3), clear carry, advance to the
/// success path. Used by getpid/getppid, getuid/geteuid, getgid/getegid.
pub fn returnSuccess2(cpu: *Cpu, lo: u32, hi: u32) void {
    cpu.setReg(R_RET, lo);
    cpu.setReg(R_RET + 1, hi);
    setCarry(cpu, false);
    advance(cpu, false);
}

/// Signal an error: errno in r2, set carry, leave control on the `br 0x455b0`.
pub fn returnError(cpu: *Cpu, errno: u32) void {
    cpu.setReg(R_RET, errno);
    setCarry(cpu, true);
    advance(cpu, true);
}

/// Recompute PC after the trap. The core left `ppc` at the `tb0`; the stub is
/// `tb0 ; br 0x455b0 ; jmp r1`. Success skips the `br` (ppc+8); error runs it
/// (ppc+4). Also clear the pipeline so no stale delayed branch fires.
fn advance(cpu: *Cpu, is_error: bool) void {
    const tb0 = cpu.ppc;
    const target = if (is_error) tb0 +% 4 else tb0 +% 8;
    cpu.branch_pending = false;
    cpu.pc = target;
    cpu.npc = target +% 4;
}

fn setCarry(cpu: *Cpu, on: bool) void {
    cpu.cf = if (on) 1 else 0;
    const mask: u32 = @as(u32, 1) << PSR_CARRY_BIT;
    if (on) {
        cpu.psr |= mask;
    } else {
        cpu.psr &= ~mask;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const std = @import("std");
const mem = @import("../mem.zig");
const machine = @import("../machine.zig");

fn opOrImm(d: u5, s1: u5, imm: u16) u32 {
    // or rD, rS1, imm ; the real stubs use op 0x16 (`or`), encoded
    // 0x5920_00NN for `or r9,r0,N`. Build it generically.
    return (@as(u32, 0x16) << 26) | (@as(u32, d) << 21) | (@as(u32, s1) << 16) | imm;
}

test "dgux: gate classification" {
    try std.testing.expectEqual(Gate.std, gateOf(syscall_vector).?);
    try std.testing.expectEqual(Gate.ext, gateOf(syscall_vector_ext).?);
    try std.testing.expect(gateOf(451) == null);
}

test "dgux std gate: success advances past br to jmp r1; error lands on br" {
    var memory = try mem.Memory.init(std.testing.allocator);
    defer memory.deinit();
    defer mem.setActive(null);
    memory.enforce = false;

    const entry: u32 = 0x10000;
    memory.write32(entry + 0, opOrImm(R_NUM, 0, 68)); // or r9,r0,68 (Std.write)
    memory.write32(entry + 4, 0xf000d1c2); // tb0 0,r0,0x1c2 (vector 450)
    memory.write32(entry + 8, 0xc0000000); // br 0x455b0 (error path)
    memory.write32(entry + 12, 0xf400c001); // jmp r1 (success)

    // success case
    {
        var r = machine.Runner.init(&memory);
        r.attachBus();
        r.setPc(entry);
        _ = r.run(2); // run the number-load + tb0 (traps)
        try std.testing.expectEqual(syscall_vector, r.cpu.last_exception);
        try std.testing.expectEqual(Gate.std, gateOf(r.cpu.last_exception).?);
        try std.testing.expectEqual(@as(u32, 68), syscallNumber(&r.cpu));
        returnSuccess(&r.cpu, 7);
        try std.testing.expectEqual(entry + 12, r.cpu.pc); // jmp r1
        try std.testing.expectEqual(@as(u32, 7), r.cpu.getReg(R_RET));
        try std.testing.expectEqual(@as(u1, 0), r.cpu.cf);
    }
    // error case
    {
        var r = machine.Runner.init(&memory);
        r.attachBus();
        r.setPc(entry);
        _ = r.run(2);
        returnError(&r.cpu, 2); // ENOENT
        try std.testing.expectEqual(entry + 8, r.cpu.pc); // br 0x455b0
        try std.testing.expectEqual(@as(u32, 2), r.cpu.getReg(R_RET));
        try std.testing.expectEqual(@as(u1, 1), r.cpu.cf);
    }
}

test "dgux ext gate: traps to vector 128, number in r9" {
    var memory = try mem.Memory.init(std.testing.allocator);
    defer memory.deinit();
    defer mem.setActive(null);
    memory.enforce = false;

    const entry: u32 = 0x20000;
    memory.write32(entry + 0, opOrImm(R_NUM, 0, 218)); // or r9,r0,218 (Ext.mmap)
    memory.write32(entry + 4, 0xf000d080); // tb0 0,r0,0x080 (vector 128)
    memory.write32(entry + 8, 0xc0000000); // br 0x455b0
    memory.write32(entry + 12, 0xf400c001); // jmp r1

    var r = machine.Runner.init(&memory);
    r.attachBus();
    r.setPc(entry);
    _ = r.run(2);
    try std.testing.expectEqual(syscall_vector_ext, r.cpu.last_exception);
    try std.testing.expectEqual(Gate.ext, gateOf(r.cpu.last_exception).?);
    try std.testing.expectEqual(@as(u32, 218), syscallNumber(&r.cpu));
}

test "dgux: syscall number is r9, args from r2..r9" {
    var cpu = Cpu{};
    cpu.setReg(9, 40); // Std.read
    cpu.setReg(2, 0xaa);
    cpu.setReg(3, 0xbb);
    cpu.setReg(8, 0xff);
    try std.testing.expectEqual(@as(u32, 40), syscallNumber(&cpu));
    try std.testing.expectEqual(@as(u32, 0xaa), arg(&cpu, 0));
    try std.testing.expectEqual(@as(u32, 0xbb), arg(&cpu, 1));
    try std.testing.expectEqual(@as(u32, 0xff), arg(&cpu, 6));
}
