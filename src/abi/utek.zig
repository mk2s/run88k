//! Tektronix UTek XD88 (m88k) personality: the ABI-specific glue between the
//! CPU core and the syscall dispatcher.
//!
//! Recovered convention (from ~/Documents/FUSE-utek/tekroot; libc.a stubs +
//! crt0.o + a linked /bin/echo, verified byte-for-byte — see docs/abi-utek.md):
//!   - syscall trap: `tb0 0, r0, 450`  -> exception vector 450 (0x1c2)
//!   - syscall number: r9   (loaded via `or r9,r0,<N>` == 0x6120_00NN)
//!   - arguments: r2..r8 (SVR4 m88k C calling convention)
//!   - return value: r2 (second word r3 for dual-return calls: getpid/getppid,
//!     getuid/geteuid, getgid/getegid, and pipe's two fds)
//!   - error signalling / return PC: "skip-on-success". The libc stub is
//!         or r9,r0,<N> ; tb0 0,r0,450 ; br err ; jmp r1
//!     On SUCCESS the kernel advances past `br err` so control reaches
//!     `jmp r1`. On ERROR it leaves control on `br err`. The kernel sets the
//!     PSR carry bit (PSR_C = 0x10000000, bit 28 — confirmed in
//!     sys/m88kbcs.h) on error and clears it on success.
//!
//! UTek is BSD-derived (its filesystem is UFS1/FFS) but its userland errno
//! numbers and process startup follow the AT&T/UniSoft SysV lineage. Compared
//! to the other m88k personalities:
//!   - SysV/88 (abi/sysv88.zig): SAME number register (r9) and startup, but
//!     trap vector 451 and a DIFFERENT, much larger syscall number table.
//!   - OpenBSD (abi/openbsd.zig): SAME trap vector (450), but number register
//!     r13 and a stack (auxv) startup contract.
//! So mechanically UTek == SysV/88 with the vector changed from 451 to 450,
//! plus its own compact syscall number table (see syscalls/table_utek.zig).
//!
//! PC handling detail (identical to the other personalities, verified against
//! the core): after a trapped step the core has redirected pc/npc to the
//! exception vector and left `ppc` pointing at the `tb0`. This personality
//! RECOMPUTES pc from `ppc`: success -> ppc+8 (the `jmp r1`), error -> ppc+4
//! (the `br err`).

const m88k = @import("m88k");

const Cpu = m88k.Cpu;

pub const syscall_vector: u32 = 450;

/// The "local"/Tektronix trap vector (449, 0x1c1): a second syscall entry the
/// libc uses for getrlimit(2)/setrlimit(1) and the `sys_local` multiplexor.
/// The number is still in r9; the run loop routes this vector to the same
/// dispatcher, which reads `cpu.last_exception` to tell 449 from 450.
pub const syscall_vector_local: u32 = 449;

/// Register indices (UTek/m88k).
pub const R_NUM: u5 = 9; // syscall number (same as SysV/88)
pub const R_RET: u5 = 2; // return value (and first arg)
pub const R_ARG0: u5 = 2; // args r2..r8
pub const R_ARG_LAST: u5 = 8;
pub const PSR_CARRY_BIT: u5 = 28;

/// Read the syscall number (r9).
pub fn syscallNumber(cpu: *const Cpu) u32 {
    return cpu.getReg(R_NUM);
}

/// Read the Nth syscall argument (0-based): arg0=r2, arg1=r3, ... arg6=r8.
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
/// success path. Used by getpid/getppid, getuid/geteuid, getgid/getegid, and
/// pipe (fds in r2:r3).
pub fn returnSuccess2(cpu: *Cpu, lo: u32, hi: u32) void {
    cpu.setReg(R_RET, lo);
    cpu.setReg(R_RET + 1, hi);
    setCarry(cpu, false);
    advance(cpu, false);
}

/// Signal an error: errno in r2, set carry, leave control on the `br err`.
pub fn returnError(cpu: *Cpu, errno: u32) void {
    cpu.setReg(R_RET, errno);
    setCarry(cpu, true);
    advance(cpu, true);
}

/// Recompute PC after the trap. The core left `ppc` at the `tb0`; the stub is
/// `tb0 ; br err ; jmp r1`. Success skips the `br err` (ppc+8); error runs it
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
    // or rD, rS1, imm  == 0x58000000 | ... ; the real stubs use op 0x16
    // (`or`), encoded 0x6120_00NN for `or r9,r0,N`. Build it generically.
    return (@as(u32, 0x16) << 26) | (@as(u32, d) << 21) | (@as(u32, s1) << 16) | imm;
}

test "utek: success advances PC past br err to jmp r1; error lands on br err" {
    var memory = try mem.Memory.init(std.testing.allocator);
    defer memory.deinit();
    defer mem.setActive(null);
    memory.enforce = false;

    const entry: u32 = 0x10000;
    memory.write32(entry + 0, opOrImm(R_NUM, 0, 68)); // or r9,r0,68 (SYS_write)
    memory.write32(entry + 4, 0xf000d1c2); // tb0 0,r0,450
    memory.write32(entry + 8, 0xc0000000); // br (error path)
    memory.write32(entry + 12, 0xf400c001); // jmp r1 (success)

    // success case
    {
        var r = machine.Runner.init(&memory);
        r.attachBus();
        r.setPc(entry);
        _ = r.run(2); // run the number-load + tb0 (traps)
        try std.testing.expectEqual(syscall_vector, r.cpu.last_exception);
        try std.testing.expectEqual(@as(u32, 68), syscallNumber(&r.cpu));
        returnSuccess(&r.cpu, 7);
        // tb0 is at entry+4 (ppc); success lands on jmp r1 at ppc+8 = entry+12.
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
        // error lands on br err at ppc+4 = entry+8.
        try std.testing.expectEqual(entry + 8, r.cpu.pc); // br err
        try std.testing.expectEqual(@as(u32, 2), r.cpu.getReg(R_RET));
        try std.testing.expectEqual(@as(u1, 1), r.cpu.cf);
    }
}

test "utek: syscall number is r9, args from r2..r8" {
    var cpu = Cpu{};
    cpu.setReg(9, 40); // SYS_read
    cpu.setReg(2, 0xaa);
    cpu.setReg(3, 0xbb);
    cpu.setReg(8, 0xff);
    try std.testing.expectEqual(@as(u32, 40), syscallNumber(&cpu));
    try std.testing.expectEqual(@as(u32, 0xaa), arg(&cpu, 0));
    try std.testing.expectEqual(@as(u32, 0xbb), arg(&cpu, 1));
    try std.testing.expectEqual(@as(u32, 0xff), arg(&cpu, 6));
}
