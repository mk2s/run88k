//! NetBSD/luna88k (m88k) personality: the ABI-specific glue between the CPU
//! core and the syscall dispatcher.
//!
//! Recovered convention (from /mnt/netbsd, NetBSD 3.0.1_STABLE/luna88k,
//! verified via nono + Ghidra — see docs/abi-netbsd.md):
//!   - syscall trap: `tb0 0, r0, 128`  -> exception vector 128 (0x80)
//!   - syscall number: r13
//!   - arguments: r2.. (m88k C calling convention, contiguous from r2)
//!   - return value: r2 (second word r3 for 64-bit returns, e.g. lseek off_t)
//!   - error signalling / return PC: "skip-on-success" — the libc stub is
//!         or r13,r0,<N> ; tb0 0,r0,128 ; br err ; jmp r1
//!     On SUCCESS the kernel advances past `br err` so control reaches
//!     `jmp r1`. On ERROR it leaves control on `br err`. The kernel sets the
//!     PSR carry bit on error and clears it on success.
//!
//! This is the SAME trap mechanism as OpenBSD (see abi/openbsd.zig) and
//! SysV/88 (abi/sysv88.zig); the ONLY difference from OpenBSD is the trap
//! vector (128 vs 450). The number register (r13), carry-based error
//! signalling and skip-on-success PC recompute from `ppc` are identical.
//!
//! PC handling detail (verified against the core): after a trapped step the
//! core has redirected pc/npc to the exception vector and left `ppc` pointing
//! at the `tb0`. This personality RECOMPUTES pc from `ppc`: success -> ppc+8
//! (the `jmp r1`), error -> ppc+4 (the `br err`).

const m88k = @import("m88k");

const Cpu = m88k.Cpu;

pub const syscall_vector: u32 = 128;

/// Register indices (NetBSD/m88k — same as OpenBSD).
pub const R_NUM: u5 = 13; // syscall number
pub const R_RET: u5 = 2; // return value (and first arg)
pub const R_ARG0: u5 = 2; // args r2..
pub const PSR_CARRY_BIT: u5 = 28;

/// Read the syscall number (r13).
pub fn syscallNumber(cpu: *const Cpu) u32 {
    return cpu.getReg(R_NUM);
}

/// Read the Nth syscall argument (0-based): arg0=r2, arg1=r3, ...
/// The m88k C convention passes the first arguments in r2..r12; the libc stub
/// pre-spills any stack args into r10/r11/r12 before the trap, so up to 11
/// argument registers are valid.
pub fn arg(cpu: *const Cpu, n: u5) u32 {
    return cpu.getReg(R_ARG0 + n);
}

/// Overwrite a syscall argument register. Used to re-shape one syscall's args
/// into another's convention before delegating (indirect __syscall).
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

/// Write a 64-bit success return (r2:r3), clear carry, advance to success path.
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

fn opAdduImm(d: u5, s1: u5, imm: u16) u32 {
    return (@as(u32, 0x18) << 26) | (@as(u32, d) << 21) | (@as(u32, s1) << 16) | imm;
}

test "netbsd: success advances PC past br err to jmp r1; error lands on br err" {
    var memory = try mem.Memory.init(std.testing.allocator);
    defer memory.deinit();
    defer mem.setActive(null);
    memory.enforce = false;

    const entry: u32 = 0x10000;
    memory.write32(entry + 0, opAdduImm(R_NUM, 0, 4)); // addu r13,r0,4 (SYS_write)
    memory.write32(entry + 4, 0xf000d080); // tb0 0,r0,128
    memory.write32(entry + 8, 0xc0000002); // br (error path)
    memory.write32(entry + 12, 0xf400c001); // jmp r1 (success)

    // success case
    {
        var r = machine.Runner.init(&memory);
        r.attachBus();
        r.setPc(entry);
        _ = r.run(2); // run addu + tb0 (traps)
        try std.testing.expectEqual(syscall_vector, r.cpu.last_exception);
        try std.testing.expectEqual(@as(u32, 4), syscallNumber(&r.cpu));
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

test "netbsd: syscall number is r13, args from r2" {
    var cpu = Cpu{};
    cpu.setReg(13, 272); // SYS_getdents
    cpu.setReg(2, 0xaa);
    cpu.setReg(3, 0xbb);
    cpu.setReg(9, 0xff);
    try std.testing.expectEqual(@as(u32, 272), syscallNumber(&cpu));
    try std.testing.expectEqual(@as(u32, 0xaa), arg(&cpu, 0));
    try std.testing.expectEqual(@as(u32, 0xbb), arg(&cpu, 1));
    try std.testing.expectEqual(@as(u32, 0xff), arg(&cpu, 7));
}
