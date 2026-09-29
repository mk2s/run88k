//! Process startup for UNIX System V/88 R4.0 (m88k).
//!
//! The recovered `_start` contract (crt1.o via Ghidra; see docs/abi-sysv88.md)
//! is a REGISTER handoff — the kernel does not push argc/argv for the crt to
//! scan; it hands them in registers:
//!   r2 = argc, r3 = argv (char**), r4 = envp (char**), r6 = cleanup fn or 0,
//!   r31 = stack pointer (8-byte aligned), r1 = return address.
//!
//! We still lay the argv/envp strings and NULL-terminated pointer vectors into
//! a stack region (the crt / main dereference r3/r4), then point r3/r4 at them
//! and set r2/r6/r31/r1. This matches what the real kernel builds.

const std = @import("std");
const mem = @import("mem.zig");
const machine = @import("machine.zig");

pub const StartError = error{ ArgsTooLong, OutOfStack };

/// Top of the user stack (exclusive). The stack grows down from here. Chosen
/// well above the loaded image + heap for a static SysV/88 binary.
pub const stack_top: u32 = 0x0C00_0000;
/// How much stack region to map rw below stack_top.
pub const stack_size: u32 = 0x0010_0000; // 1 MiB

/// Address of a halt trampoline the initial r1 points at, so a stray `jmp r1`
/// out of `_start` (which only happens after exit) lands somewhere inert. We
/// place a syscall-exit stub here as a safety net: `addu r9,r0,1; tb0 0,r0,451`
/// (SYS_exit). Mapped r-x by setup.
pub const halt_pad: u32 = 0x0BFF_F000;

pub const Layout = struct {
    sp: u32,
    argc: u32,
    argv_ptr: u32, // guest address of argv[0] slot
    envp_ptr: u32, // guest address of envp[0] slot
};

/// One ELF auxiliary-vector entry ({ id, val }, 8 bytes). OpenBSD's `_start`/
/// libc walks the auxv (after the envp NULL) for AT_PHDR/PAGESZ/ENTRY/etc.,
/// terminated by an AUX_null entry — omitting it makes libc read off the end
/// of the stack.
pub const AuxEntry = struct { id: u32, val: u32 };

/// Build the argv/envp image on the stack and return the layout. Enforcement
/// is toggled off while scribbling and restored. `auxv` (may be empty) is
/// appended after the envp NULL; an AUX_null terminator is always added.
pub fn buildStack(
    memory: *mem.Memory,
    argv: []const []const u8,
    envp: []const []const u8,
) StartError!Layout {
    return buildStackAux(memory, argv, envp, &.{});
}

pub fn buildStackAux(
    memory: *mem.Memory,
    argv: []const []const u8,
    envp: []const []const u8,
    auxv: []const AuxEntry,
) StartError!Layout {
    const was = memory.enforce;
    memory.enforce = false;
    defer memory.enforce = was;

    // Total string bytes (each NUL-terminated).
    var strbytes: usize = 0;
    for (argv) |a| strbytes += a.len + 1;
    for (envp) |e| strbytes += e.len + 1;

    const MAX_VEC = 4096;
    if (argv.len > MAX_VEC or envp.len > MAX_VEC) return error.ArgsTooLong;
    if (strbytes > stack_size / 2) return error.ArgsTooLong;

    var argv_addrs: [MAX_VEC]u32 = undefined;
    var envp_addrs: [MAX_VEC]u32 = undefined;

    // Strings live at the top, 4-byte aligned base.
    var string_area: u32 = stack_top - @as(u32, @intCast(strbytes));
    string_area &= ~@as(u32, 3);

    var cursor = string_area;
    for (argv, 0..) |a, i| {
        memory.writeBytes(cursor, a);
        memory.write8(cursor + @as(u32, @intCast(a.len)), 0);
        argv_addrs[i] = cursor;
        cursor += @intCast(a.len + 1);
    }
    for (envp, 0..) |e, i| {
        memory.writeBytes(cursor, e);
        memory.write8(cursor + @as(u32, @intCast(e.len)), 0);
        envp_addrs[i] = cursor;
        cursor += @intCast(e.len + 1);
    }

    // Pointer table below the strings (high to low): argc, argv[]+NULL,
    // envp[]+NULL, auxv[]+{AUX_null,0}, all 4-byte words. Lay it out from a
    // longword-aligned sp.
    const n_argv: u32 = @intCast(argv.len);
    const n_envp: u32 = @intCast(envp.len);
    const n_aux: u32 = @intCast(auxv.len);
    // aux entries are 2 words each, plus the {0,0} AUX_null terminator (2 words).
    const total_words: u32 = 1 + (n_argv + 1) + (n_envp + 1) + (n_aux * 2 + 2);
    const table_bytes = total_words * 4;

    var sp = string_area - table_bytes;
    sp &= ~@as(u32, 7); // 8-byte aligned SP per the ABI

    if (sp < stack_top - stack_size) return error.OutOfStack;

    var w = sp;
    memory.write32(w, n_argv);
    w += 4;
    const argv_ptr = w;
    for (argv_addrs[0..argv.len]) |addr| {
        memory.write32(w, addr);
        w += 4;
    }
    memory.write32(w, 0); // argv NULL
    w += 4;
    const envp_ptr = w;
    for (envp_addrs[0..envp.len]) |addr| {
        memory.write32(w, addr);
        w += 4;
    }
    memory.write32(w, 0); // envp NULL
    w += 4;
    // ELF auxiliary vector, terminated by AUX_null {0,0}.
    for (auxv) |a| {
        memory.write32(w, a.id);
        memory.write32(w + 4, a.val);
        w += 8;
    }
    memory.write32(w, 0); // AUX_null id
    memory.write32(w + 4, 0); // AUX_null val

    return .{ .sp = sp, .argc = n_argv, .argv_ptr = argv_ptr, .envp_ptr = envp_ptr };
}

/// Map the stack region and the halt pad, then set the SysV/88 entry register
/// state on the runner. Call after the ELF is loaded and the runner's bus is
/// attached (attachBus calls cpu.reset()).
/// Initial heap pre-mapped RW above the program break. Real SysV hands the
/// process a writable break page; crt/libc startup often writes at `_end`
/// (the initial break) before its first explicit `brk`. We map a generous
/// initial heap so those writes succeed, and advance the tracked break to its
/// top so `brk` extends from there.
pub const initial_heap: u32 = 0x0010_0000; // 1 MiB

pub fn setup(
    runner: *machine.Runner,
    entry: u32,
    brk: u32,
    argv: []const []const u8,
    envp: []const []const u8,
) StartError!void {
    const memory = runner.memory;

    // Map the stack rw and the halt pad r-x.
    memory.addRegion(stack_top - stack_size, stack_size, .{ .read = true, .write = true }) catch return error.OutOfStack;
    memory.addRegion(halt_pad, 8, .{ .read = true, .exec = true }) catch return error.OutOfStack;

    // Pre-map an initial heap [brk, brk+initial_heap) as RW, zero-filled.
    {
        const w = memory.enforce;
        memory.enforce = false;
        memory.zero(brk, initial_heap);
        memory.enforce = w;
    }
    memory.addRegion(brk, initial_heap, .{ .read = true, .write = true }) catch return error.OutOfStack;
    runner.brk = brk + initial_heap;
    runner.brk_base = brk;

    // Halt pad: SYS_exit stub so a stray jmp r1 terminates cleanly.
    {
        const w = memory.enforce;
        memory.enforce = false;
        memory.write32(halt_pad + 0, (@as(u32, 0x18) << 26) | (@as(u32, 9) << 21) | 1); // addu r9,r0,1
        memory.write32(halt_pad + 4, 0xf000_d1c3); // tb0 0,r0,451
        memory.enforce = w;
    }

    const layout = try buildStack(memory, argv, envp);

    // Clean register file (a real exec hands off zeroed GPRs; on exec from a
    // forked child the CPU still holds the caller's values).
    var ri: u5 = 0;
    while (true) {
        runner.setReg(ri, 0);
        if (ri == 31) break;
        ri += 1;
    }
    runner.cpu.branch_pending = false;

    // Register handoff (docs/abi-sysv88.md).
    runner.setReg(2, layout.argc); // r2 = argc
    runner.setReg(3, layout.argv_ptr); // r3 = argv
    runner.setReg(4, layout.envp_ptr); // r4 = envp
    runner.setReg(6, 0); // r6 = cleanup fn (none)
    runner.setReg(machine.Reg.sp, layout.sp); // r31 = SP
    runner.setReg(machine.Reg.link, halt_pad); // r1 = return address -> halt pad
    runner.setPc(entry);
}

/// Tektronix UTek XD88 process setup. UTek's `_start` uses the SAME register
/// handoff as SysV/88 (r2=argc, r3=argv, r4=envp, r6=0, r31=SP; confirmed from
/// crt0.o and a linked /bin/echo entry). The ONLY difference from setup() is
/// the halt-pad exit stub, which must issue UTek's syscall trap: SYS_exit is
/// number 9 in r9, trap vector 450 (`tb0 0,r0,450`), not SysV/88's 1 / 451.
pub fn setupUtek(
    runner: *machine.Runner,
    entry: u32,
    brk: u32,
    argv: []const []const u8,
    envp: []const []const u8,
) StartError!void {
    const memory = runner.memory;

    memory.addRegion(stack_top - stack_size, stack_size, .{ .read = true, .write = true }) catch return error.OutOfStack;
    memory.addRegion(halt_pad, 8, .{ .read = true, .exec = true }) catch return error.OutOfStack;

    // Low "zero page": UTek maps a readable page at address 0 (classic
    // pre-MMU-strict Unix behavior). Programs like `ld` rely on it — e.g. a
    // strcmp against a null symbol name reads `*NULL == 0`, treats it as an
    // empty string, and returns a mismatch instead of faulting. Map a small
    // read-only zero region [0, 0x2000) below the lowest text vaddr (0x2200).
    // NOT writable, so a null STORE still faults (a real bug the guest'd hit).
    memory.addRegion(0, 0x2000, .{ .read = true, .write = false }) catch return error.OutOfStack;

    {
        const w = memory.enforce;
        memory.enforce = false;
        memory.zero(brk, initial_heap);
        memory.enforce = w;
    }
    memory.addRegion(brk, initial_heap, .{ .read = true, .write = true }) catch return error.OutOfStack;
    runner.brk = brk + initial_heap;
    runner.brk_base = brk;

    // Halt pad: UTek SYS_exit stub (`addu r9,r0,9; tb0 0,r0,450`) so a stray
    // `jmp r1` out of _start terminates cleanly.
    {
        const w = memory.enforce;
        memory.enforce = false;
        memory.write32(halt_pad + 0, (@as(u32, 0x18) << 26) | (@as(u32, 9) << 21) | 9); // addu r9,r0,9
        memory.write32(halt_pad + 4, 0xf000_d1c2); // tb0 0,r0,450
        memory.enforce = w;
    }

    const layout = try buildStack(memory, argv, envp);

    var ri: u5 = 0;
    while (true) {
        runner.setReg(ri, 0);
        if (ri == 31) break;
        ri += 1;
    }
    runner.cpu.branch_pending = false;

    // Register handoff (identical to SysV/88).
    runner.setReg(2, layout.argc); // r2 = argc
    runner.setReg(3, layout.argv_ptr); // r3 = argv
    runner.setReg(4, layout.envp_ptr); // r4 = envp
    runner.setReg(6, 0); // r6 = cleanup fn (none)
    runner.setReg(machine.Reg.sp, layout.sp); // r31 = SP
    runner.setReg(machine.Reg.link, halt_pad); // r1 = return address -> halt pad
    runner.setPc(entry);
}

/// OpenBSD/luna88k process setup. Unlike SysV/88, OpenBSD's `_start` reads
/// argc/argv/envp off the STACK itself (r2=mem[sp], r3=sp+4, envp derived) and
/// does NOT rely on a register handoff. So we build the same stack image via
/// buildStack() but leave r2..r6 alone; only r31 (SP) and PC matter. The halt
/// pad uses the OpenBSD exit stub (vector 450, number in r13).
pub fn setupOpenbsd(
    runner: *machine.Runner,
    entry: u32,
    brk: u32,
    argv: []const []const u8,
    envp: []const []const u8,
    auxv: []const AuxEntry,
) StartError!void {
    const memory = runner.memory;

    memory.addRegion(stack_top - stack_size, stack_size, .{ .read = true, .write = true }) catch return error.OutOfStack;
    // Pad holds the exit stub (@halt_pad) and the signal-return trampoline
    // (@halt_pad+16); map 32 bytes r-x.
    memory.addRegion(halt_pad, 32, .{ .read = true, .exec = true }) catch return error.OutOfStack;

    // Pre-map an initial heap [brk, brk+initial_heap) as RW, zero-filled.
    {
        const w = memory.enforce;
        memory.enforce = false;
        memory.zero(brk, initial_heap);
        memory.enforce = w;
    }
    memory.addRegion(brk, initial_heap, .{ .read = true, .write = true }) catch return error.OutOfStack;
    runner.brk = brk + initial_heap;
    runner.brk_base = brk;

    {
        const w = memory.enforce;
        memory.enforce = false;
        // Halt pad @halt_pad: OpenBSD SYS_exit stub (`or r13,r0,1; tb0 0,r0,450`)
        // so a stray `jmp r1` out of _start terminates cleanly.
        memory.write32(halt_pad + 0, (@as(u32, 0x16) << 26) | (@as(u32, 13) << 21) | 1); // or r13,r0,1
        memory.write32(halt_pad + 4, 0xf000_d1c2); // tb0 0,r0,450
        // Signal-return trampoline @halt_pad+16: `or r2,r0,r31` (scp = sp, which
        // points at the sigcontext) then `sigreturn` (r13=103; tb0 0,r0,450).
        // A signal handler returns here (r1 = sig_tramp).
        memory.write32(halt_pad + 16, 0xf440_581f); // or r2, r0, r31
        memory.write32(halt_pad + 20, (@as(u32, 0x16) << 26) | (@as(u32, 13) << 21) | 103); // or r13,r0,103
        memory.write32(halt_pad + 24, 0xf000_d1c2); // tb0 0,r0,450
        memory.enforce = w;
    }
    runner.sig_tramp = halt_pad + 16;

    const layout = try buildStackAux(memory, argv, envp, auxv);

    // A real exec(2) hands the new program a CLEAN register file. On the
    // initial launch cpu.reset() already zeroed the GPRs, but on exec (this is
    // reached from a forked child servicing execve) the CPU still holds the
    // caller's register values. Zero them so the new image never reads a stale
    // parent register — OpenBSD's _start reads several GPRs before initializing
    // them, and a leftover parent pointer (e.g. make's) makes a static echo
    // fault. (SysV/88 relies on the register handoff below and is similarly
    // cleared by its own setup path.)
    var ri: u5 = 0;
    while (true) {
        runner.setReg(ri, 0);
        if (ri == 31) break;
        ri += 1;
    }
    runner.cpu.branch_pending = false;

    // No register handoff: _start reads argc/argv/envp from the stack.
    runner.setReg(machine.Reg.sp, layout.sp); // r31 = SP (points at argc)
    runner.setReg(machine.Reg.link, halt_pad); // r1 = return address -> halt pad
    runner.setPc(entry);
}

/// NetBSD/luna88k process setup. NetBSD's `_start`/`__start` reads
/// argc/argv/envp off the STACK, but (unlike OpenBSD, which reads argc from
/// *r31) the kernel passes a POINTER to the argc block in **r2** — `__start`
/// does `argc = *r2; argv = r2 + 4` (verified via Ghidra, docs/abi-netbsd.md).
/// So we build the classic argc/argv/envp stack image and set BOTH r31 (SP)
/// and r2 to point at argc. No ELF aux vector is needed for a static binary.
/// The halt pad uses the NetBSD exit stub (vector 128, number in r13).
pub fn setupNetbsd(
    runner: *machine.Runner,
    entry: u32,
    brk: u32,
    argv: []const []const u8,
    envp: []const []const u8,
) StartError!void {
    const memory = runner.memory;

    memory.addRegion(stack_top - stack_size, stack_size, .{ .read = true, .write = true }) catch return error.OutOfStack;
    // Pad holds the exit stub (@halt_pad) and the signal-return trampoline
    // (@halt_pad+16); map 32 bytes r-x.
    memory.addRegion(halt_pad, 32, .{ .read = true, .exec = true }) catch return error.OutOfStack;

    // Pre-map an initial heap [brk, brk+initial_heap) as RW, zero-filled.
    {
        const w = memory.enforce;
        memory.enforce = false;
        memory.zero(brk, initial_heap);
        memory.enforce = w;
    }
    memory.addRegion(brk, initial_heap, .{ .read = true, .write = true }) catch return error.OutOfStack;
    runner.brk = brk + initial_heap;
    runner.brk_base = brk;

    {
        const w = memory.enforce;
        memory.enforce = false;
        // Halt pad @halt_pad: NetBSD SYS_exit stub (`or r13,r0,1; tb0 0,r0,128`)
        // so a stray `jmp r1` out of _start terminates cleanly.
        memory.write32(halt_pad + 0, (@as(u32, 0x16) << 26) | (@as(u32, 13) << 21) | 1); // or r13,r0,1
        memory.write32(halt_pad + 4, 0xf000_d080); // tb0 0,r0,128
        // Signal-return trampoline @halt_pad+16: `or r2,r0,r31` (scp = sp) then
        // `sigreturn` (r13=295 = SYS___sigreturn14; tb0 0,r0,128).
        memory.write32(halt_pad + 16, 0xf440_581f); // or r2, r0, r31
        memory.write32(halt_pad + 20, (@as(u32, 0x16) << 26) | (@as(u32, 13) << 21) | 295); // or r13,r0,295
        memory.write32(halt_pad + 24, 0xf000_d080); // tb0 0,r0,128
        memory.enforce = w;
    }
    runner.sig_tramp = halt_pad + 16;

    const layout = try buildStack(memory, argv, envp);

    // A real exec(2) hands the new program a CLEAN register file.
    var ri: u5 = 0;
    while (true) {
        runner.setReg(ri, 0);
        if (ri == 31) break;
        ri += 1;
    }
    runner.cpu.branch_pending = false;

    // r2 = pointer to the argc block (NetBSD __start reads argc = *r2), and
    // r31 = SP points at the same block.
    runner.setReg(2, layout.sp); // r2 = &argc
    runner.setReg(machine.Reg.sp, layout.sp); // r31 = SP (points at argc)
    runner.setReg(machine.Reg.link, halt_pad); // r1 = return address -> halt pad
    runner.setPc(entry);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "stack image: argc/argv/envp vectors and strings" {
    var memory = try mem.Memory.init(std.testing.allocator);
    defer memory.deinit();

    const argv = [_][]const u8{ "echo", "hello", "world" };
    const envp = [_][]const u8{ "PATH=/bin", "HOME=/" };
    const layout = try buildStack(&memory, &argv, &envp);

    try std.testing.expectEqual(@as(u32, 3), memory.read32(layout.sp));
    try std.testing.expectEqual(layout.sp + 4, layout.argv_ptr);

    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("echo", memory.readCStr(memory.read32(layout.argv_ptr + 0), &buf));
    try std.testing.expectEqualStrings("hello", memory.readCStr(memory.read32(layout.argv_ptr + 4), &buf));
    try std.testing.expectEqualStrings("world", memory.readCStr(memory.read32(layout.argv_ptr + 8), &buf));
    try std.testing.expectEqual(@as(u32, 0), memory.read32(layout.argv_ptr + 12)); // argv NULL

    try std.testing.expectEqualStrings("PATH=/bin", memory.readCStr(memory.read32(layout.envp_ptr + 0), &buf));
    try std.testing.expectEqualStrings("HOME=/", memory.readCStr(memory.read32(layout.envp_ptr + 4), &buf));
    try std.testing.expectEqual(@as(u32, 0), memory.read32(layout.envp_ptr + 8)); // envp NULL

    // SP is 8-byte aligned.
    try std.testing.expectEqual(@as(u32, 0), layout.sp & 7);
}
