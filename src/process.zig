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

/// Build the argv/envp image on the stack and return the layout. Enforcement
/// is toggled off while scribbling and restored.
pub fn buildStack(
    memory: *mem.Memory,
    argv: []const []const u8,
    envp: []const []const u8,
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
    // envp[]+NULL, all 4-byte words. Lay it out from a longword-aligned sp.
    const n_argv: u32 = @intCast(argv.len);
    const n_envp: u32 = @intCast(envp.len);
    const total_words: u32 = 1 + (n_argv + 1) + (n_envp + 1);
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

    // Register handoff (docs/abi-sysv88.md).
    runner.setReg(2, layout.argc); // r2 = argc
    runner.setReg(3, layout.argv_ptr); // r3 = argv
    runner.setReg(4, layout.envp_ptr); // r4 = envp
    runner.setReg(6, 0); // r6 = cleanup fn (none)
    runner.setReg(machine.Reg.sp, layout.sp); // r31 = SP
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
