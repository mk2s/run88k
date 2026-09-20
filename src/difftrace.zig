//! Differential-trace mode: run the guest and, over a chosen PC window, emit a
//! JSONL trace of each instruction as (pre-registers, opcode word, memory
//! operand, post-registers). A companion Python driver (tools/difftrace.py)
//! replays each opword through the nono LUNA-88k oracle from the same
//! pre-state and reports the first divergence — pinpointing a core bug without
//! manual instruction archaeology.
//!
//! Emitted per line (one JSON object per executed instruction in the window):
//!   { "pc":.., "op":.., "pre":[r0..r31], "cf":.., "post":[r0..r31], "cf2":..,
//!     "mem_addr":.., "mem_pre":.., "mem_post":.. }
//! mem_* are present for load/store instructions so the driver can prime nono's
//! memory (loads) and check stores. Word-sized; good enough for the integer
//! setlocale path we are chasing.

const std = @import("std");
const m88k = @import("m88k");
const mem = @import("mem.zig");
const machine = @import("machine.zig");
const elf = @import("loaders/elf.zig");
const process = @import("process.zig");
const sysv = @import("abi/sysv88.zig");
const dispatch = @import("syscalls/dispatch.zig");
const fsmod = @import("fs.zig");
const dynamic = @import("loaders/dynamic.zig");
const procmodel = @import("procmodel.zig");

extern "c" fn dprintf(fd: c_int, fmt: [*:0]const u8, ...) c_int;
extern "c" fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern "c" fn close(fd: c_int) c_int;

const Cpu = m88k.Cpu;

/// Decode the memory operand address for load/store opcodes so the driver can
/// prime/verify nono memory. Returns null for non-memory ops. Mirrors the
/// core's EA computation (immediate and register-indexed forms).
fn memOperand(cpu: *const Cpu, op: u32) ?u32 {
    const op1 = (op >> 26) & 0x3f;
    const s1 = cpu.getReg(@intCast((op >> 16) & 0x1f));
    switch (op1) {
        // Immediate load/store/xmem: EA = rS1 + zext(imm16)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b => {
            return s1 +% (op & 0xffff);
        },
        // Register-indexed load/store/xmem live in op1=0x3d with op4 in 15..12.
        0x3d => {
            const op4 = (op >> 12) & 0xf;
            if (op4 == 0x0 or op4 == 0x1 or op4 == 0x2) {
                const s2 = cpu.getReg(@intCast(op & 0x1f));
                const ty10 = (op >> 10) & 0x3;
                const scaled = ((op >> 9) & 1) != 0;
                const scale: u32 = switch (ty10) {
                    0 => 8,
                    1 => 4,
                    2 => 2,
                    else => 1,
                };
                return if (scaled) s1 +% s2 *% scale else s1 +% s2;
            }
            return null;
        },
        else => return null,
    }
}

fn emitRegs(cpu: *const Cpu) void {
    var i: u5 = 0;
    _ = dprintf(1, "[");
    while (i < 31) : (i += 1) {
        _ = dprintf(1, "%u,", cpu.getReg(i));
    }
    _ = dprintf(1, "%u]", cpu.getReg(31));
}

/// Run cat-style: load ELF, set up process, and trace instructions whose PC is
/// in [win_lo, win_hi) once we have executed at least `skip` instructions.
pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    argv: []const []const u8,
    win_lo: u32,
    win_hi: u32,
    max_emit: usize,
    mounts: []const fsmod.Mount,
) !void {
    const image = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 * 1024 * 1024)) catch {
        _ = dprintf(2, "difftrace: cannot read binary\n");
        return;
    };
    defer gpa.free(image);

    var memory = try mem.Memory.init(gpa);
    defer memory.deinit();
    defer mem.setActive(null);
    const img = try elf.load(&memory, image);

    // Guest filesystem (mount table + fd table), if any mounts were given.
    // sh and dynamic binaries need this to resolve paths and libraries.
    var fs: ?fsmod.Fs = null;
    if (mounts.len > 0) {
        fs = try fsmod.Fs.init(gpa);
        for (mounts) |m| fs.?.addMount(m.guest_prefix, m.host_root) catch {};
    }
    defer if (fs) |*f| f.deinit();

    var runner = machine.Runner.init(&memory);
    runner.attachBus();
    runner.syscall_vector = sysv.syscall_vector;
    runner.handler = &dispatch.dispatch;
    if (fs) |*f| runner.fs = f;

    // Process model (fork/exec/wait/pipe), only when a mount table is present.
    var pm: ?procmodel.HostProcess = null;
    if (fs) |*f| {
        pm = procmodel.HostProcess.init(&runner, f, io, gpa);
        runner.procmodel = &pm.?;
    }

    // Dynamic linking: load NEEDED libraries and apply relocations.
    if (img.is_dynamic) {
        if (fs) |*f| {
            dynamic.reset();
            dynamic.link(&memory, f, io, gpa, img.dynamic_vaddr, img.brk) catch {
                _ = dprintf(2, "difftrace: dynamic link failed\n");
                return;
            };
        } else {
            _ = dprintf(2, "difftrace: binary is dynamic; pass --root/--mount\n");
            return;
        }
    }

    const envp = [_][]const u8{"PATH=/usr/bin:/bin"};
    try process.setup(&runner, img.entry, img.brk, argv, &envp);
    memory.enforce = true;

    var emitted: usize = 0;
    var i: usize = 0;
    const cpu = &runner.cpu;
    while (i < 50_000_000 and emitted < max_emit) : (i += 1) {
        const pc = cpu.pc;
        const in_win = pc >= win_lo and pc < win_hi;
        if (in_win) {
            const op = memory.read32(pc);
            const maddr = memOperand(cpu, op);
            const mpre: u32 = if (maddr) |a| (if (@as(u64, a) + 4 <= mem.Memory.size) memory.read32(a) else 0) else 0;

            // pre-state
            _ = dprintf(1, "{\"pc\":%u,\"op\":%u,\"pre\":", pc, op);
            emitRegs(cpu);
            _ = dprintf(1, ",\"cf\":%u", @as(c_uint, cpu.cf));

            const res = m88k.step(cpu);
            if (res == .trapped and cpu.last_exception == sysv.syscall_vector) {
                _ = dispatch.dispatch(&runner);
            }

            const mpost: u32 = if (maddr) |a| (if (@as(u64, a) + 4 <= mem.Memory.size) memory.read32(a) else 0) else 0;
            _ = dprintf(1, ",\"post\":");
            emitRegs(cpu);
            _ = dprintf(1, ",\"cf2\":%u", @as(c_uint, cpu.cf));
            if (maddr) |a| {
                _ = dprintf(1, ",\"maddr\":%u,\"mpre\":%u,\"mpost\":%u", a, mpre, mpost);
            }
            _ = dprintf(1, "}\n");
            emitted += 1;
        } else {
            const res = m88k.step(cpu);
            if (res == .trapped and cpu.last_exception == sysv.syscall_vector) {
                if (!dispatch.dispatch(&runner)) break;
            }
        }
        if (memory.fault.kind != .none) {
            _ = dprintf(2, "difftrace: fault at ppc=%x addr=%x after %d insns\n", cpu.ppc, memory.fault.address, @as(c_int, @intCast(i)));
            break;
        }
        if (runner.exit_status != null) break;
    }
    _ = dprintf(2, "difftrace: emitted %d instructions\n", @as(c_int, @intCast(emitted)));
}
