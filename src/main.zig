//! run88k — m88k user-mode syscall emulator (CLI entry).
//!
//! `run <binary> [args...]` loads an MC88000 executable (ELF32-BE or, for
//! Tektronix UTek, 88K BCS COFF), sets up the per-personality process stack,
//! installs the matching syscall dispatcher, and runs the guest, servicing
//! syscalls against the host. Five personalities are supported — SysV/88,
//! OpenBSD, NetBSD, Tektronix UTek, and DG/UX — auto-detected from the image or
//! forced with `--os`. Static and dynamically-linked binaries both run (SysV/88
//! and DG/UX self-link in-process; OpenBSD runs the guest's own ld.so).
//!
//! `difftrace <binary> <lo> <hi> <max> [args...]` emits a per-instruction JSONL
//! trace for a PC window, for lockstep differential testing against the nono
//! oracle. `--selftest` runs a core-integration self-check.
//!
//! Uses the current Zig "full" main signature `main(init: std.process.Init)`
//! and a libc `write` extern for output (stable across the churning std.Io
//! API, same as the sibling runupc). libc is linked in build.zig.

const std = @import("std");
const m88k = @import("m88k");
const mem = @import("mem.zig");
const machine = @import("machine.zig");
const elf = @import("loaders/elf.zig");
const coff = @import("loaders/coff.zig");
const process = @import("process.zig");
const sysv = @import("abi/sysv88.zig");
const obsd = @import("abi/openbsd.zig");
const utek = @import("abi/utek.zig");
const dgux_abi = @import("abi/dgux.zig");
const dispatch = @import("syscalls/dispatch.zig");
const dispatch_openbsd = @import("syscalls/dispatch_openbsd.zig");
const dispatch_utek = @import("syscalls/dispatch_utek.zig");
const dispatch_dgux = @import("syscalls/dispatch_dgux.zig");
const dispatch_netbsd = @import("syscalls/dispatch_netbsd.zig");
const nbsd = @import("abi/netbsd.zig");
const difftrace = @import("difftrace.zig");
const fsmod = @import("fs.zig");
const dynamic = @import("loaders/dynamic.zig");
const procmodel = @import("procmodel.zig");

extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

fn out(bytes: []const u8) void {
    _ = write(2, bytes.ptr, bytes.len);
}

fn outf(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    out(std.fmt.bufPrint(&buf, fmt, args) catch return);
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    // Parse leading flags. --root sets guest "/"; --mount GUEST=HOST adds a
    // mount (repeatable). Up to 16 mounts.
    var i: usize = 1;
    var mounts: [16]fsmod.Mount = undefined;
    var nmounts: usize = 0;
    var init_cwd: ?[]const u8 = null;
    var os_choice: ?Os = null; // null => auto-detect from the ELF
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--trace")) {
            dispatch.trace = true;
            dispatch_openbsd.trace = true;
            dispatch_utek.trace = true;
            dispatch_dgux.trace = true;
            dispatch_netbsd.trace = true;
        } else if (std.mem.eql(u8, args[i], "--trace-all")) {
            // Per-instruction PC/register trace to stderr (deep core debugging).
            machine.trace_all = true;
        } else if (std.mem.eql(u8, args[i], "--watch") and i + 1 < args.len) {
            machine.watch_addr = std.fmt.parseInt(u32, args[i + 1], 16) catch 0;
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--max-steps") and i + 1 < args.len) {
            // Per-process instruction budget (0 = unlimited). A heavy -O2
            // compile can need billions of emulated instructions.
            machine.Runner.default_max_steps = std.fmt.parseInt(u64, args[i + 1], 10) catch machine.Runner.default_max_steps;
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--os") and i + 1 < args.len) {
            if (std.mem.eql(u8, args[i + 1], "openbsd")) {
                os_choice = .openbsd;
            } else if (std.mem.eql(u8, args[i + 1], "sysv88") or std.mem.eql(u8, args[i + 1], "sysv")) {
                os_choice = .sysv88;
            } else if (std.mem.eql(u8, args[i + 1], "utek")) {
                os_choice = .utek;
            } else if (std.mem.eql(u8, args[i + 1], "dgux")) {
                os_choice = .dgux;
            } else if (std.mem.eql(u8, args[i + 1], "netbsd")) {
                os_choice = .netbsd;
            } else {
                outf("run88k: unknown --os '{s}' (use sysv88, openbsd, netbsd, utek or dgux)\n", .{args[i + 1]});
                return;
            }
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--selftest")) {
            try selftest(gpa);
            return;
        } else if (std.mem.eql(u8, args[i], "--cwd") and i + 1 < args.len) {
            // Set the guest's initial working directory (guest-absolute). Tools
            // like cc run their sub-tools with output paths relative to CWD, so
            // this must point at a writable mount to compile into.
            init_cwd = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--root") and i + 1 < args.len) {
            if (nmounts < mounts.len) {
                mounts[nmounts] = .{ .guest_prefix = "/", .host_root = args[i + 1] };
                nmounts += 1;
            }
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--mount") and i + 1 < args.len) {
            const spec = args[i + 1];
            if (std.mem.indexOfScalar(u8, spec, '=')) |eq| {
                if (nmounts < mounts.len) {
                    mounts[nmounts] = .{ .guest_prefix = spec[0..eq], .host_root = spec[eq + 1 ..] };
                    nmounts += 1;
                }
            }
            i += 1;
        } else break;
    }

    const rest = args[i..];
    if (rest.len >= 2 and std.mem.eql(u8, rest[0], "run")) {
        const code = try cmdRun(gpa, io, rest[1], rest[1..], mounts[0..nmounts], init_cwd, os_choice);
        std.process.exit(@intCast(code & 0xff));
    }

    // difftrace <binary> <win_lo_hex> <win_hi_hex> <max> [args...]
    // Emit a per-instruction JSONL trace on stdout for instructions whose PC is
    // in [win_lo, win_hi). Diagnostics go to stderr.
    if (rest.len >= 5 and std.mem.eql(u8, rest[0], "difftrace")) {
        const lo = std.fmt.parseInt(u32, rest[2], 16) catch 0;
        const hi = std.fmt.parseInt(u32, rest[3], 16) catch 0xffffffff;
        const max = std.fmt.parseInt(usize, rest[4], 10) catch 2000;
        const prog_args = rest[5..];
        // argv[0] = binary name; if no extra args, pass just the binary.
        var argv_buf: [64][]const u8 = undefined;
        argv_buf[0] = rest[1];
        var n: usize = 1;
        for (prog_args) |a| {
            if (n >= argv_buf.len) break;
            argv_buf[n] = a;
            n += 1;
        }
        try difftrace.run(gpa, io, rest[1], argv_buf[0..n], lo, hi, max, mounts[0..nmounts]);
        return;
    }

    out(
        \\run88k — m88k user-mode syscall emulator
        \\
        \\Usage:
        \\  run88k [flags] run <binary> [args...]
        \\      Load and run an MC88000 guest binary, servicing its syscalls.
        \\  run88k [flags] difftrace <binary> <lo-hex> <hi-hex> <max> [args...]
        \\      Emit a per-instruction JSONL trace for PCs in [lo,hi) (core debugging).
        \\  run88k --selftest
        \\      Core-integration self-check.
        \\
        \\Flags:
        \\  --root DIR         mount DIR as the guest /
        \\  --mount G=H        mount host path H at guest prefix G (repeatable)
        \\  --cwd DIR          guest-absolute initial working directory
        \\  --os NAME          force personality: sysv88, openbsd, netbsd, utek, dgux
        \\                     (auto-detected from the image when omitted)
        \\  --trace            strace-style per-syscall logging to stderr
        \\  --trace-all        per-instruction PC/register trace (deep core debugging)
        \\  --watch HEX        watch a guest memory address
        \\  --max-steps N      instruction budget (0 = unlimited)
        \\
        \\Formats: ELF32-BE MC88000 (SysV/88, OpenBSD, NetBSD, DG/UX) and 88K BCS
        \\COFF (UTek). Static and dynamically-linked binaries are both supported.
        \\
    );
}

/// Guest OS personality.
const Os = enum { sysv88, openbsd, netbsd, utek, dgux };

/// Load base for the OpenBSD interpreter (/usr/libexec/ld.so). Chosen above the
/// exec + heap and below the mmap bump region (0x08000000) and stack
/// (0x0c000000). ld.so is ~0x40000 bytes; leave plenty of room.
const OBSD_LDSO_BASE: u32 = 0x0400_0000;

/// Load and run a guest ELF binary. `path` is the host path to the binary;
/// `argv` is the guest argument vector (argv[0] = program name). `os_choice`
/// forces a personality; when null it is auto-detected from the ELF.
fn cmdRun(gpa: std.mem.Allocator, io: std.Io, path: []const u8, argv: []const []const u8, mounts: []const fsmod.Mount, init_cwd: ?[]const u8, os_choice: ?Os) !u32 {
    // Read the whole binary.
    const image = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 * 1024 * 1024)) catch |e| {
        outf("run88k: cannot read '{s}': {s}\n", .{ path, @errorName(e) });
        return 127;
    };
    defer gpa.free(image);

    var memory = try mem.Memory.init(gpa);
    defer memory.deinit();
    defer mem.setActive(null);

    // Guest filesystem (mount table + fd table), if any mounts were given.
    // Built before loading so the COFF/UTek path can use it too.
    var fs: ?fsmod.Fs = null;
    if (mounts.len > 0) {
        fs = try fsmod.Fs.init(gpa);
        for (mounts) |m| fs.?.addMount(m.guest_prefix, m.host_root) catch {};
        if (init_cwd) |cw| fs.?.chdir(cw) catch {
            outf("run88k: --cwd '{s}' invalid\n", .{cw});
            return 126;
        };
    }
    defer if (fs) |*f| f.deinit();

    // Rewrite argv[0] to the GUEST path. The run target is given as a host
    // path (e.g. /mnt/netbsd/usr/bin/cc) so we can read it, but the guest
    // program must see its own guest-absolute argv[0] (/usr/bin/cc). GCC in
    // particular derives its tool-search "exec prefix" from argv[0]; leaving
    // the host prefix there makes cc look for cc1 under /mnt/netbsd/usr/bin and
    // never find /usr/libexec/cc1. Reverse-map through the mount table.
    var argv_buf: [256][]const u8 = undefined;
    var argv_g: []const []const u8 = argv;
    if (fs) |*f| {
        if (argv.len > 0 and argv.len <= argv_buf.len) {
            var g0buf: [2048]u8 = undefined;
            if (f.hostToGuest(argv[0], &g0buf)) |g0| {
                // g0 points into g0buf; copy so it outlives this scope (freed at exit).
                const g0_owned = gpa.dupe(u8, g0) catch argv[0];
                argv_buf[0] = g0_owned;
                for (argv[1..], 1..) |a, k| argv_buf[k] = a;
                argv_g = argv_buf[0..argv.len];
            }
        }
    }

    // Tektronix UTek XD88: a static 88K BCS COFF binary. Detected by the COFF
    // magic (or forced with --os utek). This is a self-contained path — UTek
    // binaries are statically linked, so there is no dynamic-linking branch.
    if (os_choice == .utek or (os_choice == null and coff.detect(image))) {
        return cmdRunUtek(&memory, image, path, argv_g, if (fs) |*f| f else null, io, gpa);
    }

    const img = elf.load(&memory, image) catch |e| {
        outf("run88k: cannot load '{s}': {s}\n", .{ path, @errorName(e) });
        return 126;
    };

    // Select the personality: explicit --os wins, else auto-detect from the
    // ELF (OpenBSD markers -> openbsd, NetBSD note -> netbsd, otherwise
    // SysV/88).
    const os: Os = os_choice orelse (if (img.is_openbsd) .openbsd else if (img.is_netbsd) .netbsd else .sysv88);

    var runner = machine.Runner.init(&memory);
    runner.attachBus(); // sets bus + cpu.reset(); mem.active = &memory
    switch (os) {
        .sysv88 => {
            runner.syscall_vector = sysv.syscall_vector;
            runner.handler = &dispatch.dispatch;
        },
        .openbsd => {
            runner.syscall_vector = obsd.syscall_vector;
            runner.handler = &dispatch_openbsd.dispatch;
            // ld.so uses `tb0 0,r0,451` as a cache-flush after writing PLT/GOT;
            // treat it as a benign no-op (our memory is coherent).
            runner.cacheflush_vector = 451;
        },
        .netbsd => {
            runner.syscall_vector = nbsd.syscall_vector; // 128
            runner.handler = &dispatch_netbsd.dispatch;
        },
        .dgux => {
            // DG/UX has TWO syscall gates: 0x1c2 (450, standard) and 0x080
            // (128, DG-extended). Route both to the dgux dispatcher, which
            // reads cpu.last_exception to tell the gates apart.
            runner.syscall_vector = dgux_abi.syscall_vector; // 450 (std)
            runner.syscall_vector2 = dgux_abi.syscall_vector_ext; // 128 (ext)
            runner.syscall_vector3 = dgux_abi.syscall_vector_local; // 449 (local)
            runner.syscall_vector4 = dgux_abi.syscall_vector_fast; // 503 (fast)
            runner.handler = &dispatch_dgux.dispatch;
            // 448 (sigreturn) is also a DG/UX gate; route it too. The runner
            // has four vector slots, so fold sigreturn into the cacheflush slot
            // (both are "skip and continue" style) — the dispatcher handles it.
            runner.cacheflush_vector = dgux_abi.syscall_vector_sigret;
        },
        .utek => unreachable, // handled by the early COFF branch above
    }
    if (fs) |*f| runner.fs = f;

    // Process model (fork/exec/wait/pipe) — needs the fs for exec path
    // resolution. Only wired when a mount table is present.
    var pm: ?procmodel.HostProcess = null;
    if (fs) |*f| {
        pm = procmodel.HostProcess.init(&runner, f, io, gpa);
        pm.?.openbsd = (os == .openbsd);
        pm.?.dgux = (os == .dgux);
        pm.?.netbsd = (os == .netbsd);
        runner.procmodel = &pm.?;
    }

    // start_pc is where the guest begins. For a static exec (or the SysV
    // self-linked path) this is the exec's own entry. For an OpenBSD dynamic
    // exec we map the interpreter (ld.so) and start THERE; ld.so maps the
    // libraries and eventually transfers to the exec's AT_ENTRY itself.
    var start_pc = img.entry;
    var interp_base: u32 = 0;

    // Dynamic linking.
    if (img.is_dynamic) {
        if (fs == null) {
            outf("run88k: '{s}' is dynamically linked; pass --root/--mount so libraries resolve\n", .{path});
            return 126;
        }
        switch (os) {
            .sysv88 => {
                // SysV/88: we self-link (load NEEDED libs + apply relocations).
                dynamic.reset();
                dynamic.link(&memory, &fs.?, io, gpa, img.dynamic_vaddr, img.brk) catch |e| {
                    outf("run88k: dynamic link failed: {s}\n", .{@errorName(e)});
                    return 126;
                };
            },
            .openbsd => {
                // OpenBSD: run the guest's real /usr/libexec/ld.so. Map it at a
                // load base and hand control to its entry; it does the rest.
                const interp = elf.interpPath(image) orelse "/usr/libexec/ld.so";
                var hbuf: [2048]u8 = undefined;
                const hp = fs.?.resolve(interp, &hbuf) catch {
                    outf("run88k: cannot resolve interpreter '{s}'\n", .{interp});
                    return 126;
                };
                const ldimg = std.Io.Dir.cwd().readFileAlloc(io, hp, gpa, .limited(16 * 1024 * 1024)) catch |e| {
                    outf("run88k: cannot read interpreter '{s}': {s}\n", .{ interp, @errorName(e) });
                    return 126;
                };
                defer gpa.free(ldimg);
                const was = memory.enforce;
                memory.enforce = false;
                const ldobj = elf.mapSegments(&memory, ldimg, OBSD_LDSO_BASE) catch |e| {
                    memory.enforce = was;
                    outf("run88k: cannot map interpreter: {s}\n", .{@errorName(e)});
                    return 126;
                };
                memory.enforce = was;
                interp_base = OBSD_LDSO_BASE;
                start_pc = ldobj.entry; // biased ld.so entry
            },
            .dgux => {
                // DG/UX dynamic binaries use the guest's own /usr/dglib
                // ld.so; that path is a follow-on. For now self-link like
                // SysV/88 (both are SVR4) so simple dynamic execs can load.
                dynamic.reset();
                dynamic.link(&memory, &fs.?, io, gpa, img.dynamic_vaddr, img.brk) catch |e| {
                    outf("run88k: dynamic link failed: {s}\n", .{@errorName(e)});
                    return 126;
                };
            },
            .netbsd => {
                // NetBSD/luna88k dynamic binaries would run the guest's own
                // /usr/libexec/ld.elf_so (like the OpenBSD ld.so path). Our
                // NetBSD workload is statically linked, so this isn't wired yet.
                outf("run88k: NetBSD dynamic linking not yet supported ('{s}' is dynamic)\n", .{path});
                return 126;
            },
            .utek => unreachable, // UTek is static-only, handled earlier
        }
    }

    // Environment: minimal for now.
    const envp = [_][]const u8{"PATH=/usr/bin:/bin"};
    switch (os) {
        .sysv88, .dgux => process.setup(&runner, start_pc, img.brk, argv_g, &envp) catch |e| {
            // DG/UX static preinit uses the same SVR4 register handoff
            // (r2=argc, r3=argv, r4=envp) — verified from its entry at 0x10011c.
            outf("run88k: process setup failed: {s}\n", .{@errorName(e)});
            return 126;
        },
        .openbsd => {
            // OpenBSD's _start / ld.so walk the ELF aux vector after envp.
            // AT_BASE is ld.so's load base (0 for a static exec); AT_PHDR/PHENT/
            // PHNUM/ENTRY always describe the EXEC (never ld.so), so ld.so can
            // find and start the program it was asked to run.
            const aux = [_]process.AuxEntry{
                .{ .id = 3, .val = img.phdr_vaddr }, // AUX_phdr (exec)
                .{ .id = 4, .val = img.phent }, // AUX_phent
                .{ .id = 5, .val = img.phnum }, // AUX_phnum
                .{ .id = 6, .val = 0x1000 }, // AUX_pagesz
                .{ .id = 7, .val = interp_base }, // AUX_base (ld.so, 0 if static)
                .{ .id = 9, .val = img.entry }, // AUX_entry (exec)
            };
            process.setupOpenbsd(&runner, start_pc, img.brk, argv_g, &envp, &aux) catch |e| {
                outf("run88k: process setup failed: {s}\n", .{@errorName(e)});
                return 126;
            };
        },
        .netbsd => process.setupNetbsd(&runner, start_pc, img.brk, argv_g, &envp) catch |e| {
            outf("run88k: process setup failed: {s}\n", .{@errorName(e)});
            return 126;
        },
        .utek => unreachable, // handled by the early COFF branch above
    }

    // Enforce permissions now that loading + stack setup are done.
    memory.enforce = true;

    if (dispatch.trace) {
        outf("run88k: entry={x} brk={x} argc={d}\n", .{ img.entry, img.brk, argv.len });
    }

    const reason = runner.run(machine.Runner.default_max_steps);
    switch (reason) {
        .exited => return runner.exit_status orelse 0,
        .halted => return 0,
        .fault => {
            faultReport(&runner);
            return 139; // SIGSEGV-ish
        },
        .timed_out => {
            outf("run88k: guest hit the {d}-instruction budget (raise it with --max-steps N, 0=unlimited; a heavy -O2 compile can need billions)\n", .{runner.steps_run});
            out("recent PCs: ");
            var k: usize = 0;
            while (k < runner.pc_ring.len) : (k += 1) {
                outf("{x} ", .{runner.pc_ring[(runner.pc_ring_i + k) % runner.pc_ring.len]});
            }
            out("\n");
            return 124;
        },
        .trap => {
            outf("run88k: unexpected trap vector {d} at ppc={x} (not the syscall vector)\n", .{ runner.last_trap, runner.cpu.ppc });
            return 132;
        },
    }
}

/// Load and run a Tektronix UTek XD88 binary: a static 88K BCS COFF
/// executable. Self-contained (no dynamic linking): load the COFF image, set
/// up the SysV-style register handoff with a UTek exit trampoline, install the
/// UTek dispatcher (vector 450, number r9), and run.
fn cmdRunUtek(
    memory: *mem.Memory,
    image: []const u8,
    path: []const u8,
    argv: []const []const u8,
    fs: ?*fsmod.Fs,
    io: std.Io,
    gpa: std.mem.Allocator,
) !u32 {
    const img = coff.load(memory, image) catch |e| {
        outf("run88k: cannot load '{s}' as 88K BCS COFF: {s}\n", .{ path, @errorName(e) });
        return 126;
    };

    var runner = machine.Runner.init(memory);
    runner.attachBus(); // sets bus + cpu.reset(); mem.active = memory
    runner.syscall_vector = utek.syscall_vector; // 450 (main syscalls)
    runner.syscall_vector2 = utek.syscall_vector_local; // 449 (getrlimit/setrlimit/sys_local)
    runner.handler = &dispatch_utek.dispatch;
    if (fs) |f| runner.fs = f;

    // Process model (fork/exec/wait/pipe), when a mount table is present.
    var pm: ?procmodel.HostProcess = null;
    if (fs) |f| {
        pm = procmodel.HostProcess.init(&runner, f, io, gpa);
        pm.?.utek = true; // exec loads static 88K BCS COFF via the UTek path
        runner.procmodel = &pm.?;
    }

    const envp = [_][]const u8{"PATH=/usr/bin:/bin"};
    process.setupUtek(&runner, img.entry, img.brk, argv, &envp) catch |e| {
        outf("run88k: process setup failed: {s}\n", .{@errorName(e)});
        return 126;
    };

    memory.enforce = true;

    if (dispatch_utek.trace) {
        outf("run88k: [utek] entry={x} brk={x} argc={d}\n", .{ img.entry, img.brk, argv.len });
    }

    const reason = runner.run(machine.Runner.default_max_steps);
    switch (reason) {
        .exited => return runner.exit_status orelse 0,
        .halted => return 0,
        .fault => {
            faultReport(&runner);
            out("recent PCs: ");
            var k: usize = 0;
            while (k < runner.pc_ring.len) : (k += 1) {
                outf("{x} ", .{runner.pc_ring[(runner.pc_ring_i + k) % runner.pc_ring.len]});
            }
            out("\n");
            return 139;
        },
        .timed_out => {
            outf("run88k: guest hit the {d}-instruction budget (raise it with --max-steps N, 0=unlimited; a heavy -O2 compile can need billions)\n", .{runner.steps_run});
            return 124;
        },
        .trap => {
            outf("run88k: unexpected trap vector {d} at ppc={x} (not the syscall vector)\n", .{ runner.last_trap, runner.cpu.ppc });
            return 132;
        },
    }
}

fn faultReport(runner: *machine.Runner) void {
    const f = runner.memory.fault;
    outf(
        "run88k: FAULT kind={s} addr={x} pc={x} ppc={x} ir={x}\n",
        .{ @tagName(f.kind), f.address, runner.cpu.pc, runner.cpu.ppc, runner.cpu.ir },
    );
    // Dump r1..r13 for context (the ABI-relevant registers).
    var idx: u5 = 1;
    while (idx <= 13) : (idx += 1) {
        outf("  r{d}={x}\n", .{ idx, runner.cpu.getReg(idx) });
    }
}

/// Core-integration self-check: assemble and run a SysV/88 syscall trap.
fn selftest(gpa: std.mem.Allocator) !void {
    var memory = try mem.Memory.init(gpa);
    defer memory.deinit();
    defer mem.setActive(null);
    memory.enforce = false;

    const entry: u32 = 0x0001_0000;
    memory.write32(entry + 0, (@as(u32, 0x18) << 26) | (@as(u32, 9) << 21) | 4); // addu r9,r0,4
    memory.write32(entry + 4, 0xf000_d1c3); // tb0 0,r0,451

    var runner = machine.Runner.init(&memory);
    runner.attachBus();
    runner.setPc(entry);

    const reason = runner.run(100);
    const num = runner.getReg(machine.Reg.syscall_num);
    outf("selftest: stop={s} last_trap={d} r9={d}\n", .{ @tagName(reason), runner.last_trap, num });
    if (reason == .trap and runner.last_trap == 451 and num == 4) {
        out("selftest: PASS\n");
    } else {
        out("selftest: FAIL\n");
        return error.SelftestFailed;
    }
}
