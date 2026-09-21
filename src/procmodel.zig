//! Process model for run88k: fork / execve / wait / pipe.
//!
//! Host-process backend (ported from the sibling runupc): a guest process maps
//! onto a host process. Guest `fork` == host `fork()`, which copies the whole
//! emulator — guest memory included — so the child continues emulating from the
//! same point with fork returning the child convention. Guest `wait` ==
//! `waitpid`; guest `pipe` == host `pipe()` wired into the guest fd table;
//! guest `execve` reloads a new ELF into the current address space and signals
//! the run loop to continue at the new entry.
//!
//! POSIX-only (needs host fork/waitpid/pipe). The syscall handlers call through
//! this so an in-process backend could replace it later for Windows.

const std = @import("std");
const builtin = @import("builtin");
const mem = @import("mem.zig");
const machine = @import("machine.zig");
const elf = @import("loaders/elf.zig");
const process = @import("process.zig");
const sysv = @import("abi/sysv88.zig");
const fsmod = @import("fs.zig");
const dynamic = @import("loaders/dynamic.zig");

/// Load base for the OpenBSD interpreter (/usr/libexec/ld.so). Kept in sync
/// with main.zig's OBSD_LDSO_BASE.
pub const OBSD_LDSO_BASE: u32 = 0x0400_0000;

const is_posix = builtin.os.tag != .windows;
const libc = if (is_posix) struct {
    pub extern "c" fn fork() c_int;
    pub extern "c" fn waitpid(pid: c_int, status: *c_int, options: c_int) c_int;
    pub extern "c" fn pipe(fds: *[2]c_int) c_int;
    pub extern "c" fn getpid() c_int;
} else struct {};

pub const ProcError = error{ NotSupported, ForkFailed, ExecFailed, PipeFailed, NoChild };

pub const WaitResult = struct {
    pid: u32,
    /// SVR wait status word: (exit_code & 0xff) << 8 for a normal exit.
    status: u32,
};

/// Host-process backend. One instance per Runner; stored (type-erased) on the
/// Runner so dispatch can reach it.
pub const HostProcess = struct {
    runner: *machine.Runner,
    fs: *fsmod.Fs,
    io: std.Io,
    gpa: std.mem.Allocator,
    /// Set by exec: the new entry point. The run loop, after a successful
    /// exec, sets PC here and continues (no PC advance past the trap).
    exec_entry: ?u32 = null,
    /// Break for the exec'd image; the dispatcher copies it into the Runner.
    new_brk: u32 = 0,
    /// True when running an OpenBSD guest: exec must map ld.so + build the ELF
    /// aux vector + use the stack-based startup instead of the SysV path.
    openbsd: bool = false,

    pub fn init(runner: *machine.Runner, fs: *fsmod.Fs, io: std.Io, gpa: std.mem.Allocator) HostProcess {
        return .{ .runner = runner, .fs = fs, .io = io, .gpa = gpa };
    }

    /// fork: host fork(). Returns the host rc: >0 child pid (parent), 0 (child).
    pub fn doFork(self: *HostProcess) ProcError!u32 {
        _ = self;
        if (!is_posix) return error.NotSupported;
        const rc = libc.fork();
        if (rc < 0) return error.ForkFailed;
        return @intCast(rc);
    }

    /// wait: reap any child; return {pid, SVR status word}. `nohang` maps to
    /// WNOHANG — when set and no child has exited yet, returns pid 0 (not an
    /// error), which is what a job scheduler like make polls for.
    pub fn doWait(self: *HostProcess) ProcError!WaitResult {
        return self.doWaitOpts(false);
    }
    pub fn doWaitOpts(self: *HostProcess, nohang: bool) ProcError!WaitResult {
        _ = self;
        if (!is_posix) return error.NotSupported;
        var status: c_int = 0;
        const WNOHANG: c_int = 1;
        const pid = libc.waitpid(-1, &status, if (nohang) WNOHANG else 0);
        if (pid < 0) return error.NoChild;
        if (pid == 0) return .{ .pid = 0, .status = 0 }; // WNOHANG: none ready
        const exit_code: u32 = (@as(u32, @bitCast(status)) >> 8) & 0xff;
        return .{ .pid = @intCast(pid), .status = (exit_code & 0xff) << 8 };
    }

    /// Peek whether any child has exited and is reapable, WITHOUT reaping it
    /// (WNOHANG|WNOWAIT). Used to decide whether to deliver SIGCHLD; the guest's
    /// handler then calls wait4 to actually reap. Returns true if a child is
    /// ready. On platforms without WNOWAIT support this still works because we
    /// only use it as a hint.
    pub fn childReapable(self: *HostProcess) bool {
        _ = self;
        if (!is_posix) return false;
        var status: c_int = 0;
        const WNOHANG: c_int = 1;
        const WNOWAIT: c_int = 8; // don't reap; leave the child waitable
        const pid = libc.waitpid(-1, &status, WNOHANG | WNOWAIT);
        return pid > 0;
    }

    /// Whether the process currently has any children (running or reapable).
    /// A WNOHANG peek returning ECHILD (-1) means none; 0 or >0 means some.
    pub fn hasChildren(self: *HostProcess) bool {
        _ = self;
        if (!is_posix) return false;
        var status: c_int = 0;
        const WNOHANG: c_int = 1;
        const WNOWAIT: c_int = 8;
        const pid = libc.waitpid(-1, &status, WNOHANG | WNOWAIT);
        return pid >= 0; // >=0 means a child exists (0 running, >0 reapable)
    }

    /// Block until a child is reapable, WITHOUT reaping it (so the guest's
    /// SIGCHLD handler can wait4 it). Returns true if a child became ready,
    /// false if there are no children. Used by sigsuspend to avoid spinning.
    pub fn blockUntilChild(self: *HostProcess) bool {
        _ = self;
        if (!is_posix) return false;
        var status: c_int = 0;
        const WNOWAIT: c_int = 8; // leave the child waitable for the guest
        const pid = libc.waitpid(-1, &status, WNOWAIT);
        return pid > 0;
    }

    /// pipe: host pipe(), both ends registered in the guest fd table.
    pub fn doPipe(self: *HostProcess) ProcError![2]u32 {
        if (!is_posix) return error.NotSupported;
        var fds: [2]c_int = undefined;
        if (libc.pipe(&fds) < 0) return error.PipeFailed;
        const rfd = self.fs.allocFd(fds[0]) orelse return error.PipeFailed;
        const wfd = self.fs.allocFd(fds[1]) orelse return error.PipeFailed;
        return .{ rfd, wfd };
    }

    /// execve: load a new ELF into the current address space and set up the
    /// stack/registers. On success sets `exec_entry`; the run loop continues
    /// there. Does NOT return to the caller's code on success.
    pub fn doExec(
        self: *HostProcess,
        path: []const u8,
        argv: []const []const u8,
        envp: []const []const u8,
    ) ProcError!void {
        try self.doExecDepth(path, argv, envp, 0);
    }

    /// Maximum `#!` interpreter chains to follow before giving up (matches the
    /// kernel's guard against interpreter loops).
    const max_shebang_depth: u32 = 4;

    fn doExecDepth(
        self: *HostProcess,
        path: []const u8,
        argv: []const []const u8,
        envp: []const []const u8,
        depth: u32,
    ) ProcError!void {
        // Resolve + read the executable.
        var hbuf: [2048]u8 = undefined;
        const hpath = self.fs.resolve(path, &hbuf) catch return error.ExecFailed;
        const image = std.Io.Dir.cwd().readFileAlloc(self.io, hpath, self.gpa, .limited(64 * 1024 * 1024)) catch
            return error.ExecFailed;
        defer self.gpa.free(image);

        // `#!interp [arg]` scripts: re-exec the interpreter with the script
        // path spliced into argv, like the kernel does. Bounded to avoid loops.
        if (image.len >= 2 and image[0] == '#' and image[1] == '!') {
            if (depth >= max_shebang_depth) return error.ExecFailed;
            return self.execShebang(image, path, argv, envp, depth);
        }

        // Validate before clobbering memory.
        elf.checkHeader(image) catch return error.ExecFailed;

        const memory = self.runner.memory;
        // Fresh address space: drop all regions AND wipe the backing RAM, so no
        // stale code/data from the previous image (e.g. the parent's libc/ld.so
        // after a fork) lingers at addresses the new image doesn't map.
        memory.clearRegions();
        memory.enforce = false;
        @memset(memory.bytes, 0);

        const img = elf.load(memory, image) catch return error.ExecFailed;

        // Reset heap/mmap for the fresh address space.
        self.runner.brk = img.brk;
        self.runner.brk_base = img.brk;
        self.runner.mmap_next = 0x0800_0000;

        if (self.openbsd) {
            // OpenBSD: run the guest's real ld.so for a dynamic child; static
            // children start at their own entry. Build the aux vector either
            // way (ld.so + libc read it).
            var start_pc = img.entry;
            var interp_base: u32 = 0;
            if (img.is_dynamic) {
                const interp = elf.interpPath(image) orelse "/usr/libexec/ld.so";
                var ibuf: [2048]u8 = undefined;
                const ipath = self.fs.resolve(interp, &ibuf) catch return error.ExecFailed;
                const ldimg = std.Io.Dir.cwd().readFileAlloc(self.io, ipath, self.gpa, .limited(16 * 1024 * 1024)) catch
                    return error.ExecFailed;
                defer self.gpa.free(ldimg);
                const ldobj = elf.mapSegments(memory, ldimg, OBSD_LDSO_BASE) catch return error.ExecFailed;
                interp_base = OBSD_LDSO_BASE;
                start_pc = ldobj.entry;
            }
            const aux = [_]process.AuxEntry{
                .{ .id = 3, .val = img.phdr_vaddr },
                .{ .id = 4, .val = img.phent },
                .{ .id = 5, .val = img.phnum },
                .{ .id = 6, .val = 0x1000 },
                .{ .id = 7, .val = interp_base },
                .{ .id = 9, .val = img.entry },
            };
            process.setupOpenbsd(self.runner, start_pc, img.brk, argv, envp, &aux) catch return error.ExecFailed;
            memory.enforce = true;
            self.new_brk = img.brk;
            self.exec_entry = start_pc;
            return;
        }

        // SysV/88: self-link the dynamic image, then the register handoff.
        if (img.is_dynamic) {
            dynamic.reset();
            dynamic.link(memory, self.fs, self.io, self.gpa, img.dynamic_vaddr, img.brk) catch
                return error.ExecFailed;
        }
        process.setup(self.runner, img.entry, img.brk, argv, envp) catch return error.ExecFailed;
        memory.enforce = true;
        self.new_brk = img.brk;
        self.exec_entry = img.entry;
    }

    /// Handle a `#!interpreter [arg]` script: parse the first line, then re-exec
    /// the interpreter with argv rebuilt as
    ///   [interp, (optional single arg), scriptpath, orig_argv[1..]]
    /// The kernel passes exactly one optional argument (everything after the
    /// interpreter path up to end-of-line is a single token in SysV).
    fn execShebang(
        self: *HostProcess,
        image: []const u8,
        script_path: []const u8,
        argv: []const []const u8,
        envp: []const []const u8,
        depth: u32,
    ) ProcError!void {
        // Extract the shebang line (after "#!", up to newline), stripped.
        const nl = std.mem.indexOfScalar(u8, image, '\n') orelse image.len;
        var line = image[2..nl];
        // Trim leading blanks.
        while (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) line = line[1..];
        // Trim trailing blanks/CR.
        while (line.len > 0 and (line[line.len - 1] == ' ' or line[line.len - 1] == '\t' or line[line.len - 1] == '\r'))
            line = line[0 .. line.len - 1];
        if (line.len == 0) return error.ExecFailed;

        // Split into interpreter path and (at most one) argument.
        const sp = std.mem.indexOfAny(u8, line, " \t");
        const interp = if (sp) |i| line[0..i] else line;
        var arg: []const u8 = &.{};
        if (sp) |i| {
            var rest = line[i..];
            while (rest.len > 0 and (rest[0] == ' ' or rest[0] == '\t')) rest = rest[1..];
            arg = rest; // single token (may contain spaces per SysV convention)
        }

        // Copy the pieces into stable local storage that outlives the recursion
        // (the incoming `image` buffer is freed when doExecDepth returns).
        var interp_buf: [1024]u8 = undefined;
        var arg_buf: [1024]u8 = undefined;
        var script_buf: [1024]u8 = undefined;
        if (interp.len >= interp_buf.len or arg.len >= arg_buf.len or script_path.len >= script_buf.len)
            return error.ExecFailed;
        @memcpy(interp_buf[0..interp.len], interp);
        @memcpy(arg_buf[0..arg.len], arg);
        @memcpy(script_buf[0..script_path.len], script_path);
        const interp_s = interp_buf[0..interp.len];
        const arg_s = arg_buf[0..arg.len];
        const script_s = script_buf[0..script_path.len];

        // Build the new argv: interp, [arg], script, then the original args
        // after argv[0].
        var new_argv: [128][]const u8 = undefined;
        var n: usize = 0;
        new_argv[n] = interp_s;
        n += 1;
        if (arg_s.len > 0) {
            new_argv[n] = arg_s;
            n += 1;
        }
        new_argv[n] = script_s;
        n += 1;
        var i: usize = 1;
        while (i < argv.len and n < new_argv.len) : (i += 1) {
            new_argv[n] = argv[i];
            n += 1;
        }

        return self.doExecDepth(interp_s, new_argv[0..n], envp, depth + 1);
    }
};

test "wait status encoding" {
    const code: u32 = 42;
    try std.testing.expectEqual(@as(u32, 0x2A00), (code & 0xff) << 8);
}
