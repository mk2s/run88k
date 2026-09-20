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

    /// wait: block for any child; return {pid, SVR status word}.
    pub fn doWait(self: *HostProcess) ProcError!WaitResult {
        _ = self;
        if (!is_posix) return error.NotSupported;
        var status: c_int = 0;
        const pid = libc.waitpid(-1, &status, 0);
        if (pid < 0) return error.NoChild;
        const exit_code: u32 = (@as(u32, @bitCast(status)) >> 8) & 0xff;
        return .{ .pid = @intCast(pid), .status = (exit_code & 0xff) << 8 };
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
        // Fresh address space: drop all regions, then map the new image.
        memory.clearRegions();
        memory.enforce = false;

        const img = elf.load(memory, image) catch return error.ExecFailed;

        // Dynamic linking for the new image, if needed.
        if (img.is_dynamic) {
            dynamic.reset();
            dynamic.link(memory, self.fs, self.io, self.gpa, img.dynamic_vaddr, img.brk) catch
                return error.ExecFailed;
        }

        // New stack + entry register state.
        self.runner.brk = img.brk;
        self.runner.brk_base = img.brk;
        self.runner.mmap_next = 0x0800_0000;
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
