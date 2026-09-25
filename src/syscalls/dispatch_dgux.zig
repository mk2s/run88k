//! Data General DG/UX (m88k) syscall dispatcher + host-backed implementations.
//!
//! Separate from the SysV/88, OpenBSD, and UTek dispatchers: the personalities
//! share the same trap mechanism but differ in syscall numbers, errno values,
//! and struct layouts. This is a focused DG/UX dispatcher grown from the
//! minimal set the static `/sbin/preinit` needs to reach its first syscalls,
//! mirroring how the other three were bootstrapped.
//!
//! Convention (abi/dgux.zig): number in r9, args r2..r9, return r2 (+r3 for
//! dual-return), carry-flag error, skip-on-success PC, and TWO trap gates:
//!   - vector 450 (0x1c2) -> the STANDARD table (table_dgux.Std)
//!   - vector 128 (0x080) -> the DG-EXTENDED table (table_dgux.Ext)
//! The two tables overlap numerically, so `dispatch` routes on the GATE
//! (cpu.last_exception) first, then on the number within that gate.
//!
//! DG/UX is SVR4-derived; its errno numbers and `struct stat` are the SVR4
//! layouts, so much of the host plumbing matches the SysV/88 dispatcher.

const std = @import("std");
const m88k = @import("m88k");
const mem = @import("../mem.zig");
const machine = @import("../machine.zig");
const dgux = @import("../abi/dgux.zig");
const table = @import("table_dgux.zig");
const fsmod = @import("../fs.zig");
const procmodel = @import("../procmodel.zig");

const Cpu = m88k.Cpu;
const Std = table.Std;
const Ext = table.Ext;

fn fsOf(runner: *machine.Runner) ?*fsmod.Fs {
    const p = runner.fs orelse return null;
    return @ptrCast(@alignCast(p));
}

fn pmOf(runner: *machine.Runner) ?*procmodel.HostProcess {
    const p = runner.procmodel orelse return null;
    return @ptrCast(@alignCast(p));
}

// Host libc primitives (portable, stable).
extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern "c" fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern "c" fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn lseek(fd: c_int, off: c_long, whence: c_int) c_long;
extern "c" fn dup(fd: c_int) c_int;
extern "c" fn chmod(path: [*:0]const u8, mode: c_uint) c_int;
extern "c" fn fcntl(fd: c_int, cmd: c_int, arg: c_int) c_int;
extern "c" fn time(t: ?*c_long) c_long;
extern "c" fn isatty(fd: c_int) c_int;
extern "c" fn __errno_location() *c_int;

// Host stat shim (src/host_stat.c). Fixed, host-independent layout.
const HostStat = extern struct {
    size: u64,
    mode: c_uint,
    nlink: c_uint,
    uid: c_uint,
    gid: c_uint,
    dev: c_uint,
    rdev: c_uint,
    ino: c_uint,
    atime: c_long,
    mtime: c_long,
    ctime: c_long,
    ok: c_int,
    err: c_int,
};
extern fn r88k_fstat(fd: c_int, out: *HostStat) void;
extern fn r88k_stat(path: [*:0]const u8, out: *HostStat) void;

// Directory-read shim (src/host_dir.c).
extern fn r88k_dirread(handle: c_int, ino_out: *c_ulong, name_out: [*]u8) c_int;

fn hostErrno() u32 {
    return @intCast(__errno_location().*);
}

fn traceOut(bytes: []const u8) void {
    _ = write(2, bytes.ptr, bytes.len);
}

/// Shared with the other dispatchers' flag (main.zig sets dispatch.trace).
pub var trace: bool = false;

// -- errno values (DG/UX = SVR4 numbers) -------------------------------------
const EPERM: u32 = 1;
const ENOENT: u32 = 2;
const EINTR: u32 = 4;
const EBADF: u32 = 9;
const ECHILD: u32 = 10;
const ENOMEM: u32 = 12;
const EFAULT: u32 = 14;
const EINVAL: u32 = 22;
const ENOTTY: u32 = 25;
const ENOSYS: u32 = 89; // SVR4: function not implemented

/// Map a host (Linux) errno to a DG/UX errno. DG/UX's low numbers are the SVR4
/// set, which coincides with Linux for the common 1..34 range; anything
/// unknown becomes EINVAL. Refine as specific mismatches surface.
fn mapErrno(host: u32) u32 {
    return switch (host) {
        1 => EPERM,
        2 => ENOENT,
        4 => EINTR,
        9 => EBADF,
        10 => ECHILD,
        12 => ENOMEM,
        14 => EFAULT,
        22 => EINVAL,
        25 => ENOTTY,
        else => if (host >= 1 and host <= 44) host else EINVAL,
    };
}

/// The dispatcher, installed as the runner's syscall handler. Returns true to
/// continue the guest, false to stop (exit / fatal). Routes on the trap GATE
/// (cpu.last_exception) first because the two DG/UX tables overlap numerically.
pub fn dispatch(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gate = dgux.gateOf(cpu.last_exception) orelse {
        failFastGate(runner);
        return false;
    };
    return switch (gate) {
        .std => dispatchStd(runner),
        .ext => dispatchExt(runner),
        .local => dispatchLocal(runner),
        .fast => dispatchFast(runner),
        .sigret => {
            // sigreturn (vector 448): no signal delivery yet, so nothing to
            // restore. Skip the trap and continue.
            const at = cpu.ppc +% 4;
            cpu.branch_pending = false;
            cpu.pc = at;
            cpu.npc = at +% 4;
            return true;
        },
    };
}

// -- gate 0x1c1 (449): local multiplexor ------------------------------------

// Numbers (in r9, with r8=2) recovered from libc.so.1 stubs: 1,2,3,4. These
// are the getrlimit/setrlimit-family "local" calls (matching the UTek local
// vector). getrlimit(resource, rlp): resource in r2, rlp in r3.
const LOCAL_1: u32 = 1;
const LOCAL_GETRLIMIT: u32 = 2;
const LOCAL_3: u32 = 3;
const LOCAL_4: u32 = 4;

fn dispatchLocal(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const num = dgux.syscallNumber(cpu);
    if (trace) traceSyscall("local", num, "local", cpu);
    switch (num) {
        LOCAL_GETRLIMIT => {
            const resource = dgux.arg(cpu, 0);
            const rlp = dgux.arg(cpu, 1);
            const cur: u32, const max: u32 = switch (resource) {
                5 => .{ fsmod.MAX_FD, fsmod.MAX_FD }, // RLIMIT_NOFILE
                3 => .{ 0x0010_0000, 0x0010_0000 }, // RLIMIT_STACK
                else => .{ RLIM_INFINITY, RLIM_INFINITY },
            };
            if (rlp != 0 and @as(u64, rlp) + 8 <= mem.Memory.size) {
                const was = runner.memory.enforce;
                runner.memory.enforce = false;
                runner.memory.write32(rlp + 0, cur);
                runner.memory.write32(rlp + 4, max);
                runner.memory.enforce = was;
            }
            dgux.returnSuccess(cpu, 0);
            return true;
        },
        LOCAL_1, LOCAL_3, LOCAL_4 => {
            // setrlimit / other local resource calls: accept and ignore (we
            // don't enforce guest resource limits).
            dgux.returnSuccess(cpu, 0);
            return true;
        },
        else => {
            dgux.returnError(cpu, ENOSYS);
            return true;
        },
    }
}

// -- gate 0x1f7 (503): fast/internal trap ------------------------------------

/// Vector 503 is a libc-internal fast trap that does not carry a syscall
/// number in r9. Its uses in libc/the tools are benign from an emulation
/// standpoint (cache/scheduling hints, fast time reads). Accept it as a no-op
/// success and continue, so tools relying on it proceed.
fn dispatchFast(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    if (trace) traceSyscall("fast", 0, "fast503", cpu);
    dgux.returnSuccess(cpu, 0);
    return true;
}

// -- gate 0x1c2: standard SVR4 table -----------------------------------------

fn dispatchStd(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const num = dgux.syscallNumber(cpu);
    const sc: Std = @enumFromInt(num);

    if (trace) traceSyscall("std", num, stdName(sc), cpu);

    switch (sc) {
        .exit => {
            runner.exit_status = dgux.arg(cpu, 0);
            return false;
        },
        .write => return sysWrite(runner),
        .read => return sysRead(runner),
        .bcs_open => return sysOpen(runner), // BCS-compat open (static SDE tools)
        .close => return sysClose(runner),
        .lseek => return sysLseek(runner),
        .bcs_brk => return sysBrk(runner),
        .bcs_ioctl => return sysIoctl(runner),
        .bcs_sysconf => return sysSysconf(runner),
        .bcs_time => return sysTime(runner),
        .times => return sysTimes(runner),
        .getcwd => return sysGetcwd(runner),
        .fstat => return sysFstat(runner),
        .stat => return sysStat(runner),
        .access => return sysAccess(runner),
        .chdir => return sysChdir(runner),
        .chmod => return sysChmod(runner),
        .unlink => return sysUnlink(runner),
        .rename => return sysRename(runner),
        .mkdir => return sysMkdir(runner),
        .rmdir => return sysRmdir(runner),
        .getdents => return sysGetdents(runner),

        // Process model (fork/exec/wait) — the toolchain drivers (cc/as) exec
        // their real phases.
        .fork => return sysFork(runner),
        .execve => return sysExec(runner),

        // Identity syscalls: report plausible values (running as root). The
        // dual-return calls hand the second value back in r3.
        .getpid => {
            dgux.returnSuccess2(cpu, 1, 0); // pid=1, ppid=0
            return true;
        },
        .getuid => {
            dgux.returnSuccess2(cpu, 0, 0); // uid=0, euid=0
            return true;
        },
        .getgid => {
            dgux.returnSuccess2(cpu, 0, 0); // gid=0, egid=0
            return true;
        },
        .getgroups => {
            dgux.returnSuccess(cpu, 0);
            return true;
        },
        .getpgrp => {
            dgux.returnSuccess(cpu, 1);
            return true;
        },
        .setpgid, .setsid, .setuid, .setgid => {
            dgux.returnSuccess(cpu, 0);
            return true;
        },
        .umask => {
            const old = runner.umask;
            runner.umask = dgux.arg(cpu, 0) & 0o777;
            dgux.returnSuccess(cpu, old);
            return true;
        },

        // Signal syscalls: no delivery yet — accept, return benign success.
        .sigpending, .sigprocmask, .sigsuspend, .bcs_sigaction, .bcs_sigfillset => {
            dgux.returnSuccess(cpu, 0);
            return true;
        },

        else => {
            failFast(runner, "std", num, stdName(sc));
            return false;
        },
    }
}

// -- gate 0x080: DG-extended table -------------------------------------------

fn dispatchExt(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const num = dgux.syscallNumber(cpu);
    const sc: Ext = @enumFromInt(num);

    if (trace) traceSyscall("ext", num, extName(sc), cpu);

    switch (sc) {
        .open => return sysOpen(runner),
        .fcntl => return sysFcntl(runner),
        .dg_ioctl => return sysDgIoctl(runner),
        .dg_mstat => return sysStat(runner), // dg_mstat(path, struct stat*) == stat
        .dup => return sysDup(runner),
        .mmap => return sysMmap(runner),
        .munmap => {
            dgux.returnSuccess(cpu, 0);
            return true;
        },
        .mprotect => {
            dgux.returnSuccess(cpu, 0);
            return true;
        },
        .dg_getpagesize => {
            dgux.returnSuccess(cpu, 0x1000);
            return true;
        },
        .getrlimit => return sysGetrlimit(runner),
        .setrlimit => {
            dgux.returnSuccess(cpu, 0);
            return true;
        },
        .uname => return sysUname(runner),

        // Signal syscalls: accept, return benign success.
        .dg_sigaction, .dg_sigblock, .dg_sigsetmask, .sighold, .sigrelse, .sigignore => {
            dgux.returnSuccess(cpu, 0);
            return true;
        },

        else => {
            failFast(runner, "ext", num, extName(sc));
            return false;
        },
    }
}

// -- shared helpers ----------------------------------------------------------

/// @tagName panics on a non-exhaustive enum's unnamed value; these guard it so
/// tracing an unknown syscall number reports "?" instead of crashing.
fn stdName(sc: Std) []const u8 {
    return std.enums.tagName(Std, sc) orelse "?";
}

fn extName(sc: Ext) []const u8 {
    return std.enums.tagName(Ext, sc) orelse "?";
}

fn traceSyscall(gate: []const u8, num: u32, name: []const u8, cpu: *const Cpu) void {
    var buf: [128]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "syscall[{s}] {d} ({s}) a0={x} a1={x} a2={x}\n", .{
        gate, num, name, dgux.arg(cpu, 0), dgux.arg(cpu, 1), dgux.arg(cpu, 2),
    }) catch "syscall (fmt err)\n";
    traceOut(line);
}

fn readGuestPath(runner: *machine.Runner, ptr: u32, buf: []u8) ?[]const u8 {
    const s = runner.memory.readCStr(ptr, buf[0 .. buf.len - 1]);
    if (s.len >= buf.len - 1) return null;
    buf[s.len] = 0;
    return buf[0..s.len];
}

fn hostFd(runner: *machine.Runner, gfd: u32) ?c_int {
    if (fsOf(runner)) |fs| {
        const h = fs.get(gfd) orelse return null;
        return @intCast(h);
    }
    return @intCast(gfd);
}

/// Resolve a single guest path argument to a NUL-terminated host path, writing
/// errors on the standard failures. Returns null if it already reported an
/// error (caller returns true).
fn resolveArgPath(runner: *machine.Runner, arg_index: u5, gbuf: []u8, hbuf: []u8) ?[*:0]const u8 {
    const cpu = &runner.cpu;
    const path_ptr = dgux.arg(cpu, arg_index);
    const gpath = readGuestPath(runner, path_ptr, gbuf) orelse {
        dgux.returnError(cpu, EINVAL);
        return null;
    };
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, hbuf) catch {
            dgux.returnError(cpu, ENOENT);
            return null;
        };
        return hp.ptr;
    }
    return @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
}

// -- path syscalls -----------------------------------------------------------

fn sysChdir(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const path_ptr = dgux.arg(cpu, 0);
    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        dgux.returnError(cpu, EINVAL);
        return true;
    };
    if (fsOf(runner)) |fs| {
        var hbuf: [2048]u8 = undefined;
        const hp = fs.resolve(gpath, &hbuf) catch {
            dgux.returnError(cpu, ENOENT);
            return true;
        };
        if (fsmod.c.access(hp, 0) < 0) {
            dgux.returnError(cpu, ENOENT);
            return true;
        }
        fs.chdir(gpath) catch {
            dgux.returnError(cpu, EINVAL);
            return true;
        };
    }
    dgux.returnSuccess(cpu, 0);
    return true;
}

fn sysChmod(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const mode = dgux.arg(cpu, 1);
    var gbuf: [1024]u8 = undefined;
    var hbuf: [2048]u8 = undefined;
    const cpath = resolveArgPath(runner, 0, &gbuf, &hbuf) orelse return true;
    if (chmod(cpath, @intCast(mode & 0o7777)) < 0) dgux.returnError(cpu, mapErrno(hostErrno())) else dgux.returnSuccess(cpu, 0);
    return true;
}

fn sysUnlink(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    var gbuf: [1024]u8 = undefined;
    var hbuf: [2048]u8 = undefined;
    const cpath = resolveArgPath(runner, 0, &gbuf, &hbuf) orelse return true;
    if (fsmod.c.unlink(cpath) < 0) dgux.returnError(cpu, mapErrno(hostErrno())) else dgux.returnSuccess(cpu, 0);
    return true;
}

fn sysRename(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    var gbuf1: [1024]u8 = undefined;
    var hbuf1: [2048]u8 = undefined;
    var gbuf2: [1024]u8 = undefined;
    var hbuf2: [2048]u8 = undefined;
    const oldp = resolveArgPath(runner, 0, &gbuf1, &hbuf1) orelse return true;
    const newp = resolveArgPath(runner, 1, &gbuf2, &hbuf2) orelse return true;
    if (fsmod.c.rename(oldp, newp) < 0) dgux.returnError(cpu, mapErrno(hostErrno())) else dgux.returnSuccess(cpu, 0);
    return true;
}

fn sysMkdir(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const mode = dgux.arg(cpu, 1);
    var gbuf: [1024]u8 = undefined;
    var hbuf: [2048]u8 = undefined;
    const cpath = resolveArgPath(runner, 0, &gbuf, &hbuf) orelse return true;
    if (fsmod.c.mkdir(cpath, @intCast(mode & 0o7777)) < 0) dgux.returnError(cpu, mapErrno(hostErrno())) else dgux.returnSuccess(cpu, 0);
    return true;
}

fn sysRmdir(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    var gbuf: [1024]u8 = undefined;
    var hbuf: [2048]u8 = undefined;
    const cpath = resolveArgPath(runner, 0, &gbuf, &hbuf) orelse return true;
    if (fsmod.c.rmdir(cpath) < 0) dgux.returnError(cpu, mapErrno(hostErrno())) else dgux.returnSuccess(cpu, 0);
    return true;
}

// -- I/O ---------------------------------------------------------------------

fn sysWrite(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = dgux.arg(cpu, 0);
    const buf = dgux.arg(cpu, 1);
    const count = dgux.arg(cpu, 2);
    const hfd = hostFd(runner, gfd) orelse {
        dgux.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, buf) + count > mem.Memory.size) {
        dgux.returnError(cpu, EFAULT);
        return true;
    }
    const slice = runner.memory.bytes[buf .. buf + count];
    const n = write(hfd, slice.ptr, slice.len);
    if (n < 0) dgux.returnError(cpu, mapErrno(hostErrno())) else dgux.returnSuccess(cpu, @intCast(n));
    return true;
}

fn sysRead(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = dgux.arg(cpu, 0);
    const buf = dgux.arg(cpu, 1);
    const count = dgux.arg(cpu, 2);
    const hfd = hostFd(runner, gfd) orelse {
        dgux.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, buf) + count > mem.Memory.size) {
        dgux.returnError(cpu, EFAULT);
        return true;
    }
    const slice = runner.memory.bytes[buf .. buf + count];
    const n = read(hfd, slice.ptr, slice.len);
    if (n < 0) dgux.returnError(cpu, mapErrno(hostErrno())) else dgux.returnSuccess(cpu, @intCast(n));
    return true;
}

// DG/UX O_* open flags (usr/include/sys/fcntl.h): O_RDONLY=0, O_WRONLY=1,
// O_RDWR=2, O_APPEND=0x8, O_CREAT=0x100, O_TRUNC=0x200, O_EXCL=0x400 (SVR4).
// Host (Linux) values differ; translate.
const H_O_CREAT: c_int = 0o100;
const H_O_TRUNC: c_int = 0o1000;
const H_O_EXCL: c_int = 0o200;
const H_O_APPEND: c_int = 0o2000;

fn translateOpenFlags(guest: u32) c_int {
    var h: c_int = @intCast(guest & 0x3); // RDONLY/WRONLY/RDWR line up 0/1/2
    if (guest & 0x100 != 0) h |= H_O_CREAT;
    if (guest & 0x200 != 0) h |= H_O_TRUNC;
    if (guest & 0x400 != 0) h |= H_O_EXCL;
    if (guest & 0x8 != 0) h |= H_O_APPEND;
    return h;
}

fn sysOpen(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const path_ptr = dgux.arg(cpu, 0);
    const flags = dgux.arg(cpu, 1);
    const mode = dgux.arg(cpu, 2);

    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        dgux.returnError(cpu, EINVAL);
        return true;
    };

    var hbuf: [2048]u8 = undefined;
    var cpath: [*:0]const u8 = @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, &hbuf) catch {
            dgux.returnError(cpu, ENOENT);
            return true;
        };
        cpath = hp.ptr;
    }

    const hfd = open(cpath, translateOpenFlags(flags), @intCast(mode));
    if (hfd < 0) {
        dgux.returnError(cpu, mapErrno(hostErrno()));
        return true;
    }
    if (fsOf(runner)) |fs| {
        var canonbuf: [1024]u8 = undefined;
        const gcanon = fs.canonicalGuest(gpath, &canonbuf) orelse gpath;
        if (fs.openDir(cpath, gcanon, hfd)) |gdir| {
            dgux.returnSuccess(cpu, gdir);
            return true;
        }
        const gfd = fs.allocFd(hfd) orelse {
            _ = close(hfd);
            dgux.returnError(cpu, EBADF);
            return true;
        };
        dgux.returnSuccess(cpu, gfd);
    } else {
        dgux.returnSuccess(cpu, @intCast(hfd));
    }
    return true;
}

fn sysClose(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = dgux.arg(cpu, 0);
    if (fsOf(runner)) |fs| {
        if (fs.closeFd(gfd)) dgux.returnSuccess(cpu, 0) else dgux.returnError(cpu, EBADF);
        return true;
    }
    if (gfd <= 2) {
        dgux.returnSuccess(cpu, 0);
        return true;
    }
    const rc = close(@intCast(gfd));
    if (rc < 0) dgux.returnError(cpu, mapErrno(hostErrno())) else dgux.returnSuccess(cpu, 0);
    return true;
}

fn sysLseek(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = dgux.arg(cpu, 0);
    const off = dgux.arg(cpu, 1);
    const whence = dgux.arg(cpu, 2);
    const fd = hostFd(runner, gfd) orelse {
        dgux.returnError(cpu, EBADF);
        return true;
    };
    const pos = lseek(fd, @as(c_long, @intCast(@as(i32, @bitCast(off)))), @intCast(whence));
    if (pos < 0) dgux.returnError(cpu, mapErrno(hostErrno())) else dgux.returnSuccess(cpu, @intCast(pos & 0xffff_ffff));
    return true;
}

fn sysDup(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = dgux.arg(cpu, 0);
    const fd = hostFd(runner, gfd) orelse {
        dgux.returnError(cpu, EBADF);
        return true;
    };
    const nfd = dup(fd);
    if (nfd < 0) {
        dgux.returnError(cpu, mapErrno(hostErrno()));
        return true;
    }
    if (fsOf(runner)) |fs| {
        const gnew = fs.allocFd(nfd) orelse {
            _ = close(nfd);
            dgux.returnError(cpu, EBADF);
            return true;
        };
        dgux.returnSuccess(cpu, gnew);
    } else {
        dgux.returnSuccess(cpu, @intCast(nfd));
    }
    return true;
}

/// DG/UX fcntl cmds match SVR4: F_DUPFD=0, F_GETFD=1, F_SETFD=2, F_GETFL=3,
/// F_SETFL=4. Minimal: report success/benign values so libc startup proceeds.
fn sysFcntl(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const cmd = dgux.arg(cpu, 1);
    switch (cmd) {
        0 => return sysDup(runner), // F_DUPFD (approx: ignores the min-fd arg)
        1, 3 => {
            dgux.returnSuccess(cpu, 0); // F_GETFD/F_GETFL -> 0
            return true;
        },
        else => {
            dgux.returnSuccess(cpu, 0); // F_SETFD/F_SETFL and friends
            return true;
        },
    }
}

// -- brk / mmap --------------------------------------------------------------

/// DG/UX `brk` (BCS variant, gate 0x1c2 #2): the argument is the absolute new
/// break address. Grow/shrink the heap and return 0.
fn sysBrk(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const newbrk = dgux.arg(cpu, 0);
    if (newbrk >= 0x0B00_0000) {
        dgux.returnError(cpu, ENOMEM);
        return true;
    }
    if (newbrk < runner.brk_base) {
        dgux.returnSuccess(cpu, 0);
        return true;
    }
    if (newbrk > runner.brk) {
        const was = runner.memory.enforce;
        runner.memory.enforce = false;
        runner.memory.zero(runner.brk, newbrk - runner.brk);
        runner.memory.addRegion(runner.brk, newbrk - runner.brk, .{ .read = true, .write = true }) catch {};
        runner.memory.enforce = was;
    }
    runner.brk = newbrk;
    dgux.returnSuccess(cpu, 0);
    return true;
}

/// DG/UX `mmap` (gate 0x080 #218). Minimal anonymous-only backing: carve from
/// the top of the break region. Real file-backed mmap is a follow-on.
fn sysMmap(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    // mmap(addr, len, prot, flags, fd, off) — SVR4 order.
    const len = dgux.arg(cpu, 1);
    // Not implemented yet; report ENOSYS so libc can fall back where possible.
    _ = len;
    dgux.returnError(cpu, ENOSYS);
    return true;
}

// -- rlimit ------------------------------------------------------------------

const RLIM_INFINITY: u32 = 0x7fffffff;

fn sysGetrlimit(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const resource = dgux.arg(cpu, 0);
    const rlp = dgux.arg(cpu, 1);
    const cur: u32, const max: u32 = switch (resource) {
        5 => .{ fsmod.MAX_FD, fsmod.MAX_FD }, // RLIMIT_NOFILE
        3 => .{ 0x0010_0000, 0x0010_0000 }, // RLIMIT_STACK (1 MiB)
        else => .{ RLIM_INFINITY, RLIM_INFINITY },
    };
    if (rlp != 0 and @as(u64, rlp) + 8 <= mem.Memory.size) {
        const was = runner.memory.enforce;
        runner.memory.enforce = false;
        runner.memory.write32(rlp + 0, cur);
        runner.memory.write32(rlp + 4, max);
        runner.memory.enforce = was;
    }
    dgux.returnSuccess(cpu, 0);
    return true;
}

// -- stat --------------------------------------------------------------------

// DG/UX `struct stat` — exact layout from usr/include/sys/stat.h (SVR4/DGUX
// target, m88k big-endian, natural alignment). All the leading scalar fields
// are 4 bytes (dev_t/uid_t/gid_t=int, ino_t/mode_t/nlink_t=ulong,
// off_t/time_t=long):
//   st_dev@0 st_ino@4 st_mode@8 st_nlink@12 st_uid@16 st_gid@20 st_rdev@24
//   st_size@28 st_atime@32 st_ausec@36 st_mtime@40 st_musec@44 st_ctime@48
//   st_cusec@52
// then the DGUX SVR4 extension:
//   st_atim@56(8) st_mtim@64(8) st_ctim@72(8) st_blksize@80 st_blocks@84
//   st_fstype[16]@88   -> sizeof 104. Round the buffer we clear to 128.
const STAT_SIZE: u32 = 128;

fn writeGuestStat(memory: *mem.Memory, addr: u32, hs: *const HostStat) void {
    memory.zero(addr, STAT_SIZE);
    // Present the entire guest namespace as ONE device. The host backs mounts
    // with several real filesystems (different st_dev), but the guest must see
    // a single coherent filesystem or a getcwd() walk that compares (dev,ino)
    // to detect the root — and to match a parent entry against '.' — fails
    // across mount boundaries.
    memory.write32(addr + 0, 1); // st_dev (virtual, constant)
    memory.write32(addr + 4, hs.ino); // st_ino
    memory.write32(addr + 8, hs.mode); // st_mode (S_IF* match host)
    memory.write32(addr + 12, hs.nlink); // st_nlink
    memory.write32(addr + 16, hs.uid); // st_uid
    memory.write32(addr + 20, hs.gid); // st_gid
    memory.write32(addr + 24, hs.rdev); // st_rdev
    memory.write32(addr + 28, @truncate(hs.size)); // st_size
    memory.write32(addr + 32, @bitCast(@as(i32, @truncate(hs.atime)))); // st_atime
    memory.write32(addr + 40, @bitCast(@as(i32, @truncate(hs.mtime)))); // st_mtime
    memory.write32(addr + 48, @bitCast(@as(i32, @truncate(hs.ctime)))); // st_ctime
    // SVR4 extension: st_atim/mtim/ctim (timestruc: sec@+0, nsec@+4).
    memory.write32(addr + 56, @bitCast(@as(i32, @truncate(hs.atime)))); // st_atim.tv_sec
    memory.write32(addr + 64, @bitCast(@as(i32, @truncate(hs.mtime)))); // st_mtim.tv_sec
    memory.write32(addr + 72, @bitCast(@as(i32, @truncate(hs.ctime)))); // st_ctim.tv_sec
    memory.write32(addr + 80, 0x1000); // st_blksize
    const blocks: u32 = @truncate((hs.size + 511) / 512);
    memory.write32(addr + 84, blocks); // st_blocks
}

fn sysFstat(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = dgux.arg(cpu, 0);
    const statbuf = dgux.arg(cpu, 1);
    const fd = hostFd(runner, gfd) orelse {
        dgux.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, statbuf) + STAT_SIZE > mem.Memory.size) {
        dgux.returnError(cpu, EFAULT);
        return true;
    }
    var hs: HostStat = undefined;
    r88k_fstat(fd, &hs);
    if (hs.ok == 0) {
        dgux.returnError(cpu, mapErrno(@intCast(hs.err)));
        return true;
    }
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    writeGuestStat(runner.memory, statbuf, &hs);
    runner.memory.enforce = was;
    dgux.returnSuccess(cpu, 0);
    return true;
}

fn sysStat(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const path_ptr = dgux.arg(cpu, 0);
    const statbuf = dgux.arg(cpu, 1);
    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        dgux.returnError(cpu, EINVAL);
        return true;
    };
    if (@as(u64, statbuf) + STAT_SIZE > mem.Memory.size) {
        dgux.returnError(cpu, EFAULT);
        return true;
    }
    var cpath: [*:0]const u8 = @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
    var hbuf: [2048]u8 = undefined;
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, &hbuf) catch {
            dgux.returnError(cpu, ENOENT);
            return true;
        };
        cpath = hp.ptr;
    }
    var hs: HostStat = undefined;
    r88k_stat(cpath, &hs);
    if (trace) {
        var tb: [1152]u8 = undefined;
        const tl = std.fmt.bufPrint(&tb, "  stat '{s}' ok={d} ino={d}\n", .{ gpath, hs.ok, hs.ino }) catch "";
        traceOut(tl);
    }
    if (hs.ok == 0) {
        dgux.returnError(cpu, mapErrno(@intCast(hs.err)));
        return true;
    }
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    writeGuestStat(runner.memory, statbuf, &hs);
    runner.memory.enforce = was;
    dgux.returnSuccess(cpu, 0);
    return true;
}

// -- getdents ----------------------------------------------------------------

/// getdents(fd, buf, nbyte): fill buf with SVR4 `struct dirent`:
///   ino_t d_ino (4) ; off_t d_off (4) ; unsigned short d_reclen (2) ;
///   char d_name[] (NUL-terminated, then pad to align d_reclen to 4).
/// Returns bytes written, 0 at end of directory. (DG/UX dirent is the SVR4
/// layout; refine against usr/include/sys/dirent.h if a mismatch surfaces.)
fn sysGetdents(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = dgux.arg(cpu, 0);
    const buf = dgux.arg(cpu, 1);
    const nbyte = dgux.arg(cpu, 2);
    const fs = fsOf(runner) orelse {
        dgux.returnError(cpu, EBADF);
        return true;
    };
    const handle = fs.dirHandleFor(gfd) orelse {
        dgux.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, buf) + nbyte > mem.Memory.size) {
        dgux.returnError(cpu, EFAULT);
        return true;
    }
    var written: u32 = 0;
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    defer runner.memory.enforce = was;

    const emit = struct {
        fn one(rn: *machine.Runner, base: u32, off: *u32, cap: u32, dino: u32, nm: []const u8) bool {
            const raw = 10 + nm.len + 1;
            const reclen: u32 = @intCast(std.mem.alignForward(usize, raw, 4));
            if (off.* + reclen > cap) return false;
            const at = base + off.*;
            rn.memory.write32(at + 0, dino); // d_ino
            rn.memory.write32(at + 4, off.* + reclen); // d_off (next offset)
            rn.memory.write16(at + 8, @intCast(reclen)); // d_reclen
            rn.memory.writeBytes(at + 10, nm);
            rn.memory.write8(at + 10 + @as(u32, @intCast(nm.len)), 0);
            off.* += reclen;
            return true;
        }
    }.one;

    const dirpath: ?[]const u8 = fs.dirGuestPath(gfd);
    var real_done = false;
    while (true) {
        var ino: c_ulong = 0;
        var namebuf: [256]u8 = undefined;
        const rc = r88k_dirread(handle, &ino, &namebuf);
        if (rc <= 0) {
            real_done = true;
            break;
        }
        const name = std.mem.sliceTo(&namebuf, 0);
        // If this entry is itself a mount point (a mount overlaying a real
        // host directory), report the MOUNTED dir's inode instead of the
        // shadowed real one, so a getcwd() inode-match walk succeeds.
        var dino: u32 = @intCast(ino & 0xffffffff);
        if (dirpath) |dp| {
            if (fs.mountAt(dp, name)) |host_root| {
                var hs: HostStat = undefined;
                var rootz: [1024]u8 = undefined;
                const rn = @min(host_root.len, rootz.len - 1);
                @memcpy(rootz[0..rn], host_root[0..rn]);
                rootz[rn] = 0;
                r88k_stat(@ptrCast(&rootz), &hs);
                if (hs.ok != 0) dino = hs.ino;
            }
        }
        if (!emit(runner, buf, &written, nbyte, dino, name)) {
            fs.dirPushback(handle);
            break;
        }
    }

    // Once the real stream is exhausted, append synthetic entries for any mount
    // points that live directly under this directory but are not real children
    // on the host (e.g. a writable /tmp or /var/tmp overlay on a separate host
    // fs). Their d_ino is the backing dir's host inode, matching what stat() of
    // the mount point returns — this is what a userland getcwd() relies on to
    // climb across the mount boundary.
    if (real_done) {
        if (dirpath) |dp2| {
            while (fs.mountChild(dp2, fs.dirSynthNext(gfd))) |child| {
                var hs: HostStat = undefined;
                var rootz: [1024]u8 = undefined;
                const rn = @min(child.host_root.len, rootz.len - 1);
                @memcpy(rootz[0..rn], child.host_root[0..rn]);
                rootz[rn] = 0;
                r88k_stat(@ptrCast(&rootz), &hs);
                const dino: u32 = if (hs.ok != 0) hs.ino else 0xffff_fffe;
                if (!emit(runner, buf, &written, nbyte, dino, child.name)) break;
                fs.dirSynthAdvance(gfd);
            }
        }
    }
    dgux.returnSuccess(cpu, written);
    return true;
}

fn sysAccess(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const path_ptr = dgux.arg(cpu, 0);
    const amode = dgux.arg(cpu, 1);
    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        dgux.returnError(cpu, EINVAL);
        return true;
    };
    var cpath: [*:0]const u8 = @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
    var hbuf: [2048]u8 = undefined;
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, &hbuf) catch {
            dgux.returnError(cpu, ENOENT);
            return true;
        };
        cpath = hp.ptr;
    }
    const hmode: c_int = @intCast(amode & 0x7);
    if (fsmod.c.access(cpath, hmode) < 0) dgux.returnError(cpu, mapErrno(hostErrno())) else dgux.returnSuccess(cpu, 0);
    return true;
}

// -- uname -------------------------------------------------------------------

// SVR4 `struct utsname`: five (or six) SYS_NMLN-byte fields. DG/UX SYS_NMLN is
// 257 on later releases; refine when a uname-using guest runs. Fields:
// sysname, nodename, release, version, machine.
const UTS_NMLN: u32 = 257;

fn sysUname(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const buf = dgux.arg(cpu, 0);
    if (buf == 0 or @as(u64, buf) + UTS_NMLN * 5 > mem.Memory.size) {
        dgux.returnError(cpu, EFAULT);
        return true;
    }
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    defer runner.memory.enforce = was;
    runner.memory.zero(buf, UTS_NMLN * 5);
    writeField(runner.memory, buf + UTS_NMLN * 0, "dgux");
    writeField(runner.memory, buf + UTS_NMLN * 1, "run88k");
    writeField(runner.memory, buf + UTS_NMLN * 2, "5.4"); // release
    writeField(runner.memory, buf + UTS_NMLN * 3, "R4000"); // version
    writeField(runner.memory, buf + UTS_NMLN * 4, "m88k"); // machine
    dgux.returnSuccess(cpu, 0);
    return true;
}

fn writeField(memory: *mem.Memory, addr: u32, s: []const u8) void {
    for (s, 0..) |c, i| memory.write8(addr + @as(u32, @intCast(i)), c);
}

// -- ioctl -------------------------------------------------------------------

// SVR4 termio ioctls (usr/include/sys/termio.h). `struct termio` is 18 bytes:
// c_iflag(2) c_oflag(2) c_cflag(2) c_lflag(2) c_line(1) c_cc[8].
const TCGETA: u32 = 0x5401;
const TCSETA: u32 = 0x5402;
const TCSETAW: u32 = 0x5403;
const TCSETAF: u32 = 0x5404;
const TERMIO_LEN: u32 = 18;

fn sysIoctl(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = dgux.arg(cpu, 0);
    const req = dgux.arg(cpu, 1);
    const argp = dgux.arg(cpu, 2);
    switch (req) {
        TCGETA => {
            const hfd = hostFd(runner, gfd) orelse {
                dgux.returnError(cpu, EBADF);
                return true;
            };
            if (isatty(hfd) != 1) {
                dgux.returnError(cpu, ENOTTY);
                return true;
            }
            if (argp != 0 and @as(u64, argp) + TERMIO_LEN <= mem.Memory.size) {
                const was = runner.memory.enforce;
                runner.memory.enforce = false;
                runner.memory.zero(argp, TERMIO_LEN);
                runner.memory.write16(argp + 0, 0x0502); // c_iflag
                runner.memory.write16(argp + 2, 0x0005); // c_oflag
                runner.memory.write16(argp + 4, 0x00bd); // c_cflag
                runner.memory.write16(argp + 6, 0x000b); // c_lflag
                runner.memory.enforce = was;
            }
            dgux.returnSuccess(cpu, 0);
            return true;
        },
        TCSETA, TCSETAW, TCSETAF => {
            const hfd = hostFd(runner, gfd) orelse {
                dgux.returnError(cpu, EBADF);
                return true;
            };
            if (isatty(hfd) != 1) dgux.returnError(cpu, ENOTTY) else dgux.returnSuccess(cpu, 0);
            return true;
        },
        else => {
            dgux.returnError(cpu, ENOTTY);
            return true;
        },
    }
}

/// DG-native ioctl (ext gate 29). Uses the BSD `_IOC` request encoding
/// (dir<<30 | len<<16 | group<<8 | num). The static SDE tools probe their
/// input/output fds with tty-group ('t'/'T') ioctls to decide whether they are
/// terminals; on a regular file the correct answer is ENOTTY, which makes the
/// tool proceed in file mode. For a genuine tty we accept the common queries.
fn sysDgIoctl(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = dgux.arg(cpu, 0);
    const req = dgux.arg(cpu, 1);
    const group: u8 = @truncate((req >> 8) & 0xff);
    const hfd = hostFd(runner, gfd) orelse {
        dgux.returnError(cpu, EBADF);
        return true;
    };
    // tty-family groups: 't' (BSD sgtty/TIOC) and 'T' (SVR4 termios).
    if (group == 't' or group == 'T') {
        if (isatty(hfd) != 1) {
            dgux.returnError(cpu, ENOTTY);
            return true;
        }
        // Real tty: accept the query benignly (zero-fill any OUT buffer).
        const argp = dgux.arg(cpu, 2);
        const len: u32 = (req >> 16) & 0x3fff;
        if ((req & 0x4000_0000) != 0 and argp != 0 and len != 0 and @as(u64, argp) + len <= mem.Memory.size) {
            const was = runner.memory.enforce;
            runner.memory.enforce = false;
            runner.memory.zero(argp, len);
            runner.memory.enforce = was;
        }
        dgux.returnSuccess(cpu, 0);
        return true;
    }
    // Non-tty ioctl: not supported yet — report ENOTTY so the tool falls back.
    dgux.returnError(cpu, ENOTTY);
    return true;
}

// -- sysconf / time ----------------------------------------------------------

// sysconf(name): return a system limit/parameter (SVR4 _SC_* values). Return
// plausible values; unknown names get -1/EINVAL.
fn sysSysconf(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const name = dgux.arg(cpu, 0);
    const val: ?u32 = switch (name) {
        1 => 0x10000, // _SC_ARG_MAX
        2 => 64, // _SC_CHILD_MAX
        3 => 100, // _SC_CLK_TCK (HZ)
        4 => 16, // _SC_NGROUPS_MAX
        5 => fsmod.MAX_FD, // _SC_OPEN_MAX
        6 => 1, // _SC_JOB_CONTROL
        7 => 1, // _SC_SAVED_IDS
        8 => 199009, // _SC_VERSION (POSIX.1 stamp)
        else => null,
    };
    if (val) |v| dgux.returnSuccess(cpu, v) else dgux.returnError(cpu, EINVAL);
    return true;
}

fn sysTime(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const t: u32 = @intCast(@as(i64, time(null)) & 0xffff_ffff);
    const tptr = dgux.arg(cpu, 0);
    if (tptr != 0 and @as(u64, tptr) + 4 <= mem.Memory.size) {
        const was = runner.memory.enforce;
        runner.memory.enforce = false;
        runner.memory.write32(tptr, t);
        runner.memory.enforce = was;
    }
    dgux.returnSuccess(cpu, t);
    return true;
}

// times(buf): fill `struct tms { long tms_utime,tms_stime,tms_cutime,
// tms_cstime; }` (4 longs) and return elapsed real time in clock ticks. The
// assembler/compiler phases call this for timing; exact values don't matter,
// only that it succeeds and advances. Report a small increasing tick count.
var times_tick: u32 = 1;

fn sysTimes(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const buf = dgux.arg(cpu, 0);
    if (buf != 0 and @as(u64, buf) + 16 <= mem.Memory.size) {
        const was = runner.memory.enforce;
        runner.memory.enforce = false;
        runner.memory.write32(buf + 0, times_tick); // tms_utime
        runner.memory.write32(buf + 4, 0); // tms_stime
        runner.memory.write32(buf + 8, 0); // tms_cutime
        runner.memory.write32(buf + 12, 0); // tms_cstime
        runner.memory.enforce = was;
    }
    times_tick +%= 1;
    dgux.returnSuccess(cpu, times_tick);
    return true;
}

/// getcwd (std gate 67, used by the static SDE tools' baked-in libc). The SVR4
/// raw getcwd fills the caller's buffer with the absolute CWD and returns its
/// length (>=0) or -errno. The arg order in the static tools is buf then size;
/// we accept whichever of the first two args is a plausible writable guest
/// pointer and write the guest CWD (NUL-terminated) there.
fn sysGetcwd(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const fs = fsOf(runner) orelse {
        dgux.returnError(cpu, EINVAL);
        return true;
    };
    const cwd = fs.cwdPath();
    // The static SDE libc stub puts the buffer in r3 (arg1) and passes r2=-1
    // as a sentinel (verified by disassembling as-v2: `or r3,r0,r2` places the
    // caller's buf in r3, then `or r5,r0,r3` before the trap; the caller reads
    // buf[0] and errors if it is 0). So the buffer is arg1.
    const a1 = dgux.arg(cpu, 1);
    const a0 = dgux.arg(cpu, 0);
    const bufptr: u32 = if (a1 != 0 and @as(u64, a1) < mem.Memory.size) a1 else a0;
    if (bufptr == 0 or @as(u64, bufptr) + cwd.len + 1 > mem.Memory.size) {
        dgux.returnError(cpu, EINVAL);
        return true;
    }
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    runner.memory.writeBytes(bufptr, cwd);
    runner.memory.write8(bufptr + @as(u32, @intCast(cwd.len)), 0);
    runner.memory.enforce = was;
    // SVR4 getcwd(2) returns the number of bytes written INCLUDING the NUL
    // terminator (a positive count); <0 signals error (buffer too small ->
    // ERANGE). The static SDE libc retries with a larger buffer while the
    // return is an error, and accepts the first non-error (>0) result.
    dgux.returnSuccess(cpu, @intCast(cwd.len + 1));
    return true;
}

// -- process model -----------------------------------------------------------

/// fork (std gate 11). DG/UX SVR4 raw convention: the kernel returns the child
/// pid in r2 for BOTH processes and a discriminator in r3 (0 = parent, 1 =
/// child); libc turns r3=1 into a 0 return. We map the host fork() result
/// (pid>0 in parent, 0 in child) onto that: parent -> r2=pid,r3=0; child ->
/// r2=0,r3=1.
fn sysFork(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        dgux.returnError(cpu, EINVAL);
        return true;
    };
    const rc = pm.doFork() catch {
        dgux.returnError(cpu, ENOMEM);
        return true;
    };
    if (rc == 0) {
        dgux.returnSuccess2(cpu, 0, 1); // child: r2=0, r3=1
    } else {
        dgux.returnSuccess2(cpu, rc, 0); // parent: r2=childpid, r3=0
    }
    return true;
}

fn readStrVec(runner: *machine.Runner, vec_ptr: u32, out: [][]const u8, bufs: anytype) usize {
    if (vec_ptr == 0) return 0;
    var n: usize = 0;
    while (n < out.len) {
        const p = runner.memory.read32(vec_ptr + @as(u32, @intCast(n)) * 4);
        if (p == 0) break;
        const s = runner.memory.readCStr(p, bufs[n][0 .. bufs[n].len - 1]);
        bufs[n][s.len] = 0;
        out[n] = bufs[n][0..s.len];
        n += 1;
    }
    return n;
}

fn sysExec(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        dgux.returnError(cpu, EINVAL);
        return true;
    };
    const path_ptr = dgux.arg(cpu, 0);
    const argv_ptr = dgux.arg(cpu, 1);
    const envp_ptr = dgux.arg(cpu, 2);

    var pbuf: [1024]u8 = undefined;
    const path = readGuestPath(runner, path_ptr, &pbuf) orelse {
        dgux.returnError(cpu, EINVAL);
        return true;
    };

    var argv_store: [128][]const u8 = undefined;
    var envp_store: [256][]const u8 = undefined;
    var argv_bufs: [128][256]u8 = undefined;
    var envp_bufs: [256][256]u8 = undefined;
    const argc = readStrVec(runner, argv_ptr, &argv_store, &argv_bufs);
    const envc = readStrVec(runner, envp_ptr, &envp_store, &envp_bufs);

    if (trace) {
        var buf: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "  execve '{s}' argc={d}\n", .{ path, argc }) catch "";
        traceOut(line);
    }
    pm.doExec(path, argv_store[0..argc], envp_store[0..envc]) catch {
        dgux.returnError(cpu, ENOENT);
        return true;
    };
    runner.memory.clearFault();
    runner.exec_pending = true;
    return true;
}

// -- fail-fast ---------------------------------------------------------------

fn failFast(runner: *machine.Runner, gate: []const u8, num: u32, name: []const u8) void {
    runner.aborted = true;
    var buf: [192]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buf,
        "run88k: UNIMPLEMENTED dgux syscall[{s}] {d} ({s}) at ppc={x} r2={x} r3={x} r4={x}\n",
        .{ gate, num, name, runner.cpu.ppc, runner.cpu.getReg(2), runner.cpu.getReg(3), runner.cpu.getReg(4) },
    ) catch "run88k: unimplemented syscall (fmt err)\n";
    traceOut(line);
}

fn failFastGate(runner: *machine.Runner) void {
    runner.aborted = true;
    var buf: [128]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buf,
        "run88k: dgux trap on non-syscall vector {d} at ppc={x}\n",
        .{ runner.cpu.last_exception, runner.cpu.ppc },
    ) catch "run88k: dgux bad trap (fmt err)\n";
    traceOut(line);
}
