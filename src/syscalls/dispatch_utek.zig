//! Tektronix UTek XD88 (m88k) syscall dispatcher + host-backed implementations.
//!
//! Separate from the SysV/88 dispatcher (dispatch.zig) and the OpenBSD one
//! (dispatch_openbsd.zig): the three OSes share the same trap mechanism but
//! differ in syscall numbers, errno values, and struct layouts. This is a
//! focused UTek dispatcher grown from the minimal set a static `echo`/`cat`/
//! `pwd`/`ls` needs, mirroring how the other two were bootstrapped.
//!
//! Convention (abi/utek.zig): number in r9, args r2..r8, return r2 (+r3 for
//! dual-return), carry-flag error, skip-on-success PC, trap vector 450.
//!
//! UTek is BSD-derived (UFS1 filesystem) but its userland errno numbers follow
//! the AT&T/UniSoft SysV lineage, and its `struct stat`/`struct dirent` are the
//! all-32-bit SysV-style layouts (see docs/abi-utek.md), so much of the host
//! plumbing matches the SysV/88 dispatcher — only the number table, the exact
//! `struct stat` field set, and a few conventions differ.

const std = @import("std");
const m88k = @import("m88k");
const mem = @import("../mem.zig");
const machine = @import("../machine.zig");
const utek = @import("../abi/utek.zig");
const table = @import("table_utek.zig");
const fsmod = @import("../fs.zig");
const procmodel = @import("../procmodel.zig");

const Cpu = m88k.Cpu;
const Syscall = table.Syscall;

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
extern "c" fn fcntl(fd: c_int, cmd: c_int, arg: c_int) c_int;
extern "c" fn dup(fd: c_int) c_int;
extern "c" fn chmod(path: [*:0]const u8, mode: c_uint) c_int;
extern "c" fn time(t: ?*c_long) c_long;
extern "c" fn isatty(fd: c_int) c_int;
extern "c" fn getpid() c_int;
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
extern fn r88k_lstat(path: [*:0]const u8, out: *HostStat) void;

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

// -- errno values (UTek = AT&T SysV numbers, usr/include/sys/errno.h) --------
const EPERM: u32 = 1;
const ENOENT: u32 = 2;
const EINTR: u32 = 4;
const EBADF: u32 = 9;
const ECHILD: u32 = 10;
const ENOMEM: u32 = 12;
const EFAULT: u32 = 14;
const EINVAL: u32 = 22;
const ENOTTY: u32 = 25;
const ENOSYS: u32 = 89; // UTek/SysV: function not implemented

/// Map a host (Linux) errno to a UTek errno. UTek's low numbers are the AT&T
/// SysV set, which coincides with Linux for the common 1..34 range; anything
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
/// continue the guest, false to stop (exit / fatal).
pub fn dispatch(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;

    // The "local"/Tektronix trap (vector 449) is a separate syscall entry used
    // for getrlimit/setrlimit and the sys_local multiplexor. Handle it apart
    // from the main vector-450 table.
    if (cpu.last_exception == utek.syscall_vector_local) {
        return dispatchLocal(runner);
    }

    const num = utek.syscallNumber(cpu);
    const sc: Syscall = @enumFromInt(num);

    if (trace) {
        var buf: [96]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "syscall {d} ({s}) a0={x} a1={x} a2={x}\n", .{
            num, @tagName(sc), utek.arg(cpu, 0), utek.arg(cpu, 1), utek.arg(cpu, 2),
        }) catch "syscall (fmt err)\n";
        traceOut(line);
    }

    switch (sc) {
        .exit => {
            runner.exit_status = utek.arg(cpu, 0);
            return false;
        },
        .write => return sysWrite(runner),
        .read => return sysRead(runner),
        .open => return sysOpen(runner),
        .close => return sysClose(runner),
        .lseek => return sysLseek(runner),
        .brk => return sysBrk(runner),
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
        .ioctl => return sysIoctl(runner),
        .fcntl => return sysFcntl(runner),
        .time => return sysTime(runner),
        .uname => return sysUname(runner),
        .sysconf => return sysSysconf(runner),
        .fpathconf, .pathconf => return sysPathconf(runner),
        .ulimit => return sysUlimit(runner),
        .utime => return sysUtime(runner),
        .times => return sysTimes(runner),

        // Identity syscalls: report plausible values (running as root). The
        // dual-return calls hand the second value back in r3 (getppid/geteuid/
        // getegid read r3).
        .getpid => {
            utek.returnSuccess2(cpu, 1, 0); // pid=1, ppid=0
            return true;
        },
        .getuid => {
            utek.returnSuccess2(cpu, 0, 0); // uid=0, euid=0
            return true;
        },
        .getgid => {
            utek.returnSuccess2(cpu, 0, 0); // gid=0, egid=0
            return true;
        },
        .getgroups => {
            utek.returnSuccess(cpu, 0); // no supplementary groups
            return true;
        },
        .getpgrp => {
            utek.returnSuccess(cpu, 1);
            return true;
        },
        .setpgid, .setsid, .setuid, .setgid => {
            utek.returnSuccess(cpu, 0);
            return true;
        },
        .umask => {
            const old = runner.umask;
            runner.umask = utek.arg(cpu, 0) & 0o777;
            utek.returnSuccess(cpu, old);
            return true;
        },

        // Signal syscalls: no signal delivery yet — accept and return benign
        // success (shells/utilities install handlers at startup).
        .sigaction, .sigprocmask, .sigpending, .sigsuspend, .sigfillset => {
            utek.returnSuccess(cpu, 0);
            return true;
        },

        // Process model (fork/exec/wait/pipe) for the shell milestone.
        .fork => return sysFork(runner),
        .execve => return sysExec(runner),
        .waitpid => return sysWaitpid(runner),
        .pipe => return sysPipe(runner),

        else => {
            failFast(runner, num, sc);
            return false;
        },
    }
}

// -- vector 449: "local"/Tektronix multiplexed calls -------------------------

// Local-call numbers on vector 449 (from the libc stubs): setrlimit=1,
// getrlimit=2. (sys_local is a further multiplexor loaded into r10..r19.)
const LOCAL_SETRLIMIT: u32 = 1;
const LOCAL_GETRLIMIT: u32 = 2;

// getrlimit/setrlimit(resource, struct rlimit *rlp). struct rlimit is two
// longs { rlim_cur, rlim_max }, big-endian. Resource ids (SysV rlimit.h):
// RLIMIT_CPU=0, FSIZE=1, DATA=2, STACK=3, CORE=4, NOFILE=5, VMEM/AS=6.
const RLIM_INFINITY: u32 = 0x7fffffff;

fn dispatchLocal(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const num = utek.syscallNumber(cpu); // r9

    if (trace) {
        var buf: [96]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "syscall.local {d} a0={x} a1={x}\n", .{
            num, utek.arg(cpu, 0), utek.arg(cpu, 1),
        }) catch "syscall.local\n";
        traceOut(line);
    }

    switch (num) {
        LOCAL_GETRLIMIT => {
            // Two call shapes reach vector 449 with number 2:
            //  (a) libc getrlimit(resource, rlp): resource in r2, rlp in r3
            //      (the stub sets r8=0x300, r9=2 and does NOT shuffle).
            //  (b) the sys_local multiplexor (inlined by e.g. ls): a register
            //      rotation leaves the args shifted, so r2/r3 are not the
            //      (resource, rlp) pair. To stay memory-safe we only fill a
            //      buffer when the arg looks like a real writable pointer.
            const resource = utek.arg(cpu, 0);
            const rlp = utek.arg(cpu, 1);
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
            utek.returnSuccess(cpu, 0);
            return true;
        },
        LOCAL_SETRLIMIT => {
            // Accept and ignore (we don't enforce guest resource limits).
            utek.returnSuccess(cpu, 0);
            return true;
        },
        else => {
            // Unknown local call: report not-implemented so the guest can fall
            // back, rather than aborting the whole run.
            utek.returnError(cpu, ENOSYS);
            return true;
        },
    }
}

// -- path helpers ------------------------------------------------------------

fn readGuestPath(runner: *machine.Runner, ptr: u32, buf: []u8) ?[]const u8 {
    const s = runner.memory.readCStr(ptr, buf[0 .. buf.len - 1]);
    if (s.len >= buf.len - 1) return null;
    buf[s.len] = 0;
    return buf[0..s.len];
}

/// Resolve a single guest path argument to a NUL-terminated host path, writing
/// errors on the standard failures. Returns null if it already reported an
/// error (caller returns true).
fn resolveArgPath(runner: *machine.Runner, arg_index: u5, gbuf: []u8, hbuf: []u8) ?[*:0]const u8 {
    const cpu = &runner.cpu;
    const path_ptr = utek.arg(cpu, arg_index);
    const gpath = readGuestPath(runner, path_ptr, gbuf) orelse {
        utek.returnError(cpu, EINVAL);
        return null;
    };
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, hbuf) catch {
            utek.returnError(cpu, ENOENT);
            return null;
        };
        return hp.ptr;
    }
    return @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
}

/// Map a guest fd to a host fd. With an fs, go through the fd table; without,
/// the guest fd IS the host fd.
fn hostFd(runner: *machine.Runner, gfd: u32) ?c_int {
    if (fsOf(runner)) |fs| {
        const h = fs.get(gfd) orelse return null;
        return @intCast(h);
    }
    return @intCast(gfd);
}

// -- I/O ---------------------------------------------------------------------

fn sysWrite(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = utek.arg(cpu, 0);
    const buf = utek.arg(cpu, 1);
    const count = utek.arg(cpu, 2);
    const hfd = hostFd(runner, gfd) orelse {
        utek.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, buf) + count > mem.Memory.size) {
        utek.returnError(cpu, EFAULT);
        return true;
    }
    const slice = runner.memory.bytes[buf .. buf + count];
    const n = write(hfd, slice.ptr, slice.len);
    if (n < 0) utek.returnError(cpu, mapErrno(hostErrno())) else utek.returnSuccess(cpu, @intCast(n));
    return true;
}

fn sysRead(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = utek.arg(cpu, 0);
    const buf = utek.arg(cpu, 1);
    const count = utek.arg(cpu, 2);
    const hfd = hostFd(runner, gfd) orelse {
        utek.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, buf) + count > mem.Memory.size) {
        utek.returnError(cpu, EFAULT);
        return true;
    }
    const slice = runner.memory.bytes[buf .. buf + count];
    const n = read(hfd, slice.ptr, slice.len);
    if (n < 0) utek.returnError(cpu, mapErrno(hostErrno())) else utek.returnSuccess(cpu, @intCast(n));
    return true;
}

// UTek O_* open flags (from usr/include/sys/fcntl.h): O_RDONLY=0, O_WRONLY=1,
// O_RDWR=2, O_APPEND=0x8, O_CREAT=0x100, O_TRUNC=0x200, O_EXCL=0x400. Host
// (Linux) values differ; translate.
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
    const path_ptr = utek.arg(cpu, 0);
    const flags = utek.arg(cpu, 1);
    const mode = utek.arg(cpu, 2);

    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        utek.returnError(cpu, EINVAL);
        return true;
    };

    var hbuf: [2048]u8 = undefined;
    var cpath: [*:0]const u8 = @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, &hbuf) catch {
            utek.returnError(cpu, ENOENT);
            return true;
        };
        cpath = hp.ptr;
    }

    const hfd = open(cpath, translateOpenFlags(flags), @intCast(mode));
    if (hfd < 0) {
        utek.returnError(cpu, mapErrno(hostErrno()));
        return true;
    }
    if (fsOf(runner)) |fs| {
        var canonbuf: [1024]u8 = undefined;
        const gcanon = fs.canonicalGuest(gpath, &canonbuf) orelse gpath;
        if (fs.openDir(cpath, gcanon, hfd)) |gdir| {
            utek.returnSuccess(cpu, gdir);
            return true;
        }
        const gfd = fs.allocFd(hfd) orelse {
            _ = close(hfd);
            utek.returnError(cpu, EBADF);
            return true;
        };
        utek.returnSuccess(cpu, gfd);
    } else {
        utek.returnSuccess(cpu, @intCast(hfd));
    }
    return true;
}

fn sysClose(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = utek.arg(cpu, 0);
    if (fsOf(runner)) |fs| {
        if (fs.closeFd(gfd)) utek.returnSuccess(cpu, 0) else utek.returnError(cpu, EBADF);
        return true;
    }
    if (gfd <= 2) {
        utek.returnSuccess(cpu, 0);
        return true;
    }
    const rc = close(@intCast(gfd));
    if (rc < 0) utek.returnError(cpu, mapErrno(hostErrno())) else utek.returnSuccess(cpu, 0);
    return true;
}

fn sysLseek(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = utek.arg(cpu, 0);
    const off = utek.arg(cpu, 1);
    const whence = utek.arg(cpu, 2);
    const fd = hostFd(runner, gfd) orelse {
        utek.returnError(cpu, EBADF);
        return true;
    };
    const pos = lseek(fd, @as(c_long, @intCast(@as(i32, @bitCast(off)))), @intCast(whence));
    if (pos < 0) utek.returnError(cpu, mapErrno(hostErrno())) else utek.returnSuccess(cpu, @intCast(pos & 0xffff_ffff));
    return true;
}

fn sysAccess(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const amode = utek.arg(cpu, 1);
    var gbuf: [1024]u8 = undefined;
    var hbuf: [2048]u8 = undefined;
    const cpath = resolveArgPath(runner, 0, &gbuf, &hbuf) orelse return true;
    // access(2) amode: F_OK=0, X_OK=1, W_OK=2, R_OK=4 (low 3 bits match Linux).
    const hmode: c_int = @intCast(amode & 0x7);
    if (fsmod.c.access(cpath, hmode) < 0) utek.returnError(cpu, mapErrno(hostErrno())) else utek.returnSuccess(cpu, 0);
    return true;
}

fn sysChdir(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const path_ptr = utek.arg(cpu, 0);
    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        utek.returnError(cpu, EINVAL);
        return true;
    };
    if (fsOf(runner)) |fs| {
        var hbuf: [2048]u8 = undefined;
        const hp = fs.resolve(gpath, &hbuf) catch {
            utek.returnError(cpu, ENOENT);
            return true;
        };
        if (fsmod.c.access(hp, 0) < 0) {
            utek.returnError(cpu, ENOENT);
            return true;
        }
        fs.chdir(gpath) catch {
            utek.returnError(cpu, EINVAL);
            return true;
        };
    }
    utek.returnSuccess(cpu, 0);
    return true;
}

fn sysChmod(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const mode = utek.arg(cpu, 1);
    var gbuf: [1024]u8 = undefined;
    var hbuf: [2048]u8 = undefined;
    const cpath = resolveArgPath(runner, 0, &gbuf, &hbuf) orelse return true;
    if (chmod(cpath, @intCast(mode & 0o7777)) < 0) utek.returnError(cpu, mapErrno(hostErrno())) else utek.returnSuccess(cpu, 0);
    return true;
}

fn sysUnlink(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    var gbuf: [1024]u8 = undefined;
    var hbuf: [2048]u8 = undefined;
    const cpath = resolveArgPath(runner, 0, &gbuf, &hbuf) orelse return true;
    if (fsmod.c.unlink(cpath) < 0) utek.returnError(cpu, mapErrno(hostErrno())) else utek.returnSuccess(cpu, 0);
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
    if (fsmod.c.rename(oldp, newp) < 0) utek.returnError(cpu, mapErrno(hostErrno())) else utek.returnSuccess(cpu, 0);
    return true;
}

fn sysMkdir(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const mode = utek.arg(cpu, 1);
    var gbuf: [1024]u8 = undefined;
    var hbuf: [2048]u8 = undefined;
    const cpath = resolveArgPath(runner, 0, &gbuf, &hbuf) orelse return true;
    if (fsmod.c.mkdir(cpath, @intCast(mode & 0o7777)) < 0) utek.returnError(cpu, mapErrno(hostErrno())) else utek.returnSuccess(cpu, 0);
    return true;
}

fn sysRmdir(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    var gbuf: [1024]u8 = undefined;
    var hbuf: [2048]u8 = undefined;
    const cpath = resolveArgPath(runner, 0, &gbuf, &hbuf) orelse return true;
    if (fsmod.c.rmdir(cpath) < 0) utek.returnError(cpu, mapErrno(hostErrno())) else utek.returnSuccess(cpu, 0);
    return true;
}

// -- brk ---------------------------------------------------------------------

/// UTek `brk`: the argument is the absolute new break address. Grow/shrink the
/// heap and return 0 (like the kernel; libc's sbrk tracks the old break).
fn sysBrk(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const newbrk = utek.arg(cpu, 0);
    if (newbrk >= 0x0B00_0000) {
        utek.returnError(cpu, ENOMEM);
        return true;
    }
    if (newbrk < runner.brk_base) {
        utek.returnSuccess(cpu, 0);
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
    utek.returnSuccess(cpu, 0);
    return true;
}

// -- stat --------------------------------------------------------------------

// UTek `struct stat` (usr/include/sys/stat.h; all fields are 4-byte `long`,
// big-endian). Layout, total 512 bytes (the trailing st_pad[456] is zeroed):
//   st_dev@0 st_ino@4 st_mode@8 st_nlink@12 st_uid@16 st_gid@20 st_rdev@24
//   st_size@28 st_atime@32 st_ausec@36 st_mtime@40 st_musec@44 st_ctime@48
//   st_cusec@52  (then st_pad[456])
// S_IF* type bits match host Linux (S_IFDIR=0x4000, S_IFREG=0x8000, ...).
const STAT_SIZE: u32 = 512;

fn writeGuestStat(memory: *mem.Memory, addr: u32, hs: *const HostStat) void {
    memory.zero(addr, STAT_SIZE);
    memory.write32(addr + 0, hs.dev); // st_dev
    memory.write32(addr + 4, hs.ino); // st_ino
    memory.write32(addr + 8, hs.mode); // st_mode (full 32-bit; S_IF* match host)
    memory.write32(addr + 12, hs.nlink); // st_nlink
    memory.write32(addr + 16, hs.uid); // st_uid
    memory.write32(addr + 20, hs.gid); // st_gid
    memory.write32(addr + 24, hs.rdev); // st_rdev
    memory.write32(addr + 28, @truncate(hs.size)); // st_size
    memory.write32(addr + 32, @bitCast(@as(i32, @truncate(hs.atime)))); // st_atime
    memory.write32(addr + 40, @bitCast(@as(i32, @truncate(hs.mtime)))); // st_mtime
    memory.write32(addr + 48, @bitCast(@as(i32, @truncate(hs.ctime)))); // st_ctime
}

fn sysFstat(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = utek.arg(cpu, 0);
    const statbuf = utek.arg(cpu, 1);
    const fd = hostFd(runner, gfd) orelse {
        utek.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, statbuf) + STAT_SIZE > mem.Memory.size) {
        utek.returnError(cpu, EFAULT);
        return true;
    }
    var hs: HostStat = undefined;
    r88k_fstat(fd, &hs);
    if (hs.ok == 0) {
        utek.returnError(cpu, mapErrno(@intCast(hs.err)));
        return true;
    }
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    writeGuestStat(runner.memory, statbuf, &hs);
    runner.memory.enforce = was;
    utek.returnSuccess(cpu, 0);
    return true;
}

fn sysStat(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const path_ptr = utek.arg(cpu, 0);
    const statbuf = utek.arg(cpu, 1);
    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        utek.returnError(cpu, EINVAL);
        return true;
    };
    if (@as(u64, statbuf) + STAT_SIZE > mem.Memory.size) {
        utek.returnError(cpu, EFAULT);
        return true;
    }
    var hbuf: [2048]u8 = undefined;
    var cpath: [*:0]const u8 = @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, &hbuf) catch {
            utek.returnError(cpu, ENOENT);
            return true;
        };
        cpath = hp.ptr;
    }
    var hs: HostStat = undefined;
    r88k_stat(cpath, &hs);
    if (hs.ok == 0) {
        utek.returnError(cpu, mapErrno(@intCast(hs.err)));
        return true;
    }
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    writeGuestStat(runner.memory, statbuf, &hs);
    runner.memory.enforce = was;
    utek.returnSuccess(cpu, 0);
    return true;
}

// -- getdents ----------------------------------------------------------------

/// getdents(fd, buf, nbyte): fill buf with UTek `struct dirent`:
///   ino_t d_ino (4) ; off_t d_off (4) ; unsigned short d_reclen (2) ;
///   char d_name[] (NUL-terminated, then pad to align d_reclen to 4).
/// Same layout as SysV/88. Returns bytes written, 0 at end of directory.
fn sysGetdents(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = utek.arg(cpu, 0);
    const buf = utek.arg(cpu, 1);
    const nbyte = utek.arg(cpu, 2);
    const fs = fsOf(runner) orelse {
        utek.returnError(cpu, EBADF);
        return true;
    };
    const handle = fs.dirHandleFor(gfd) orelse {
        utek.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, buf) + nbyte > mem.Memory.size) {
        utek.returnError(cpu, EFAULT);
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

    while (true) {
        var ino: c_ulong = 0;
        var namebuf: [256]u8 = undefined;
        const rc = r88k_dirread(handle, &ino, &namebuf);
        if (rc <= 0) break;
        const name = std.mem.sliceTo(&namebuf, 0);
        if (!emit(runner, buf, &written, nbyte, @intCast(ino & 0xffffffff), name)) {
            fs.dirPushback(handle);
            break;
        }
    }
    utek.returnSuccess(cpu, written);
    return true;
}

// -- ioctl / fcntl / time / uname -------------------------------------------

// UTek terminal ioctls (SysV termio family, from usr/include/sys/termio.h).
const TCGETA: u32 = 0x5401;
const TCSETA: u32 = 0x5402;
const TCSETAW: u32 = 0x5403;
const TCSETAF: u32 = 0x5404;
const TERMIO_LEN: u32 = 18;

fn sysIoctl(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = utek.arg(cpu, 0);
    const req = utek.arg(cpu, 1);
    const argp = utek.arg(cpu, 2);
    switch (req) {
        TCGETA => {
            const hfd = hostFd(runner, gfd) orelse {
                utek.returnError(cpu, EBADF);
                return true;
            };
            if (isatty(hfd) != 1) {
                utek.returnError(cpu, ENOTTY);
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
            utek.returnSuccess(cpu, 0);
            return true;
        },
        TCSETA, TCSETAW, TCSETAF => {
            const hfd = hostFd(runner, gfd) orelse {
                utek.returnError(cpu, EBADF);
                return true;
            };
            if (isatty(hfd) != 1) utek.returnError(cpu, ENOTTY) else utek.returnSuccess(cpu, 0);
            return true;
        },
        else => {
            utek.returnError(cpu, ENOTTY);
            return true;
        },
    }
}

/// fcntl. UTek cmds match SysV: F_DUPFD=0, F_GETFD=1, F_SETFD=2, F_GETFL=3,
/// F_SETFL=4.
fn sysFcntl(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = utek.arg(cpu, 0);
    const cmd = utek.arg(cpu, 1);
    const arg3 = utek.arg(cpu, 2);
    const fd = hostFd(runner, gfd) orelse {
        utek.returnError(cpu, EBADF);
        return true;
    };
    switch (cmd) {
        0 => { // F_DUPFD
            const hnew = dup(fd);
            if (hnew < 0) {
                utek.returnError(cpu, mapErrno(hostErrno()));
                return true;
            }
            if (fsOf(runner)) |fs| {
                const gnew = fs.allocFdFrom(hnew, arg3) orelse {
                    _ = close(hnew);
                    utek.returnError(cpu, EBADF);
                    return true;
                };
                utek.returnSuccess(cpu, gnew);
            } else {
                utek.returnSuccess(cpu, @intCast(hnew));
            }
        },
        1, 2 => {
            const rc = fcntl(fd, @intCast(cmd), @intCast(arg3));
            if (rc < 0) utek.returnError(cpu, mapErrno(hostErrno())) else utek.returnSuccess(cpu, @intCast(rc));
        },
        3 => utek.returnSuccess(cpu, 0), // F_GETFL
        4 => utek.returnSuccess(cpu, 0), // F_SETFL
        else => utek.returnSuccess(cpu, 0),
    }
    return true;
}

fn sysTime(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const t: u32 = @intCast(@as(i64, time(null)) & 0xffff_ffff);
    const tptr = utek.arg(cpu, 0);
    if (tptr != 0 and @as(u64, tptr) + 4 <= mem.Memory.size) {
        const was = runner.memory.enforce;
        runner.memory.enforce = false;
        runner.memory.write32(tptr, t);
        runner.memory.enforce = was;
    }
    utek.returnSuccess(cpu, t);
    return true;
}

// uname(2): fill a SysV `struct utsname` (five NUL-terminated SYS_NMLN-byte
// fields). SYS_NMLN on this userland is checked at implementation time; SVR3/4
// commonly use 9 (old) — but UTek's utsname is larger. Use the guest header's
// value if a mismatch surfaces; 257 is a safe upper bound that libc reads
// field-by-field from fixed offsets, so keep the classic 9-byte SysV layout.
const SYS_NMLN: u32 = 257;

fn sysUname(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const buf = utek.arg(cpu, 0);
    const total = SYS_NMLN * 5;
    if (buf == 0 or @as(u64, buf) + total > mem.Memory.size) {
        utek.returnError(cpu, EFAULT);
        return true;
    }
    const fields = [_][]const u8{ "UTek", "run88k", "4.0", "1", "m88k" };
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    runner.memory.zero(buf, total);
    for (fields, 0..) |f, i| {
        const base = buf + @as(u32, @intCast(i)) * SYS_NMLN;
        runner.memory.writeBytes(base, f);
        runner.memory.write8(base + @as(u32, @intCast(f.len)), 0);
    }
    runner.memory.enforce = was;
    utek.returnSuccess(cpu, 0);
    return true;
}

// sysconf(name): return a system limit/parameter. Names are the guest's
// _SC_* values (usr/include/sys/unistd.h). libc startup queries several of
// these (notably _SC_CPUID=33, which the C library reads at init). Return
// plausible values; unknown names get -1/EINVAL like the real kernel.
fn sysSysconf(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const name = utek.arg(cpu, 0);
    const val: ?u32 = switch (name) {
        1 => 0x10000, // _SC_ARG_MAX
        2 => 64, // _SC_CHILD_MAX
        3 => 100, // _SC_CLK_TCK (HZ)
        4 => 16, // _SC_NGROUPS_MAX
        5 => fsmod.MAX_FD, // _SC_OPEN_MAX
        6 => 1, // _SC_JOB_CONTROL
        7 => 1, // _SC_SAVED_IDS
        8 => 198808, // _SC_VERSION (POSIX.1 stamp)
        9 => 1, // _SC_BCS_VERSION
        12 => 0x8000, // _SC_MAXUMEMV (1-KB pages)
        13 => 64, // _SC_MAXUPROC
        27 => 0x10000, // _SC_PHYSMEM (kb)
        28 => 0x8000, // _SC_AVAILMEM (kb)
        29 => 1, // _SC_NICE
        30 => 1, // _SC_MEMCTL_UNIT
        31 => 0x1000, // _SC_SHMLBA
        // _SC_CPUID: libc startup (linked into every BCS binary) reads this as
        // the CPU "mask level" and REQUIRES it to be >= 13 (0xd) or it prints
        // "Minimum CPU mask level required is 13" and aborts. Verified by
        // disassembly of /bin/cat: `cmp r10,r25,0xd; bb1 ge,...`. Report a
        // late-mask MC88100 level (>= 13). 0x1a matches a real XD88.
        33 => 0x0000001a, // _SC_CPUID (CPU mask level; must be >= 13)
        else => null,
    };
    if (val) |v| utek.returnSuccess(cpu, v) else utek.returnError(cpu, EINVAL);
    return true;
}

// times(buf): fill `struct tms { long tms_utime, tms_stime, tms_cutime,
// tms_cstime; }` (4 longs) with process/child CPU times in clock ticks, and
// return the elapsed real time in ticks. The toolchain (as/ccom) calls this to
// report phase timings; exact values don't matter, only that it succeeds and
// advances. We report a small, monotonically increasing tick count.
var times_tick: u32 = 1;

fn sysTimes(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const buf = utek.arg(cpu, 0);
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
    utek.returnSuccess(cpu, times_tick);
    return true;
}

// ulimit(cmd, newlimit): SVR4/UTek resource limits.
//   1 UL_GFILLIM  get file-size limit (512-byte blocks)
//   2 UL_SFILLIM  set file-size limit
//   3 UL_GMEMLIM  get max break address (data-size ceiling)
//   4 UL_GDESLIM  get max file descriptors
// sort/other tools query these at startup to size buffers.
fn sysUlimit(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const cmd = utek.arg(cpu, 0);
    switch (cmd) {
        1 => utek.returnSuccess(cpu, 0x0020_0000), // large file limit (blocks)
        2 => utek.returnSuccess(cpu, utek.arg(cpu, 1)), // accept the set, echo it
        3 => utek.returnSuccess(cpu, 0x0800_0000), // max break (below mmap region)
        4 => utek.returnSuccess(cpu, fsmod.MAX_FD), // max fds
        else => utek.returnError(cpu, EINVAL),
    }
    return true;
}

// utime(path, times): set a file's access/modification times. times is a
// pointer to two longs {actime, modtime}, or 0 for "now". Route to the host.
extern "c" fn utime(path: [*:0]const u8, times: ?*const [2]c_long) c_int;

fn sysUtime(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const times_ptr = utek.arg(cpu, 1);
    var gbuf: [1024]u8 = undefined;
    var hbuf: [2048]u8 = undefined;
    const cpath = resolveArgPath(runner, 0, &gbuf, &hbuf) orelse return true;
    var tv: [2]c_long = undefined;
    var tp: ?*const [2]c_long = null;
    if (times_ptr != 0 and @as(u64, times_ptr) + 8 <= mem.Memory.size) {
        tv[0] = @intCast(runner.memory.read32(times_ptr + 0));
        tv[1] = @intCast(runner.memory.read32(times_ptr + 4));
        tp = &tv;
    }
    if (utime(cpath, tp) < 0) utek.returnError(cpu, mapErrno(hostErrno())) else utek.returnSuccess(cpu, 0);
    return true;
}

// pathconf(path, name) / fpathconf(fd, name): return a pathname-configurable
// limit. The name is the 2nd arg (r3). _PC_* values (sys/unistd.h):
// _PC_LINK_MAX=1, _PC_MAX_CANON=2, _PC_MAX_INPUT=3, _PC_NAME_MAX=4,
// _PC_PATH_MAX=5, _PC_PIPE_BUF=6, _PC_CHOWN_RESTRICTED=7, _PC_NO_TRUNC=8,
// _PC_VDISABLE=9. Return plausible values; unknown -> EINVAL.
fn sysPathconf(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const name = utek.arg(cpu, 1);
    const val: ?u32 = switch (name) {
        1 => 32767, // _PC_LINK_MAX
        2 => 256, // _PC_MAX_CANON
        3 => 256, // _PC_MAX_INPUT
        4 => 255, // _PC_NAME_MAX (UFS)
        5 => 1024, // _PC_PATH_MAX
        6 => 5120, // _PC_PIPE_BUF
        7 => 1, // _PC_CHOWN_RESTRICTED
        8 => 1, // _PC_NO_TRUNC
        9 => 0, // _PC_VDISABLE
        else => null,
    };
    if (val) |v| utek.returnSuccess(cpu, v) else utek.returnError(cpu, EINVAL);
    return true;
}

// -- process model -----------------------------------------------------------

/// fork. UTek is BSD-style: parent gets child pid in r2, child gets 0 in r2.
/// (Unlike SVR4's r2=pid/r3=flag split; UTek's fork stub — number 11 — returns
/// a single value like BSD.)
fn sysFork(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        utek.returnError(cpu, EINVAL);
        return true;
    };
    const rc = pm.doFork() catch {
        utek.returnError(cpu, ENOMEM);
        return true;
    };
    // rc: 0 in the child, child-pid in the parent.
    utek.returnSuccess(cpu, rc);
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
        utek.returnError(cpu, EINVAL);
        return true;
    };
    const path_ptr = utek.arg(cpu, 0);
    const argv_ptr = utek.arg(cpu, 1);
    const envp_ptr = utek.arg(cpu, 2);

    var pbuf: [1024]u8 = undefined;
    const path = readGuestPath(runner, path_ptr, &pbuf) orelse {
        utek.returnError(cpu, EINVAL);
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
        utek.returnError(cpu, ENOENT);
        return true;
    };
    runner.memory.clearFault();
    runner.exec_pending = true;
    return true;
}

fn sysWaitpid(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        utek.returnError(cpu, EINVAL);
        return true;
    };
    // waitpid(pid, statptr, options) — DUAL RETURN: the kernel returns the
    // reaped pid in r2 and the status word in r3. The libc stub itself does
    // `st r3, statptr` after the trap (verified from waitpid.o), so the kernel
    // must NOT write the buffer — it only sets r2:r3. Writing the buffer here
    // would be clobbered by the stub's store of r3 and corrupt the caller's
    // status (this is exactly what made `cc` misread cpp's exit status).
    const res = pm.doWait() catch {
        utek.returnError(cpu, ECHILD);
        return true;
    };
    utek.returnSuccess2(cpu, res.pid, res.status);
    return true;
}

fn sysPipe(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        utek.returnError(cpu, EINVAL);
        return true;
    };
    const fds = pm.doPipe() catch {
        utek.returnError(cpu, ENOMEM);
        return true;
    };
    // UTek pipe: read fd in r2, write fd in r3 (dual return, like getpid).
    utek.returnSuccess2(cpu, fds[0], fds[1]);
    return true;
}

fn failFast(runner: *machine.Runner, num: u32, sc: Syscall) void {
    runner.aborted = true;
    var buf: [160]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buf,
        "run88k: UNIMPLEMENTED utek syscall {d} ({s}) at ppc={x} r2={x} r3={x} r4={x}\n",
        .{ num, @tagName(sc), runner.cpu.ppc, runner.cpu.getReg(2), runner.cpu.getReg(3), runner.cpu.getReg(4) },
    ) catch "run88k: unimplemented syscall (fmt err)\n";
    traceOut(line);
}
