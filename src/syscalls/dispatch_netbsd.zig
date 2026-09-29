//! NetBSD/luna88k (m88k) syscall dispatcher.
//!
//! Separate from the OpenBSD dispatcher (dispatch_openbsd.zig): the two OSes
//! share the same BSD trap mechanism (number in r13, carry-error,
//! skip-on-success) but differ in the trap vector (128 vs 450), the syscall
//! number table (NetBSD 3.0, versioned __stat13/getdents), and the struct
//! layouts (NetBSD 3.0 has 32-bit time_t, so `struct stat` and `struct dirent`
//! are the older, smaller shapes). This is a focused BSD dispatcher grown
//! incrementally from the minimal set a static `echo` needs, mirroring how the
//! OpenBSD side was bootstrapped.
//!
//! Convention (abi/netbsd.zig): number in r13, args r2.., return r2 (+r3),
//! carry-flag error, skip-on-success PC, trap vector 128.
//!
//! NetBSD's libc routes the 64-bit-offset calls (lseek/mmap/pread/ftruncate)
//! through the indirect `__syscall`(198) gate; the indirect normalization
//! below shifts the argument window so those handlers read args exactly like
//! OpenBSD's (off_t in the even/odd register pair).

const std = @import("std");
const machine = @import("../machine.zig");
const mem = @import("../mem.zig");
const fsmod = @import("../fs.zig");
const procmodel = @import("../procmodel.zig");
const nbsd = @import("../abi/netbsd.zig");
const Syscall = @import("table_netbsd.zig").Syscall;

extern "c" fn getpid() c_int;
extern "c" fn getppid() c_int;
extern "c" fn dup(fd: c_int) c_int;
extern "c" fn dup2(oldfd: c_int, newfd: c_int) c_int;

fn pmOf(runner: *machine.Runner) ?*procmodel.HostProcess {
    const p = runner.procmodel orelse return null;
    return @ptrCast(@alignCast(p));
}

const ECHILD: u32 = 10;

// Host libc primitives (same set the other dispatchers use).
extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern "c" fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern "c" fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn lseek(fd: c_int, off: c_long, whence: c_int) c_long;
extern "c" fn pread(fd: c_int, buf: [*]u8, count: usize, off: c_long) isize;
extern "c" fn __errno_location() *c_int;
extern "c" fn isatty(fd: c_int) c_int;
extern "c" fn time(t: ?*c_long) c_long;

fn hostErrno() u32 {
    return @intCast(__errno_location().*);
}

fn traceOut(bytes: []const u8) void {
    _ = write(2, bytes.ptr, bytes.len);
}

/// Set by main.zig when --trace is passed.
pub var trace: bool = false;

// --- NetBSD errno values (sys/errno.h) — match the BSD low range ----------
const EPERM: u32 = 1;
const ENOENT: u32 = 2;
const EINTR: u32 = 4;
const EBADF: u32 = 9;
const ENOMEM: u32 = 12;
const EFAULT: u32 = 14;
const EINVAL: u32 = 22;
const ENOTTY: u32 = 25;
const ERANGE: u32 = 34;
const ENOSYS: u32 = 78; // NetBSD ENOSYS = 78

fn fsOf(runner: *machine.Runner) ?*fsmod.Fs {
    if (runner.fs) |p| return @ptrCast(@alignCast(p));
    return null;
}

/// Map a host (Linux) errno to the NetBSD errno the guest expects. The low
/// numbers line up (EPERM=1, ENOENT=2, ...); ranges diverge above ~34, but for
/// the utilities we run the common ones match. Refine as mismatches surface.
fn mapErrno(host: u32) u32 {
    return switch (host) {
        1 => EPERM,
        2 => ENOENT,
        9 => EBADF,
        12 => ENOMEM,
        14 => EFAULT,
        22 => EINVAL,
        25 => ENOTTY,
        else => if (host >= 1 and host <= 34) host else EINVAL,
    };
}

/// Map a guest fd to a host fd through the fs table (or identity if no fs).
fn hostFd(runner: *machine.Runner, gfd: u32) ?c_int {
    if (fsOf(runner)) |fs| {
        const h = fs.get(gfd) orelse return null;
        return @intCast(h);
    }
    return @intCast(gfd);
}

/// The dispatcher installed as the runner's syscall handler for NetBSD guests.
pub fn dispatch(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    var num = nbsd.syscallNumber(cpu);

    // Indirect forms carry the real syscall number in the leading argument(s).
    // Two shapes, distinguished by the gate number:
    //   SYS_syscall(0):    `int syscall(int number, ...)`  — number in r2
    //     (arg0, a single word). Args start at r3, so shift the window by 1.
    //   SYS___syscall(198): `quad_t __syscall(quad_t number, ...)` — number is
    //     a 64-bit value in the r2:r3 pair (high word r2, low word r3 on
    //     big-endian m88k). The real number is the low word (r3, arg1) and the
    //     args start at r4, so shift the window by 2. NetBSD's libc routes the
    //     64-bit-offset calls (lseek/mmap/pread/ftruncate) through __syscall.
    if (num == 0) {
        num = nbsd.arg(cpu, 0);
        var k: u5 = 0;
        while (k < 10) : (k += 1) nbsd.setArg(cpu, k, nbsd.arg(cpu, k + 1));
    } else if (num == 198) {
        num = nbsd.arg(cpu, 1); // low word of the quad_t number
        var k: u5 = 0;
        while (k < 9) : (k += 1) nbsd.setArg(cpu, k, nbsd.arg(cpu, k + 2));
    }
    const sc: Syscall = @enumFromInt(num);

    if (trace) {
        var buf: [96]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "nbsd syscall {d} ({s}) a0={x} a1={x} a2={x}\n", .{
            num, @tagName(sc), nbsd.arg(cpu, 0), nbsd.arg(cpu, 1), nbsd.arg(cpu, 2),
        }) catch "nbsd syscall (fmt err)\n";
        traceOut(line);
    }

    switch (sc) {
        .exit => {
            runner.exit_status = nbsd.arg(cpu, 0);
            return false;
        },
        .write => return sysWrite(runner),
        .read => return sysRead(runner),
        .writev => return sysWritev(runner),
        .open => return sysOpen(runner),
        .close => return sysClose(runner),
        .lseek => return sysLseek(runner),
        .pread => return sysPread(runner),

        .sysarch => {
            // m88k sysarch: TLS/cache ops. Accept as a no-op success.
            nbsd.returnSuccess(cpu, 0);
            return true;
        },

        // --- signals: accept/record; we deliver only SIGCHLD ---------------
        .__sigaction14, .__sigaction_sigtramp => return sysSigaction(runner),
        .__sigreturn14 => return sysSigreturn(runner),
        .__sigprocmask14, .__sigaltstack14, .__sigpending14 => {
            nbsd.returnSuccess(cpu, 0);
            return true;
        },
        .__sigsuspend14 => return sysSigsuspend(runner),

        .issetugid => {
            nbsd.returnSuccess(cpu, 0); // not set-uid/gid
            return true;
        },
        .getgroups => {
            const len = nbsd.arg(cpu, 0);
            const set = nbsd.arg(cpu, 1);
            if (len >= 1 and set != 0 and @as(u64, set) + 4 <= mem.Memory.size) {
                const was = runner.memory.enforce;
                runner.memory.enforce = false;
                runner.memory.write32(set, 0);
                runner.memory.enforce = was;
            }
            nbsd.returnSuccess(cpu, 1); // one group (gid 0)
            return true;
        },
        .getpid => {
            nbsd.returnSuccess(cpu, @intCast(getpid()));
            return true;
        },
        .getppid => {
            nbsd.returnSuccess(cpu, @intCast(getppid()));
            return true;
        },
        .getrusage => {
            const ru = nbsd.arg(cpu, 1);
            if (ru != 0 and @as(u64, ru) + 72 <= mem.Memory.size) {
                const was = runner.memory.enforce;
                runner.memory.enforce = false;
                runner.memory.zero(ru, 72);
                runner.memory.enforce = was;
            }
            nbsd.returnSuccess(cpu, 0);
            return true;
        },
        .getpgid, .getpgrp, .getsid => {
            nbsd.returnSuccess(cpu, 1);
            return true;
        },
        .setpgid, .setsid => {
            nbsd.returnSuccess(cpu, 0);
            return true;
        },
        .kill => {
            nbsd.returnSuccess(cpu, 0);
            return true;
        },
        .gettimeofday => return sysGettimeofday(runner),
        .clock_gettime => return sysClockGettime(runner),
        .getuid, .geteuid, .getgid, .getegid => {
            nbsd.returnSuccess(cpu, 0); // root
            return true;
        },
        .__getcwd => return sysGetcwd(runner),
        .chdir => return sysChdir(runner),
        .fchdir => return sysFchdir(runner),
        .fork, .vfork, .__vfork14 => return sysFork(runner),
        .execve => return sysExec(runner),
        .wait4 => return sysWait4(runner),
        .pipe => return sysPipe(runner),
        .dup => return sysDup(runner),
        .dup2 => return sysDup2(runner),
        .access => return sysAccess(runner),
        .unlink => return sysUnlink(runner),
        .rename, .__posix_rename => return sysRename(runner),
        .mkdir => return sysMkdir(runner),
        .rmdir => return sysRmdir(runner),
        .link => return sysLink(runner),
        .symlink => return sysSymlink(runner),
        .readlink => return sysReadlink(runner),
        .ftruncate => return sysFtruncate(runner),
        .chmod => return sysChmod(runner),
        .fchmod => return sysFchmod(runner),
        .chown, .__posix_chown => return sysChown(runner, false),
        .lchown, .__posix_lchown => return sysChown(runner, true),
        .fchown, .__posix_fchown => return sysFchown(runner),
        .umask => {
            const old = runner.umask;
            runner.umask = nbsd.arg(cpu, 0) & 0o777;
            nbsd.returnSuccess(cpu, old);
            return true;
        },
        .getrlimit => {
            // struct rlimit { rlim_t cur; rlim_t max; } rlim_t = 64-bit.
            const rlp = nbsd.arg(cpu, 1);
            if (rlp != 0 and @as(u64, rlp) + 16 <= mem.Memory.size) {
                const was = runner.memory.enforce;
                runner.memory.enforce = false;
                runner.memory.write32(rlp + 0, 0x7fffffff);
                runner.memory.write32(rlp + 4, 0xffffffff);
                runner.memory.write32(rlp + 8, 0x7fffffff);
                runner.memory.write32(rlp + 12, 0xffffffff);
                runner.memory.enforce = was;
            }
            nbsd.returnSuccess(cpu, 0);
            return true;
        },
        .setrlimit => {
            nbsd.returnSuccess(cpu, 0);
            return true;
        },
        .fcntl => return sysFcntl(runner),
        .@"break" => return sysBrk(runner),
        .mmap => return sysMmap(runner),
        .munmap, .mprotect, .madvise, .minherit, .__msync13, .mlock, .munlock => {
            nbsd.returnSuccess(cpu, 0);
            return true;
        },
        .__fstat13 => return sysFstat(runner),
        .__stat13 => return sysStatPath(runner, false),
        .__lstat13 => return sysStatPath(runner, true),
        .getdents => return sysGetdents(runner),
        .ioctl => return sysIoctl(runner),
        .__sysctl => return sysSysctl(runner),
        .fsync, .fdatasync => {
            nbsd.returnSuccess(cpu, 0);
            return true;
        },
        .statvfs1 => return sysStatvfs(runner, false),
        .fstatvfs1 => return sysStatvfs(runner, true),

        else => {
            failFast(runner, num, sc);
            return false;
        },
    }
}

fn sysWrite(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = nbsd.arg(cpu, 0);
    const buf = nbsd.arg(cpu, 1);
    const count = nbsd.arg(cpu, 2);
    const hfd = hostFd(runner, gfd) orelse {
        nbsd.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, buf) + count > mem.Memory.size) {
        nbsd.returnError(cpu, EFAULT);
        return true;
    }
    const slice = runner.memory.bytes[buf .. buf + count];
    const n = write(hfd, slice.ptr, slice.len);
    if (n < 0) nbsd.returnError(cpu, mapErrno(hostErrno())) else nbsd.returnSuccess(cpu, @intCast(n));
    return true;
}

/// writev(fd, iov, iovcnt): iovec is {u32 iov_base; u32 iov_len} on 32-bit BE.
fn sysWritev(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = nbsd.arg(cpu, 0);
    const iov = nbsd.arg(cpu, 1);
    const iovcnt = nbsd.arg(cpu, 2);
    const hfd = hostFd(runner, gfd) orelse {
        nbsd.returnError(cpu, EBADF);
        return true;
    };
    var total: u32 = 0;
    var k: u32 = 0;
    while (k < iovcnt) : (k += 1) {
        const ent = iov + k * 8;
        if (@as(u64, ent) + 8 > mem.Memory.size) {
            nbsd.returnError(cpu, EFAULT);
            return true;
        }
        const base = runner.memory.read32(ent + 0);
        const len = runner.memory.read32(ent + 4);
        if (len == 0) continue;
        if (@as(u64, base) + len > mem.Memory.size) {
            nbsd.returnError(cpu, EFAULT);
            return true;
        }
        const slice = runner.memory.bytes[base .. base + len];
        const n = write(hfd, slice.ptr, slice.len);
        if (n < 0) {
            nbsd.returnError(cpu, mapErrno(hostErrno()));
            return true;
        }
        total += @intCast(n);
        if (@as(u32, @intCast(n)) < len) break; // short write
    }
    nbsd.returnSuccess(cpu, total);
    return true;
}

fn sysRead(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = nbsd.arg(cpu, 0);
    const buf = nbsd.arg(cpu, 1);
    const count = nbsd.arg(cpu, 2);
    const hfd = hostFd(runner, gfd) orelse {
        nbsd.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, buf) + count > mem.Memory.size) {
        nbsd.returnError(cpu, EFAULT);
        return true;
    }
    const slice = runner.memory.bytes[buf .. buf + count];
    const n = read(hfd, slice.ptr, slice.len);
    if (n < 0) nbsd.returnError(cpu, mapErrno(hostErrno())) else nbsd.returnSuccess(cpu, @intCast(n));
    return true;
}

// NetBSD O_* (sys/fcntl.h): O_RDONLY=0 O_WRONLY=1 O_RDWR=2, O_CREAT=0x200,
// O_TRUNC=0x400, O_EXCL=0x800, O_APPEND=0x8. Translate to host (Linux) values.
const H_O_CREAT: c_int = 0o100;
const H_O_TRUNC: c_int = 0o1000;
const H_O_EXCL: c_int = 0o200;
const H_O_APPEND: c_int = 0o2000;

fn translateOpenFlags(guest: u32) c_int {
    var h: c_int = @intCast(guest & 0x3);
    if (guest & 0x0200 != 0) h |= H_O_CREAT;
    if (guest & 0x0400 != 0) h |= H_O_TRUNC;
    if (guest & 0x0800 != 0) h |= H_O_EXCL;
    if (guest & 0x0008 != 0) h |= H_O_APPEND;
    return h;
}

fn readGuestPath(runner: *machine.Runner, ptr: u32, buf: []u8) ?[]const u8 {
    const s = runner.memory.readCStr(ptr, buf[0 .. buf.len - 1]);
    if (s.len >= buf.len - 1) return null;
    buf[s.len] = 0;
    return buf[0..s.len];
}

/// NetBSD mounts an fdesc filesystem at /dev, so `/dev/stdin`, `/dev/stdout`,
/// `/dev/stderr`, and `/dev/fd/N` name the process's own descriptors. Tools
/// like `sort` reopen their input via `/dev/stdin`. We can't open the guest's
/// char-device nodes on the host, so intercept these paths and dup the matching
/// open descriptor instead (what the fdesc fs does). Returns the source guest
/// fd to dup, or null if `gpath` isn't an fdesc path.
fn fdescTarget(gpath: []const u8) ?u32 {
    if (std.mem.eql(u8, gpath, "/dev/stdin")) return 0;
    if (std.mem.eql(u8, gpath, "/dev/stdout")) return 1;
    if (std.mem.eql(u8, gpath, "/dev/stderr")) return 2;
    if (std.mem.startsWith(u8, gpath, "/dev/fd/")) {
        return std.fmt.parseInt(u32, gpath["/dev/fd/".len..], 10) catch null;
    }
    return null;
}

fn sysOpen(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const path_ptr = nbsd.arg(cpu, 0);
    const flags = nbsd.arg(cpu, 1);
    const mode = nbsd.arg(cpu, 2);
    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        nbsd.returnError(cpu, EINVAL);
        return true;
    };
    // Common /dev nodes -> open the HOST equivalent directly (the guest's
    // char-device inodes can't be opened through the mount table). /dev/null
    // and /dev/zero behave identically on the host; /dev/tty maps to the host
    // controlling tty. `config`/`make` open /dev/null constantly.
    if (std.mem.eql(u8, gpath, "/dev/null") or std.mem.eql(u8, gpath, "/dev/zero") or std.mem.eql(u8, gpath, "/dev/tty")) {
        const host_dev: [*:0]const u8 = if (std.mem.eql(u8, gpath, "/dev/tty")) "/dev/tty" else if (std.mem.eql(u8, gpath, "/dev/zero")) "/dev/zero" else "/dev/null";
        const hfd = open(host_dev, translateOpenFlags(flags), @intCast(mode));
        if (hfd < 0) {
            nbsd.returnError(cpu, mapErrno(hostErrno()));
            return true;
        }
        if (fsOf(runner)) |fs| {
            const gfd = fs.allocFd(hfd) orelse {
                _ = close(hfd);
                nbsd.returnError(cpu, EBADF);
                return true;
            };
            nbsd.returnSuccess(cpu, gfd);
        } else {
            nbsd.returnSuccess(cpu, @intCast(hfd));
        }
        return true;
    }
    // fdesc: /dev/stdin|stdout|stderr|fd/N -> dup the named descriptor.
    if (fdescTarget(gpath)) |srcfd| {
        const hsrc = hostFd(runner, srcfd) orelse {
            nbsd.returnError(cpu, EBADF);
            return true;
        };
        const hnew = dup(hsrc);
        if (hnew < 0) {
            nbsd.returnError(cpu, mapErrno(hostErrno()));
            return true;
        }
        if (fsOf(runner)) |fs| {
            const gnew = fs.allocFd(hnew) orelse {
                _ = close(hnew);
                nbsd.returnError(cpu, EBADF);
                return true;
            };
            nbsd.returnSuccess(cpu, gnew);
        } else {
            nbsd.returnSuccess(cpu, @intCast(hnew));
        }
        return true;
    }
    var hbuf: [2048]u8 = undefined;
    var cpath: [*:0]const u8 = @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, &hbuf) catch {
            nbsd.returnError(cpu, ENOENT);
            return true;
        };
        cpath = hp.ptr;
    }
    const hfd = open(cpath, translateOpenFlags(flags), @intCast(mode));
    if (hfd < 0) {
        nbsd.returnError(cpu, mapErrno(hostErrno()));
        return true;
    }
    if (fsOf(runner)) |fs| {
        var canonbuf: [1024]u8 = undefined;
        const gcanon = fs.canonicalGuest(gpath, &canonbuf) orelse gpath;
        if (fs.openDir(cpath, gcanon, hfd)) |gdir| {
            nbsd.returnSuccess(cpu, gdir);
            return true;
        }
        const gfd = fs.allocFd(hfd) orelse {
            _ = close(hfd);
            nbsd.returnError(cpu, EBADF);
            return true;
        };
        nbsd.returnSuccess(cpu, gfd);
    } else {
        nbsd.returnSuccess(cpu, @intCast(hfd));
    }
    return true;
}

fn sysClose(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = nbsd.arg(cpu, 0);
    if (fsOf(runner)) |fs| {
        if (fs.closeFd(gfd)) nbsd.returnSuccess(cpu, 0) else nbsd.returnError(cpu, EBADF);
        return true;
    }
    if (gfd <= 2) {
        nbsd.returnSuccess(cpu, 0);
        return true;
    }
    const rc = close(@intCast(gfd));
    if (rc < 0) nbsd.returnError(cpu, mapErrno(hostErrno())) else nbsd.returnSuccess(cpu, 0);
    return true;
}

/// lseek(fd, off, whence): after the indirect-__syscall shift the args are
/// fd=arg0, pad=arg1, off_hi=arg2, off_lo=arg3, whence=arg4 (off_t in the
/// r4:r5 pair, high word first on big-endian m88k). Same layout as OpenBSD.
fn sysLseek(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = nbsd.arg(cpu, 0);
    const off_hi: u64 = nbsd.arg(cpu, 2);
    const off_lo: u64 = nbsd.arg(cpu, 3);
    const off: i64 = @bitCast((off_hi << 32) | off_lo);
    const whence = nbsd.arg(cpu, 4);
    const hfd = hostFd(runner, gfd) orelse {
        nbsd.returnError(cpu, EBADF);
        return true;
    };
    const pos = lseek(hfd, @intCast(off), @intCast(whence));
    if (pos < 0) {
        nbsd.returnError(cpu, mapErrno(hostErrno()));
    } else {
        // lseek returns a 64-bit off_t. On big-endian m88k a 64-bit value in a
        // register pair is HIGH word first, so the kernel returns the position
        // as r2 = high word, r3 = low word. (`returnSuccess2(a, b)` sets
        // r2=a, r3=b, so pass hi first.) Getting this backwards made libc/BFD
        // read the low word (e.g. 0xc000) as the HIGH half of its 64-bit file
        // position — every subsequent seek then targeted offset<<32 and the
        // archive looked "truncated" (the nm/ld libc.a bug).
        const upos: u64 = @intCast(pos);
        const hi: u32 = @truncate(upos >> 32);
        const lo: u32 = @truncate(upos & 0xffff_ffff);
        nbsd.returnSuccess2(cpu, hi, lo);
    }
    return true;
}

/// pread(fd, buf, nbyte, off): off_t 64-bit in the r6:r7 pair (arg3 is the
/// alignment pad). off_hi = arg4, off_lo = arg5. (After indirect shift for the
/// __syscall gate.)
fn sysPread(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = nbsd.arg(cpu, 0);
    const buf = nbsd.arg(cpu, 1);
    const count = nbsd.arg(cpu, 2);
    const off_hi: u64 = nbsd.arg(cpu, 4);
    const off_lo: u64 = nbsd.arg(cpu, 5);
    const off: u64 = (off_hi << 32) | off_lo;
    const hfd = hostFd(runner, gfd) orelse {
        nbsd.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, buf) + count > mem.Memory.size) {
        nbsd.returnError(cpu, EFAULT);
        return true;
    }
    const slice = runner.memory.bytes[buf .. buf + count];
    const n = pread(hfd, slice.ptr, slice.len, @intCast(off));
    if (n < 0) nbsd.returnError(cpu, mapErrno(hostErrno())) else nbsd.returnSuccess(cpu, @intCast(n));
    return true;
}

// NetBSD fcntl commands (sys/fcntl.h): F_DUPFD=0 F_GETFD=1 F_SETFD=2
// F_GETFL=3 F_SETFL=4.
const F_DUPFD: u32 = 0;
const F_GETFD: u32 = 1;
const F_SETFD: u32 = 2;
const F_GETFL: u32 = 3;
const F_SETFL: u32 = 4;

fn sysFcntl(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = nbsd.arg(cpu, 0);
    const cmd = nbsd.arg(cpu, 1);
    const hfd = hostFd(runner, gfd) orelse {
        nbsd.returnError(cpu, EBADF);
        return true;
    };
    switch (cmd) {
        F_GETFD, F_GETFL => nbsd.returnSuccess(cpu, 0),
        F_SETFD, F_SETFL => nbsd.returnSuccess(cpu, 0),
        F_DUPFD => {
            const hnew = dup(hfd);
            if (hnew < 0) {
                nbsd.returnError(cpu, mapErrno(hostErrno()));
                return true;
            }
            if (fsOf(runner)) |fs| {
                const gnew = fs.allocFdFrom(hnew, nbsd.arg(cpu, 2)) orelse {
                    _ = close(hnew);
                    nbsd.returnError(cpu, EBADF);
                    return true;
                };
                nbsd.returnSuccess(cpu, gnew);
            } else {
                nbsd.returnSuccess(cpu, @intCast(hnew));
            }
        },
        else => nbsd.returnError(cpu, EINVAL),
    }
    return true;
}

/// brk(addr): set the program break. NetBSD's libc sbrk uses SYS_break; return
/// 0 on success (the libc stub tracks the break itself). We grow the mapped
/// heap up to `addr` and update the tracked break.
fn sysBrk(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const addr = nbsd.arg(cpu, 0);
    if (addr == 0) {
        nbsd.returnSuccess(cpu, runner.brk);
        return true;
    }
    if (addr < runner.brk_base) {
        nbsd.returnError(cpu, ENOMEM);
        return true;
    }
    if (addr > runner.brk) {
        // Extend the heap region up to the rounded address.
        const new_top = std.mem.alignForward(u32, addr, 0x1000);
        if (new_top > runner.brk) {
            const was = runner.memory.enforce;
            runner.memory.enforce = false;
            runner.memory.zero(runner.brk, new_top - runner.brk);
            runner.memory.addRegion(runner.brk, new_top - runner.brk, .{ .read = true, .write = true }) catch {};
            runner.memory.enforce = was;
            runner.brk = new_top;
        }
    }
    nbsd.returnSuccess(cpu, 0);
    return true;
}

// NetBSD mmap flags (sys/mman.h): MAP_PRIVATE=0x0002, MAP_FIXED=0x0010,
// MAP_ANON=0x1000.
const NBSD_MAP_ANON: u32 = 0x1000;
const NBSD_MAP_FIXED: u32 = 0x0010;

/// mmap(addr,len,prot,flags,fd,offset). Anonymous maps served from the downward
/// bump allocator; file-backed private maps read the file bytes in. off_t is
/// 64-bit in the r8:r9 pair after the __syscall shift: off_hi=arg6, off_lo=arg7.
fn sysMmap(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const addr = nbsd.arg(cpu, 0);
    const len = nbsd.arg(cpu, 1);
    const flags = nbsd.arg(cpu, 3);
    const gfd = nbsd.arg(cpu, 4);
    const off = nbsd.arg(cpu, 7);

    const anon = (flags & NBSD_MAP_ANON) != 0 or gfd == 0xffffffff;
    var hfd: c_int = -1;
    if (!anon) {
        hfd = hostFd(runner, gfd) orelse {
            nbsd.returnError(cpu, EBADF);
            return true;
        };
    }
    if (len > 0x4000_0000) {
        nbsd.returnError(cpu, ENOMEM);
        return true;
    }
    const size = std.mem.alignForward(u32, if (len == 0) 1 else len, 0x1000);

    var base: u32 = undefined;
    if (addr != 0 and (@as(u64, addr) + size) <= mem.Memory.size and
        ((flags & NBSD_MAP_FIXED) != 0 or addr >= runner.brk))
    {
        base = addr;
    } else {
        if (runner.mmap_next < runner.brk + 0x10000 or runner.mmap_next -% size < runner.brk) {
            nbsd.returnError(cpu, ENOMEM);
            return true;
        }
        base = runner.mmap_next -% size;
        runner.mmap_next = base;
    }

    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    runner.memory.zero(base, size);
    runner.memory.addRegion(base, size, .{ .read = true, .write = true }) catch {};
    if (!anon) {
        var done: u32 = 0;
        while (done < len) {
            const dst = runner.memory.bytes[base + done .. base + len];
            const n = pread(hfd, dst.ptr, dst.len, @intCast(off + done));
            if (n <= 0) break;
            done += @intCast(n);
        }
    }
    runner.memory.enforce = was;
    nbsd.returnSuccess(cpu, base);
    return true;
}

fn sysAccess(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const path_ptr = nbsd.arg(cpu, 0);
    const amode = nbsd.arg(cpu, 1);
    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        nbsd.returnError(cpu, EINVAL);
        return true;
    };
    var hbuf: [2048]u8 = undefined;
    var cpath: [*:0]const u8 = @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, &hbuf) catch {
            nbsd.returnError(cpu, ENOENT);
            return true;
        };
        cpath = hp.ptr;
    }
    // access modes: F_OK=0, X_OK=1, W_OK=2, R_OK=4 — same low 3 bits as host.
    const arc = fsmod.c.access(cpath, @intCast(amode & 0x7));
    if (arc < 0) nbsd.returnError(cpu, mapErrno(hostErrno())) else nbsd.returnSuccess(cpu, 0);
    return true;
}

/// Read a guest path arg (index n) and resolve it to a host path via the fs.
fn resolveArg(runner: *machine.Runner, n: u5, gbuf: []u8, hbuf: []u8) ?[*:0]const u8 {
    const cpu = &runner.cpu;
    const gpath = readGuestPath(runner, nbsd.arg(cpu, n), gbuf) orelse {
        nbsd.returnError(cpu, EINVAL);
        return null;
    };
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, hbuf) catch {
            nbsd.returnError(cpu, ENOENT);
            return null;
        };
        return hp.ptr;
    }
    return @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
}

fn sysUnlink(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    var gb: [1024]u8 = undefined;
    var hb: [2048]u8 = undefined;
    const cp = resolveArg(runner, 0, &gb, &hb) orelse return true;
    if (fsmod.c.unlink(cp) < 0) nbsd.returnError(cpu, mapErrno(hostErrno())) else nbsd.returnSuccess(cpu, 0);
    return true;
}

fn sysRmdir(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    var gb: [1024]u8 = undefined;
    var hb: [2048]u8 = undefined;
    const cp = resolveArg(runner, 0, &gb, &hb) orelse return true;
    if (fsmod.c.rmdir(cp) < 0) nbsd.returnError(cpu, mapErrno(hostErrno())) else nbsd.returnSuccess(cpu, 0);
    return true;
}

fn sysMkdir(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    var gb: [1024]u8 = undefined;
    var hb: [2048]u8 = undefined;
    const cp = resolveArg(runner, 0, &gb, &hb) orelse return true;
    const mode = nbsd.arg(cpu, 1);
    if (fsmod.c.mkdir(cp, mode) < 0) nbsd.returnError(cpu, mapErrno(hostErrno())) else nbsd.returnSuccess(cpu, 0);
    return true;
}

/// rename(old, new): both paths resolved through the mount table.
fn sysRename(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const fs = fsOf(runner) orelse {
        nbsd.returnError(cpu, EINVAL);
        return true;
    };
    var gb0: [1024]u8 = undefined;
    var gb1: [1024]u8 = undefined;
    const g0 = readGuestPath(runner, nbsd.arg(cpu, 0), &gb0) orelse {
        nbsd.returnError(cpu, EINVAL);
        return true;
    };
    const g1 = readGuestPath(runner, nbsd.arg(cpu, 1), &gb1) orelse {
        nbsd.returnError(cpu, EINVAL);
        return true;
    };
    var hb0: [2048]u8 = undefined;
    var hb1: [2048]u8 = undefined;
    const h0 = fs.resolve(g0, &hb0) catch {
        nbsd.returnError(cpu, ENOENT);
        return true;
    };
    const h1 = fs.resolve(g1, &hb1) catch {
        nbsd.returnError(cpu, ENOENT);
        return true;
    };
    if (fsmod.c.rename(h0, h1) < 0) nbsd.returnError(cpu, mapErrno(hostErrno())) else nbsd.returnSuccess(cpu, 0);
    return true;
}

fn sysLink(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const fs = fsOf(runner) orelse {
        nbsd.returnError(cpu, EINVAL);
        return true;
    };
    var gb0: [1024]u8 = undefined;
    var gb1: [1024]u8 = undefined;
    const g0 = readGuestPath(runner, nbsd.arg(cpu, 0), &gb0) orelse {
        nbsd.returnError(cpu, EINVAL);
        return true;
    };
    const g1 = readGuestPath(runner, nbsd.arg(cpu, 1), &gb1) orelse {
        nbsd.returnError(cpu, EINVAL);
        return true;
    };
    var hb0: [2048]u8 = undefined;
    var hb1: [2048]u8 = undefined;
    const h0 = fs.resolve(g0, &hb0) catch {
        nbsd.returnError(cpu, ENOENT);
        return true;
    };
    const h1 = fs.resolve(g1, &hb1) catch {
        nbsd.returnError(cpu, ENOENT);
        return true;
    };
    if (fsmod.c.link(h0, h1) < 0) nbsd.returnError(cpu, mapErrno(hostErrno())) else nbsd.returnSuccess(cpu, 0);
    return true;
}

/// symlink(target, linkpath): target is a literal string (not resolved); only
/// linkpath goes through the mount table.
fn sysSymlink(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const fs = fsOf(runner) orelse {
        nbsd.returnError(cpu, EINVAL);
        return true;
    };
    var tb: [1024]u8 = undefined;
    var gb: [1024]u8 = undefined;
    const target = readGuestPath(runner, nbsd.arg(cpu, 0), &tb) orelse {
        nbsd.returnError(cpu, EINVAL);
        return true;
    };
    const g1 = readGuestPath(runner, nbsd.arg(cpu, 1), &gb) orelse {
        nbsd.returnError(cpu, EINVAL);
        return true;
    };
    var hb: [2048]u8 = undefined;
    const h1 = fs.resolve(g1, &hb) catch {
        nbsd.returnError(cpu, ENOENT);
        return true;
    };
    const tcp: [*:0]const u8 = @ptrCast(tb[0 .. target.len + 1].ptr);
    if (fsmod.c.symlink(tcp, h1) < 0) nbsd.returnError(cpu, mapErrno(hostErrno())) else nbsd.returnSuccess(cpu, 0);
    return true;
}

/// readlink(path, buf, bufsize): read a symlink's target into the guest buffer.
fn sysReadlink(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const buf = nbsd.arg(cpu, 1);
    const bufsize = nbsd.arg(cpu, 2);
    var gb: [1024]u8 = undefined;
    var hb: [2048]u8 = undefined;
    const cp = resolveArg(runner, 0, &gb, &hb) orelse return true;
    if (@as(u64, buf) + bufsize > mem.Memory.size) {
        nbsd.returnError(cpu, EFAULT);
        return true;
    }
    var tmp: [2048]u8 = undefined;
    const cap = @min(bufsize, tmp.len);
    const n = fsmod.c.readlink(cp, &tmp, cap);
    if (n < 0) {
        nbsd.returnError(cpu, mapErrno(hostErrno()));
        return true;
    }
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    runner.memory.writeBytes(buf, tmp[0..@intCast(n)]);
    runner.memory.enforce = was;
    nbsd.returnSuccess(cpu, @intCast(n));
    return true;
}

/// ftruncate(fd, length): 64-bit off_t `length` in the r4:r5 pair (arg1 pad);
/// len_hi = arg2, len_lo = arg3 (after the __syscall shift).
fn sysFtruncate(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = nbsd.arg(cpu, 0);
    const len_hi: u64 = nbsd.arg(cpu, 2);
    const len_lo: u64 = nbsd.arg(cpu, 3);
    const len: i64 = @bitCast((len_hi << 32) | len_lo);
    const hfd = hostFd(runner, gfd) orelse {
        nbsd.returnError(cpu, EBADF);
        return true;
    };
    if (fsmod.c.ftruncate(hfd, @intCast(len)) < 0) nbsd.returnError(cpu, mapErrno(hostErrno())) else nbsd.returnSuccess(cpu, 0);
    return true;
}

fn sysChmod(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    var gb: [1024]u8 = undefined;
    var hb: [2048]u8 = undefined;
    const cp = resolveArg(runner, 0, &gb, &hb) orelse return true;
    const mode = nbsd.arg(cpu, 1) & 0o7777;
    if (fsmod.c.chmod(cp, mode) < 0) nbsd.returnError(cpu, mapErrno(hostErrno())) else nbsd.returnSuccess(cpu, 0);
    return true;
}

fn sysFchmod(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = nbsd.arg(cpu, 0);
    const mode = nbsd.arg(cpu, 1) & 0o7777;
    const hfd = hostFd(runner, gfd) orelse {
        nbsd.returnError(cpu, EBADF);
        return true;
    };
    if (fsmod.c.fchmod(hfd, mode) < 0) nbsd.returnError(cpu, mapErrno(hostErrno())) else nbsd.returnSuccess(cpu, 0);
    return true;
}

/// chown(path, uid, gid) / lchown(path, uid, gid). We run as an unprivileged
/// host user, so a real chown to root usually fails with EPERM — which would
/// break `ar`/`install`. Since the guest expects to be root (uid 0), accept the
/// call as a no-op success rather than propagate the host EPERM. (We don't
/// model guest ownership; files just carry the host user's ids.)
fn sysChown(runner: *machine.Runner, is_lchown: bool) bool {
    const cpu = &runner.cpu;
    var gb: [1024]u8 = undefined;
    var hb: [2048]u8 = undefined;
    const cp = resolveArg(runner, 0, &gb, &hb) orelse return true;
    const owner = nbsd.arg(cpu, 1);
    const group = nbsd.arg(cpu, 2);
    const rc = if (is_lchown) fsmod.c.lchown(cp, owner, group) else fsmod.c.chown(cp, owner, group);
    // Ignore EPERM (unprivileged host): the guest believes it is root.
    if (rc < 0 and hostErrno() != EPERM) {
        nbsd.returnError(cpu, mapErrno(hostErrno()));
    } else {
        nbsd.returnSuccess(cpu, 0);
    }
    return true;
}

/// fchown(fd, uid, gid): as chown but on a descriptor. EPERM ignored (see above).
fn sysFchown(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = nbsd.arg(cpu, 0);
    const owner = nbsd.arg(cpu, 1);
    const group = nbsd.arg(cpu, 2);
    const hfd = hostFd(runner, gfd) orelse {
        nbsd.returnError(cpu, EBADF);
        return true;
    };
    const rc = fsmod.c.fchown(hfd, owner, group);
    if (rc < 0 and hostErrno() != EPERM) {
        nbsd.returnError(cpu, mapErrno(hostErrno()));
    } else {
        nbsd.returnSuccess(cpu, 0);
    }
    return true;
}

/// __getcwd(buf, len): NetBSD has a real getcwd syscall. Copy the fs-tracked
/// cwd (NUL-terminated) into the guest buffer.
fn sysGetcwd(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const buf = nbsd.arg(cpu, 0);
    const len = nbsd.arg(cpu, 1);
    const cwd = if (fsOf(runner)) |fs| fs.cwdPath() else "/";
    if (cwd.len + 1 > len) {
        nbsd.returnError(cpu, ERANGE);
        return true;
    }
    if (@as(u64, buf) + cwd.len + 1 > mem.Memory.size) {
        nbsd.returnError(cpu, EFAULT);
        return true;
    }
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    runner.memory.writeBytes(buf, cwd);
    runner.memory.write8(buf + @as(u32, @intCast(cwd.len)), 0);
    runner.memory.enforce = was;
    nbsd.returnSuccess(cpu, 0);
    return true;
}

fn sysChdir(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const path_ptr = nbsd.arg(cpu, 0);
    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        nbsd.returnError(cpu, EINVAL);
        return true;
    };
    if (fsOf(runner)) |fs| {
        var hbuf: [2048]u8 = undefined;
        const hp = fs.resolve(gpath, &hbuf) catch {
            nbsd.returnError(cpu, ENOENT);
            return true;
        };
        if (fsmod.c.access(hp, 0) < 0) {
            nbsd.returnError(cpu, ENOENT);
            return true;
        }
        fs.chdir(gpath) catch {
            nbsd.returnError(cpu, EINVAL);
            return true;
        };
    }
    nbsd.returnSuccess(cpu, 0);
    return true;
}

fn sysFchdir(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = nbsd.arg(cpu, 0);
    const fs = fsOf(runner) orelse {
        nbsd.returnSuccess(cpu, 0);
        return true;
    };
    const gpath = fs.dirGuestPath(gfd) orelse {
        nbsd.returnError(cpu, EBADF);
        return true;
    };
    fs.chdir(gpath) catch {
        nbsd.returnError(cpu, EINVAL);
        return true;
    };
    nbsd.returnSuccess(cpu, 0);
    return true;
}

/// gettimeofday(tv, tz): struct timeval {time_t tv_sec (i32 on NetBSD 3.0);
/// suseconds_t tv_usec (i32)}. NetBSD 3.0 time_t is 32-bit, so tv_sec is a
/// single word (no hi/lo pair, unlike OpenBSD).
fn sysGettimeofday(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const tv = nbsd.arg(cpu, 0);
    if (tv != 0) {
        if (@as(u64, tv) + 8 > mem.Memory.size) {
            nbsd.returnError(cpu, EFAULT);
            return true;
        }
        const secs = time(null);
        const was = runner.memory.enforce;
        runner.memory.enforce = false;
        runner.memory.write32(tv + 0, @bitCast(@as(i32, @truncate(secs)))); // tv_sec
        runner.memory.write32(tv + 4, 0); // tv_usec
        runner.memory.enforce = was;
    }
    nbsd.returnSuccess(cpu, 0);
    return true;
}

/// clock_gettime(clock_id, tp): struct timespec {time_t sec (i32); long nsec}.
fn sysClockGettime(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const tp = nbsd.arg(cpu, 1);
    if (tp != 0) {
        if (@as(u64, tp) + 8 > mem.Memory.size) {
            nbsd.returnError(cpu, EFAULT);
            return true;
        }
        const secs = time(null);
        const was = runner.memory.enforce;
        runner.memory.enforce = false;
        runner.memory.write32(tp + 0, @bitCast(@as(i32, @truncate(secs)))); // tv_sec
        runner.memory.write32(tp + 4, 0); // tv_nsec
        runner.memory.enforce = was;
    }
    nbsd.returnSuccess(cpu, 0);
    return true;
}

// --- NetBSD struct stat (__stat13, sys/stat.h) -----------------------------
// 32-bit m88k layout, time_t = int (32-bit) so timespec = 8 bytes. off_t /
// blkcnt_t are 8-byte-aligned long long. Total size 96. See docs/abi-netbsd.md.
//   st_dev   u32 @0    st_ino   u32 @4    st_mode  u32 @8    st_nlink u32 @12
//   st_uid   u32 @16   st_gid   u32 @20   st_rdev  u32 @24
//   st_atim  {i32 sec@28, i32 nsec@32}
//   st_mtim  {i32 sec@36, i32 nsec@40}
//   st_ctim  {i32 sec@44, i32 nsec@48}
//   (pad @52)  st_size i64 @56    st_blocks i64 @64
//   st_blksize u32 @72  st_flags @76  st_gen @80  st_spare0 @84
//   st_birthtim {i32 sec@88, i32 nsec@92}
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

const NBSD_STAT_SIZE: u32 = 96;

fn writeGuestStat(runner: *machine.Runner, statbuf: u32, hs: *const HostStat) void {
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    const m = runner.memory;
    m.zero(statbuf, NBSD_STAT_SIZE);
    m.write32(statbuf + 0, hs.dev); // st_dev
    m.write32(statbuf + 4, hs.ino); // st_ino
    m.write32(statbuf + 8, hs.mode); // st_mode (S_IF* bits match host)
    m.write32(statbuf + 12, hs.nlink); // st_nlink
    m.write32(statbuf + 16, hs.uid); // st_uid
    m.write32(statbuf + 20, hs.gid); // st_gid
    m.write32(statbuf + 24, hs.rdev); // st_rdev
    m.write32(statbuf + 28, @bitCast(@as(i32, @truncate(hs.atime)))); // st_atim.sec
    m.write32(statbuf + 36, @bitCast(@as(i32, @truncate(hs.mtime)))); // st_mtim.sec
    m.write32(statbuf + 44, @bitCast(@as(i32, @truncate(hs.ctime)))); // st_ctim.sec
    m.write32(statbuf + 56, @truncate(hs.size >> 32)); // st_size hi
    m.write32(statbuf + 60, @truncate(hs.size)); // st_size lo
    const blocks: u64 = (hs.size + 511) / 512;
    m.write32(statbuf + 64, @truncate(blocks >> 32)); // st_blocks hi
    m.write32(statbuf + 68, @truncate(blocks)); // st_blocks lo
    m.write32(statbuf + 72, 0x1000); // st_blksize
    runner.memory.enforce = was;
}

fn sysFstat(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = nbsd.arg(cpu, 0);
    const statbuf = nbsd.arg(cpu, 1);
    const hfd = hostFd(runner, gfd) orelse {
        nbsd.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, statbuf) + NBSD_STAT_SIZE > mem.Memory.size) {
        nbsd.returnError(cpu, EFAULT);
        return true;
    }
    var hs: HostStat = undefined;
    r88k_fstat(hfd, &hs);
    if (hs.ok == 0) {
        nbsd.returnError(cpu, mapErrno(@intCast(hs.err)));
        return true;
    }
    writeGuestStat(runner, statbuf, &hs);
    nbsd.returnSuccess(cpu, 0);
    return true;
}

fn sysStatPath(runner: *machine.Runner, is_lstat: bool) bool {
    const cpu = &runner.cpu;
    const path_ptr = nbsd.arg(cpu, 0);
    const statbuf = nbsd.arg(cpu, 1);
    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        nbsd.returnError(cpu, EINVAL);
        return true;
    };
    if (@as(u64, statbuf) + NBSD_STAT_SIZE > mem.Memory.size) {
        nbsd.returnError(cpu, EFAULT);
        return true;
    }
    var hbuf: [2048]u8 = undefined;
    var cpath: [*:0]const u8 = @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, &hbuf) catch {
            nbsd.returnError(cpu, ENOENT);
            return true;
        };
        cpath = hp.ptr;
    }
    var hs: HostStat = undefined;
    if (is_lstat) r88k_lstat(cpath, &hs) else r88k_stat(cpath, &hs);
    if (hs.ok == 0) {
        nbsd.returnError(cpu, mapErrno(@intCast(hs.err)));
        return true;
    }
    writeGuestStat(runner, statbuf, &hs);
    nbsd.returnSuccess(cpu, 0);
    return true;
}

// Directory-stream shim (shared C helper).
extern fn r88k_dirread(handle: c_int, ino_out: *c_ulong, name_out: [*]u8) c_int;

/// getdents(fd, buf, nbyte): fill buf with NetBSD 3.0 `struct dirent` (the OLD
/// 32-bit-fileno layout): d_fileno(u32)@0, d_reclen(u16)@4, d_type(u8)@6,
/// d_namlen(u8)@7, d_name@8. Records padded to 4 bytes.
fn sysGetdents(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = nbsd.arg(cpu, 0);
    const buf = nbsd.arg(cpu, 1);
    const nbyte = nbsd.arg(cpu, 2);
    const fs = fsOf(runner) orelse {
        nbsd.returnError(cpu, EBADF);
        return true;
    };
    const handle = fs.dirHandleFor(gfd) orelse {
        nbsd.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, buf) + nbyte > mem.Memory.size) {
        nbsd.returnError(cpu, EFAULT);
        return true;
    }
    var written: u32 = 0;
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    defer runner.memory.enforce = was;
    while (true) {
        var ino: c_ulong = 0;
        var namebuf: [256]u8 = undefined;
        const rc = r88k_dirread(handle, &ino, &namebuf);
        if (rc <= 0) break;
        const name = std.mem.sliceTo(&namebuf, 0);
        // header(8) + name + 1 NUL, padded to 4.
        const raw = 8 + name.len + 1;
        const reclen: u32 = @intCast(std.mem.alignForward(usize, raw, 4));
        if (written + reclen > nbyte) {
            fs.dirPushback(handle);
            break;
        }
        const at = buf + written;
        runner.memory.write32(at + 0, @intCast(ino & 0xffffffff)); // d_fileno
        runner.memory.write16(at + 4, @intCast(reclen)); // d_reclen
        runner.memory.write8(at + 6, 0); // d_type = DT_UNKNOWN
        runner.memory.write8(at + 7, @intCast(name.len)); // d_namlen
        runner.memory.writeBytes(at + 8, name);
        runner.memory.write8(at + 8 + @as(u32, @intCast(name.len)), 0);
        written += reclen;
    }
    nbsd.returnSuccess(cpu, written);
    return true;
}

// sysctl top-level (CTL_*) and second-level ids we answer.
const CTL_KERN: u32 = 1;
const CTL_HW: u32 = 6;
const HW_PAGESIZE: u32 = 7;
const HW_NCPU: u32 = 3;
const KERN_OSTYPE: u32 = 1;
const KERN_OSRELEASE: u32 = 2;

/// __sysctl(name, namelen, oldp, oldlenp, newp, newlen). libc startup + malloc
/// query a few MIB keys (notably {CTL_HW,HW_PAGESIZE}). Answer the keys we know;
/// otherwise report 0 bytes and succeed.
fn sysSysctl(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const name = nbsd.arg(cpu, 0);
    const namelen = nbsd.arg(cpu, 1);
    const oldp = nbsd.arg(cpu, 2);
    const oldlenp = nbsd.arg(cpu, 3);
    const m = runner.memory;

    if (namelen < 1 or @as(u64, name) + namelen * 4 > mem.Memory.size) {
        nbsd.returnError(cpu, EINVAL);
        return true;
    }
    const top = m.read32(name);
    const sub = if (namelen >= 2) m.read32(name + 4) else 0;

    const putInt = struct {
        fn go(rn: *machine.Runner, op: u32, olp: u32, val: u32) void {
            const mm = rn.memory;
            const was = mm.enforce;
            mm.enforce = false;
            if (olp != 0) {
                const cap = mm.read32(olp);
                if (cap >= 4 and op != 0) mm.write32(op, val);
                mm.write32(olp, 4);
            }
            mm.enforce = was;
            nbsd.returnSuccess(&rn.cpu, 0);
        }
    }.go;

    const putStr = struct {
        fn go(rn: *machine.Runner, op: u32, olp: u32, s: []const u8) void {
            const mm = rn.memory;
            const was = mm.enforce;
            mm.enforce = false;
            const need: u32 = @intCast(s.len + 1);
            if (olp != 0) {
                const cap = mm.read32(olp);
                if (op != 0 and cap >= need) {
                    mm.writeBytes(op, s);
                    mm.write8(op + @as(u32, @intCast(s.len)), 0);
                }
                mm.write32(olp, need);
            }
            mm.enforce = was;
            nbsd.returnSuccess(&rn.cpu, 0);
        }
    }.go;

    if (top == CTL_HW and sub == HW_PAGESIZE) {
        putInt(runner, oldp, oldlenp, 0x1000);
        return true;
    }
    if (top == CTL_HW and sub == HW_NCPU) {
        putInt(runner, oldp, oldlenp, 1);
        return true;
    }
    const HW_MACHINE: u32 = 1;
    const HW_MODEL: u32 = 2;
    const KERN_VERSION: u32 = 4;
    const KERN_HOSTNAME: u32 = 10;
    if (top == CTL_KERN and sub == KERN_OSTYPE) {
        putStr(runner, oldp, oldlenp, "NetBSD");
        return true;
    }
    if (top == CTL_KERN and sub == KERN_OSRELEASE) {
        putStr(runner, oldp, oldlenp, "3.0.1_STABLE");
        return true;
    }
    if (top == CTL_KERN and sub == KERN_VERSION) {
        putStr(runner, oldp, oldlenp, "NetBSD 3.0.1_STABLE (GENERIC)\n");
        return true;
    }
    if (top == CTL_KERN and sub == KERN_HOSTNAME) {
        putStr(runner, oldp, oldlenp, "luna88k");
        return true;
    }
    if (top == CTL_HW and sub == HW_MACHINE) {
        putStr(runner, oldp, oldlenp, "luna88k");
        return true;
    }
    if (top == CTL_HW and sub == HW_MODEL) {
        putStr(runner, oldp, oldlenp, "LUNA-88K");
        return true;
    }

    const was = m.enforce;
    m.enforce = false;
    if (oldlenp != 0) m.write32(oldlenp, 0);
    m.enforce = was;
    nbsd.returnSuccess(cpu, 0);
    return true;
}

// NetBSD `struct statvfs` (sys/statvfs.h): a large struct whose leading fields
// are 4 `unsigned long`s (f_flag, f_bsize, f_frsize, f_iosize), then 64-bit
// block/file counts, ids, and name buffers (_VFS_NAMELEN=32 + 2×_VFS_MNAMELEN
// =1024). ls only needs f_bsize/f_frsize sensible and the call to succeed, so
// we zero the whole struct and fill the block sizes + namemax.
const NBSD_STATVFS_SIZE: u32 = 2248;

/// statvfs1(path, buf, flags) / fstatvfs1(fd, buf, flags): fill a statvfs.
fn sysStatvfs(runner: *machine.Runner, is_f: bool) bool {
    const cpu = &runner.cpu;
    const buf = if (is_f) nbsd.arg(cpu, 1) else nbsd.arg(cpu, 1);
    if (is_f) {
        // Validate the fd exists.
        _ = hostFd(runner, nbsd.arg(cpu, 0)) orelse {
            nbsd.returnError(cpu, EBADF);
            return true;
        };
    }
    if (buf == 0 or @as(u64, buf) + NBSD_STATVFS_SIZE > mem.Memory.size) {
        nbsd.returnError(cpu, EFAULT);
        return true;
    }
    const m = runner.memory;
    const was = m.enforce;
    m.enforce = false;
    m.zero(buf, NBSD_STATVFS_SIZE);
    m.write32(buf + 0, 0); // f_flag
    m.write32(buf + 4, 0x1000); // f_bsize
    m.write32(buf + 8, 0x1000); // f_frsize
    m.write32(buf + 12, 0x1000); // f_iosize
    // f_namemax: 4 ulongs (16) + 12 64-bit counts (96) + fsid_t (8) + f_fsid
    // (4) => f_namemax at offset 16+96+8+4 = 124.
    m.write32(buf + 124, 255); // f_namemax
    m.enforce = was;
    nbsd.returnSuccess(cpu, 0);
    return true;
}

fn sysIoctl(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = nbsd.arg(cpu, 0);
    const hfd = hostFd(runner, gfd) orelse {
        nbsd.returnError(cpu, EBADF);
        return true;
    };
    if (isatty(hfd) == 1) {
        nbsd.returnSuccess(cpu, 0);
    } else {
        nbsd.returnError(cpu, ENOTTY);
    }
    return true;
}

// --- signal delivery (minimal: SIGCHLD for shell/make child-wait) ---------
// Same private-sigcontext scheme as the OpenBSD dispatcher.
const SIGCHLD: u32 = 20;
const SC_MAGIC: u32 = 0x5311_5347;
const SC_WORDS: u32 = 39;

fn sysSigaction(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const signo = nbsd.arg(cpu, 0);
    const act = nbsd.arg(cpu, 1);
    const oact = nbsd.arg(cpu, 2);
    if (oact != 0 and signo < 64 and @as(u64, oact) + 12 <= mem.Memory.size) {
        const was = runner.memory.enforce;
        runner.memory.enforce = false;
        runner.memory.write32(oact + 0, runner.sig_handlers[signo]);
        runner.memory.enforce = was;
    }
    if (act != 0 and signo < 64) {
        const h = runner.memory.read32(act + 0);
        runner.sig_handlers[signo] = if (h <= 1) 0 else h;
    }
    nbsd.returnSuccess(cpu, 0);
    return true;
}

fn deliverSigchld(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const handler = runner.sig_handlers[SIGCHLD];
    if (handler == 0) return false;
    var sp = cpu.getReg(31);
    sp -%= SC_WORDS * 4;
    sp &= ~@as(u32, 15);
    if (sp < 0x0100_0000) return false;

    const m = runner.memory;
    const was = m.enforce;
    m.enforce = false;
    m.write32(sp + 0, SC_MAGIC);
    m.write32(sp + 4, cpu.pc);
    m.write32(sp + 8, cpu.npc);
    m.write32(sp + 12, cpu.psr);
    m.write32(sp + 16, cpu.cf);
    m.write32(sp + 20, if (cpu.branch_pending) 1 else 0);
    m.write32(sp + 24, cpu.branch_target);
    var i: u5 = 0;
    while (true) {
        m.write32(sp + 28 + @as(u32, i) * 4, cpu.getReg(i));
        if (i == 31) break;
        i += 1;
    }
    m.enforce = was;

    cpu.setReg(2, SIGCHLD);
    cpu.setReg(3, 0);
    cpu.setReg(4, sp);
    cpu.setReg(1, runner.sig_tramp);
    cpu.setReg(31, sp);
    cpu.branch_pending = false;
    cpu.pc = handler;
    cpu.npc = handler +% 4;
    return true;
}

fn sysSigreturn(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const scp = nbsd.arg(cpu, 0);
    const m = runner.memory;
    if (@as(u64, scp) + SC_WORDS * 4 > mem.Memory.size or m.read32(scp) != SC_MAGIC) {
        nbsd.returnError(cpu, EINVAL);
        return true;
    }
    const pc = m.read32(scp + 4);
    const npc = m.read32(scp + 8);
    const psr = m.read32(scp + 12);
    const cf = m.read32(scp + 16);
    const bp = m.read32(scp + 20);
    const bt = m.read32(scp + 24);
    var i: u5 = 0;
    while (true) {
        cpu.setReg(i, m.read32(scp + 28 + @as(u32, i) * 4));
        if (i == 31) break;
        i += 1;
    }
    cpu.psr = psr;
    cpu.cf = @truncate(cf);
    cpu.branch_pending = bp != 0;
    cpu.branch_target = bt;
    cpu.pc = pc;
    cpu.npc = npc;
    return true;
}

fn sysSigsuspend(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        nbsd.returnError(cpu, EINTR);
        return true;
    };
    if (runner.sig_handlers[SIGCHLD] != 0) {
        var ready = pm.childReapable();
        if (!ready and pm.hasChildren()) {
            ready = pm.blockUntilChild();
        }
        nbsd.returnError(cpu, EINTR);
        if (ready) _ = deliverSigchld(runner);
        return true;
    }
    nbsd.returnError(cpu, EINTR);
    return true;
}

// --- process model: fork / execve / wait4 / pipe / dup2 -------------------

/// fork/vfork. NetBSD's raw fork(2)/vfork(2) uses the classic BSD **r2/r3
/// dual-return** to distinguish parent from child (verified by disassembling
/// sh's `__vfork14` stub, which does `bcnd eq0, r3, parent`):
///   - parent: r2 = child pid, **r3 = 0**
///   - child:  r2 = child pid (unused), **r3 = 1**  (the libc stub then zeros
///             r2 in the child so vfork() returns 0)
/// So BOTH sides get the child pid in r2 and the discriminator in r3. Getting
/// this wrong (only setting r2) made the parent ALSO take the child's exec
/// branch — the "double echo" bug. (OpenBSD's fork differs: it returns 0 in r2
/// to the child with no r3 flag.)
fn sysFork(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        nbsd.returnError(cpu, EINVAL);
        return true;
    };
    const rc = pm.doFork() catch {
        nbsd.returnError(cpu, ENOMEM);
        return true;
    };
    if (rc == 0) {
        // Child: r3 = 1 (discriminator), r2 = 0 (own pid is irrelevant here;
        // the stub zeroes it anyway, but keep it 0 for a raw vfork() caller).
        cpu.setReg(3, 1);
        nbsd.returnSuccess(cpu, 0);
    } else {
        // Parent: r3 = 0, r2 = child pid.
        cpu.setReg(3, 0);
        nbsd.returnSuccess(cpu, rc);
    }
    return true;
}

fn sysExec(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        nbsd.returnError(cpu, EINVAL);
        return true;
    };
    const path_ptr = nbsd.arg(cpu, 0);
    const argv_ptr = nbsd.arg(cpu, 1);
    const envp_ptr = nbsd.arg(cpu, 2);
    var pbuf: [1024]u8 = undefined;
    const path = readGuestPath(runner, path_ptr, &pbuf) orelse {
        nbsd.returnError(cpu, EINVAL);
        return true;
    };
    // argv/envp entries can be large — a compiler command line or a shell's
    // multi-KB awk program passed as one argument (the kernel build's
    // genassym.sh / m88k-move.sh do exactly this). A 256-byte per-arg cap
    // silently truncated such args and corrupted the awk program. Use a 4 KB
    // per-arg buffer, allocated on the heap to keep this stack frame small.
    //
    // The entry *count* also has to be generous: a static kernel link runs ld
    // with one token per object file, and GENERIC's link line is >300 tokens.
    // A 256-entry cap truncated the object list and produced thousands of
    // bogus "undefined reference" errors. 1024 leaves ample headroom.
    const ARG_MAX_LEN = 4096;
    const ARG_MAX_COUNT = 1024;
    var argv_store: [ARG_MAX_COUNT][]const u8 = undefined;
    var envp_store: [ARG_MAX_COUNT][]const u8 = undefined;
    const argv_bufs = pm.gpa.alloc([ARG_MAX_LEN]u8, ARG_MAX_COUNT) catch {
        nbsd.returnError(cpu, ENOMEM);
        return true;
    };
    defer pm.gpa.free(argv_bufs);
    const envp_bufs = pm.gpa.alloc([ARG_MAX_LEN]u8, ARG_MAX_COUNT) catch {
        nbsd.returnError(cpu, ENOMEM);
        return true;
    };
    defer pm.gpa.free(envp_bufs);
    const argc = readStrVec(runner, argv_ptr, &argv_store, argv_bufs);
    const envc = readStrVec(runner, envp_ptr, &envp_store, envp_bufs);
    if (trace) {
        var buf: [1088]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "nbsd execve '{s}' argc={d}\n", .{ path, argc }) catch "";
        traceOut(line);
    }
    pm.doExec(path, argv_store[0..argc], envp_store[0..envc]) catch {
        nbsd.returnError(cpu, ENOENT);
        return true;
    };
    runner.memory.clearFault();
    runner.exec_pending = true;
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

fn sysWait4(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        nbsd.returnError(cpu, ECHILD);
        return true;
    };
    const statptr = nbsd.arg(cpu, 1);
    const res = pm.doWaitOpts(false) catch {
        nbsd.returnError(cpu, ECHILD);
        return true;
    };
    if (res.pid != 0 and statptr != 0 and @as(u64, statptr) + 4 <= mem.Memory.size) {
        const was = runner.memory.enforce;
        runner.memory.enforce = false;
        runner.memory.write32(statptr, res.status);
        runner.memory.enforce = was;
    }
    nbsd.returnSuccess(cpu, res.pid);
    return true;
}

/// pipe(): NetBSD's pipe(2) returns the two fds in r2 (read) and r3 (write) —
/// the classic BSD dual-return. libc's pipe() wrapper stores them into the
/// user int[2]. We return them via r2:r3.
fn sysPipe(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        nbsd.returnError(cpu, EINVAL);
        return true;
    };
    const fds = pm.doPipe() catch {
        nbsd.returnError(cpu, ENOMEM);
        return true;
    };
    nbsd.returnSuccess2(cpu, fds[0], fds[1]);
    return true;
}

fn sysDup(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = nbsd.arg(cpu, 0);
    const hfd = hostFd(runner, gfd) orelse {
        nbsd.returnError(cpu, EBADF);
        return true;
    };
    const hnew = dup(hfd);
    if (hnew < 0) {
        nbsd.returnError(cpu, mapErrno(hostErrno()));
        return true;
    }
    if (fsOf(runner)) |fs| {
        const gnew = fs.allocFd(hnew) orelse {
            nbsd.returnError(cpu, EBADF);
            return true;
        };
        nbsd.returnSuccess(cpu, gnew);
    } else {
        nbsd.returnSuccess(cpu, @intCast(hnew));
    }
    return true;
}

fn sysDup2(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gold = nbsd.arg(cpu, 0);
    const gnew = nbsd.arg(cpu, 1);
    const holdfd = hostFd(runner, gold) orelse {
        nbsd.returnError(cpu, EBADF);
        return true;
    };
    if (gold == gnew) {
        nbsd.returnSuccess(cpu, gnew);
        return true;
    }
    const fs = fsOf(runner) orelse {
        if (dup2(holdfd, @intCast(gnew)) < 0) nbsd.returnError(cpu, mapErrno(hostErrno())) else nbsd.returnSuccess(cpu, gnew);
        return true;
    };
    _ = fs.closeFd(gnew);
    const hnew = dup(holdfd);
    if (hnew < 0) {
        nbsd.returnError(cpu, mapErrno(hostErrno()));
        return true;
    }
    if (fs.allocFdAt(gnew, hnew)) {
        nbsd.returnSuccess(cpu, gnew);
    } else {
        nbsd.returnError(cpu, EBADF);
    }
    return true;
}

fn failFast(runner: *machine.Runner, num: u32, sc: Syscall) void {
    var buf: [160]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buf,
        "run88k(netbsd): unimplemented syscall {d} ({s}) at ppc={x}\n",
        .{ num, @tagName(sc), runner.cpu.ppc },
    ) catch "run88k(netbsd): unimplemented syscall\n";
    traceOut(line);
}
