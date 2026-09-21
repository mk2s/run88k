//! OpenBSD/luna88k (m88k) syscall dispatcher.
//!
//! Separate from the SysV/88 dispatcher (dispatch.zig): the two OSes share the
//! same trap mechanism but differ in syscall numbers, errno values, and struct
//! layouts (BSD vs SVR4). Rather than force one switch to serve both, this is a
//! focused BSD dispatcher grown incrementally from the minimal set a static
//! `echo` needs, mirroring how the SysV/88 side was bootstrapped.
//!
//! Convention (abi/openbsd.zig): number in r13, args r2.., return r2 (+r3),
//! carry-flag error, skip-on-success PC, trap vector 450.

const std = @import("std");
const machine = @import("../machine.zig");
const mem = @import("../mem.zig");
const fsmod = @import("../fs.zig");
const procmodel = @import("../procmodel.zig");
const obsd = @import("../abi/openbsd.zig");
const Syscall = @import("table_openbsd.zig").Syscall;

extern "c" fn getpid() c_int;
extern "c" fn getppid() c_int;
extern "c" fn dup(fd: c_int) c_int;
extern "c" fn dup2(oldfd: c_int, newfd: c_int) c_int;

fn pmOf(runner: *machine.Runner) ?*procmodel.HostProcess {
    const p = runner.procmodel orelse return null;
    return @ptrCast(@alignCast(p));
}

const ECHILD: u32 = 10;

// Host libc primitives (same set the SysV dispatcher uses).
extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern "c" fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern "c" fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn lseek(fd: c_int, off: c_long, whence: c_int) c_long;
extern "c" fn __errno_location() *c_int;
extern "c" fn isatty(fd: c_int) c_int;

fn hostErrno() u32 {
    return @intCast(__errno_location().*);
}

fn traceOut(bytes: []const u8) void {
    _ = write(2, bytes.ptr, bytes.len);
}

/// Shared with the SysV dispatcher's flag (main.zig sets dispatch.trace).
pub var trace: bool = false;

// --- OpenBSD errno values (sys/errno.h) -----------------------------------
// These differ from SVR4; a few we actually return.
const EPERM: u32 = 1;
const ENOENT: u32 = 2;
const EBADF: u32 = 9;
const ENOMEM: u32 = 12;
const EFAULT: u32 = 14;
const EINVAL: u32 = 22;
const ENOTTY: u32 = 25;
const ENOSYS: u32 = 78; // OpenBSD ENOSYS = 78 (function not implemented)
const EINTR: u32 = 4; // interrupted system call

fn fsOf(runner: *machine.Runner) ?*fsmod.Fs {
    if (runner.fs) |p| return @ptrCast(@alignCast(p));
    return null;
}

/// Map a host (Linux) errno to the OpenBSD errno the guest expects. The low
/// numbers line up (EPERM=1, ENOENT=2, ...); the ranges diverge above ~34, but
/// for the utilities we run the common ones match closely enough. Refine as
/// specific mismatches surface.
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

/// The dispatcher installed as the runner's syscall handler for OpenBSD guests.
pub fn dispatch(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    var num = obsd.syscallNumber(cpu);

    // Indirect forms: SYS_syscall(0) and SYS___syscall(198) carry the real
    // syscall number in the first argument. Normalize by shifting the argument
    // registers down one (r2<-r3, r3<-r4, ... r8<-r9) so every handler below
    // reads its args from r2.. as usual.
    if (num == 0 or num == 198) {
        num = obsd.arg(cpu, 0);
        var k: u5 = 0;
        while (k < 7) : (k += 1) obsd.setArg(cpu, k, obsd.arg(cpu, k + 1));
    }
    const sc: Syscall = @enumFromInt(num);

    if (trace) {
        var buf: [96]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "obsd syscall {d} ({s}) a0={x} a1={x} a2={x}\n", .{
            num, @tagName(sc), obsd.arg(cpu, 0), obsd.arg(cpu, 1), obsd.arg(cpu, 2),
        }) catch "obsd syscall (fmt err)\n";
        traceOut(line);
    }

    switch (sc) {
        .exit => {
            runner.exit_status = obsd.arg(cpu, 0);
            return false;
        },
        .write => return sysWrite(runner),
        .read => return sysRead(runner),
        .writev => return sysWritev(runner),
        .open => return sysOpen(runner),
        .close => return sysClose(runner),
        .lseek => return sysLseek(runner),
        .pread => return sysPread(runner),

        // --- startup / sandbox syscalls: satisfy without side effects ------
        // pledge/unveil: pretend the sandbox request succeeded (we impose no
        // restriction), so the guest proceeds normally.
        .pledge, .unveil => {
            obsd.returnSuccess(cpu, 0);
            return true;
        },
        // kbind: the runtime's mechanism for the linker to write GOT/BIND
        // slots under a per-process cookie. A static binary has nothing to
        // bind at runtime; accept it as a no-op success.
        .kbind => {
            obsd.returnSuccess(cpu, 0);
            return true;
        },
        // msyscall: registers the address range from which syscalls are
        // permitted (OpenBSD's "syscall origin" hardening). We don't enforce
        // it; accept.
        .msyscall => {
            obsd.returnSuccess(cpu, 0);
            return true;
        },
        .sigaction => return sysSigaction(runner),
        .sigreturn => return sysSigreturn(runner),
        // Mask/altstack/pending: accept (we deliver only SIGCHLD, unmasked).
        .sigprocmask, .sigaltstack, .sigpending => {
            obsd.returnSuccess(cpu, 0);
            return true;
        },
        // sigsuspend blocks until a signal. A shell/make uses it to wait for
        // SIGCHLD: it blocks here until a child exits, its SIGCHLD handler runs
        // (reaps + records), then it returns EINTR. We deliver SIGCHLD to the
        // registered handler when a child is reapable, then return EINTR.
        .sigsuspend => return sysSigsuspend(runner),
        // getentropy(buf, len): fill with a deterministic pattern (we're not
        // cryptographic; the guest just needs the bytes present).
        .getentropy => {
            const buf = obsd.arg(cpu, 0);
            const len = obsd.arg(cpu, 1);
            if (@as(u64, buf) + len > mem.Memory.size) {
                obsd.returnError(cpu, EFAULT);
                return true;
            }
            var k: u32 = 0;
            const was = runner.memory.enforce;
            runner.memory.enforce = false;
            while (k < len) : (k += 1) runner.memory.write8(buf + k, @truncate(k *% 31 +% 7));
            runner.memory.enforce = was;
            obsd.returnSuccess(cpu, 0);
            return true;
        },
        // __set_tcb: set the thread control block pointer (stack-guard/TLS).
        // Record it; __get_tcb returns it. Stored on the runner scratch.
        .__set_tcb => {
            runner.tcb = obsd.arg(cpu, 0);
            obsd.returnSuccess(cpu, 0);
            return true;
        },
        .__get_tcb => {
            obsd.returnSuccess(cpu, runner.tcb);
            return true;
        },
        // Identity / capability probes with harmless answers.
        .issetugid => {
            obsd.returnSuccess(cpu, 0); // not set-uid/gid
            return true;
        },
        .getgroups => {
            // getgroups(gidsetlen, gidset): report membership in group 0 only.
            const len = obsd.arg(cpu, 0);
            const set = obsd.arg(cpu, 1);
            if (len >= 1 and set != 0 and @as(u64, set) + 4 <= mem.Memory.size) {
                const was = runner.memory.enforce;
                runner.memory.enforce = false;
                runner.memory.write32(set, 0);
                runner.memory.enforce = was;
            }
            obsd.returnSuccess(cpu, 1); // one group (gid 0)
            return true;
        },
        .getlogin_r => {
            // getlogin_r(namebuf, namelen): copy a fixed login name.
            const buf = obsd.arg(cpu, 0);
            const len = obsd.arg(cpu, 1);
            const name = "root";
            if (buf != 0 and len >= name.len + 1 and @as(u64, buf) + name.len + 1 <= mem.Memory.size) {
                const was = runner.memory.enforce;
                runner.memory.enforce = false;
                runner.memory.writeBytes(buf, name);
                runner.memory.write8(buf + @as(u32, name.len), 0);
                runner.memory.enforce = was;
            }
            obsd.returnSuccess(cpu, 0);
            return true;
        },
        .getpid => {
            // Real host pid: fork() returns real child pids, so getpid must
            // agree for make's job tracking to line up.
            obsd.returnSuccess(cpu, @intCast(getpid()));
            return true;
        },
        .getppid => {
            obsd.returnSuccess(cpu, @intCast(getppid()));
            return true;
        },
        .getthrid => {
            obsd.returnSuccess(cpu, 1); // single thread, tid 1
            return true;
        },
        .getrusage => {
            // Zero-fill the rusage struct (arg1); we don't track resource use.
            const ru = obsd.arg(cpu, 1);
            if (ru != 0 and @as(u64, ru) + 72 <= mem.Memory.size) {
                const was = runner.memory.enforce;
                runner.memory.enforce = false;
                runner.memory.zero(ru, 72);
                runner.memory.enforce = was;
            }
            obsd.returnSuccess(cpu, 0);
            return true;
        },
        // Process-group / session job control: we run a flat process model, so
        // report/accept sensibly. getpgid/getpgrp/getsid -> group 1; setpgid/
        // setsid -> success.
        .getpgid, .getpgrp, .getsid => {
            obsd.returnSuccess(cpu, 1);
            return true;
        },
        .setpgid, .setsid => {
            obsd.returnSuccess(cpu, 0);
            return true;
        },
        .kill, .thrkill => {
            // We don't deliver guest signals; accept the request. (make sends
            // SIGCONT/SIGTERM to job groups during scheduling.)
            obsd.returnSuccess(cpu, 0);
            return true;
        },
        .gettimeofday => return sysGettimeofday(runner),
        .clock_gettime => return sysClockGettime(runner),
        .getuid, .geteuid, .getgid, .getegid => {
            obsd.returnSuccess(cpu, 0); // root
            return true;
        },
        .__getcwd => return sysGetcwd(runner),
        .chdir => return sysChdir(runner),
        .fchdir => return sysFchdir(runner),
        .fork, .vfork => return sysFork(runner),
        .execve => return sysExec(runner),
        .wait4 => return sysWait4(runner),
        .pipe, .pipe2 => return sysPipe(runner),
        .dup => return sysDup(runner),
        .dup2, .dup3 => return sysDup2(runner),
        .access => return sysAccess(runner),
        .fcntl => return sysFcntl(runner),
        .mmap => return sysMmap(runner),
        // munmap/mprotect/madvise/minherit/msync: we don't reclaim ranges (the
        // bump allocator only grows), so accept and succeed.
        .munmap, .mprotect, .madvise, .minherit, .msync, .mquery => {
            obsd.returnSuccess(cpu, 0);
            return true;
        },
        .fstat => return sysFstat(runner),
        .stat => return sysStatPath(runner, false),
        .lstat => return sysStatPath(runner, true),
        .fstatat => return sysFstatat(runner),
        .getdents => return sysGetdents(runner),
        .ioctl => return sysIoctl(runner),
        .sysctl => return sysSysctl(runner),

        else => {
            failFast(runner, num, sc);
            return false;
        },
    }
}

fn sysWrite(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = obsd.arg(cpu, 0);
    const buf = obsd.arg(cpu, 1);
    const count = obsd.arg(cpu, 2);
    const hfd = hostFd(runner, gfd) orelse {
        obsd.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, buf) + count > mem.Memory.size) {
        obsd.returnError(cpu, EFAULT);
        return true;
    }
    const slice = runner.memory.bytes[buf .. buf + count];
    const n = write(hfd, slice.ptr, slice.len);
    if (n < 0) obsd.returnError(cpu, mapErrno(hostErrno())) else obsd.returnSuccess(cpu, @intCast(n));
    return true;
}

/// writev(fd, iov, iovcnt): iovec is {u32 iov_base; u32 iov_len} on 32-bit BE.
fn sysWritev(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = obsd.arg(cpu, 0);
    const iov = obsd.arg(cpu, 1);
    const iovcnt = obsd.arg(cpu, 2);
    const hfd = hostFd(runner, gfd) orelse {
        obsd.returnError(cpu, EBADF);
        return true;
    };
    var total: u32 = 0;
    var k: u32 = 0;
    while (k < iovcnt) : (k += 1) {
        const ent = iov + k * 8;
        if (@as(u64, ent) + 8 > mem.Memory.size) {
            obsd.returnError(cpu, EFAULT);
            return true;
        }
        const base = runner.memory.read32(ent + 0);
        const len = runner.memory.read32(ent + 4);
        if (len == 0) continue;
        if (@as(u64, base) + len > mem.Memory.size) {
            obsd.returnError(cpu, EFAULT);
            return true;
        }
        const slice = runner.memory.bytes[base .. base + len];
        const n = write(hfd, slice.ptr, slice.len);
        if (n < 0) {
            obsd.returnError(cpu, mapErrno(hostErrno()));
            return true;
        }
        total += @intCast(n);
        if (@as(u32, @intCast(n)) < len) break; // short write
    }
    obsd.returnSuccess(cpu, total);
    return true;
}

fn sysRead(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = obsd.arg(cpu, 0);
    const buf = obsd.arg(cpu, 1);
    const count = obsd.arg(cpu, 2);
    const hfd = hostFd(runner, gfd) orelse {
        obsd.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, buf) + count > mem.Memory.size) {
        obsd.returnError(cpu, EFAULT);
        return true;
    }
    const slice = runner.memory.bytes[buf .. buf + count];
    const n = read(hfd, slice.ptr, slice.len);
    if (n < 0) obsd.returnError(cpu, mapErrno(hostErrno())) else obsd.returnSuccess(cpu, @intCast(n));
    return true;
}

// OpenBSD O_* (sys/fcntl.h): O_RDONLY=0 O_WRONLY=1 O_RDWR=2, O_CREAT=0x200,
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

fn sysOpen(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const path_ptr = obsd.arg(cpu, 0);
    const flags = obsd.arg(cpu, 1);
    const mode = obsd.arg(cpu, 2);
    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        obsd.returnError(cpu, EINVAL);
        return true;
    };
    var hbuf: [2048]u8 = undefined;
    var cpath: [*:0]const u8 = @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, &hbuf) catch {
            obsd.returnError(cpu, ENOENT);
            return true;
        };
        cpath = hp.ptr;
    }
    const hfd = open(cpath, translateOpenFlags(flags), @intCast(mode));
    if (hfd < 0) {
        obsd.returnError(cpu, mapErrno(hostErrno()));
        return true;
    }
    if (fsOf(runner)) |fs| {
        // If the target is a directory, open a dir stream so getdents can read
        // it (the host forbids read(2) on a dir fd).
        var canonbuf: [1024]u8 = undefined;
        const gcanon = fs.canonicalGuest(gpath, &canonbuf) orelse gpath;
        if (fs.openDir(cpath, gcanon, hfd)) |gdir| {
            obsd.returnSuccess(cpu, gdir);
            return true;
        }
        const gfd = fs.allocFd(hfd) orelse {
            _ = close(hfd);
            obsd.returnError(cpu, EBADF);
            return true;
        };
        obsd.returnSuccess(cpu, gfd);
    } else {
        obsd.returnSuccess(cpu, @intCast(hfd));
    }
    return true;
}

fn sysClose(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = obsd.arg(cpu, 0);
    if (fsOf(runner)) |fs| {
        if (fs.closeFd(gfd)) obsd.returnSuccess(cpu, 0) else obsd.returnError(cpu, EBADF);
        return true;
    }
    if (gfd <= 2) {
        obsd.returnSuccess(cpu, 0);
        return true;
    }
    const rc = close(@intCast(gfd));
    if (rc < 0) obsd.returnError(cpu, mapErrno(hostErrno())) else obsd.returnSuccess(cpu, 0);
    return true;
}

fn sysLseek(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = obsd.arg(cpu, 0);
    // lseek(fd, pad, off_lo, off_hi, whence): off_t in the r4:r5 pair (arg1 is
    // the alignment pad r3), whence in arg4 (r6). off_hi = arg3, off_lo = arg2.
    const off_lo: u64 = obsd.arg(cpu, 2);
    const off_hi: u64 = obsd.arg(cpu, 3);
    const off: i64 = @bitCast((off_hi << 32) | off_lo);
    const whence = obsd.arg(cpu, 4);
    const hfd = hostFd(runner, gfd) orelse {
        obsd.returnError(cpu, EBADF);
        return true;
    };
    const pos = lseek(hfd, @intCast(off), @intCast(whence));
    if (pos < 0) obsd.returnError(cpu, mapErrno(hostErrno())) else obsd.returnSuccess2(cpu, @intCast(@as(u64, @intCast(pos)) & 0xffff_ffff), @intCast((@as(u64, @intCast(pos)) >> 32) & 0xffff_ffff));
    return true;
}

extern "c" fn pread(fd: c_int, buf: [*]u8, count: usize, off: c_long) isize;
// OpenBSD fcntl commands (fcntl.h).
const F_DUPFD: u32 = 0;
const F_GETFD: u32 = 1;
const F_SETFD: u32 = 2;
const F_GETFL: u32 = 3;
const F_SETFL: u32 = 4;
const F_DUPFD_CLOEXEC: u32 = 10;
const F_ISATTY: u32 = 11;

fn sysFcntl(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = obsd.arg(cpu, 0);
    const cmd = obsd.arg(cpu, 1);
    const hfd = hostFd(runner, gfd) orelse {
        obsd.returnError(cpu, EBADF);
        return true;
    };
    switch (cmd) {
        F_ISATTY => {
            obsd.returnSuccess(cpu, if (isatty(hfd) == 1) 1 else 0);
        },
        F_GETFD, F_GETFL => obsd.returnSuccess(cpu, 0), // no flags set
        F_SETFD, F_SETFL => obsd.returnSuccess(cpu, 0), // accept, ignore
        F_DUPFD, F_DUPFD_CLOEXEC => {
            const hnew = dup(hfd);
            if (hnew < 0) {
                obsd.returnError(cpu, mapErrno(hostErrno()));
                return true;
            }
            if (fsOf(runner)) |fs| {
                const gnew = fs.allocFdFrom(hnew, obsd.arg(cpu, 2)) orelse {
                    _ = close(hnew);
                    obsd.returnError(cpu, EBADF);
                    return true;
                };
                obsd.returnSuccess(cpu, gnew);
            } else {
                obsd.returnSuccess(cpu, @intCast(hnew));
            }
        },
        else => obsd.returnError(cpu, EINVAL),
    }
    return true;
}

// OpenBSD mmap flags (sys/mman.h).
const OBSD_MAP_ANON: u32 = 0x1000;
const OBSD_MAP_PRIVATE: u32 = 0x0002;
const OBSD_MAP_FIXED: u32 = 0x0010;

/// mmap(addr, len, prot, flags, fd, pad, off) — m88k register ABI.
/// Anonymous maps (the crt/malloc case) are served from the downward bump
/// allocator; file-backed private maps read the file bytes into the region.
/// __getcwd(buf, len): OpenBSD has a real getcwd syscall (unlike SysV/88 which
/// walks up with getdents+lstat). Our fs layer already tracks the guest cwd, so
/// we just copy it (NUL-terminated) into the guest buffer.
fn sysGetcwd(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const buf = obsd.arg(cpu, 0);
    const len = obsd.arg(cpu, 1);
    const cwd = if (fsOf(runner)) |fs| fs.cwdPath() else "/";
    if (cwd.len + 1 > len) {
        // OpenBSD returns ERANGE (34) when the buffer is too small.
        obsd.returnError(cpu, 34);
        return true;
    }
    if (@as(u64, buf) + cwd.len + 1 > mem.Memory.size) {
        obsd.returnError(cpu, EFAULT);
        return true;
    }
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    runner.memory.writeBytes(buf, cwd);
    runner.memory.write8(buf + @as(u32, @intCast(cwd.len)), 0);
    runner.memory.enforce = was;
    // OpenBSD's __getcwd returns 0 on success (libc getcwd wraps it).
    obsd.returnSuccess(cpu, 0);
    return true;
}

/// pread(fd, buf, nbyte, pad, off_lo, off_hi): read at an explicit offset
/// without moving the file position. off_t is 64-bit; with the pad slot the
/// low word is arg4 (arg3 is the alignment pad).
fn sysPread(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = obsd.arg(cpu, 0);
    const buf = obsd.arg(cpu, 1);
    const count = obsd.arg(cpu, 2);
    // off_t is 64-bit passed in an even/odd register pair r6:r7 (arg3 is the
    // alignment pad r5). off_hi = arg4 (r6), off_lo = arg5 (r7).
    const off_hi: u64 = obsd.arg(cpu, 4);
    const off_lo: u64 = obsd.arg(cpu, 5);
    const off: u64 = (off_hi << 32) | off_lo;
    const hfd = hostFd(runner, gfd) orelse {
        obsd.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, buf) + count > mem.Memory.size) {
        obsd.returnError(cpu, EFAULT);
        return true;
    }
    const slice = runner.memory.bytes[buf .. buf + count];
    const n = pread(hfd, slice.ptr, slice.len, @intCast(off));
    if (n < 0) obsd.returnError(cpu, mapErrno(hostErrno())) else obsd.returnSuccess(cpu, @intCast(n));
    return true;
}

extern "c" fn time(t: ?*c_long) c_long;

/// gettimeofday(tv, tz): fill struct timeval {time_t tv_sec (i64); suseconds_t
/// tv_usec (i32)}. We give whole seconds from the host clock, usec 0.
fn sysGettimeofday(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const tv = obsd.arg(cpu, 0);
    if (tv != 0) {
        if (@as(u64, tv) + 16 > mem.Memory.size) {
            obsd.returnError(cpu, EFAULT);
            return true;
        }
        const secs = time(null);
        const was = runner.memory.enforce;
        runner.memory.enforce = false;
        runner.memory.write32(tv + 0, 0); // tv_sec hi
        runner.memory.write32(tv + 4, @bitCast(@as(i32, @truncate(secs)))); // tv_sec lo
        runner.memory.write32(tv + 8, 0); // tv_usec
        runner.memory.enforce = was;
    }
    obsd.returnSuccess(cpu, 0);
    return true;
}

/// clock_gettime(clock_id, tp): fill struct timespec {i64 sec; i32 nsec}.
fn sysClockGettime(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const tp = obsd.arg(cpu, 1);
    if (tp != 0) {
        if (@as(u64, tp) + 16 > mem.Memory.size) {
            obsd.returnError(cpu, EFAULT);
            return true;
        }
        const secs = time(null);
        const was = runner.memory.enforce;
        runner.memory.enforce = false;
        runner.memory.write32(tp + 0, 0);
        runner.memory.write32(tp + 4, @bitCast(@as(i32, @truncate(secs))));
        runner.memory.write32(tp + 8, 0);
        runner.memory.enforce = was;
    }
    obsd.returnSuccess(cpu, 0);
    return true;
}

fn sysAccess(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const path_ptr = obsd.arg(cpu, 0);
    const amode = obsd.arg(cpu, 1);
    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        obsd.returnError(cpu, EINVAL);
        return true;
    };
    var hbuf: [2048]u8 = undefined;
    var cpath: [*:0]const u8 = @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, &hbuf) catch {
            obsd.returnError(cpu, ENOENT);
            return true;
        };
        cpath = hp.ptr;
    }
    // OpenBSD access modes: F_OK=0, X_OK=1, W_OK=2, R_OK=4 — same low 3 bits as
    // the host, so pass them straight through.
    const arc = fsmod.c.access(cpath, @intCast(amode & 0x7));
    if (arc < 0) obsd.returnError(cpu, mapErrno(hostErrno())) else obsd.returnSuccess(cpu, 0);
    return true;
}

fn sysChdir(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const path_ptr = obsd.arg(cpu, 0);
    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        obsd.returnError(cpu, EINVAL);
        return true;
    };
    if (fsOf(runner)) |fs| {
        var hbuf: [2048]u8 = undefined;
        const hp = fs.resolve(gpath, &hbuf) catch {
            obsd.returnError(cpu, ENOENT);
            return true;
        };
        if (fsmod.c.access(hp, 0) < 0) {
            obsd.returnError(cpu, ENOENT);
            return true;
        }
        fs.chdir(gpath) catch {
            obsd.returnError(cpu, EINVAL);
            return true;
        };
    }
    obsd.returnSuccess(cpu, 0);
    return true;
}

/// fchdir(fd): set cwd to the guest path recorded for that directory fd.
fn sysFchdir(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = obsd.arg(cpu, 0);
    const fs = fsOf(runner) orelse {
        obsd.returnSuccess(cpu, 0);
        return true;
    };
    const gpath = fs.dirGuestPath(gfd) orelse {
        obsd.returnError(cpu, EBADF);
        return true;
    };
    fs.chdir(gpath) catch {
        obsd.returnError(cpu, EINVAL);
        return true;
    };
    obsd.returnSuccess(cpu, 0);
    return true;
}

fn sysMmap(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const addr = obsd.arg(cpu, 0);
    const len = obsd.arg(cpu, 1);
    const flags = obsd.arg(cpu, 3);
    const gfd = obsd.arg(cpu, 4);
    // mmap(addr,len,prot,flags,fd,offset): off_t is 64-bit in the even/odd
    // register pair r8:r9 (r7 is skipped as the alignment pad). So
    // off_hi = arg6 (r8), off_lo = arg7 (r9). We use the low word (mapped
    // files are < 4GB). Reading arg6 as the whole offset (the earlier bug) made
    // every library segment load from offset 0 -> garbage DYNAMIC.
    const off = obsd.arg(cpu, 7);

    const anon = (flags & OBSD_MAP_ANON) != 0 or gfd == 0xffffffff;
    var hfd: c_int = -1;
    if (!anon) {
        hfd = hostFd(runner, gfd) orelse {
            obsd.returnError(cpu, EBADF);
            return true;
        };
    }

    // Reject absurd lengths before aligning (avoid u32 overflow in alignForward
    // and a nonsensical reservation).
    if (len > 0x4000_0000) {
        obsd.returnError(cpu, ENOMEM);
        return true;
    }
    const size = std.mem.alignForward(u32, if (len == 0) 1 else len, 0x1000);

    // Choose the mapping address. MAP_FIXED (or a non-zero addr hint we can
    // satisfy) must land EXACTLY where requested: ld.so reserves a library's
    // whole address span, then maps each segment at a computed fixed offset and
    // writes relocations there — a wrong address corrupts everything. Otherwise
    // use the downward bump allocator.
    var base: u32 = undefined;
    if (addr != 0 and (@as(u64, addr) + size) <= mem.Memory.size and
        ((flags & OBSD_MAP_FIXED) != 0 or addr >= runner.brk))
    {
        base = addr;
    } else {
        if (runner.mmap_next < runner.brk + 0x10000 or runner.mmap_next -% size < runner.brk) {
            obsd.returnError(cpu, ENOMEM);
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
    obsd.returnSuccess(cpu, base);
    return true;
}

// --- OpenBSD struct stat (sys/stat.h) --------------------------------------
// 32-bit m88k layout (all fields present; dev/ino/timespecs are 64-bit):
//   dev_t   st_dev     (i32)   @0
//   ino_t   st_ino     (u64)   @8   (8-aligned)
//   mode_t  st_mode    (u32)   @16
//   nlink_t st_nlink   (u32)   @20
//   uid_t   st_uid     (u32)   @24
//   gid_t   st_gid     (u32)   @28
//   dev_t   st_rdev    (i32)   @32
//   timespec st_atim   @40 (8+8)   ... mtim @56, ctim @72
//   off_t   st_size    (i64)   @88
//   blkcnt_t st_blocks (i64)   @96
//   blksize_t st_blksize(i32)  @104
//   ...
// This is close enough for the fields tools read (mode/size/blksize). We fill
// the common ones and zero the rest. Total size 128.
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

const OBSD_STAT_SIZE: u32 = 128;
const AT_FDCWD: u32 = 0xffffff9c; // -100
const AT_SYMLINK_NOFOLLOW: u32 = 0x02;

/// Write a HostStat into the guest's OpenBSD `struct stat` (sys/stat.h).
/// Layout (m88k BE, time_t 64-bit, timespec = {i64 sec; i32 nsec} = 16 bytes):
///   st_mode  u32 @0
///   st_dev   i32 @4
///   st_ino   u64 @8
///   st_nlink u32 @16
///   st_uid   u32 @20
///   st_gid   u32 @24
///   st_rdev  i32 @28
///   st_atim  @32(16)  st_mtim @48(16)  st_ctim @64(16)
///   st_size  i64 @80
///   st_blocks i64 @88
///   st_blksize i32 @96
///   st_flags @100, st_gen @104, __st_birthtim @112(16) => 128 total
fn writeGuestStat(runner: *machine.Runner, statbuf: u32, hs: *const HostStat) void {
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    const m = runner.memory;
    m.zero(statbuf, OBSD_STAT_SIZE);
    m.write32(statbuf + 0, hs.mode); // st_mode (S_IF* bits match host)
    m.write32(statbuf + 4, hs.dev); // st_dev
    m.write32(statbuf + 8, 0); // st_ino hi
    m.write32(statbuf + 12, hs.ino); // st_ino lo
    m.write32(statbuf + 16, hs.nlink); // st_nlink
    m.write32(statbuf + 20, hs.uid); // st_uid
    m.write32(statbuf + 24, hs.gid); // st_gid
    m.write32(statbuf + 28, hs.rdev); // st_rdev
    m.write32(statbuf + 32, 0); // st_atim.sec hi
    m.write32(statbuf + 36, @bitCast(@as(i32, @truncate(hs.atime)))); // st_atim.sec lo
    m.write32(statbuf + 48, 0); // st_mtim.sec hi
    m.write32(statbuf + 52, @bitCast(@as(i32, @truncate(hs.mtime)))); // st_mtim.sec lo
    m.write32(statbuf + 64, 0); // st_ctim.sec hi
    m.write32(statbuf + 68, @bitCast(@as(i32, @truncate(hs.ctime)))); // st_ctim.sec lo
    m.write32(statbuf + 80, 0); // st_size hi
    m.write32(statbuf + 84, @truncate(hs.size)); // st_size lo
    m.write32(statbuf + 88, 0); // st_blocks hi
    m.write32(statbuf + 92, @intCast((hs.size + 511) / 512)); // st_blocks lo
    m.write32(statbuf + 96, 0x1000); // st_blksize
    runner.memory.enforce = was;
}

fn sysFstat(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = obsd.arg(cpu, 0);
    const statbuf = obsd.arg(cpu, 1);
    const hfd = hostFd(runner, gfd) orelse {
        obsd.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, statbuf) + OBSD_STAT_SIZE > mem.Memory.size) {
        obsd.returnError(cpu, EFAULT);
        return true;
    }
    var hs: HostStat = undefined;
    r88k_fstat(hfd, &hs);
    if (hs.ok == 0) {
        obsd.returnError(cpu, mapErrno(@intCast(hs.err)));
        return true;
    }
    writeGuestStat(runner, statbuf, &hs);
    obsd.returnSuccess(cpu, 0);
    return true;
}

/// stat(38)/lstat(40): stat a path (relative resolved against cwd via the fs).
fn sysStatPath(runner: *machine.Runner, is_lstat: bool) bool {
    const cpu = &runner.cpu;
    const path_ptr = obsd.arg(cpu, 0);
    const statbuf = obsd.arg(cpu, 1);
    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        obsd.returnError(cpu, EINVAL);
        return true;
    };
    if (@as(u64, statbuf) + OBSD_STAT_SIZE > mem.Memory.size) {
        obsd.returnError(cpu, EFAULT);
        return true;
    }
    var hbuf: [2048]u8 = undefined;
    var cpath: [*:0]const u8 = @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, &hbuf) catch {
            obsd.returnError(cpu, ENOENT);
            return true;
        };
        cpath = hp.ptr;
    }
    var hs: HostStat = undefined;
    if (is_lstat) r88k_lstat(cpath, &hs) else r88k_stat(cpath, &hs);
    if (hs.ok == 0) {
        obsd.returnError(cpu, mapErrno(@intCast(hs.err)));
        return true;
    }
    writeGuestStat(runner, statbuf, &hs);
    obsd.returnSuccess(cpu, 0);
    return true;
}

/// fstatat(fd, path, statbuf, flags): the modern *at stat. We support the
/// AT_FDCWD case (fd == -100) with an absolute or cwd-relative path, and
/// AT_SYMLINK_NOFOLLOW selecting lstat. A real dirfd base (opendir + relative)
/// isn't needed by the utilities we run yet.
fn sysFstatat(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const dirfd = obsd.arg(cpu, 0);
    const path_ptr = obsd.arg(cpu, 1);
    const statbuf = obsd.arg(cpu, 2);
    const flags = obsd.arg(cpu, 3);
    if (dirfd != AT_FDCWD) {
        // Not yet supported; fail so the caller can fall back.
        obsd.returnError(cpu, EINVAL);
        return true;
    }
    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        obsd.returnError(cpu, EINVAL);
        return true;
    };
    if (@as(u64, statbuf) + OBSD_STAT_SIZE > mem.Memory.size) {
        obsd.returnError(cpu, EFAULT);
        return true;
    }
    var hbuf: [2048]u8 = undefined;
    var cpath: [*:0]const u8 = @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, &hbuf) catch {
            obsd.returnError(cpu, ENOENT);
            return true;
        };
        cpath = hp.ptr;
    }
    var hs: HostStat = undefined;
    if ((flags & AT_SYMLINK_NOFOLLOW) != 0) r88k_lstat(cpath, &hs) else r88k_stat(cpath, &hs);
    if (hs.ok == 0) {
        obsd.returnError(cpu, mapErrno(@intCast(hs.err)));
        return true;
    }
    writeGuestStat(runner, statbuf, &hs);
    obsd.returnSuccess(cpu, 0);
    return true;
}

// Directory-stream shim (shared C helper, same as the SysV dispatcher uses).
extern fn r88k_dirread(handle: c_int, ino_out: *c_ulong, name_out: [*]u8) c_int;

/// getdents(fd, buf, nbyte): fill buf with OpenBSD `struct dirent`:
///   d_fileno(u64)@0, d_off(i64)@8, d_reclen(u16)@16, d_type(u8)@18,
///   d_namlen(u8)@19, __d_padding[4]@20, d_name@24 (NUL-term, padded to 8).
fn sysGetdents(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = obsd.arg(cpu, 0);
    const buf = obsd.arg(cpu, 1);
    const nbyte = obsd.arg(cpu, 2);
    const fs = fsOf(runner) orelse {
        obsd.returnError(cpu, EBADF);
        return true;
    };
    const handle = fs.dirHandleFor(gfd) orelse {
        obsd.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, buf) + nbyte > mem.Memory.size) {
        obsd.returnError(cpu, EFAULT);
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
        // header(24) + name + 1 NUL, padded to 8.
        const raw = 24 + name.len + 1;
        const reclen: u32 = @intCast(std.mem.alignForward(usize, raw, 8));
        if (written + reclen > nbyte) {
            fs.dirPushback(handle);
            break;
        }
        const at = buf + written;
        runner.memory.write32(at + 0, 0); // d_fileno hi
        runner.memory.write32(at + 4, @intCast(ino & 0xffffffff)); // d_fileno lo
        runner.memory.write32(at + 8, 0); // d_off hi
        runner.memory.write32(at + 12, written + reclen); // d_off lo
        runner.memory.write16(at + 16, @intCast(reclen)); // d_reclen
        runner.memory.write8(at + 18, 0); // d_type = DT_UNKNOWN
        runner.memory.write8(at + 19, @intCast(name.len)); // d_namlen
        runner.memory.writeBytes(at + 24, name);
        runner.memory.write8(at + 24 + @as(u32, @intCast(name.len)), 0);
        written += reclen;
    }
    obsd.returnSuccess(cpu, written);
    return true;
}

// sysctl top-level (CTL_*) and second-level ids we answer.
const CTL_KERN: u32 = 1;
const CTL_HW: u32 = 6;
const HW_PAGESIZE: u32 = 7;
const HW_NCPU: u32 = 3;
const KERN_OSRELEASE: u32 = 2;
const KERN_OSTYPE: u32 = 1;

/// sysctl(name, namelen, oldp, oldlenp, newp, newlen).
/// libc's startup + malloc query a few MIB keys (notably {CTL_HW,HW_PAGESIZE}
/// for the allocation granularity). Returning failure makes malloc size its
/// arena from a garbage page size (we saw mmap(len=0xffffffff)). Answer the
/// keys we know; for the rest return an int 0 success (benign) so callers get
/// a defined value rather than an error.
fn sysSysctl(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const name = obsd.arg(cpu, 0);
    const namelen = obsd.arg(cpu, 1);
    const oldp = obsd.arg(cpu, 2);
    const oldlenp = obsd.arg(cpu, 3);
    const m = runner.memory;

    if (namelen < 1 or @as(u64, name) + namelen * 4 > mem.Memory.size) {
        obsd.returnError(cpu, EINVAL);
        return true;
    }
    const top = m.read32(name);
    const sub = if (namelen >= 2) m.read32(name + 4) else 0;

    // Helper: write a 32-bit int result honoring oldp/oldlenp, then succeed.
    const putInt = struct {
        fn go(rn: *machine.Runner, op: u32, olp: u32, val: u32) void {
            const mm = rn.memory;
            const was = mm.enforce;
            mm.enforce = false;
            if (olp != 0) {
                const cap = mm.read32(olp);
                if (cap >= 4 and op != 0) mm.write32(op, val);
                mm.write32(olp, 4); // report 4 bytes returned
            }
            mm.enforce = was;
            obsd.returnSuccess(&rn.cpu, 0);
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

    // String keys uname(1)/libc query. Write the string (NUL-terminated) into
    // oldp honoring oldlenp, and report the length.
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
            obsd.returnSuccess(&rn.cpu, 0);
        }
    }.go;

    const HW_MACHINE: u32 = 1;
    const HW_MODEL: u32 = 2;
    const KERN_OSREV: u32 = 3;
    const KERN_VERSION: u32 = 4;
    if (top == CTL_KERN and sub == KERN_OSTYPE) {
        putStr(runner, oldp, oldlenp, "OpenBSD");
        return true;
    }
    if (top == CTL_KERN and sub == KERN_OSRELEASE) {
        putStr(runner, oldp, oldlenp, "7.1");
        return true;
    }
    if (top == CTL_KERN and sub == KERN_VERSION) {
        putStr(runner, oldp, oldlenp, "OpenBSD 7.1 (GENERIC) #1\n");
        return true;
    }
    if (top == CTL_KERN and sub == KERN_OSREV) {
        putInt(runner, oldp, oldlenp, 202111);
        return true;
    }
    if (top == CTL_KERN and sub == 10) { // KERN_HOSTNAME
        putStr(runner, oldp, oldlenp, "luna88k");
        return true;
    }
    if (top == CTL_KERN and sub == 22) { // KERN_DOMAINNAME
        putStr(runner, oldp, oldlenp, "");
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
    const CTL_VM: u32 = 2;
    const VM_MALLOC_CONF: u32 = 12;
    if (top == CTL_VM and sub == VM_MALLOC_CONF) {
        // Empty malloc config: an empty NUL-terminated string, len 1. Returning
        // an uninitialized buffer makes libc malloc warn "unknown char".
        putStr(runner, oldp, oldlenp, "");
        return true;
    }

    // Unknown key: report "0 bytes available" and succeed, so callers that
    // probe a length or tolerate an empty result proceed. (Refine per-key as
    // specific tools need real values.)
    const was = m.enforce;
    m.enforce = false;
    if (oldlenp != 0) m.write32(oldlenp, 0);
    m.enforce = was;
    obsd.returnSuccess(cpu, 0);
    return true;
}

fn sysIoctl(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = obsd.arg(cpu, 0);
    // Just enough for stdio buffering decisions: report tty-ness for the
    // TIOCGETA family, else ENOTTY. Full termios modelling comes later.
    const hfd = hostFd(runner, gfd) orelse {
        obsd.returnError(cpu, EBADF);
        return true;
    };
    if (isatty(hfd) == 1) {
        obsd.returnSuccess(cpu, 0);
    } else {
        obsd.returnError(cpu, ENOTTY);
    }
    return true;
}

// --- signal delivery (minimal: SIGCHLD for shell/make child-wait) ---------
//
// OpenBSD's sh/make block in sigsuspend() waiting for SIGCHLD, whose handler
// reaps the child. We record the handler (sigaction), and when a child is
// reapable we DELIVER the signal: save the CPU state into a private sigcontext
// on the guest stack, set r2=signo and r1=an injected trampoline that issues
// sigreturn, and jump to the handler. sigreturn restores the saved state.
//
// We use our OWN sigcontext layout (delivery and sigreturn are both ours; the
// handler only reads r2/reaps and never inspects the context), so we sidestep
// OpenBSD's cookie-protected kernel sigcontext entirely.

const SIGCHLD: u32 = 20;

// Our private sigcontext, written on the guest stack at delivery:
//   [0]   magic (validates sigreturn)
//   [1]   saved pc
//   [2]   saved npc
//   [3]   saved psr
//   [4]   saved cf
//   [5]   branch_pending (0/1)
//   [6]   branch_target
//   [7..38]  r0..r31 (32 words)
// total 39 words = 156 bytes.
const SC_MAGIC: u32 = 0x5311_5347; // "r88kSIG"-ish
const SC_WORDS: u32 = 39;

fn sysSigaction(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const signo = obsd.arg(cpu, 0);
    const act = obsd.arg(cpu, 1); // struct sigaction* {handler@0, mask@4, flags@8}
    const oact = obsd.arg(cpu, 2);
    // Report the previous handler if asked.
    if (oact != 0 and signo < 64 and @as(u64, oact) + 12 <= mem.Memory.size) {
        const was = runner.memory.enforce;
        runner.memory.enforce = false;
        runner.memory.write32(oact + 0, runner.sig_handlers[signo]);
        runner.memory.enforce = was;
    }
    if (act != 0 and signo < 64) {
        const h = runner.memory.read32(act + 0);
        // 0 = SIG_DFL, 1 = SIG_IGN: treat both as "no user handler".
        runner.sig_handlers[signo] = if (h <= 1) 0 else h;
    }
    obsd.returnSuccess(cpu, 0);
    return true;
}

/// Deliver SIGCHLD to the guest handler (if registered), returning true if a
/// signal frame was pushed (PC now points at the handler). The pending syscall
/// that triggered delivery must NOT also write a return value.
fn deliverSigchld(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const handler = runner.sig_handlers[SIGCHLD];
    if (handler == 0) return false;

    // Push our sigcontext below the current SP (16-byte aligned).
    var sp = cpu.getReg(31);
    sp -%= SC_WORDS * 4;
    sp &= ~@as(u32, 15);
    if (sp < 0x0100_0000) return false; // stack underflow guard

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

    // Enter the handler: r2 = signo, r3 = 0 (siginfo), r4 = &sigcontext,
    // r1 = trampoline (issues sigreturn), r31 = new sp, PC = handler.
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

/// sigreturn(scp): restore CPU state from our sigcontext. Validates our magic.
fn sysSigreturn(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const scp = obsd.arg(cpu, 0);
    const m = runner.memory;
    if (@as(u64, scp) + SC_WORDS * 4 > mem.Memory.size or m.read32(scp) != SC_MAGIC) {
        obsd.returnError(cpu, EINVAL);
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
    // Do NOT touch r2 or advance PC: we restored the exact pre-signal state,
    // which resumes the interrupted sigsuspend's return path.
    return true;
}

/// sigsuspend: block until SIGCHLD. If a child is reapable and a handler is
/// registered, deliver the signal (jump to handler; it reaps via wait4 and
/// returns through the trampoline -> sigreturn). Then the sigsuspend syscall
/// returns EINTR. If no child is ready yet, block on a real wait so we don't
/// spin, then deliver.
fn sysSigsuspend(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        obsd.returnError(cpu, EINTR);
        return true;
    };
    // If a handler is registered and a child is (or becomes) reapable, deliver
    // SIGCHLD. We set the syscall's return (EINTR) FIRST, so that when the
    // handler returns via sigreturn and resumes right after the trap, the
    // sigsuspend call sees EINTR.
    if (runner.sig_handlers[SIGCHLD] != 0) {
        // Deliver SIGCHLD only if a child is reapable RIGHT NOW. If a child is
        // still running, block until it becomes reapable, then deliver. If
        // there are NO children at all, don't deliver (nothing to report) —
        // just return EINTR so the caller's wait loop re-checks and exits.
        var ready = pm.childReapable();
        if (!ready and pm.hasChildren()) {
            ready = pm.blockUntilChild();
        }
        // Set the sigsuspend return (EINTR) into the CURRENT frame FIRST, so the
        // saved sigcontext resumes with EINTR after the handler's sigreturn.
        obsd.returnError(cpu, EINTR);
        if (ready) _ = deliverSigchld(runner); // PC now at handler if delivered
        return true;
    }
    obsd.returnError(cpu, EINTR);
    return true;
}

// --- process model: fork / execve / wait4 / pipe / dup2 -------------------

/// fork/vfork. OpenBSD's raw fork(2) stub is a plain skip-on-success trap with
/// NO r3 dual-return (unlike SysV/88): the kernel returns the child pid in r2
/// to the parent and **0 in r2 to the child**. So we mirror that directly.
fn sysFork(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        obsd.returnError(cpu, EINVAL);
        return true;
    };
    const rc = pm.doFork() catch {
        obsd.returnError(cpu, ENOMEM);
        return true;
    };
    if (rc == 0) {
        obsd.returnSuccess(cpu, 0); // child sees 0
    } else {
        obsd.returnSuccess(cpu, rc); // parent sees the child pid
    }
    return true;
}

fn sysExec(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        obsd.returnError(cpu, EINVAL);
        return true;
    };
    const path_ptr = obsd.arg(cpu, 0);
    const argv_ptr = obsd.arg(cpu, 1);
    const envp_ptr = obsd.arg(cpu, 2);
    var pbuf: [1024]u8 = undefined;
    const path = readGuestPath(runner, path_ptr, &pbuf) orelse {
        obsd.returnError(cpu, EINVAL);
        return true;
    };
    var argv_store: [128][]const u8 = undefined;
    var envp_store: [256][]const u8 = undefined;
    var argv_bufs: [128][256]u8 = undefined;
    var envp_bufs: [256][256]u8 = undefined;
    const argc = readStrVec(runner, argv_ptr, &argv_store, &argv_bufs);
    const envc = readStrVec(runner, envp_ptr, &envp_store, &envp_bufs);
    pm.doExec(path, argv_store[0..argc], envp_store[0..envc]) catch {
        obsd.returnError(cpu, ENOENT);
        return true;
    };
    // doExec (setupOpenbsd) already set PC to the new entry; just clear any
    // stale fault from the reload and continue (no PC advance / carry touch).
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

/// wait4(pid, status, options, rusage): OpenBSD's wait primitive. Returns the
/// reaped pid in r2 and writes the status word to *status.
fn sysWait4(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        obsd.returnError(cpu, ECHILD);
        return true;
    };
    const statptr = obsd.arg(cpu, 1);
    // NOTE: we IGNORE WNOHANG and always block. A shell/make polls for child
    // exit via sigsuspend(SIGCHLD)+wait4(WNOHANG), but we don't deliver signals,
    // so a non-blocking wait would spin forever. Blocking here reaps the child
    // on the first call. (Parallel-job semantics are thereby serialized, which
    // is acceptable — correctness over concurrency.)
    const res = pm.doWaitOpts(false) catch {
        obsd.returnError(cpu, ECHILD);
        return true;
    };
    // WNOHANG with no child ready: return pid 0, don't write status.
    if (res.pid != 0 and statptr != 0 and @as(u64, statptr) + 4 <= mem.Memory.size) {
        const was = runner.memory.enforce;
        runner.memory.enforce = false;
        runner.memory.write32(statptr, res.status);
        runner.memory.enforce = was;
    }
    obsd.returnSuccess(cpu, res.pid);
    return true;
}

/// pipe(fildes) / pipe2(fildes, flags): OpenBSD returns the two fds by WRITING
/// them into the user int[2] array (arg0), and returns 0 — unlike SysV which
/// returns them in r2/r3.
fn sysPipe(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        obsd.returnError(cpu, EINVAL);
        return true;
    };
    const arr = obsd.arg(cpu, 0);
    const fds = pm.doPipe() catch {
        obsd.returnError(cpu, ENOMEM);
        return true;
    };
    if (@as(u64, arr) + 8 > mem.Memory.size) {
        obsd.returnError(cpu, EFAULT);
        return true;
    }
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    runner.memory.write32(arr + 0, fds[0]);
    runner.memory.write32(arr + 4, fds[1]);
    runner.memory.enforce = was;
    obsd.returnSuccess(cpu, 0);
    return true;
}

fn sysDup(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = obsd.arg(cpu, 0);
    const hfd = hostFd(runner, gfd) orelse {
        obsd.returnError(cpu, EBADF);
        return true;
    };
    const hnew = dup(hfd);
    if (hnew < 0) {
        obsd.returnError(cpu, mapErrno(hostErrno()));
        return true;
    }
    if (fsOf(runner)) |fs| {
        const gnew = fs.allocFd(hnew) orelse {
            obsd.returnError(cpu, EBADF);
            return true;
        };
        obsd.returnSuccess(cpu, gnew);
    } else {
        obsd.returnSuccess(cpu, @intCast(hnew));
    }
    return true;
}

/// dup2(oldfd, newfd) / dup3(oldfd, newfd, flags): duplicate onto a specific
/// guest fd. The shell relies on this for stdio redirection.
fn sysDup2(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gold = obsd.arg(cpu, 0);
    const gnew = obsd.arg(cpu, 1);
    const holdfd = hostFd(runner, gold) orelse {
        obsd.returnError(cpu, EBADF);
        return true;
    };
    if (gold == gnew) {
        obsd.returnSuccess(cpu, gnew);
        return true;
    }
    const fs = fsOf(runner) orelse {
        // No fs table: fall back to a host dup2 with identity fds.
        if (dup2(holdfd, @intCast(gnew)) < 0) obsd.returnError(cpu, mapErrno(hostErrno())) else obsd.returnSuccess(cpu, gnew);
        return true;
    };
    // Close whatever occupied newfd, then point it at a dup of oldfd's host fd.
    _ = fs.closeFd(gnew);
    const hnew = dup(holdfd);
    if (hnew < 0) {
        obsd.returnError(cpu, mapErrno(hostErrno()));
        return true;
    }
    if (fs.allocFdAt(gnew, hnew)) {
        obsd.returnSuccess(cpu, gnew);
    } else {
        _ = dup2(holdfd, holdfd); // no-op; cleanup path
        obsd.returnError(cpu, EBADF);
    }
    return true;
}

fn failFast(runner: *machine.Runner, num: u32, sc: Syscall) void {
    var buf: [160]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buf,
        "run88k(openbsd): unimplemented syscall {d} ({s}) at ppc={x}\n",
        .{ num, @tagName(sc), runner.cpu.ppc },
    ) catch "run88k(openbsd): unimplemented syscall\n";
    traceOut(line);
}
