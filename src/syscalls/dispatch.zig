//! SysV/88 syscall dispatcher + minimal host-backed implementations.
//!
//! Reads the number (r9) and args (r2..r8) via the personality, services the
//! call against the host, and writes the result back with the personality's
//! success/error convention (r2 + carry + skip-on-success PC). Unimplemented
//! syscalls fail fast with a diagnostic so we learn exactly what a real binary
//! needs, in the spirit of runupc.
//!
//! This is the minimal set to run a static `/bin/echo`: exit, write, and the
//! handful crt1 / libc touch on the way in (read, open, close, brk, lseek).
//! Files are backed directly by the host for now (no chroot fs layer yet — that
//! arrives with the shell milestone).

const std = @import("std");
const builtin = @import("builtin");
const m88k = @import("m88k");
const mem = @import("../mem.zig");
const machine = @import("../machine.zig");
const sysv = @import("../abi/sysv88.zig");
const table = @import("table_sysv88.zig");
const fsmod = @import("../fs.zig");
const procmodel = @import("../procmodel.zig");

const Cpu = m88k.Cpu;
const Syscall = table.Syscall;

/// Get the filesystem from the runner (type-erased). Null if not configured
/// (early milestones ran without a guest root).
fn fsOf(runner: *machine.Runner) ?*fsmod.Fs {
    const p = runner.fs orelse return null;
    return @ptrCast(@alignCast(p));
}

fn pmOf(runner: *machine.Runner) ?*procmodel.HostProcess {
    const p = runner.procmodel orelse return null;
    return @ptrCast(@alignCast(p));
}

// Host libc for the file operations (stable, portable).
extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern "c" fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern "c" fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn lseek(fd: c_int, off: c_long, whence: c_int) c_long;
extern "c" fn pread(fd: c_int, buf: [*]u8, count: usize, off: c_long) isize;
extern "c" fn __errno_location() *c_int;

// Host stat shim (src/host_stat.c). Fixed layout, host-independent.
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
extern fn r88k_s_ifmt() c_uint;

fn hostErrno() u32 {
    return @intCast(__errno_location().*);
}

fn traceOut(bytes: []const u8) void {
    _ = write(2, bytes.ptr, bytes.len);
}

/// Whether to print an strace-style line per syscall.
pub var trace: bool = false;

/// The dispatcher, installed as the runner's syscall handler. Returns true to
/// continue the guest, false to stop (exit / fatal).
pub fn dispatch(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const num = sysv.syscallNumber(cpu);
    const sc: Syscall = @enumFromInt(num);

    if (trace) {
        var buf: [96]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "syscall {d} ({s}) a0={x} a1={x} a2={x}\n", .{
            num, @tagName(sc), sysv.arg(cpu, 0), sysv.arg(cpu, 1), sysv.arg(cpu, 2),
        }) catch "syscall (fmt err)\n";
        traceOut(line);
    }

    switch (sc) {
        .exit => {
            runner.exit_status = sysv.arg(cpu, 0);
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
        .lstat => return sysLstat(runner),
        .access => return sysAccess(runner),
        .chdir => return sysChdir(runner),
        .chmod => return sysChmod(runner),
        .fchmod => return sysFchmod(runner),
        .dup => return sysDup(runner),
        .unlink => return sysUnlink(runner),
        .rename => return sysRename(runner),
        .mkdir => return sysMkdir(runner),
        .rmdir => return sysRmdir(runner),
        .creat => return sysCreat(runner),
        // Signal syscalls: no signal delivery yet, so accept and return
        // benign success (shells install handlers at startup). sigaction may
        // return the old action; we leave the guest's oldact buffer as-is.
        .sigaction, .sigprocmask, .signal, .sigpending, .sigsuspend => {
            sysv.returnSuccess(cpu, 0);
            return true;
        },
        .pgrpsys => {
            // subcode in r2: 0 getpgrp, 1 setpgrp, 2 getsid, 3 setsid,
            // 4 getpgid, 5 setpgid. Single session/pgrp: return pid-ish 1.
            const sub = sysv.arg(cpu, 0);
            switch (sub) {
                0, 2, 4 => sysv.returnSuccess(cpu, 1), // get* -> group/session 1
                else => sysv.returnSuccess(cpu, 0), // set* -> ok
            }
            return true;
        },
        .fork, .vfork => return sysFork(runner),
        .execve => return sysExec(runner),
        .wait => return sysWait(runner),
        .waitsys => return sysWaitsys(runner),
        .uname => return sysUname(runner),
        .pipe => return sysPipe(runner),
        .ioctl => return sysIoctl(runner),
        .fcntl => return sysFcntl(runner),
        .time => return sysTime(runner),
        .mmap => return sysMmap(runner),
        // munmap(addr, len): accept and succeed. We don't reclaim the address
        // range (mmap_next only grows downward), which is fine for the guest's
        // purposes — it just wants the unmap to succeed. mprotect likewise.
        .munmap => {
            // Flush a MAP_SHARED file mapping back to its file before dropping.
            _ = flushFileMap(runner, sysv.arg(cpu, 0), sysv.arg(cpu, 1));
            sysv.returnSuccess(cpu, 0);
            return true;
        },
        .mprotect => {
            sysv.returnSuccess(cpu, 0);
            return true;
        },
        // memcntl(addr,len,cmd,...): advisory memory control (sync, lock,
        // MC_ADVISE, cache flush). No-op that succeeds; the assembler calls it
        // (likely MC_SYNC / icache flush after emitting code to its buffer).
        .memcntl => {
            sysv.returnSuccess(cpu, 0);
            return true;
        },
        // syssec: SVR4/88 security (B1/ACL/privilege) subsystem. This userland
        // is not running the security extensions, so report "not present" —
        // programs (cat et al. probe it at startup) fall back to standard
        // UNIX permissions when it fails. ENOSYS-equivalent (ENOPKG=65 on SVR4;
        // use EINVAL which the low-range mapper passes through cleanly).
        .syssec => {
            sysv.returnError(cpu, EINVAL);
            return true;
        },
        // ulimit(cmd, newlimit): SVR4 resource limits.
        //   1 UL_GFILLIM get file-size limit (in 512-byte blocks)
        //   2 UL_SFILLIM set file-size limit
        //   3 UL_GMEMLIM get max break address (process data-size ceiling)
        //   4 UL_GDESLIM get max file descriptors
        // sort/other tools query these at startup to size buffers. Report
        // generous values consistent with our address space.
        .ulimit => {
            const cmd = sysv.arg(cpu, 0);
            switch (cmd) {
                1 => sysv.returnSuccess(cpu, 0x0020_0000), // ~1GB / 512 = large file limit in blocks
                2 => sysv.returnSuccess(cpu, sysv.arg(cpu, 1)), // accept the set, echo it
                3 => sysv.returnSuccess(cpu, 0x0800_0000), // max break: keep below the mmap region (0x08000000)
                4 => sysv.returnSuccess(cpu, fsmod.MAX_FD), // max fds
                else => sysv.returnError(cpu, EINVAL),
            }
            return true;
        },
        .getdents => return sysGetdents(runner),
        // Identity/permission syscalls: report plausible values so libc is happy.
        .getpid => {
            sysv.returnSuccess2(cpu, 1, 0); // pid=1, ppid=0
            return true;
        },
        .getuid => {
            sysv.returnSuccess2(cpu, 0, 0); // uid=0, euid=0 (root, matches guest)
            return true;
        },
        .getgid => {
            sysv.returnSuccess2(cpu, 0, 0);
            return true;
        },
        .umask => {
            const old = runner.umask;
            runner.umask = sysv.arg(cpu, 0) & 0o777;
            sysv.returnSuccess(cpu, old);
            return true;
        },
        else => {
            failFast(runner, num, sc);
            return false;
        },
    }
}

// -- errno values (SysV base) -----------------------------------------------
const EPERM: u32 = 1;
const ENOENT: u32 = 2;
const EBADF: u32 = 9;
const ENOMEM: u32 = 12;
const EFAULT: u32 = 14;
const ENOTTY: u32 = 25;
const EINVAL: u32 = 22;

/// Map a host errno to a SysV/88 errno. For the low SysV-compatible range the
/// numbers coincide; anything unknown becomes EINVAL for now. (A full table is
/// a later refinement.)
fn mapErrno(host: u32) u32 {
    return switch (host) {
        1 => EPERM,
        2 => ENOENT,
        9 => EBADF,
        12 => ENOMEM,
        14 => EFAULT,
        22 => EINVAL,
        25 => ENOTTY,
        else => if (host >= 1 and host <= 44) host else EINVAL,
    };
}

// -- handlers ----------------------------------------------------------------

fn sysWrite(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = sysv.arg(cpu, 0);
    const buf = sysv.arg(cpu, 1);
    const count = sysv.arg(cpu, 2);
    const hfd = hostFd(runner, gfd) orelse {
        sysv.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, buf) + count > mem.Memory.size) {
        sysv.returnError(cpu, EFAULT);
        return true;
    }
    const slice = runner.memory.bytes[buf .. buf + count];
    const n = write(hfd, slice.ptr, slice.len);
    if (n < 0) {
        sysv.returnError(cpu, mapErrno(hostErrno()));
    } else {
        sysv.returnSuccess(cpu, @intCast(n));
    }
    return true;
}

fn sysRead(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = sysv.arg(cpu, 0);
    const buf = sysv.arg(cpu, 1);
    const count = sysv.arg(cpu, 2);
    const hfd = hostFd(runner, gfd) orelse {
        sysv.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, buf) + count > mem.Memory.size) {
        sysv.returnError(cpu, EFAULT);
        return true;
    }
    const slice = runner.memory.bytes[buf .. buf + count];
    const n = read(hfd, slice.ptr, slice.len);
    if (n < 0) {
        sysv.returnError(cpu, mapErrno(hostErrno()));
    } else {
        sysv.returnSuccess(cpu, @intCast(n));
    }
    return true;
}

// SysV/88 O_* open flags (from the guest's fcntl.h): O_RDONLY=0, O_WRONLY=1,
// O_RDWR=2, O_CREAT=0x100, O_TRUNC=0x200, O_EXCL=0x400, O_APPEND=0x8. Host
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

fn readGuestPath(runner: *machine.Runner, ptr: u32, buf: []u8) ?[]const u8 {
    const s = runner.memory.readCStr(ptr, buf[0 .. buf.len - 1]);
    if (s.len >= buf.len - 1) return null;
    buf[s.len] = 0;
    return buf[0..s.len];
}

fn sysOpen(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const path_ptr = sysv.arg(cpu, 0);
    const flags = sysv.arg(cpu, 1);
    const mode = sysv.arg(cpu, 2);

    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        sysv.returnError(cpu, EINVAL);
        return true;
    };

    // Resolve through the guest mount table when an fs is configured; else pass
    // the path straight to the host (early-milestone behavior).
    var hbuf: [2048]u8 = undefined;
    var cpath: [*:0]const u8 = @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, &hbuf) catch {
            sysv.returnError(cpu, ENOENT);
            return true;
        };
        cpath = hp.ptr;
    }

    const hfd = open(cpath, translateOpenFlags(flags), @intCast(mode));
    if (hfd < 0) {
        sysv.returnError(cpu, mapErrno(hostErrno()));
        return true;
    }
    // Allocate a guest fd. With an fs, use its fd table (lowest-free); without,
    // return the host fd directly. If the target is a directory, also open a
    // dir stream so getdents can read it (the host forbids read(2) on dirs).
    if (fsOf(runner)) |fs| {
        // Canonicalize the guest path for dir-entry synthesis (getcwd walk).
        var canonbuf: [1024]u8 = undefined;
        const gcanon = fs.canonicalGuest(gpath, &canonbuf) orelse gpath;
        if (fs.openDir(cpath, gcanon, hfd)) |gdir| {
            sysv.returnSuccess(cpu, gdir);
            return true;
        }
        const gfd = fs.allocFd(hfd) orelse {
            _ = close(hfd);
            sysv.returnError(cpu, EBADF);
            return true;
        };
        sysv.returnSuccess(cpu, gfd);
    } else {
        sysv.returnSuccess(cpu, @intCast(hfd));
    }
    return true;
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

fn sysClose(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = sysv.arg(cpu, 0);
    if (fsOf(runner)) |fs| {
        if (fs.closeFd(gfd)) sysv.returnSuccess(cpu, 0) else sysv.returnError(cpu, EBADF);
        return true;
    }
    if (gfd <= 2) {
        sysv.returnSuccess(cpu, 0);
        return true;
    }
    const rc = close(@intCast(gfd));
    if (rc < 0) sysv.returnError(cpu, mapErrno(hostErrno())) else sysv.returnSuccess(cpu, 0);
    return true;
}

fn sysAccess(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const path_ptr = sysv.arg(cpu, 0);
    const amode = sysv.arg(cpu, 1);
    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        sysv.returnError(cpu, EINVAL);
        return true;
    };
    var hbuf: [2048]u8 = undefined;
    var cpath: [*:0]const u8 = @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, &hbuf) catch {
            sysv.returnError(cpu, ENOENT);
            return true;
        };
        cpath = hp.ptr;
    }
    // SysV/88 access(2) amode: F_OK=0, X_OK=1, W_OK=2, R_OK=4 (same low 3 bits
    // as Linux). SVR4 also defines EFF_ONLY_OK=8 (test effective ids) and
    // EX_OK=... higher bits that Linux's access() rejects with EINVAL. Mask to
    // the R/W/X bits Linux understands; the effective-vs-real distinction is
    // irrelevant here (we run as a single uid). Without this, the shell's PATH
    // search (access(cmd, X_OK|EFF_ONLY_OK) = amode 9) always fails EINVAL and
    // every external command "isn't found".
    const hmode: c_int = @intCast(amode & 0x7);
    const arc = fsmod.c.access(cpath, hmode);
    if (arc < 0) {
        sysv.returnError(cpu, mapErrno(hostErrno()));
    } else {
        sysv.returnSuccess(cpu, 0);
    }
    return true;
}

// Resolve a single guest path argument to a host path, writing errors on the
// standard failures. Returns the NUL-terminated host path pointer, or null if
// it already reported an error (caller returns true).
fn resolveArgPath(
    runner: *machine.Runner,
    arg_index: u2,
    gbuf: []u8,
    hbuf: []u8,
) ?[*:0]const u8 {
    const cpu = &runner.cpu;
    const path_ptr = sysv.arg(cpu, arg_index);
    const gpath = readGuestPath(runner, path_ptr, gbuf) orelse {
        sysv.returnError(cpu, EINVAL);
        return null;
    };
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, hbuf) catch {
            sysv.returnError(cpu, ENOENT);
            return null;
        };
        return hp.ptr;
    }
    return @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
}

fn sysUnlink(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    var gbuf: [1024]u8 = undefined;
    var hbuf: [2048]u8 = undefined;
    const cpath = resolveArgPath(runner, 0, &gbuf, &hbuf) orelse return true;
    if (fsmod.c.unlink(cpath) < 0) {
        sysv.returnError(cpu, mapErrno(hostErrno()));
    } else {
        sysv.returnSuccess(cpu, 0);
    }
    return true;
}

fn sysRename(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    // Two path args; resolve both. Use separate buffers so they don't alias.
    var gbuf1: [1024]u8 = undefined;
    var hbuf1: [2048]u8 = undefined;
    var gbuf2: [1024]u8 = undefined;
    var hbuf2: [2048]u8 = undefined;
    const oldp = resolveArgPath(runner, 0, &gbuf1, &hbuf1) orelse return true;
    const newp = resolveArgPath(runner, 1, &gbuf2, &hbuf2) orelse return true;
    if (fsmod.c.rename(oldp, newp) < 0) {
        sysv.returnError(cpu, mapErrno(hostErrno()));
    } else {
        sysv.returnSuccess(cpu, 0);
    }
    return true;
}

fn sysMkdir(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const mode = sysv.arg(cpu, 1);
    var gbuf: [1024]u8 = undefined;
    var hbuf: [2048]u8 = undefined;
    const cpath = resolveArgPath(runner, 0, &gbuf, &hbuf) orelse return true;
    if (fsmod.c.mkdir(cpath, @intCast(mode & 0o7777)) < 0) {
        sysv.returnError(cpu, mapErrno(hostErrno()));
    } else {
        sysv.returnSuccess(cpu, 0);
    }
    return true;
}

fn sysRmdir(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    var gbuf: [1024]u8 = undefined;
    var hbuf: [2048]u8 = undefined;
    const cpath = resolveArgPath(runner, 0, &gbuf, &hbuf) orelse return true;
    if (fsmod.c.rmdir(cpath) < 0) {
        sysv.returnError(cpu, mapErrno(hostErrno()));
    } else {
        sysv.returnSuccess(cpu, 0);
    }
    return true;
}

// creat(path, mode) == open(path, O_WRONLY|O_CREAT|O_TRUNC, mode). Route
// through the same open path so fd-table allocation and flag translation are
// shared.
fn sysCreat(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    // Rewrite args to the open() convention: r3 = flags, r4 = mode(existing).
    // creat's mode is arg1; shift it to arg2 and set flags in arg1.
    const mode = sysv.arg(cpu, 1);
    sysv.setArg(cpu, 1, 0x301); // O_WRONLY|O_CREAT|O_TRUNC (guest values)
    sysv.setArg(cpu, 2, mode);
    return sysOpen(runner);
}

// chmod(path, mode): ld/install set the mode of their output. Resolve the
// guest path through the mount table and apply on the host. Read-only mounts
// will return an error from the host, which we map through.
fn sysChmod(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const path_ptr = sysv.arg(cpu, 0);
    const mode = sysv.arg(cpu, 1);
    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        sysv.returnError(cpu, EINVAL);
        return true;
    };
    var cpath: [*:0]const u8 = @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
    var hbuf: [2048]u8 = undefined;
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, &hbuf) catch {
            sysv.returnError(cpu, ENOENT);
            return true;
        };
        cpath = hp.ptr;
    }
    if (chmod(cpath, @intCast(mode & 0o7777)) < 0) {
        sysv.returnError(cpu, mapErrno(hostErrno()));
        return true;
    }
    sysv.returnSuccess(cpu, 0);
    return true;
}

fn sysFchmod(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = sysv.arg(cpu, 0);
    const mode = sysv.arg(cpu, 1);
    const hfd = hostFd(runner, gfd) orelse {
        sysv.returnError(cpu, EBADF);
        return true;
    };
    if (fchmod(hfd, @intCast(mode & 0o7777)) < 0) {
        sysv.returnError(cpu, mapErrno(hostErrno()));
        return true;
    }
    sysv.returnSuccess(cpu, 0);
    return true;
}

fn sysChdir(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const path_ptr = sysv.arg(cpu, 0);
    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        sysv.returnError(cpu, EINVAL);
        return true;
    };
    if (fsOf(runner)) |fs| {
        // Verify the target exists (resolve + access) before committing cwd.
        var hbuf: [2048]u8 = undefined;
        const hp = fs.resolve(gpath, &hbuf) catch {
            sysv.returnError(cpu, ENOENT);
            return true;
        };
        if (fsmod.c.access(hp, 0) < 0) {
            sysv.returnError(cpu, ENOENT);
            return true;
        }
        fs.chdir(gpath) catch {
            sysv.returnError(cpu, EINVAL);
            return true;
        };
    }
    sysv.returnSuccess(cpu, 0);
    return true;
}

fn sysLseek(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = sysv.arg(cpu, 0);
    const off = sysv.arg(cpu, 1);
    const whence = sysv.arg(cpu, 2);
    const fd = hostFd(runner, gfd) orelse {
        sysv.returnError(cpu, EBADF);
        return true;
    };
    const pos = lseek(fd, @as(c_long, @intCast(@as(i32, @bitCast(off)))), @intCast(whence));
    if (pos < 0) sysv.returnError(cpu, mapErrno(hostErrno())) else sysv.returnSuccess(cpu, @intCast(pos & 0xffff_ffff));
    return true;
}

/// SysV `brk`: the argument is the absolute new break address. Grow/shrink the
/// heap region and return 0 on success (matching the kernel; libc's sbrk
/// wrapper tracks the old break in userland).
fn sysBrk(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const newbrk = sysv.arg(cpu, 0);

    if (newbrk >= 0x0B00_0000) {
        sysv.returnError(cpu, ENOMEM);
        return true;
    }
    // A break below the heap base is a no-op success (some sbrk wrappers probe
    // with a small value to read the current break); don't fail malloc.
    if (newbrk < runner.brk_base) {
        sysv.returnSuccess(cpu, 0);
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
    sysv.returnSuccess(cpu, 0);
    return true;
}

// SysV/88 old `struct stat` (from /usr/include/sys/stat.h, the non-_STYPES
// variant used by the plain stat/fstat syscalls, big-endian):
//   o_dev_t  st_dev   (short,  2) @0
//   o_ino_t  st_ino   (ushort, 2) @2
//   o_mode_t st_mode  (ushort, 2) @4
//   o_nlink_t st_nlink(short,  2) @6
//   o_uid_t  st_uid   (ushort, 2) @8
//   o_gid_t  st_gid   (ushort, 2) @10
//   o_dev_t  st_rdev  (short,  2) @12
//   off_t    st_size  (long,   4) @16  (4-byte aligned; 2 bytes pad @14)
//   time_t   st_atime (long,   4) @20
//   time_t   st_mtime (long,   4) @24
//   time_t   st_ctime (long,   4) @28
// total size 32.
const STAT_SIZE: u32 = 32;

// SysV/88 R4.0 NEW `struct stat` (user-level 4.0, maps to kernel xstat), used
// by the versioned calls lstat(88)/xstat(123)/lxstat(124)/fxstat(125). All
// leading fields are 32-bit, 4-byte aligned:
//   st_dev@0 st_ino@4 st_mode@8 st_nlink@12 st_uid@16 st_gid@20 st_rdev@24
//   st_size@28 st_atime@32 st_ausec@36 st_mtime@40 st_musec@44 st_ctime@48
//   st_cusec@52 st_atim@56(8) st_mtim@64(8) st_ctim@72(8) st_blksize@80
//   st_blocks@84 st_fstype[16]@88 st_pading[408]@104 => total 512.
const STAT_NEW_SIZE: u32 = 512;

fn writeGuestStatNew(memory: *mem.Memory, addr: u32, hs: *const HostStat) void {
    memory.zero(addr, STAT_NEW_SIZE);
    memory.write32(addr + 0, hs.dev);
    memory.write32(addr + 4, hs.ino);
    memory.write32(addr + 8, hs.mode); // full 32-bit mode (S_IF* bits match host)
    memory.write32(addr + 12, hs.nlink);
    memory.write32(addr + 16, hs.uid);
    memory.write32(addr + 20, hs.gid);
    memory.write32(addr + 24, hs.rdev);
    memory.write32(addr + 28, @truncate(hs.size));
    memory.write32(addr + 32, @bitCast(@as(i32, @truncate(hs.atime))));
    memory.write32(addr + 40, @bitCast(@as(i32, @truncate(hs.mtime))));
    memory.write32(addr + 48, @bitCast(@as(i32, @truncate(hs.ctime))));
    memory.write32(addr + 56, @bitCast(@as(i32, @truncate(hs.atime)))); // st_atim.tv_sec
    memory.write32(addr + 64, @bitCast(@as(i32, @truncate(hs.mtime)))); // st_mtim.tv_sec
    memory.write32(addr + 72, @bitCast(@as(i32, @truncate(hs.ctime)))); // st_ctim.tv_sec
    memory.write32(addr + 80, 4096); // st_blksize
    memory.write32(addr + 84, @intCast((hs.size + 511) / 512)); // st_blocks
}

fn writeGuestStat(memory: *mem.Memory, addr: u32, hs: *const HostStat) void {
    // Guest S_IF* file-type bits (S_IFCHR=0x2000, S_IFREG=0x8000, ...) match
    // the host's standard values, so the file-type field of st_mode carries
    // straight over. Keep the low 12 permission bits too.
    const mode16: u16 = @truncate(hs.mode & 0xffff);

    memory.write16(addr + 0, @truncate(hs.dev));
    memory.write16(addr + 2, @truncate(hs.ino));
    memory.write16(addr + 4, mode16);
    memory.write16(addr + 6, @truncate(hs.nlink));
    memory.write16(addr + 8, @truncate(hs.uid));
    memory.write16(addr + 10, @truncate(hs.gid));
    memory.write16(addr + 12, @truncate(hs.rdev));
    // 2 bytes pad @14
    memory.write32(addr + 16, @truncate(hs.size));
    memory.write32(addr + 20, @bitCast(@as(i32, @truncate(hs.atime))));
    memory.write32(addr + 24, @bitCast(@as(i32, @truncate(hs.mtime))));
    memory.write32(addr + 28, @bitCast(@as(i32, @truncate(hs.ctime))));
}

fn sysFstat(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = sysv.arg(cpu, 0);
    const statbuf = sysv.arg(cpu, 1);
    const fd = hostFd(runner, gfd) orelse {
        sysv.returnError(cpu, EBADF);
        return true;
    };
    if (@as(u64, statbuf) + STAT_NEW_SIZE > mem.Memory.size) {
        sysv.returnError(cpu, EFAULT);
        return true;
    }
    var hs: HostStat = undefined;
    r88k_fstat(fd, &hs);
    if (hs.ok == 0) {
        sysv.returnError(cpu, mapErrno(@intCast(hs.err)));
        return true;
    }
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    // fstat(28) on this R4.0 userland uses the NEW (xstat-style) struct, same
    // as lstat(88); the old 32-byte struct is only for the pre-4.0 stat form.
    writeGuestStatNew(runner.memory, statbuf, &hs);
    runner.memory.enforce = was;
    sysv.returnSuccess(cpu, 0);
    return true;
}

// On this R4.0 userland stat(18)/fstat(28)/lstat(88) all use the NEW
// (xstat-style) struct. stat follows symlinks, lstat does not.
fn sysStat(runner: *machine.Runner) bool {
    return sysStatImpl(runner, false, true);
}
fn sysLstat(runner: *machine.Runner) bool {
    return sysStatImpl(runner, true, true);
}

fn sysStatImpl(runner: *machine.Runner, is_lstat: bool, new_layout: bool) bool {
    const cpu = &runner.cpu;
    const path_ptr = sysv.arg(cpu, 0);
    const statbuf = sysv.arg(cpu, 1);
    var gbuf: [1024]u8 = undefined;
    const gpath = readGuestPath(runner, path_ptr, &gbuf) orelse {
        sysv.returnError(cpu, EINVAL);
        return true;
    };
    const need: u32 = if (new_layout) STAT_NEW_SIZE else STAT_SIZE;
    if (@as(u64, statbuf) + need > mem.Memory.size) {
        sysv.returnError(cpu, EFAULT);
        return true;
    }
    var hbuf: [2048]u8 = undefined;
    var cpath: [*:0]const u8 = @ptrCast(gbuf[0 .. gpath.len + 1].ptr);
    if (fsOf(runner)) |fs| {
        const hp = fs.resolve(gpath, &hbuf) catch {
            sysv.returnError(cpu, ENOENT);
            return true;
        };
        cpath = hp.ptr;
    }
    var hs: HostStat = undefined;
    if (is_lstat) r88k_lstat(cpath, &hs) else r88k_stat(cpath, &hs);
    if (hs.ok == 0) {
        sysv.returnError(cpu, mapErrno(@intCast(hs.err)));
        return true;
    }
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    if (new_layout) writeGuestStatNew(runner.memory, statbuf, &hs) else writeGuestStat(runner.memory, statbuf, &hs);
    runner.memory.enforce = was;
    sysv.returnSuccess(cpu, 0);
    return true;
}

extern "c" fn fcntl(fd: c_int, cmd: c_int, arg: c_int) c_int;
extern "c" fn dup(fd: c_int) c_int;
extern "c" fn chmod(path: [*:0]const u8, mode: c_uint) c_int;
extern "c" fn fchmod(fd: c_int, mode: c_uint) c_int;
extern "c" fn time(t: ?*c_long) c_long;

fn sysTime(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const t: u32 = @intCast(@as(i64, time(null)) & 0xffff_ffff);
    // SysV time(2): optionally stores the result at the pointer in the first
    // arg, and also returns it.
    const tptr = sysv.arg(cpu, 0);
    if (tptr != 0 and @as(u64, tptr) + 4 <= mem.Memory.size) {
        const was = runner.memory.enforce;
        runner.memory.enforce = false;
        runner.memory.write32(tptr, t);
        runner.memory.enforce = was;
    }
    sysv.returnSuccess(cpu, t);
    return true;
}

/// mmap: only anonymous, fixed-nothing allocations are supported (what libc
/// malloc uses). Hand out zeroed, RW guest memory from a downward bump region.
/// File-backed mmap is not yet supported.
extern "c" fn isatty(fd: c_int) c_int;

// SysV/88 terminal ioctls (from the guest's termio.h).
const TCGETA: u32 = 0x5401;
const TCSETA: u32 = 0x5402;
const TCSETAW: u32 = 0x5403;
const TCSETAF: u32 = 0x5404;

// SVR4 `struct termio`: unsigned short c_iflag,c_oflag,c_cflag,c_lflag;
// char c_line; unsigned char c_cc[8];  (== 18 bytes, we zero-fill and set a
// sane default so stdio's isatty()/line-buffering decision succeeds.)
const TERMIO_LEN: u32 = 18;

fn sysIoctl(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = sysv.arg(cpu, 0);
    const req = sysv.arg(cpu, 1);
    const argp = sysv.arg(cpu, 2);

    // Only terminal-control ioctls matter here. stdio issues TCGETA at startup
    // to decide stdout buffering: success -> the fd is a tty -> line-buffered
    // (each newline is written immediately); failure (ENOTTY) -> fully
    // buffered. Tools like size/nm print with printf and rely on the program
    // exit flushing; when they call _exit without flushing, only line-buffering
    // makes their output appear. Mirror the host: report tty-ness via isatty on
    // the mapped host fd, and hand back a plausible termio for TCGET.
    switch (req) {
        TCGETA => {
            const hfd = hostFd(runner, gfd) orelse {
                sysv.returnError(cpu, EBADF);
                return true;
            };
            if (isatty(hfd) != 1) {
                sysv.returnError(cpu, ENOTTY);
                return true;
            }
            if (argp != 0 and @as(u64, argp) + TERMIO_LEN <= mem.Memory.size) {
                const was = runner.memory.enforce;
                runner.memory.enforce = false;
                runner.memory.zero(argp, TERMIO_LEN);
                // c_iflag=BRKINT|ICRNL|IXON (0x2|0x100|0x400=0x502),
                // c_oflag=OPOST|ONLCR (0x1|0x4=0x5), c_cflag=B9600|CS8|CREAD (0xbd),
                // c_lflag=ISIG|ICANON|ECHO (0x1|0x2|0x8=0xb). Values are nominal;
                // only the successful return matters for buffering.
                runner.memory.write16(argp + 0, 0x0502);
                runner.memory.write16(argp + 2, 0x0005);
                runner.memory.write16(argp + 4, 0x00bd);
                runner.memory.write16(argp + 6, 0x000b);
                runner.memory.enforce = was;
            }
            sysv.returnSuccess(cpu, 0);
            return true;
        },
        TCSETA, TCSETAW, TCSETAF => {
            // Accept terminal-attribute sets on a tty; ignore the settings.
            const hfd = hostFd(runner, gfd) orelse {
                sysv.returnError(cpu, EBADF);
                return true;
            };
            if (isatty(hfd) != 1) {
                sysv.returnError(cpu, ENOTTY);
                return true;
            }
            sysv.returnSuccess(cpu, 0);
            return true;
        },
        else => {
            // Unknown ioctl: report not-a-tty, which is the benign answer most
            // callers expect for a plain file/device.
            sysv.returnError(cpu, ENOTTY);
            return true;
        },
    }
}

fn sysMmap(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    // SysV mmap(addr, len, prot, flags, fd, off) — args r2..r7.
    const len = sysv.arg(cpu, 1);
    const gfd = sysv.arg(cpu, 4);
    const off = sysv.arg(cpu, 5);
    const MAP_ANON: u32 = 0x100; // guest flag
    const flags = sysv.arg(cpu, 3);

    // File-backed mmap: libelf (used by size/nm/dump/mcs) maps the object file
    // MAP_PRIVATE and reads the ELF header straight from the mapping. Emulate a
    // private file map by allocating a region and reading the file's bytes into
    // it (copy-on-write semantics are fine for a read-only ELF map). If we
    // rejected this, libelf falls back to a malloc+read path that leaves the
    // cached Ehdr (handle+0x6c) unpopulated, so elf_getehdr fails and the tool
    // prints nothing.
    const file_backed = gfd != 0xffffffff and (flags & MAP_ANON) == 0;
    var hfd: c_int = -1;
    if (file_backed) {
        hfd = hostFd(runner, gfd) orelse {
            sysv.returnError(cpu, EBADF);
            return true;
        };
    }

    const size = std.mem.alignForward(u32, if (len == 0) 1 else len, 0x1000);
    if (runner.mmap_next < runner.brk + 0x10000 or runner.mmap_next -% size < runner.brk) {
        sysv.returnError(cpu, ENOMEM);
        return true;
    }
    const base = runner.mmap_next -% size;
    runner.mmap_next = base;
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    runner.memory.zero(base, size);
    runner.memory.addRegion(base, size, .{ .read = true, .write = true }) catch {};
    if (file_backed) {
        // Read exactly the requested length from the file offset into the map.
        var done: u32 = 0;
        while (done < len) {
            const dst = runner.memory.bytes[base + done .. base + len];
            const n = pread(hfd, dst.ptr, dst.len, @intCast(off + done));
            if (n <= 0) break; // EOF or error: leave the rest zero-filled
            done += @intCast(n);
        }
        const MAP_SHARED: u32 = 0x1;
        if ((flags & MAP_SHARED) != 0) {
            // Track for write-back on munmap. dup the fd so a later guest
            // close() doesn't strand the mapping. Silently skip tracking if
            // the table is full or dup fails (mapping still readable).
            const dupfd = dup(hfd);
            if (dupfd >= 0) {
                var slot: ?*machine.FileMap = null;
                for (&runner.file_maps) |*m| {
                    if (m.host_fd < 0) {
                        slot = m;
                        break;
                    }
                }
                if (slot) |m| {
                    m.* = .{ .base = base, .len = len, .file_off = off, .host_fd = dupfd, .shared = true };
                } else {
                    _ = close(dupfd);
                }
            }
        }
    }
    runner.memory.enforce = was;
    sysv.returnSuccess(cpu, base);
    return true;
}

extern "c" fn pwrite(fd: c_int, buf: [*]const u8, count: usize, off: c_long) isize;

/// Flush and drop any tracked file-backed MAP_SHARED region overlapping
/// [addr, addr+len). Returns true if a mapping was found and released.
fn flushFileMap(runner: *machine.Runner, addr: u32, len: u32) bool {
    var found = false;
    for (&runner.file_maps) |*m| {
        if (m.host_fd < 0 or !m.shared) continue;
        // Match if the munmap range intersects the mapping.
        const m_end = m.base +% m.len;
        const u_end = addr +% len;
        if (addr >= m_end or u_end <= m.base) continue;
        // Write the whole mapped region back to the file at its offset.
        const was = runner.memory.enforce;
        runner.memory.enforce = false;
        var done: u32 = 0;
        while (done < m.len) {
            const src = runner.memory.bytes[m.base + done .. m.base + m.len];
            const n = pwrite(m.host_fd, src.ptr, src.len, @intCast(m.file_off + done));
            if (n <= 0) break;
            done += @intCast(n);
        }
        runner.memory.enforce = was;
        _ = close(m.host_fd);
        m.* = .{};
        found = true;
    }
    return found;
}

// Directory-read shim (src/host_dir.c): opendir/readdir/closedir keyed by a
// small handle table, since modern hosts forbid read(2) on directories.
extern fn r88k_diropen(path: [*:0]const u8) c_int;
extern fn r88k_dirread(handle: c_int, ino_out: *c_ulong, name_out: [*]u8) c_int;
extern fn r88k_dirclose(handle: c_int) void;

/// getdents(fd, buf, nbyte): fill buf with SVR4 `struct dirent`:
///   ino_t d_ino (4) ; off_t d_off (4) ; unsigned short d_reclen (2) ;
///   char d_name[] (NUL-terminated, then pad to align d_reclen to 4).
/// Returns bytes written, or 0 at end of directory. Directories are opened
/// lazily here by resolving the fd's guest path — but we don't track the path,
/// so instead we open the directory stream when the guest fd was opened on a
/// directory. For simplicity we (re)open by the host fd's path via /proc is not
/// portable; instead we key a dir stream to the guest fd on first getdents by
/// using the host fd with fdopendir-like behavior in the shim.
fn sysGetdents(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = sysv.arg(cpu, 0);
    const buf = sysv.arg(cpu, 1);
    const nbyte = sysv.arg(cpu, 2);
    const fs = fsOf(runner) orelse {
        sysv.returnError(cpu, EBADF);
        return true;
    };
    const handle = fs.dirHandleFor(gfd) orelse {
        sysv.returnError(cpu, EBADF); // not a directory (or unopened)
        return true;
    };
    if (@as(u64, buf) + nbyte > mem.Memory.size) {
        sysv.returnError(cpu, EFAULT);
        return true;
    }
    var written: u32 = 0;
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    defer runner.memory.enforce = was;

    // Emit one SVR4 dirent {d_ino, d_off, d_reclen, d_name}. Returns false if
    // the record does not fit in the remaining buffer (nothing written).
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

    var real_done = false;
    while (true) {
        var ino: c_ulong = 0;
        var namebuf: [256]u8 = undefined;
        const rc = r88k_dirread(handle, &ino, &namebuf);
        if (rc <= 0) {
            real_done = true;
            break; // end of directory
        }
        const name = std.mem.sliceTo(&namebuf, 0);
        if (!emit(runner, buf, &written, nbyte, @intCast(ino & 0xffffffff), name)) {
            fs.dirPushback(handle); // didn't fit; re-emit next call
            break;
        }
    }

    // Once the real stream is exhausted, append synthetic entries for any
    // mount points that live directly under this directory but are not real
    // children on the host (e.g. a writable /work overlay on a separate host
    // fs). Their d_ino is the backing dir's host inode, which matches what
    // lstat() of the mount point returns — this is what a userland getcwd()
    // relies on to climb across the mount boundary.
    if (real_done) {
        if (fs.dirGuestPath(gfd)) |dirpath| {
            while (fs.mountChild(dirpath, fs.dirSynthNext(gfd))) |child| {
                // Skip a mount whose name already appeared as a real host entry
                // is not needed here: overlays like /work have no real parent
                // entry. Compute d_ino from the backing dir's host inode.
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
    sysv.returnSuccess(cpu, written);
    return true;
}

fn sysDup(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = sysv.arg(cpu, 0);
    const fd = hostFd(runner, gfd) orelse {
        sysv.returnError(cpu, EBADF);
        return true;
    };
    const hnew = dup(fd);
    if (hnew < 0) {
        sysv.returnError(cpu, mapErrno(hostErrno()));
        return true;
    }
    if (fsOf(runner)) |fs| {
        const gnew = fs.allocFd(hnew) orelse {
            _ = close(hnew);
            sysv.returnError(cpu, EBADF);
            return true;
        };
        sysv.returnSuccess(cpu, gnew);
    } else {
        sysv.returnSuccess(cpu, @intCast(hnew));
    }
    return true;
}

/// fcntl. SysV cmds: F_DUPFD=0, F_GETFD=1, F_SETFD=2, F_GETFL=3, F_SETFL=4.
/// Pass DUPFD/GETFD/SETFD through to the host; treat the flag queries benignly.
fn sysFcntl(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const gfd = sysv.arg(cpu, 0);
    const cmd = sysv.arg(cpu, 1);
    const arg3 = sysv.arg(cpu, 2);
    const fd = hostFd(runner, gfd) orelse {
        sysv.returnError(cpu, EBADF);
        return true;
    };
    switch (cmd) {
        0 => { // F_DUPFD: dup `fd` into the lowest free guest fd >= arg3.
            // Shells build their stdio redirections with this (close(1);
            // fcntl(pipe_wr, F_DUPFD, 1) makes guest fd 1 the pipe). The result
            // must be a GUEST fd mapping to the same host file, not a raw host
            // fd, or the guest's fd bookkeeping breaks after fork/exec.
            const hnew = dup(fd);
            if (hnew < 0) {
                sysv.returnError(cpu, mapErrno(hostErrno()));
                return true;
            }
            if (fsOf(runner)) |fs| {
                const gnew = fs.allocFdFrom(hnew, arg3) orelse {
                    _ = close(hnew);
                    sysv.returnError(cpu, EBADF);
                    return true;
                };
                sysv.returnSuccess(cpu, gnew);
            } else {
                sysv.returnSuccess(cpu, @intCast(hnew));
            }
        },
        1, 2 => { // F_GETFD / F_SETFD: pass through to the host fd.
            const rc = fcntl(fd, @intCast(cmd), @intCast(arg3));
            if (rc < 0) sysv.returnError(cpu, mapErrno(hostErrno())) else sysv.returnSuccess(cpu, @intCast(rc));
        },
        3 => sysv.returnSuccess(cpu, 0), // F_GETFL: report no special flags
        4 => sysv.returnSuccess(cpu, 0), // F_SETFL: accept
        else => sysv.returnSuccess(cpu, 0),
    }
    return true;
}

extern "c" fn getpid() c_int;

/// fork/vfork. SVR4 dual-return: parent gets r2=child_pid, r3=0; child gets
/// r2=parent_pid, r3=1 (libc's fork stub uses r3 to zero r2 in the child).
fn sysFork(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        sysv.returnError(cpu, EINVAL);
        return true;
    };
    const parent_pid: u32 = @intCast(getpid());
    const rc = pm.doFork() catch {
        sysv.returnError(cpu, ENOMEM);
        return true;
    };
    if (rc == 0) {
        // Child: r2 = parent pid, r3 = 1.
        sysv.returnSuccess2(cpu, parent_pid, 1);
    } else {
        // Parent: r2 = child pid, r3 = 0.
        sysv.returnSuccess2(cpu, rc, 0);
    }
    return true;
}

fn sysExec(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        sysv.returnError(cpu, EINVAL);
        return true;
    };
    const path_ptr = sysv.arg(cpu, 0);
    const argv_ptr = sysv.arg(cpu, 1);
    const envp_ptr = sysv.arg(cpu, 2);

    var pbuf: [1024]u8 = undefined;
    const path = readGuestPath(runner, path_ptr, &pbuf) orelse {
        sysv.returnError(cpu, EINVAL);
        return true;
    };

    // Marshal argv/envp from guest memory into host slices (bounded).
    var argv_store: [128][]const u8 = undefined;
    var envp_store: [256][]const u8 = undefined;
    var argv_bufs: [128][256]u8 = undefined;
    var envp_bufs: [256][256]u8 = undefined;
    const argc = readStrVec(runner, argv_ptr, &argv_store, &argv_bufs);
    const envc = readStrVec(runner, envp_ptr, &envp_store, &envp_bufs);

    pm.doExec(path, argv_store[0..argc], envp_store[0..envc]) catch {
        sysv.returnError(cpu, ENOENT);
        return true;
    };
    // Success: doExec set PC to the new entry via process.setup; do NOT touch
    // PC or carry. Clear any stale fault from the reload and continue.
    runner.memory.clearFault();
    runner.exec_pending = true;
    return true;
}

/// Read a NULL-terminated guest pointer vector (argv/envp) into host slices,
/// copying each string into the provided per-entry buffers. Returns the count.
fn readStrVec(
    runner: *machine.Runner,
    vec_ptr: u32,
    out: [][]const u8,
    bufs: anytype,
) usize {
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

fn sysWait(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        sysv.returnError(cpu, EINVAL);
        return true;
    };
    const statptr = sysv.arg(cpu, 0);
    const res = pm.doWait() catch {
        sysv.returnError(cpu, ECHILD);
        return true;
    };
    // SysV wait: pid in r2, status word in r3. If a status pointer was given,
    // also store the status there.
    if (statptr != 0 and @as(u64, statptr) + 4 <= mem.Memory.size) {
        const was = runner.memory.enforce;
        runner.memory.enforce = false;
        runner.memory.write32(statptr, res.status);
        runner.memory.enforce = was;
    }
    sysv.returnSuccess2(cpu, res.pid, res.status);
    return true;
}

// SVR4 waitsys(idtype, id, siginfo*, options) — syscall 107, the kernel
// primitive under libc's waitpid/wait. Reaps a child and fills a siginfo_t.
// The libc wrapper (recovered: FUN_000307c0) reads these siginfo fields:
//   +8  si_code   int   1 = CLD_EXITED (normal exit)
//   +12 si_pid    int   child pid
//   +23 si_status byte  exit code (wrapper does status<<8 when si_code==1)
// Returns 0 on success (the pid comes back via siginfo, not r2).
const SIGINFO_CODE_OFF: u32 = 8;
const SIGINFO_PID_OFF: u32 = 12;
const SIGINFO_STATUS_OFF: u32 = 23;
const CLD_EXITED: u32 = 1;

fn sysWaitsys(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        sysv.returnError(cpu, ECHILD);
        return true;
    };
    const infop = sysv.arg(cpu, 2); // siginfo_t* buffer
    const res = pm.doWait() catch {
        sysv.returnError(cpu, ECHILD);
        return true;
    };
    // doWait packs the exit code as (code & 0xff) << 8; recover the raw code.
    const exit_code: u32 = (res.status >> 8) & 0xff;
    if (infop != 0 and @as(u64, infop) + 32 <= mem.Memory.size) {
        const was = runner.memory.enforce;
        runner.memory.enforce = false;
        // Zero the leading fields (si_signo/si_errno) then set code/pid/status.
        runner.memory.write32(infop, 18); // si_signo = SIGCLD (18 on SysV/88)
        runner.memory.write32(infop + 4, 0); // si_errno
        runner.memory.write32(infop + SIGINFO_CODE_OFF, CLD_EXITED);
        runner.memory.write32(infop + SIGINFO_PID_OFF, res.pid);
        runner.memory.write8(infop + SIGINFO_STATUS_OFF, @intCast(exit_code & 0xff));
        runner.memory.enforce = was;
    }
    sysv.returnSuccess(cpu, 0);
    return true;
}

// uname(2) — syscall 135. Fills a SVR4 `struct utsname`: five NUL-terminated
// fields, each SYS_NMLN (257) bytes: sysname, nodename, release, version,
// machine. Returns 0 (non-negative) on success.
const SYS_NMLN: u32 = 257;

fn sysUname(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const buf = sysv.arg(cpu, 0);
    const total = SYS_NMLN * 5;
    if (buf == 0 or @as(u64, buf) + total > mem.Memory.size) {
        sysv.returnError(cpu, EFAULT);
        return true;
    }
    const fields = [_][]const u8{
        "UNIX_SV", // sysname
        "run88k", // nodename
        "4.0", // release
        "3.0", // version
        "m88k", // machine
    };
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    runner.memory.zero(buf, total);
    for (fields, 0..) |f, i| {
        const base = buf + @as(u32, @intCast(i)) * SYS_NMLN;
        runner.memory.writeBytes(base, f);
        runner.memory.write8(base + @as(u32, @intCast(f.len)), 0);
    }
    runner.memory.enforce = was;
    // SysV/88 uname(2) returns a NON-NEGATIVE value on success — specifically a
    // positive value (1), not 0. libelf's mmap-availability probe treats a
    // 0/negative return as "no mmap" and falls back to a malloc+read path that
    // then fails to parse the ELF header (size/nm then print nothing). Return 1.
    sysv.returnSuccess(cpu, 1);
    return true;
}

fn sysPipe(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const pm = pmOf(runner) orelse {
        sysv.returnError(cpu, EINVAL);
        return true;
    };
    const fds = pm.doPipe() catch {
        sysv.returnError(cpu, ENOMEM);
        return true;
    };
    // SysV pipe: read fd in r2, write fd in r3.
    sysv.returnSuccess2(cpu, fds[0], fds[1]);
    return true;
}

const ECHILD: u32 = 10;

fn failFast(runner: *machine.Runner, num: u32, sc: Syscall) void {
    runner.aborted = true;
    var buf: [160]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buf,
        "run88k: UNIMPLEMENTED syscall {d} ({s}) at ppc={x} r2={x} r3={x} r4={x}\n",
        .{ num, @tagName(sc), runner.cpu.ppc, runner.cpu.getReg(2), runner.cpu.getReg(3), runner.cpu.getReg(4) },
    ) catch "run88k: unimplemented syscall (fmt err)\n";
    traceOut(line);
}
