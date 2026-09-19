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

const Cpu = m88k.Cpu;
const Syscall = table.Syscall;

// Host libc for the file operations (stable, portable).
extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern "c" fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern "c" fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn lseek(fd: c_int, off: c_long, whence: c_int) c_long;
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
        // ioctl on a tty is common at startup; report "not a tty" so libc
        // treats stdout as a plain file (fine for echo redirection).
        .ioctl => {
            sysv.returnError(cpu, ENOTTY);
            return true;
        },
        .fcntl => return sysFcntl(runner),
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
    const fd = sysv.arg(cpu, 0);
    const buf = sysv.arg(cpu, 1);
    const count = sysv.arg(cpu, 2);

    // Bounds-check the guest buffer, then write from the backing store.
    if (@as(u64, buf) + count > mem.Memory.size) {
        sysv.returnError(cpu, EFAULT);
        return true;
    }
    const slice = runner.memory.bytes[buf .. buf + count];
    const n = write(@intCast(fd), slice.ptr, slice.len);
    if (n < 0) {
        sysv.returnError(cpu, mapErrno(hostErrno()));
    } else {
        sysv.returnSuccess(cpu, @intCast(n));
    }
    return true;
}

fn sysRead(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const fd = sysv.arg(cpu, 0);
    const buf = sysv.arg(cpu, 1);
    const count = sysv.arg(cpu, 2);

    if (@as(u64, buf) + count > mem.Memory.size) {
        sysv.returnError(cpu, EFAULT);
        return true;
    }
    const slice = runner.memory.bytes[buf .. buf + count];
    const n = read(@intCast(fd), slice.ptr, slice.len);
    if (n < 0) {
        sysv.returnError(cpu, mapErrno(hostErrno()));
    } else {
        sysv.returnSuccess(cpu, @intCast(n));
    }
    return true;
}

fn sysOpen(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const path_ptr = sysv.arg(cpu, 0);
    const flags = sysv.arg(cpu, 1);
    const mode = sysv.arg(cpu, 2);

    var buf: [1024]u8 = undefined;
    const path = runner.memory.readCStr(path_ptr, &buf);
    if (path.len >= buf.len) {
        sysv.returnError(cpu, EINVAL);
        return true;
    }
    buf[path.len] = 0;
    const cpath: [*:0]const u8 = @ptrCast(&buf);
    const fd = open(cpath, @intCast(flags), @intCast(mode));
    if (fd < 0) {
        sysv.returnError(cpu, mapErrno(hostErrno()));
    } else {
        sysv.returnSuccess(cpu, @intCast(fd));
    }
    return true;
}

fn sysClose(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const fd = sysv.arg(cpu, 0);
    // Don't let the guest close our host stdio.
    if (fd <= 2) {
        sysv.returnSuccess(cpu, 0);
        return true;
    }
    const rc = close(@intCast(fd));
    if (rc < 0) sysv.returnError(cpu, mapErrno(hostErrno())) else sysv.returnSuccess(cpu, 0);
    return true;
}

fn sysLseek(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const fd = sysv.arg(cpu, 0);
    const off = sysv.arg(cpu, 1);
    const whence = sysv.arg(cpu, 2);
    const pos = lseek(@intCast(fd), @as(c_long, @intCast(@as(i32, @bitCast(off)))), @intCast(whence));
    if (pos < 0) sysv.returnError(cpu, mapErrno(hostErrno())) else sysv.returnSuccess(cpu, @intCast(pos & 0xffff_ffff));
    return true;
}

/// SysV `brk`: the argument is the absolute new break address. Grow/shrink the
/// heap region and return 0 on success (matching the kernel; libc's sbrk
/// wrapper tracks the old break in userland).
fn sysBrk(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const newbrk = sysv.arg(cpu, 0);

    if (newbrk < runner.brk_base or newbrk >= 0x0B00_0000) {
        sysv.returnError(cpu, ENOMEM);
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
    const fd = sysv.arg(cpu, 0);
    const statbuf = sysv.arg(cpu, 1);
    if (@as(u64, statbuf) + STAT_SIZE > mem.Memory.size) {
        sysv.returnError(cpu, EFAULT);
        return true;
    }
    var hs: HostStat = undefined;
    r88k_fstat(@intCast(fd), &hs);
    if (hs.ok == 0) {
        sysv.returnError(cpu, mapErrno(@intCast(hs.err)));
        return true;
    }
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    writeGuestStat(runner.memory, statbuf, &hs);
    runner.memory.enforce = was;
    sysv.returnSuccess(cpu, 0);
    return true;
}

fn sysStat(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const path_ptr = sysv.arg(cpu, 0);
    const statbuf = sysv.arg(cpu, 1);
    var pbuf: [1024]u8 = undefined;
    const path = runner.memory.readCStr(path_ptr, &pbuf);
    if (path.len >= pbuf.len or @as(u64, statbuf) + STAT_SIZE > mem.Memory.size) {
        sysv.returnError(cpu, EFAULT);
        return true;
    }
    pbuf[path.len] = 0;
    var hs: HostStat = undefined;
    r88k_stat(@ptrCast(&pbuf), &hs);
    if (hs.ok == 0) {
        sysv.returnError(cpu, mapErrno(@intCast(hs.err)));
        return true;
    }
    const was = runner.memory.enforce;
    runner.memory.enforce = false;
    writeGuestStat(runner.memory, statbuf, &hs);
    runner.memory.enforce = was;
    sysv.returnSuccess(cpu, 0);
    return true;
}

extern "c" fn fcntl(fd: c_int, cmd: c_int, arg: c_int) c_int;

/// fcntl. SysV cmds: F_DUPFD=0, F_GETFD=1, F_SETFD=2, F_GETFL=3, F_SETFL=4.
/// Pass DUPFD/GETFD/SETFD through to the host; treat the flag queries benignly.
fn sysFcntl(runner: *machine.Runner) bool {
    const cpu = &runner.cpu;
    const fd = sysv.arg(cpu, 0);
    const cmd = sysv.arg(cpu, 1);
    const arg3 = sysv.arg(cpu, 2);
    switch (cmd) {
        0, 1, 2 => { // F_DUPFD / F_GETFD / F_SETFD
            const rc = fcntl(@intCast(fd), @intCast(cmd), @intCast(arg3));
            if (rc < 0) sysv.returnError(cpu, mapErrno(hostErrno())) else sysv.returnSuccess(cpu, @intCast(rc));
        },
        3 => sysv.returnSuccess(cpu, 0), // F_GETFL: report no special flags
        4 => sysv.returnSuccess(cpu, 0), // F_SETFL: accept
        else => sysv.returnSuccess(cpu, 0),
    }
    return true;
}

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
