//! Tektronix UTek XD88 (m88k) syscall number table.
//!
//! Numbers are authoritative — recovered by disassembling the `or r9,r0,<N>;
//! tb0 0,r0,450` stubs in the guest's own `/lib/libc.a` (70 distinct stubs;
//! there is no `syscall.h` in the UTek tree, so the stubs ARE the ground
//! truth). See docs/abi-utek.md.
//!
//! Convention (abi/utek.zig): syscall number in r9, trap `tb0 0,r0,450`
//! (vector 450), args in r2..r8, return in r2 (r3 for dual-return),
//! carry-based skip-on-success error handling.
//!
//! This is a COMPACT, UTek-specific numbering — NOT the SysV/88 table
//! (1..146) and NOT stock BSD. Every entry below has a real libc stub.
//!
//! A second trap vector, 449, carries the "local"/Tektronix multiplexed calls
//! (getrlimit=2, setrlimit=1, and the `sys_local` multiplexor). Vector 448 is
//! `sigret`. Those are not in this enum yet; they are dispatched (or stubbed)
//! separately when a guest needs them.

pub const Syscall = enum(u32) {
    access = 1,
    brk = 2,
    chdir = 3,
    chmod = 4,
    lchown = 5,
    chroot = 6,
    close = 7,
    execve = 8,
    exit = 9, // libc stub `_exit`
    fcntl = 10,
    fork = 11,
    fpathconf = 12,
    fstat = 13,
    getdents = 14,
    getgid = 15, // getgid/getegid share this (dual return)
    getgroups = 16,
    getitimer = 17,
    getmsg = 18,
    getpgrp = 19,
    getpid = 20, // getpid/getppid share this (dual return)
    getpsr = 21,
    getuid = 22, // getuid/geteuid share this (dual return)
    ioctl = 23,
    kill = 24,
    link = 25,
    lseek = 26,
    memctl = 27,
    mkdir = 28,
    mknod = 29,
    msgsys = 30,
    nice = 31,
    open = 32,
    pathconf = 33,
    pipe = 34,
    plock = 35,
    poll = 36,
    profil = 37,
    ptrace = 38,
    putmsg = 39,
    read = 40,
    rename = 41,
    rmdir = 42,
    semsys = 43,
    setgid = 44,
    setitimer = 45,
    setpgid = 46,
    setpsr = 47,
    setsid = 48,
    setuid = 49,
    shmsys = 50,
    sigaction = 51,
    sigfillset = 52,
    sigpending = 53,
    sigprocmask = 54,
    sigsuspend = 55,
    stat = 56,
    sync = 57,
    sysconf = 58,
    time = 59,
    times = 60,
    ulimit = 61,
    umask = 62,
    uname = 63,
    unlink = 64,
    ustat = 65,
    utime = 66,
    waitpid = 67,
    write = 68,
    _,
};
