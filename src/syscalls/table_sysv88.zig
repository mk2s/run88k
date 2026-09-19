//! UNIX System V/88 R4.0 (m88k) syscall number table.
//!
//! Numbers are authoritative from the guest's own
//! `/usr/include/sys/syscall.h` (Motorola MCG, syscall.h 1.8, 04 May 1993),
//! cross-checked against the actual `addu r9,r0,<N>; tb0 0,r0,451` stubs in
//! `/usr/ccs/lib/libc.a` (116 distinct numbers verified present as real
//! stubs). See docs/abi-sysv88.md.
//!
//! Convention (recovered): syscall number in r9, trap `tb0 0,r0,451`
//! (vector 451), args in r2..r8, return in r2, skip-on-success error handling.
//!
//! `verified` marks numbers for which a real libc stub was found; unmarked
//! entries come from the header only (kernel-internal or unused-by-libc, e.g.
//! evsys/evtrapret, or reserved subcode multiplexors).

pub const Syscall = enum(u32) {
    exit = 1,
    fork = 2,
    read = 3,
    write = 4,
    open = 5,
    close = 6,
    wait = 7,
    creat = 8,
    link = 9,
    unlink = 10,
    exec = 11,
    chdir = 12,
    time = 13,
    mknod = 14,
    chmod = 15,
    chown = 16,
    brk = 17,
    stat = 18,
    lseek = 19,
    getpid = 20, // getpid/getppid share this (dual return)
    mount = 21,
    umount = 22,
    setuid = 23,
    getuid = 24, // getuid/geteuid share this
    stime = 25,
    ptrace = 26,
    alarm = 27,
    fstat = 28,
    pause = 29,
    utime = 30,
    stty = 31,
    gtty = 32,
    access = 33,
    nice = 34,
    statfs = 35,
    sync = 36,
    kill = 37,
    fstatfs = 38,
    pgrpsys = 39, // setpgrp/setsid/getpgrp/... via subcode
    sysm88k = 50, // header calls it SYS_sys3b (50); libc stub is `sysm88k`
    dup = 41,
    pipe = 42,
    times = 43,
    profil = 44,
    plock = 45,
    setgid = 46,
    getgid = 47, // getgid/getegid share this
    signal = 48, // sigset/sighold/... via flag bits
    msgsys = 49,
    acct = 51,
    shmsys = 52,
    semsys = 53,
    ioctl = 54,
    uadmin = 55,
    // 56 reserved for exch()
    utssys = 57, // uname/ustat/fusers via subcode
    fsync = 58,
    execve = 59,
    umask = 60,
    chroot = 61,
    fcntl = 62,
    ulimit = 63,
    // 64-69 reserved for UNIX PC; 70-77 obsolete RFS
    rfsys = 78,
    rmdir = 79,
    mkdir = 80,
    getdents = 81,
    sysfs = 84,
    getmsg = 85,
    putmsg = 86,
    poll = 87,
    lstat = 88,
    symlink = 89,
    readlink = 90,
    setgroups = 91,
    getgroups = 92,
    fchmod = 93,
    fchown = 94,
    sigprocmask = 95,
    sigsuspend = 96,
    sigaltstack = 97,
    sigaction = 98,
    sigpending = 99,
    context = 100, // getcontext/setcontext via subcode
    evsys = 101, // header only (no libc stub)
    evtrapret = 102, // header only
    statvfs = 103,
    fstatvfs = 104,
    // 105 reserved
    nfssys = 106,
    waitsys = 107, // libc stub name `waitid`
    sigsendsys = 108,
    hrtsys = 109, // header only
    acancel = 110, // header only
    async = 111, // header only
    priocntlsys = 112,
    pathconf = 113,
    mincore = 114,
    mmap = 115,
    mprotect = 116,
    munmap = 117,
    fpathconf = 118,
    vfork = 119,
    fchdir = 120,
    readv = 121,
    writev = 122,
    xstat = 123,
    lxstat = 124,
    fxstat = 125,
    xmknod = 126,
    clocal = 127,
    setrlimit = 128,
    getrlimit = 129,
    lchown = 130,
    memcntl = 131,
    getpmsg = 132,
    putpmsg = 133,
    rename = 134,
    uname = 135,
    setegid = 136,
    sysconfig = 137,
    adjtime = 138,
    systeminfo = 139, // libc stub name `sysinfo`
    seteuid = 141,
    csync = 142,
    stkprotect = 143,
    mpsys = 144,
    syssec = 145, // header only (no libc stub found)
    select = 146, // NOT in syscall.h; found only in the libc stub
    _,
};
