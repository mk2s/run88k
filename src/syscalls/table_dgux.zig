//! Data General DG/UX (m88k) syscall number tables.
//!
//! Numbers are authoritative — recovered by disassembling the
//! `or r9,r0,<N>; tb0 0,r0,<gate>` stubs in the guest's own
//! `/usr/dglib/libc.so.1` (219 distinct stubs; there is no `syscall.h` in the
//! DG/UX tree, so the stubs ARE the ground truth). See docs/abi-dgux.md.
//!
//! Convention (abi/dgux.zig): syscall number in r9, args r2..r9, return r2
//! (r3 for dual-return), carry-based skip-on-success error handling.
//!
//! CRITICAL: DG/UX has TWO trap gates and the number is interpreted RELATIVE
//! TO THE GATE. The two tables overlap numerically with different meanings
//! (e.g. 41 = rename on gate 0x1c2 but open on gate 0x080; 11 = fork vs dup).
//! The dispatcher must branch on the gate (cpu.last_exception) first.
//!
//!   - Gate `tb0 0,r0,0x1c2` (450) -> the STANDARD (SVR4-style) table below.
//!   - Gate `tb0 0,r0,0x080` (128) -> the DG-EXTENDED table below.
//!
//! `_bcs_*` = BCS/SVR3 compatibility entries; `__dg_*` = DG-native
//! implementations; `_abi_*` = ABI-shim variants. Recorded here under their
//! canonical Unix names where one exists (with the raw name noted).

/// Standard syscall table, reached via `tb0 0, r0, 0x1c2` (vector 450).
pub const Std = enum(u32) {
    access = 1,
    bcs_brk = 2,
    chdir = 3,
    chmod = 4,
    lchown = 5,
    chroot = 6,
    close = 7,
    execve = 8,
    exit = 9, // libc stub `_exit`
    fork = 11,
    fpathconf = 12,
    fstat = 13,
    getdents = 14, // libc stub `_abi_getdents`
    getgid = 15, // getgid/getegid share this (dual return)
    getgroups = 16,
    getmsg = 18,
    getpgrp = 19,
    getpid = 20, // getpid/getppid share this (dual return)
    getpsr = 21,
    getuid = 22, // getuid/geteuid share this (dual return)
    bcs_ioctl = 23,
    kill = 24,
    link = 25,
    lseek = 26,
    memctl = 27, // libc stub `__dg_memctl`
    mkdir = 28,
    mknod = 29,
    msgsys = 30, // libc stub `__dg_msgsys`
    nice = 31,
    bcs_open = 32,
    pathconf = 33,
    poll = 36,
    profil = 37,
    ptrace = 38,
    putmsg = 39,
    read = 40,
    rename = 41,
    rmdir = 42,
    semsys = 43, // libc stub `__dg_semsys`
    setgid = 44,
    bcs_setitimer = 45,
    setpgid = 46,
    setpsr = 47,
    setsid = 48,
    setuid = 49,
    shmsys = 50, // libc stub `__dg_shmsys`
    bcs_sigaction = 51,
    bcs_sigfillset = 52,
    sigpending = 53,
    sigprocmask = 54,
    sigsuspend = 55,
    stat = 56,
    sync = 57,
    bcs_sysconf = 58,
    bcs_time = 59,
    times = 60,
    ulimit = 61,
    umask = 62,
    unlink = 64,
    utime = 66,
    getcwd = 67, // no libc.so.1 stub (getcwd there uses the ext-gate path),
    // but the STATIC SDE tools' baked-in libc traps getcwd as std #67.
    write = 68,
    _,
};

/// DG-extended syscall table, reached via `tb0 0, r0, 0x080` (vector 128).
pub const Ext = enum(u32) {
    acct = 2,
    dup = 11,
    dup2 = 12,
    fcntl = 19,
    dg_ioctl = 29, // libc stub `__dg_ioctl`
    mount = 35,
    open = 41,
    pause = 42,
    setpgrp = 53,
    dg_signal = 59, // libc stub `__dg_signal`
    stime = 62,
    uname = 69, // uname/nuname share this
    vfork = 74, // libc stub `_abi_vfork`
    dg_bind = 88,
    dg_connect = 89,
    dg_getsockname = 93,
    dg_recvfrom = 97,
    dg_select = 99,
    dg_sendto = 102,
    dg_socket = 107,
    dg_sigblock = 113,
    dg_sigsetmask = 115,
    setgroups = 121,
    dg_getpagesize = 122,
    gettimeofday = 126, // libc stub `_abi_gettimeofday`
    settimeofday = 127,
    getrlimit = 130,
    setrlimit = 131,
    fchmod = 134,
    fchown = 135,
    fsync = 136,
    truncate = 138, // libc stub `_abi_truncate`
    readv = 139,
    writev = 140,
    dg_process_info = 145,
    dg_mstat = 147,
    umount = 149,
    dg_getdomainname = 150,
    sighold = 160,
    sigrelse = 161,
    sigignore = 162,
    sigpause = 163,
    getpgid = 182,
    fchdir = 204,
    statvfs = 206,
    fstatvfs = 207,
    getsid = 208,
    memcntl = 211,
    sigsendset = 212,
    waitid = 213,
    getcontext = 214,
    setcontext = 215,
    sigaltstack = 217,
    mmap = 218,
    munmap = 219,
    mprotect = 220,
    sysinfo = 222, // libc stub `_abi_sysinfo`
    getpmsg = 233,
    putpmsg = 234,
    dg_sigaction = 235,
    stkprotect = 274,
    dg_register_signal_prehandler = 306,
    _,
};
