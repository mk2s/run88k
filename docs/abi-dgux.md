# Data General DG/UX (m88k) — User-Mode Syscall ABI

Ground truth for the DG/UX personality, recovered by disassembling the syscall
stubs in the guest's own `/usr/dglib/libc.so.1` (the real, decompressed
439 KB shared object), cross-checked in Ghidra against the shared error
trampoline and the exported dynamic symbols, and against the full DG/UX
installation header tree at `/mnt/dguxusr/include`.

DG/UX is Data General's SVR4-derived Unix for the AViiON workstations and
servers (MC88100/MC88110, big-endian). Unlike UTek and SysV/88, the DG/UX
userland is **dynamically linked** (ELF32-BE, interpreter
`/usr/dglib/libc.so.1`), though the boot/install tools include a few static
executables (e.g. `/sbin/preinit`).

Guest filesystems used for recovery:
- `/mnt/dgux` (root), `/mnt/dguxusr` (`/usr`, incl. `include/`, `dglib/`).
- `.../aviionbootdgux.img.extracted/4735054/sbin/preinit` (static target).

## Platform identity

- OS: **DG/UX** on Data General **AViiON**, MC88000, big-endian.
- Executable format: **ELF32-BE**, `MC88000`, flags `0x80000000`.
  - Static: `EXEC`, e.g. `sbin/preinit` (entry `0x10011c`).
  - Dynamic: `DYN`/`EXEC` with interpreter `/usr/dglib/libc.so.1`
    (e.g. `mkfs`). (Contrast: UTek uses 88K BCS COFF.)
  - The kernel `/mnt/dgux/dgux` is **88K BCS COFF** (`0x016d`), `.Ktext`@0,
    `.Kdata`@0x180000, entry `0x13d990` — used only as an RE reference.
- errno numbers: SVR4/AT&T set (same low range as SysV/88 and UTek).

## Calling convention — TWO trap gates

Recovered from 219 `libc.so.1` stubs. Every syscall wrapper has the shape:

```
    or   r9, r0, <N>     ; syscall number -> r9   (encoded 0x5920_00NN)
    tb0  0, r0, <gate>   ; SYSCALL TRAP                         <- the trap
    br   0x455b0         ; instruction after the trap: error trampoline
    jmp  r1              ; success return (kernel skips the br to land here)
```

DG/UX uses **two distinct trap gates**, and the syscall number in r9 is
interpreted **relative to the gate**:

| Gate                 | Meaning                                                   |
|----------------------|-----------------------------------------------------------|
| `tb0 0, r0, 0x1c2` (450) | **Standard** SVR4-style call table (low numbers 1..68).   |
| `tb0 0, r0, 0x080` (128) | **DG-extended** call table (dup/fcntl/mmap/sockets/...).  |

**The two tables overlap numerically with different meanings** — e.g. number
41 is `rename` under gate 0x1c2 but `open` under gate 0x080; number 11 is
`fork` (0x1c2) vs `dup` (0x080). The dispatcher therefore MUST branch on the
**gate first** (`cpu.last_exception`), then on the number. This is the key
structural difference from UTek (whose second vector 449 was only a small
multiplexor).

| Aspect            | Convention                                                   |
|-------------------|--------------------------------------------------------------|
| Trap instruction  | `tb0 0, r0, 0x1c2` **or** `tb0 0, r0, 0x080`.                |
| Syscall number    | In **r9** (`or r9, r0, <N>`), interpreted per gate.          |
| Arguments         | r2..r9 (SVR4 m88k C calling convention), passed through the  |
|                   | stub **unmodified** (the stub only sets r9 and traps).       |
| Return value      | r2 (r3 for dual/64-bit returns).                             |
| Error signalling  | Carry-based **skip-on-success**, identical shape to UTek/    |
|                   | SysV/88: on success the kernel advances past `br 0x455b0` to |
|                   | reach `jmp r1`; on error control lands on the `br`. On error |
|                   | r2 holds the errno value; the shared trampoline at libc      |
|                   | `0x455b0` stores it into the global `errno` and forces the   |
|                   | returned value to -1. The PSR carry bit (bit 28) mirrors     |
|                   | success/error.                                               |

### The shared error trampoline (libc `0x455b0`)

Confirmed in Ghidra. On the error path the stub branches here; the trampoline
computes the PIC data base, loads `&errno` (data-base + 0x1a0), stores r2 into
it, and sets the returned value to -1 before returning to the caller. On
success the kernel skips the branch entirely, so the trampoline never runs.

## PC handling detail

Identical mechanism to the other personalities. After a trapped step the core
has redirected pc/npc to the exception vector and left `ppc` pointing at the
`tb0`. The personality RECOMPUTES pc from `ppc`: success -> ppc+8 (the
`jmp r1`), error -> ppc+4 (the `br 0x455b0`), and clears the pipeline.

## Syscall number tables — RECOVERED

There is no `sys/syscall.h` in the DG/UX tree; the libc stubs are the ground
truth. Encoded in `src/syscalls/table_dgux.zig` as two enums, one per gate.

### Gate 0x1c2 — standard (61 stubs)

```
 1 access    2 (bcs_brk) 3 chdir     4 chmod     5 lchown    6 chroot
 7 close     8 execve    9 _exit    11 fork     12 fpathconf 13 fstat
14 getdents 15 getgid   16 getgroups 18 getmsg   19 getpgrp  20 getpid
21 getpsr   22 getuid   23 (bcs_ioctl) 24 kill   25 link     26 lseek
27 memctl   28 mkdir    29 mknod     30 msgsys   31 nice     32 (bcs_open)
33 pathconf 36 poll     37 profil    38 ptrace   39 putmsg   40 read
41 rename   42 rmdir    43 semsys    44 setgid   45 (bcs_setitimer)
46 setpgid  47 setpsr   48 setsid    49 setuid   50 shmsys
51 (bcs_sigaction) 52 (bcs_sigfillset) 53 sigpending 54 sigprocmask
55 sigsuspend 56 stat   57 sync      58 (bcs_sysconf) 59 (bcs_time)
60 times    61 ulimit   62 umask     64 unlink   66 utime    68 write
```

### Gate 0x080 — DG-extended (62 stubs)

```
  2 acct     11 dup      12 dup2     19 fcntl    29 dg_ioctl 35 mount
 41 open     42 pause    53 setpgrp  59 dg_signal 62 stime   69 uname
 74 vfork    88 dg_bind  89 dg_connect 93 dg_getsockname 97 dg_recvfrom
 99 dg_select 102 dg_sendto 107 dg_socket 113 dg_sigblock 115 dg_sigsetmask
121 setgroups 122 dg_getpagesize 126 gettimeofday 127 settimeofday
130 getrlimit 131 setrlimit 134 fchmod 135 fchown 136 fsync 138 truncate
139 readv    140 writev   145 dg_process_info 147 dg_mstat 149 umount
150 dg_getdomainname 160 sighold 161 sigrelse 162 sigignore 163 sigpause
182 getpgid  204 fchdir   206 statvfs 207 fstatvfs 208 getsid 211 memcntl
212 sigsendset 213 waitid 214 getcontext 215 setcontext 217 sigaltstack
218 mmap     219 munmap   220 mprotect 222 sysinfo 233 getpmsg 234 putpmsg
235 dg_sigaction 274 stkprotect 306 dg_register_signal_prehandler
```

The `__dg_*` and `_bcs_*` prefixes are DG/UX's own: `__dg_*` are DG-native
implementations (sockets, ioctl, signals) and `_bcs_*` are the BCS
(Binary Compatibility Standard / SVR3) compatibility entries. `_abi_*` are the
ABI-shim variants. These are recorded under their canonical names in the table.

## Files (planned / in progress)

- `src/abi/dgux.zig` — personality (gates 0x1c2 + 0x080, r9, carry/skip).
- `src/syscalls/table_dgux.zig` — the two syscall number enums.
- `src/syscalls/dispatch_dgux.zig` — host-backed dispatcher (both gates).
- `src/loaders/elf.zig` — reused (ELF32-BE already supported).
- `src/main.zig` — `--os dgux` (to be wired).

## Status

ABI + number tables recovered and encoded. Dispatcher scaffolded from the UTek
dispatcher. First target: static `/sbin/preinit` (entry `0x10011c`) to the
first syscall. Dynamic binaries (interpreter `/usr/dglib/libc.so.1`) are a
follow-on once the static path runs.
