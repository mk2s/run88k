# NetBSD/luna88k (m88k) — User-Mode Syscall ABI

Fourth BSD-family platform. Ground truth recovered from a real
**NetBSD 3.0.1_STABLE/luna88k** root filesystem (mounted at `/mnt/netbsd`) by
disassembling the syscall stubs in the static `/bin` utilities (via the nono
LUNA-88k oracle and the Ghidra m88k disassembler) and cross-checking the
guest's own headers (`/usr/include/sys/syscall.h`, `sys/stat.h`,
`sys/dirent.h`, `sys/errno.h`, `m88k/ansi.h`). Every fact below was read from
the real image, not assumed.

## Platform identity
- OS: **NetBSD 3.0.1_STABLE/luna88k** (`/etc/release`), MC88100/88110,
  big-endian.
- Executable format: **ELF 32-bit MSB, Machine = MC88000, statically linked,
  not stripped**, `OS/ABI = UNIX - System V`, "for NetBSD 3.0.10" (the note's
  version tag). Same ELF32-BE m88k class the existing loader already accepts
  (`EM_88K`), so no loader changes were needed to *map* them.
- NetBSD marker: a **`PT_NOTE` segment carrying a `.note.netbsd.ident`** note
  with owner name `"NetBSD\0"` (namesz=7), `n_type = 1` (NT_NETBSD_IDENT), and a
  4-byte version descriptor (`0x11e1a6e8`). run88k auto-detects this note to
  pick the personality (see `elf.zig` `is_netbsd`); `--os netbsd` forces it.

## Syscall convention (verified via nono + Ghidra)
Identical trap *mechanism* to OpenBSD/SysV/88 — only the trap **vector**
differs. A direct stub (e.g. `write`, SYS 4) looks like:
```
    ld   r10, r31, 0x20    ; spill up to 3 stack args into r10/r11/r12
    ld   r11, r31, 0x24
    ld   r12, r31, 0x28
    or   r13, r0, <N>      ; syscall number -> r13
    tb0  0, r0, 128        ; trap, vector 128 (0x80)   <- the syscall trap
    br   err               ; taken on error (skip-on-success)
    jmp  r1                ; return to caller on success
```
- **Syscall number:** `r13`  (same as OpenBSD; SysV/88 uses r9).
- **Trap vector:** **128 (0x80)**  (OpenBSD uses 450, SysV/88 uses 451). The
  trap word is `0xf000d080`.
- **Arguments:** `r2..r12` (m88k C calling convention, contiguous from r2; the
  kernel reads up to 11 words, and the libc stub pre-spills stack args into
  r10/r11/r12 before the trap).
- **Return value:** `r2` (and `r3` for the 2nd word of a 64-bit return).
- **Error signalling:** PSR carry set on error / cleared on success; errno in
  `r2`. **Skip-on-success** PC handling: on success the kernel advances past the
  `br err` (ppc+8, the `jmp r1`); on error it lands on the `br err` (ppc+4).
  Byte-for-byte the same as `abi/openbsd.zig`, so `abi/netbsd.zig` reuses the
  same `advance()`/`setCarry()` logic with `syscall_vector = 128`.

### Indirect `__syscall` gate (used for the 64-bit-arg calls)
Unlike OpenBSD (direct stubs everywhere), NetBSD's libc routes the 64-bit-offset
calls — **`lseek`, `mmap`, `pread`, `pwrite`, `ftruncate`, `truncate`** — through
the indirect `__syscall`(198) wrapper. The wrapper is:
```
__syscall:
    ld  r10, r31, 0x20    ; reload spilled args
    ld  r11, r31, 0x24
    ld  r12, r31, 0x28
    or  r13, r0, 0xc6     ; 0xc6 = 198 = SYS___syscall
    tb0 0, r0, 128
    br  err
    jmp r1
```
The real syscall number is passed as the **first argument** (`r3` after the
`r2 = 0` indirect selector). run88k's dispatcher already normalizes this: when
`num == 0` (SYS_syscall) or `num == 198` (SYS___syscall) it takes the real
number from arg0 and shifts the argument window down one (`r2<-r3, r3<-r4, ...`).
**After that shift the argument layout matches OpenBSD's** for these calls, so
the same off_t register-pair handling applies:
- `lseek(fd, off, whence)`: fd=arg0, pad=arg1, off_hi=arg2, off_lo=arg3,
  whence=arg4.
- `mmap(addr,len,prot,flags,fd,offset)`: off_hi=arg6, off_lo=arg7 (r7 is the
  alignment pad).
- `ftruncate(fd,length)`: fd=arg0, pad=arg1, len_hi=arg2, len_lo=arg3.
Big-endian m88k stores a 64-bit value **high word first**, so the even
(lower-numbered) register of a pair holds the HIGH word.

## Process startup contract (verified by disassembling `__start` @ 0x1100)
The kernel hands the argc/argv/envp block **on the stack** and passes a pointer
to it in **`r2`** (as well as leaving it at the initial `r31`). `__start`:
```
    ld   r13, r0, r2       ; argc = *r2
    addu r23, r2, 4        ; argv = r2 + 4
    lda  r13, r23, r13     ; envp = argv + argc*4
    addu r13, r13, 4       ;      + 4  (skip the argv NULL)
```
So run88k builds the classic argc/argv/envp stack image and sets **`r2 = r31 =
sp`** (both pointing at argc) and `pc = e_entry`. No ELF aux vector is required
for a static binary (unlike OpenBSD, whose `_start`/libc walks the auxv). This
is `process.setupNetbsd`.

## Syscall numbers
Authoritative from the guest `/usr/include/sys/syscall.h`
(`$NetBSD: syscall.h,v 1.156 2005/02/27$`, generated from `syscalls.master,v
1.145`, `SYS_MAXSYSCALL = 375`), transcribed into
`syscalls/table_netbsd.zig`. Notables (differ from OpenBSD):
`exit=1, fork=2, read=3, write=4, open=5, close=6, wait4=7, link=9, unlink=10,
chdir=12, fchdir=13, chmod=15, break=17, getpid=20, access=33, kill=37,
getppid=39, dup=41, pipe=42, getegid=43, getgid=47, ioctl=54, symlink=57,
readlink=58, execve=59, umask=60, munmap=73, mprotect=74, madvise=75,
getgroups=79, dup2=90, fcntl=92, select=93, fsync=95, gettimeofday=116,
getrusage=117, readv=120, writev=121, fchown=123, fchmod=124, rename=128,
mkdir=136, rmdir=137, setsid=147, pread=173, pwrite=174, mmap=197,
__syscall=198, lseek=199, truncate=200, ftruncate=201, __sysctl=202, poll=209,
nanosleep=240, getdents=272, minherit=273, __stat13=278, __fstat13=279,
__lstat13=280, __getcwd=296, issetugid=305, getcontext=307,
__sigaction_sigtramp=340, kqueue=344`.
- **stat/fstat/lstat** are the versioned **`__stat13`(278)/`__fstat13`(279)/
  `__lstat13`(280)** (the `struct stat` revision 13 with 32-bit `time_t`).
- **getdents = 272** (the old 32-bit-fileno `struct dirent`).
- **`__getcwd`(296)** is a real syscall (like OpenBSD), so `pwd` does not need
  the getdents-walk that SysV/88 required.

## Struct layouts (recovered from guest headers)
NetBSD 3.0's key difference from OpenBSD is **32-bit `time_t`** (`m88k/ansi.h`:
`_BSD_TIME_T_ = int`), so `struct timespec = {i32 tv_sec; i32 tv_nsec}` = 8
bytes, and the `struct stat`/`dirent` layouts are the older, smaller ones.

- **`struct stat` (`__stat13`, `sys/stat.h`)** — all fields naturally aligned,
  `off_t`/`blkcnt_t` are `long long` (8-byte aligned):
  ```
  st_dev    u32 @0     st_ino   u32 @4     st_mode u32 @8     st_nlink u32 @12
  st_uid    u32 @16    st_gid   u32 @20    st_rdev u32 @24
  st_atimespec {i32 sec@28, i32 nsec@32}
  st_mtimespec {i32 sec@36, i32 nsec@40}
  st_ctimespec {i32 sec@44, i32 nsec@48}
  (pad @52)  st_size   i64 @56    st_blocks i64 @64
  st_blksize u32 @72   st_flags u32 @76   st_gen u32 @80   st_spare0 u32 @84
  st_birthtimespec {i32 sec@88, i32 nsec@92}       => sizeof 96
  ```
  (`st_dev`, not `st_mode`, is first — the reverse of OpenBSD; `st_mode` is at
  **offset 8**.)
- **`struct dirent` (`sys/dirent.h`)** — the OLD 32-bit-fileno layout (differs
  from OpenBSD's 64-bit `d_fileno`):
  ```
  d_fileno u32 @0    d_reclen u16 @4    d_type u8 @6    d_namlen u8 @7
  d_name @8
  ```
  Records are padded to **4 bytes**: `d_reclen = 8 + ((d_namlen + 1 + 3) & ~3)`.

## errno
Matches the BSD low range (`sys/errno.h`): `EPERM=1 … ERANGE=34, EAGAIN=35`,
identical to OpenBSD's low range, so the same `mapErrno` (host→guest identity
for ≤34) applies. Ranges diverge above 34; refine as specific mismatches
surface (NetBSD `ENOSYS=78`, like OpenBSD).

## Relationship to the other personalities
NetBSD is the third instance of the shared **BSD trap mechanism** (after
OpenBSD and the SysV/88-shaped SVR4 gate): carry-error, skip-on-success PC
recompute from `ppc`. The ONLY differences from OpenBSD are:
1. trap **vector 128** (vs 450),
2. the **syscall number table** (NetBSD 3.0 numbers, versioned `__stat13`/
   `getdents`),
3. the **struct layouts** (32-bit `time_t`; old `stat`/`dirent`),
4. **process startup** (`r2 = sp`, no auxv, vs OpenBSD's stack-read + auxv),
5. libc routes the 64-bit-arg calls through the **indirect `__syscall` gate**
   (normalized by the dispatcher's existing indirect handling).

Selected via `--os netbsd` or auto-detected from the `.note.netbsd.ident` note.

## Verified working
Static binaries against the real NetBSD 3.0.1/luna88k root (mounted at
`/mnt/netbsd`, `--root /mnt/netbsd`):
- `echo` (multiple args, `-n`, empty),
- `cat` (file: `/etc/release`; and stdin via a host pipe),
- `ls` (columnated) and **`ls -l`** — permissions, link count, uid/gid names
  (root/wheel), **sizes matching the host byte-for-byte** (validates the
  `__stat13` layout, notably `st_mode`@8 and `st_size`@56), dates, `total`,
- `pwd` (`__getcwd`, `--cwd /bin` → `/bin`),
- `date` (gettimeofday), `hostname` (sysctl), `expr 3 + 4` → `7`, `sleep 0`.

The first-run gap that surfaced (and was fixed): NetBSD's libc routes the
64-bit-offset calls through **`__syscall`(198) with a `quad_t` number**, so the
real syscall number is the LOW word of the r2:r3 pair (r3 = arg1), and the
actual arguments start at r4 — the indirect normalization shifts the window by
**2** for the 198 gate (by 1 for the plain `syscall`(0) gate). Also added
`statvfs1`/`fstatvfs1` (zero-filled with a sane `f_bsize`/`f_namemax`) that `ls`
calls at startup.

The other personalities (SysV/88, OpenBSD, UTek, DG/UX) remain unregressed;
`zig build test` stays green.

## Toolchain (as / cc / ld / make) — WORKING
The full native toolchain runs end to end: `cc -o hello hello.c` drives
cpp → cc1 → as → **ld** (against the static `/usr/lib/libc.a`) to a valid
statically-linked ELF32-BE MC88000 NetBSD executable that then RUNS under run88k
(prints via printf, correct exit code). `make <exe>`, `cc -c`, `as`, and
`nm /usr/lib/libc.a` all work. `/bin/sh` drives it (fork/exec/wait/pipe,
redirection, pipelines). See `docs/toolchain.md`.

Key fixes that unblocked it:
- **lseek 64-bit return word order**: return r2=high word, r3=low word (m88k
  big-endian pair). Returning it backwards made libc/BFD read the low word as
  the high half of its file position → every seek targeted `pos<<32` → archives
  looked "File truncated". This was the last blocker (a syscall bug, not a core
  bug — verified via `tools/m88k_eval.py`, which found zero CPU divergences).
- **argv[0] guest path**: GCC derives its tool-search exec prefix from argv[0];
  `cmdRun` rewrites the host run-target path to its guest path via
  `fs.hostToGuest()` so cc finds `/usr/libexec/cc1`.
- vfork r2/r3 dual-return; `/dev/{stdin,stdout,stderr,fd/N}` fdesc mapping.

Also verified: multi-file `cc -c`/`cc -o` link, `cc -O2` with malloc/qsort/free,
floating point (`x/y` via the FPU through NetBSD libc), `awk` arithmetic,
`ar cr` + `nm` + linking against a user-built static archive, `strip`, `size`,
`sed`, and a shell one-liner that writes a `.c`, compiles it with `cc`, and runs
the result (`sh -c 'echo ... > t.c && cc -o t t.c && ./t'`). Shell globbing
(`for f in *.c`) works.

## Known gaps / next
- **Dynamic linking** is not wired: NetBSD dynamic execs would need the guest's
  `/usr/libexec/ld.elf_so` mapped and started (the OpenBSD ld.so approach). The
  base `/bin` and `/rescue` utilities and the toolchain are static, so this
  hasn't been needed.
- errno mapping is host→NetBSD identity for the low range (≤34); refine as
  specific mismatches surface.
- `ioctl` answers only the isatty(TIOCGETA-family) probe; full termios later.
- `chown`/`fchown`/`lchown` accept and ignore host EPERM (we run unprivileged
  but the guest believes it is root) — good enough for `ar`/`install`; real
  ownership is not modeled.
