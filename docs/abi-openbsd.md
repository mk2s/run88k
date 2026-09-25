# OpenBSD/luna88k (m88k) — User-Mode Syscall ABI

Second platform (Milestone 6). Ground truth recovered from a real OpenBSD 7.1
luna88k root filesystem (mounted at `/mnt/hd6`) by disassembling the syscall
stubs in the static `/bin` utilities via nono, and cross-checking the guest's
own headers (`/usr/include/sys/syscall.h`, `sys/stat.h`, `sys/dirent.h`,
`sys/exec_elf.h`, `fcntl.h`, `sys/sysctl.h`). Every fact below was read from the
real image, not assumed.

## Platform identity
- OS: **OpenBSD 7.1 (GENERIC)**, luna88k, MC88100/88110, big-endian
  (`/etc/motd`: "OpenBSD 7.1 (GENERIC) #1 ... 2022").
- Executable format: **ELF 32-bit MSB, Machine = MC88000, for OpenBSD,
  statically linked, stripped** (the base `/bin` utilities). Same ELF32-BE
  m88k class the SysV/88 loader already accepts (EM_88K), so no loader changes
  were needed to *map* them.
- OpenBSD markers: a `PT_OPENBSD_RANDOMIZE` (0x65a3dbe6) program header plus a
  `.note.openbsd.ident` note. run88k auto-detects these to pick the personality
  (see `elf.zig` `is_openbsd`); `--os openbsd` forces it.

## Syscall convention (verified via nono)
Identical trap *mechanism* to SysV/88 — only the vector and number register
differ. A stub looks like:
```
    or   r13, r0, <N>      ; syscall number -> r13
    tb0  0, r0, 450        ; trap, vector 450 (0x1c2)
    br   err               ; taken on error (skip-on-success)
    jmp  r1                ; return to caller on success
```
- **Syscall number:** `r13`  (SysV/88 uses r9).
- **Trap vector:** **450 (0x1c2)**  (SysV/88 uses 451).
- **Arguments:** `r2..` (m88k C calling convention, contiguous from r2).
- **Return value:** `r2` (and `r3` for the 2nd word of a 64-bit return).
- **Error signalling:** PSR carry set on error / cleared on success; errno in
  `r2`. **Skip-on-success** PC handling: on success the kernel advances past the
  `br err` (ppc+8, the `jmp r1`); on error it lands on the `br err` (ppc+4).
  This is byte-for-byte the same as `abi/sysv88.zig`, so `abi/openbsd.zig`
  reuses the same `advance()`/`setCarry()` logic.
- **64-bit args (off_t):** passed in an even/odd **register pair** with an
  alignment pad. Big-endian m88k stores a 64-bit value **high word first**, so
  the even (lower-numbered) register of the pair holds off_hi and the odd
  register holds off_lo. For `pread(fd, buf, nbyte, off)`: fd=r2, buf=r3,
  nbyte=r4, pad=r5, off_hi=r6, off_lo=r7 (arg indices 4=hi, 5=lo). For
  `lseek(fd, off, whence)`: fd=r2, pad=r3, off_hi=r4, off_lo=r5, whence=r6 (arg
  indices 2=hi, 3=lo). For `ftruncate(fd, length)`: fd=r2, pad=r3, len_hi=r4,
  len_lo=r5 (arg 2=hi, 3=lo). For `mmap(...offset)`: off_hi=r8, off_lo=r9 (arg
  6=hi, 7=lo). Getting the pair layout wrong made the libc DB code (getpwuid)
  re-read offset 0 forever (the `ls -l` hang); getting the **word order** within
  the pair backwards (off_lo/off_hi swapped) made `as` seek to a multi-terabyte
  sparse offset — a 692-byte `.o` reported as 2.9 TB — and made `ld` read
  garbage for a shared library's ELF header ("File format not recognized").
- **Indirect syscalls:** `SYS_syscall`(0) and `SYS___syscall`(198) carry the
  real number in the first argument; the dispatcher shifts r2..r8 down one and
  re-dispatches.

## Process startup contract (verified by disassembling `_start` @ 0x1190)
Unlike SysV/88 (register handoff), OpenBSD's `_start` reads everything off the
**stack**:
```
    ld   r2, r31, 0        ; argc = *sp
    addu r3, r31, 4        ; argv = sp + 4
    lda  r4, r3[r2] ; +4   ; envp = argv + (argc+1)*4
```
So run88k builds the classic ELF stack image and sets only `r31 = sp` (pointing
at argc) and `pc = e_entry`; no argument registers are preloaded
(`process.setupOpenbsd`).

**ELF auxiliary vector (required).** After the envp NULL, `_start`/libc walks
the ELF aux vector. Omitting it makes libc read off the end of the stack and
fault at `stack_top` (0x0C000000) — the exact symptom seen before it was added.
run88k appends an auxv terminated by `AUX_null`, with the entries libc reads:
`AUX_phdr(3), AUX_phent(4), AUX_phnum(5), AUX_pagesz(6)=0x1000, AUX_entry(9)`.
(IDs from the guest `sys/exec_elf.h`: null=0, phdr=3, phent=4, phnum=5,
pagesz=6, base=7, flags=8, entry=9.) `process.buildStackAux` writes them;
`elf.zig` supplies `phdr_vaddr`/`phent`/`phnum`.

## Syscall numbers
Authoritative from the guest `/usr/include/sys/syscall.h`
(`$OpenBSD: syscall.h,v 1.232 2022/02/24 ...$`, the 7.1 release), transcribed
into `syscalls/table_openbsd.zig` (0..330). Notables that differ from SVR4:
`getentropy=7, break=17, stat=38, lstat=40, fstatat=42, sigaction=46, mmap=49,
fstat=53, ioctl=54, getdents=99, pledge=108, unveil=114, writev=121, lseek=166,
pread=169, sysctl=202, issetugid=253, __getcwd=304, __set_tcb=329,
__get_tcb=330`. OpenBSD has a real `__getcwd` syscall, so `pwd` does NOT need
the getdents-walk that SysV/88 required.

## Struct layouts (differ from SVR4 — recovered from guest headers)
- **`struct stat`** (sys/stat.h, 128 bytes, time_t 64-bit, timespec = {i64 sec;
  i32 nsec} = 16 bytes). Field order starts with **st_mode**, not st_dev:
  `st_mode u32 @0, st_dev i32 @4, st_ino u64 @8, st_nlink u32 @16, st_uid @20,
  st_gid @24, st_rdev @28, st_atim @32(16), st_mtim @48(16), st_ctim @64(16),
  st_size i64 @80, st_blocks i64 @88, st_blksize i32 @96, st_flags @100,
  st_gen @104, __st_birthtim @112(16)`. Getting st_mode's offset wrong makes
  `ls` treat directories as plain files (it printed just the arg name) — the
  bug fixed to make `ls` list directories.
- **`struct dirent`** (sys/dirent.h): `d_fileno u64 @0, d_off i64 @8,
  d_reclen u16 @16, d_type u8 @18, d_namlen u8 @19, __d_padding[4] @20,
  d_name @24`. `getdents` emits records padded to 8 bytes.

## Syscalls implemented (dispatch_openbsd.zig)
Grown incrementally from a static `echo` up through `ls -l`, the same
bootstrap arc as SysV/88:
- I/O: `read`, `write`, `writev`, `pread`, `open` (opens directories as dir
  streams for getdents), `close`, `lseek`, `fstat`, `stat`, `lstat`, `fstatat`
  (AT_FDCWD), `getdents`, `access`, `fcntl` (F_ISATTY/GETFD/SETFD/GETFL/SETFL/
  DUPFD), `ioctl` (isatty-based tty probe), `chdir`, `fchdir`, `__getcwd`,
  `__realpath`.
- Filesystem mutation (for the toolchain writing temp files + output): `unlink`,
  `rename`, `mkdir`, `rmdir`, `link`, `ftruncate`, `chmod`, `fchmod`, `umask`,
  `access`.
- Memory: `mmap` (anonymous bump-allocator downward from `mmap_next`;
  file-backed private via pread), `munmap`/`mprotect`/`madvise`/`minherit`/
  `msync`/`mquery` (accept, no reclaim).
- Time: `gettimeofday`, `clock_gettime` (whole seconds from the host clock).
- Startup / sandbox / identity: `pledge`/`unveil`/`kbind`/`msyscall` (success
  no-op — we impose no sandbox), `getentropy` (deterministic fill),
  `__set_tcb`/`__get_tcb` (stored on `runner.tcb`), `issetugid`→0,
  `getpid`/`getthrid`→1, `getuid`/`geteuid`/`getgid`/`getegid`→0,
  `sysctl` ({CTL_HW,HW_PAGESIZE}→4096, HW_NCPU→1, else empty success).
- `exit`.
Unimplemented syscalls hit a `failFast` that prints the number+name+ppc, so the
next gap is obvious — the same "grow on demand" loop used for SysV/88.

## Verified working
`echo` (args, `-n`, empty), `cat` (file + stdin pipe), `pwd` (`/`, `/usr`,
`/work`, nested), `ls` (columnated), `ls -l` / `ls -ln` (permissions, link
count, uid/gid names via getpwuid, size, date). SysV/88 remains unregressed;
`zig build test` and the musashi `difftest` (50/50) stay green.

## Dynamic linking — run the guest's real `ld.so` (Approach A)
Dynamic OpenBSD execs request interpreter `/usr/libexec/ld.so` (an ELF DYN,
entry `_dl_start` @ 0xaac0). Rather than reimplement OpenBSD's relocation +
kbind + retguard machinery, run88k **runs the guest's own `ld.so`** — the same
thing the real kernel does. It's both more faithful and less code.

- **Loader (`main.zig`, OpenBSD dynamic path):** the exec is mapped at its own
  fixed vaddrs (bias 0). `elf.interpPath()` reads PT_INTERP; run88k reads the
  interpreter file and `mapSegments`es it at `OBSD_LDSO_BASE = 0x04000000` (above
  exec+heap, below the mmap region 0x08000000 and the stack 0x0c000000).
- **Startup:** PC = ld.so's (biased) entry, `r31` = sp. The aux vector carries
  `AT_base(7)` = ld.so's load base, and `AT_phdr/phent/phnum/entry` describe the
  **exec** (never ld.so) so ld.so can find and start the program. `_dl_start`
  reads all of this off the stack + auxv (verified by disassembly).
- ld.so then: `open`s the library, `read`s its header, `mmap`s a PROT_NONE span
  to reserve the address range, overlays each segment with `MAP_FIXED`
  file-backed maps, applies relocations, flushes the cache, and jumps to the
  exec's entry.

Three emulator pieces made this work:
1. **`mmap` must honor `MAP_FIXED` (0x0010) and address hints.** ld.so reserves a
   library's whole span then maps segments at computed fixed addresses; the bump
   allocator ignoring the requested address corrupted every library. Now a
   non-zero addr (fixed, or a hint at/above the break) is honored verbatim.
2. **`mmap` off_t is in the r8:r9 register pair, not r6.** Args are
   `mmap(addr=r2,len=r3,prot=r4,flags=r5,fd=r6,offset)`; the 64-bit offset uses
   the next even/odd pair after the r7 pad, so **off_lo = arg7 (r9)**, off_hi =
   arg6 (r8). Reading arg6 as the whole offset made every library segment load
   from file offset 0 → garbage DYNAMIC array → fault in ld.so's Dyn parser.
   (Same pattern as the pread/lseek off_t pairs.)
3. **`tb0 0,r0,451` is a cache-flush trap, not a syscall.** ld.so
   (`_dl_cacheflush`) issues it after writing PLT/GOT. Our memory is coherent, so
   the run loop treats `cacheflush_vector = 451` as a benign no-op (advance past
   it). Added `Runner.cacheflush_vector`; only the OpenBSD path sets it.

**Verified dynamic binaries:** `/usr/bin/{true,false}` (exit codes),
`id` (`uid=0(root) gid=0(wheel) groups=0(wheel)` — getpwuid/getgrgid through
dynamic libc), `logname`, `uname -sr` (`OpenBSD 7.1`), `sed`, `wc`, `grep`.
Startup syscalls added for the dynamic path: `getgroups`→{0}, `getlogin_r`→root,
and `sysctl` string/int keys (KERN_OSTYPE/OSRELEASE/VERSION/OSREV/HOSTNAME,
HW_MACHINE/MODEL, and **VM_MALLOC_CONF→"" — an empty NUL-terminated string, or
libc malloc warns "unknown char in MALLOC_OPTIONS"**).

## Scripting + toolchain (awk, make, and the full cc→as→ld pipeline work)
- **awk** (dynamic) works fully — arithmetic, FP (via the musashi FPU through
  OpenBSD libc), modulo, sqrt, field processing, printf, string concat. It only
  needed `sigaction` + friends accepted as no-ops (awk installs handlers but
  doesn't depend on delivery). Single-process, no fork.
- **fork/exec/wait/pipe** are wired for OpenBSD (`dispatch_openbsd` + a
  personality-aware `procmodel.doExecDepth` that maps ld.so + builds the auxv
  for a dynamic child). Key ABI facts recovered from the guest libc:
  - `fork(2)` is a **plain skip-on-success stub with NO r3 dual-return**: the
    kernel returns the child pid in r2 to the parent and **0 in r2 to the
    child** (unlike SysV/88's r2/r3 dual-return). `sysFork` mirrors this.
  - `pipe`/`pipe2` return the two fds by **writing them into the user int[2]**
    (arg0) and returning 0 (not r2/r3 like SysV).
  - `getpid`/`getppid` return the **real host pid** so make's job tracking lines
    up with the pids `fork` returns.
  - `setPc` now clears `branch_pending` so a stale delay slot can't fire after
    an execve reload.
  Verified: `sh -c '/bin/echo hi'` forks, the child execs `/bin/echo`, and it
  **prints correctly** — fork+exec+static-child works end to end.

- **Signal delivery (SIGCHLD) — IMPLEMENTED and working.**
  OpenBSD's shell and make wait for children with
  `sigaction(SIGCHLD, handler)` + `sigsuspend()`: they block in `sigsuspend`
  until SIGCHLD is delivered to their handler (which reaps + records the child),
  then proceed. (This differs from the SysV/88 shell, which polls via `wait` and
  needs no delivery.) run88k delivers signals:
  - `sigaction` records the per-signal handler in `runner.sig_handlers[]`.
  - `sigsuspend` reaps a child (blocking on a real host wait if none is ready
    yet) and **delivers SIGCHLD**: `deliverSigchld` saves the full CPU state
    into a private sigcontext on the guest stack, sets r2=signo, r4=&sigcontext,
    r1=an injected return trampoline (`or r2,r0,r31; sigreturn` at halt_pad+16),
    and jumps to the handler.
  - `sigreturn(103)` restores the saved state. We use our OWN sigcontext layout
    (a 39-word frame with a magic word) rather than OpenBSD's cookie-protected
    kernel `struct sigcontext`, since both the push and the restore are ours and
    the handler never inspects the frame — this sidesteps the kernel cookie.
  - **Reaped children are cached** (`procmodel` `reaped[]`): `sigsuspend`
    reaps-and-caches, and the handler's own `wait4(-1, ...)` drains exactly that
    cached child. The earlier "sh loops re-entering sigsuspend" bug was a
    *double reap* — a WNOWAIT peek that then let the handler's wait4 return
    ECHILD; caching the reap fixed it. `decodeWait` returns `status = s & 0xffff`
    (raw host low-16), which preserves the W* macros for both personalities.

- **Zeroing the register file on exec.** `process.setup`/`setupOpenbsd` zero
  r0..r31 and clear `branch_pending` before the ABI handoff. A forked child that
  execs was inheriting the parent's stale GPRs, so OpenBSD `_start` (which reads
  its stack pointer and argv off registers/stack seeded from a clean state) ran
  against garbage and faulted. This is the same bug class as the runupc
  "child gets parent's stack" fix — here it was the *register* file leaking, not
  memory (memory was already `@memset` to 0 on exec). This fix is what made
  `make` and the compiler driver work.

## Verified toolchain — full cc → as → ld pipeline
The OpenBSD 7.1 luna88k toolchain (GCC 3.3.6, dynamic binaries under
`/usr/bin`) runs end to end:
- **`make`** (`/usr/bin/make`): default, named, and `clean` targets produce
  correct output, exit 0. `sh -c '...'` works for single commands (PATH search),
  `;` sequences, file redirection, and **pipelines** (`echo x | wc -w`,
  multi-stage `echo | tr | wc`) with correct exit-status propagation — the
  fork/exec/wait/SIGCHLD path plus a real host pipe shared across the host-fork.

  **Pipeline fd-leak fix (`fs.zig` `closeFd`).** A pipeline stalled with the
  reader blocked forever on `read` because the pipe's write end never closed.
  The fd table skipped the host `close()` for guest fds 0/1/2 (to protect the
  emulator's own stdio). But a shell dup2's a pipe end onto guest fd 1 (stdout)
  and later replaces it; skipping the close orphaned that host fd (a live pipe
  write end), so every `fork`ed stage inherited an open write end and no reader
  ever saw EOF. Fixed by guarding the host `close()` on the *host* fd value
  (close any host fd ≥ 3, i.e. anything we allocated) rather than the guest fd
  number. This also made SysV/88 `sh` pipelines work (the two personalities
  share `fs.zig`).
- **`cc -c hi.c`**: cpp → cc1 → as produces a valid **728-byte** ELF32-BE
  MC88000 relocatable (9 sections: `.text`, `.rela.text`, `.rodata`, `.symtab`,
  `.strtab`, ...), clean under host `readelf`.
- **`cc -o hi hi.c`**: the full driver — cpp → cc1 → as → **ld** linking against
  `/usr/lib/libc.so.96.1` — produces an executable-mode **dynamically linked**
  ELF32-BE MC88000 executable (interpreter `/usr/libexec/ld.so`, for OpenBSD).
  Running the result under run88k (through the guest's real `ld.so`) prints the
  expected output and exits 0.

Two ABI fixes unblocked linking (both are the off_t pair issue above): the
`lseek`/`ftruncate` **word-order** correction (the terabyte-`.o` and the
`ld: File format not recognized` symptoms shared this root cause — `ld` reads a
library's ELF header via `lseek`+`read`, and a swapped-word seek landed on a
sparse hole), plus implementing `chmod`/`fchmod` so the driver can mark its
output executable.

## Known gaps / next
- **SysV/88 `cc`** faults (`kind=unmapped addr=0` in the driver, ~pc 0x5034164)
  on both `-c` and `-o`. This is a **pre-existing** SysV/88 issue (reproduces
  identically at a clean tree), independent of the OpenBSD toolchain work above;
  SysV/88 `make` is unaffected. Not yet investigated.
- errno mapping is host→OpenBSD only for the low, matching range (≤34); refine
  as specific mismatches surface (OpenBSD `ENOSYS=78`, ranges diverge above 34).
- `fstatat` supports only AT_FDCWD (no dirfd-relative base yet).
- `uname -a`'s kernel-version detail field is imperfect (KERN_VERSION string);
  `-s`/`-r`/`-m`/`-n` are correct.
- Signals, threads, sockets, and the `*at` family beyond fstatat are stubs/absent.
- Lazy binding via `kbind` is currently accepted as a no-op success; if a binary
  relies on true lazy PLT resolution (rather than ld.so's up-front binding),
  revisit.
