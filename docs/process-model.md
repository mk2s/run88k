# Process model (fork / execve / wait / pipe) — status

## Implemented (src/procmodel.zig + dispatch.zig)

A host-process backend (ported from the sibling runupc): a guest process maps
onto a host process.

- **fork/vfork (2/119)**: host `fork()`, which copies the whole emulator (guest
  memory included) so the child continues emulating. SVR4 dual-return:
  parent gets r2=child_pid, r3=0; child gets r2=parent_pid, r3=1 (libc's fork
  stub uses r3 to zero r2 in the child). Verified from the libc fork stub.
- **execve (59)**: resolves the path via the mount table, reads the ELF, clears
  the address space, loads the new image (static or dynamic — runs the dynamic
  linker if needed), rebuilds the argv/envp stack and entry registers, resets
  brk/mmap. Sets the run loop to continue at the new entry (no PC advance).
- **wait (7)**: host `waitpid`; the status is re-encoded to the SVR word
  `(exit_code & 0xff) << 8`; returns pid in r2, status in r3, and stores the
  status word at the caller's pointer.
- **pipe (42)**: host `pipe()`, both ends registered in the guest fd table;
  read fd in r2, write fd in r3.

Also added the startup syscalls a shell needs: `pgrpsys` (39, get/set
pgrp/session — benign values), and the signal syscalls (`sigaction`/
`sigprocmask`/`signal`/`sigpending`/`sigsuspend`) accepted as no-ops (no signal
delivery yet). getpid/getuid/getgid/umask already existed.

Wired only when a mount table is present (exec needs path resolution). Runner
gained `procmodel` and `exec_pending`; the run loop records a PC ring buffer for
runaway diagnostics.

## Status running `/sbin/sh` (static) — WORKING for single commands

`sh -c "echo hi"` **prints `hi` and exits 0.** `echo` is a shell builtin, so sh
services it directly (write(1,"hi\n")). External single commands also work:
`sh -c "/usr/bin/pwd"` forks, execs pwd, prints `/`, reaps the child, exits 0.
`sh -c "/usr/bin/uname"` prints `UNIX_SV`.

### The blocker was a core bug, found with the harness
sh was NOT looping in a lexer as first suspected — it was reading stdin because
a **core instruction bug** (`ld.hu`/`ld.bu` immediate loads not decoded) made
sh's first-time init counter read as garbage, so `main` skipped the block that
wires `-c` input to the command string (leaving the input fd at 0). Full
write-up in `docs/core-fixes.md` #3. Found by extending `difftrace` with
`--root`/`--mount` (so sh could be traced with its files mounted) and searching
the trace for the divergent instruction, confirmed against the nono oracle.

### Additional syscalls added for the shell
- **waitsys (107)** — the SVR4 kernel primitive under libc `waitpid`/`wait`
  (sh uses this, not the older `wait`(7)). Reaps a child and fills a
  `siginfo_t`: `+8 si_code = CLD_EXITED(1)`, `+12 si_pid`, `+23 si_status`
  (byte). Layout recovered from the libc `waitpid` wrapper (`FUN_000307c0`).
- **uname (135)** — fills a SVR4 `struct utsname` (five 257-byte fields:
  sysname/nodename/release/version/machine) with plausible SysV/88 values.

## Sequencing, pipelines, and `#!` scripts — WORKING

All of these now run end-to-end (verified against `/sbin/sh`):

- `sh -c "/usr/bin/pwd; /usr/bin/uname"` — sequencing (`;`)
- `sh -c "/usr/bin/pwd | /usr/bin/cat"` and 3-stage `pwd | cat | cat` — pipelines
- `sh -c "echo hello | /usr/bin/cat"` — builtin piped into an external
- `sh -c "/usr/bin/true && echo yes"` / `"/usr/bin/false || echo fallback"` —
  `&&`/`||` (validates exit-status propagation through waitsys)
- `sh -c "pwd"` — PATH resolution to `/usr/bin/pwd`
- `sh -c "/usr/bin/true; echo done"` — `#!/sbin/sh` script via execve

### Two fixes made
1. **Pipeline fd redirection — `fcntl(F_DUPFD)` returned a host fd.**
   Shells build their stdio wiring with `close(1); fcntl(pipe_wr, F_DUPFD, 1)`,
   expecting the result to be a *guest* fd (an index into the guest fd table)
   at or above the given floor. Our handler passed F_DUPFD straight to host
   `fcntl`, returning a raw host fd number that the guest then treated as a
   guest fd — corrupting its fd bookkeeping after fork/exec, so the downstream
   `cat` couldn't read the pipe. Fixed: F_DUPFD now `dup()`s the host fd and
   registers it via a new `Fs.allocFdFrom(hfd, floor)` (lowest free guest fd
   >= floor), returning the guest fd. F_GETFD/F_SETFD still pass through.
   The guest fd table survives execve (doExec does not reset `self.fs`), so the
   redirection carries into the exec'd program as Unix requires.

2. **`#!interpreter [arg]` scripts in execve.** `/usr/bin/true` (and much of the
   userland, incl. cc wrappers) are `#!/sbin/sh` scripts, not ELF. execve now
   detects a leading `#!`, parses `interp [single-arg]`, and re-execs the
   interpreter with argv rebuilt as `[interp, arg?, scriptpath, orig_argv[1..]]`,
   bounded to 4 chained interpreters. Non-`#!` non-ELF files still fail cleanly.

### Regression guards
- `Fs.allocFdFrom` floor behavior unit-tested in `src/fs.zig`.
- Statics (echo/cat/ls/pwd) and dynamic `date` unaffected; full `zig build test`
  green.

The process-model plumbing (fork/exec/wait/waitsys/pipe + F_DUPFD redirection +
`#!` scripts) is complete for `-c` command lines with sequencing, pipelines, and
conditionals.

## Known remaining
- Individual external programs may still hit unimplemented syscalls; the
  fail-fast dispatcher reports them by number/name (that is how uname(135) and
  waitsys(107) were surfaced).

## RESOLVED: pipelines / `;` / external commands (the "fork fault")

Symptom: `sh -c 'echo hi | cat'`, `cat file`, `ls | sort | head`, and most
external-command invocations aborted with a NULL deref inside sh's message
formatter (`ld.b r21,r0[r15]` at guest pc 0x312bc, r15=0). It looked like a
fork/pipe bug but the fork/pipe plumbing was fine — the child just failed to
find its command and fell into sh's (buggy) error path.

Root cause was `access(2)` amode translation:
- The shell's PATH search calls `access(cmd, X_OK|EFF_ONLY_OK)` = **amode 9**
  (SVR4 `EFF_ONLY_OK`=8 tests effective ids). Linux's `access()` rejects any
  amode bit outside R/W/X (0-7) with **EINVAL**, so every lookup failed and
  every external command "wasn't found".
- Fix: `sysAccess` masks the guest amode to the low 3 bits (`amode & 0x7`)
  before calling the host. The effective-vs-real distinction is irrelevant
  under a single uid.

Two more syscalls surfaced once commands started exec'ing:
- **syssec (145)**: SVR4 B1/ACL security subsystem probe at process startup
  (cat et al.). Report "not present" (EINVAL) so programs fall back to standard
  UNIX permissions.
- **ulimit (63)**: resource-limit query (sort sizes its buffers via cmd 3,
  UL_GMEMLIM). Return generous values: file-size limit, max break 0x08000000
  (below the mmap region), max fds = Fs.MAX_FD.

Now working via `sh -c`: pipelines (incl. multi-stage `a | b | c`), `;`
sequencing, `&&`/`||`, `>` redirection, `for` loops, external commands
(cat/ls/sort/head/wc), and **backtick** command substitution.

### Still rough: sh error-message formatting (narrow, sh-specific)
Shell-level *syntax* errors and command-not-found still fault at 0x312c0. This
`/sbin/sh` is a pre-POSIX Bourne shell: it does NOT support `$(( ))` arithmetic
or `$( )` command substitution (use backticks), so those parse as errors. On any
such error sh looks up a message in `/usr/lib/locale/C/LC_MESSAGES/uxlibc`
(which we mmap correctly — verified the mapped bytes match the file) and passes
the looked-up pointer to its internal `_doprnt` as the format string. For these
message ids the lookup yields NULL and sh derefs it. Verified this is sh's own
gettxt/`_doprnt` NULL handling, not an emulator defect: every syscall succeeds,
the catalog data is present and correct, and other tools (cat, cc) format
catalog-based errors fine. Page 0 is unmapped on real SysV/88 too. Left as-is
(mapping a zero page to mask it was rejected — it would hide real null derefs).


## OPEN: `tr` (and likely other stdio writers) lose piped/file output — copy-reloc of `_iob`

`tr '[a-z]' '[A-Z]'` (correct bracket syntax — bare `a-z` is literal chars on
this SysV tr, not a bug) transforms correctly but produces NO output to a pipe
or file (works to a tty via line-buffering). Traced precisely:
- tr's putc buffers all chars into its stdout FILE at **0x42220** (verified
  _ptr advances base..base+6 correctly).
- At exit, `_cleanup` -> `fflush(NULL)` walks libc's iop table. The table base
  pointer (`[__iob_hdr+0x1c4]`) resolves to **0x4000000** and the array there
  (20 entries, stride 0x20, plus a chain at +0xc = NULL) does **not** include
  tr's stdout iop at 0x42220. So tr's buffer is never flushed.
- i.e. tr's `stdout` (`_iob[1]`) address (0x42220, in tr's bss) and libc's
  internal flush-list array (0x4000000) **disagree**. They must be the same
  object. This is a **copy-relocation / `.rela.bss` dynamic-linking** issue:
  `_iob`/`stdout` is a libc data symbol that must be COPY-relocated into the
  executable's bss with both sides agreeing on one address. Our eager linker
  appears to leave libc pointing at its own copy (0x4000000-ish) while tr uses
  its bss copy (0x42220).
- Scope: affects dynamically-linked programs that write via buffered stdio to a
  non-tty AND rely on exit-flush (tr). cat/ls/echo (raw write) and statically
  linked tools (wc) are unaffected, which is why pipelines mostly work.
- Next: inspect `.rela.bss` / copy relocs in dynamic.zig; ensure `_iob` (and
  similar libc data symbols) resolve to a single shared address.


## OPEN: sh error messages fault (pfmt NULL format on catalog miss)

Shell-level errors (command-not-found, and unsupported syntax like `$((`/`$(`
which this pre-POSIX Bourne sh rejects — backticks work) fault at guest pc
0x312bc (`ld.b r21,r0[r15]`, r15=0). Fully traced the call chain:
- sh's error emitter at **0x227e8** deliberately calls the SVR4 `pfmt` wrapper
  (0x2f650) with **format = NULL** (`or r4,r0,0x0`). In SVR4, a NULL pfmt
  format means "fetch the localized message from the catalog by severity/msgid"
  (r2/r3).
- pfmt (0x2f6b8) -> its internal `_doprnt` (0x311f0) is ultimately handed that
  catalog-looked-up pointer as the format string. For sh's message ids the
  lookup yields NULL, and `_doprnt` scans it with `ld.b r0[r15]` -> deref 0.
- The `uxlibc` catalog is mmap'd correctly (verified mapped bytes == file:
  count 0x6b, offset table intact). So this is pfmt/catgets returning NULL for a
  missing message id and NOT falling back to a builtin default — a guest-libc
  NULL-handling gap, not an emulator defect (every syscall succeeds).
- Possibly related to the `_iob` copy-reloc mismatch (a catalog-descriptor
  global resolving to the wrong address would make every lookup miss); worth
  re-checking after the copy-reloc/`.rela.bss` fix.
- Impact is cosmetic-adjacent: all VALID shell input works (pipelines, `;`,
  `&&`/`||`, redirection, loops, backtick subst, external commands); only the
  *error message* for bad input faults instead of printing.


## UPDATE: `tr` pipe/file output — RESOLVED (see dynamic-linking.md)

The `tr` no-output-to-pipe/file issue above is FIXED. It was the stdio
exit-flush bug: libc's `__first_link` (the stdio FILE-flush registry that
`fflush(NULL)`/`_cleanup` walk) was being mis-initialized by the old
`buildLinkMap`. `initStdioRegistry` now points `__first_link[0]` at the true
`__iob` (the exe's COPY-relocated copy, or libc's own for non-COPY programs).
`tr '[a-z]' '[A-Z]'` now yields `HELLO` through a pipe and to a file. As a
bonus, `size`/`nm` now work to a pipe/file too (previously tty-only). Full
write-up in docs/dynamic-linking.md.

## UPDATE: sh error-message fault — SEPARATE, static-binary sh internal (not fixed)

The `__first_link`/`__iob` fix does NOT affect the sh 0x312c0 fault, and
investigation confirmed why: **`/sbin/sh` is STATICALLY linked** (ET_EXEC, no
`.dynsym`/`.rela.bss`/`.interp`) — the dynamic linker never touches it. The
fault is purely sh's own logic: its error path calls `pfmt(stderr, flags,
format)` with a hardcoded **NULL format** (sh code at 0x227e8 `or r4,r0,0x0`)
and message category/id = 0/0 (the wrapper at 0x227b0 is entered with r2=0,
r3=0). pfmt (0x2f6b8) takes the NULL straight through (`r17=r4=0` from entry to
the fprintf/`_doprnt` call) and `_doprnt` derefs it. The `uxlibc` catalog is
mmap'd and read correctly. So sh supplies neither a valid catalog msgid nor a
fallback format — a genuine sh NULL-deref on its error path that would also
SIGSEGV on real SysV/88 (page 0 unmapped), most likely because `sh -c` skips
the message-catalog/locale setup a login shell performs. Not an emulator or
dynamic-linking defect; not fixable emulator-side without masking real null
derefs. All VALID shell input works (pipelines, `;`, `&&`/`||`, redirection,
loops, backtick subst, external commands incl. `tr`).

## RESOLVED: `make` getcwd() fails across a virtual mount boundary ("getcwd (bu5)")

- **Symptom:** `make` run with `--cwd /work` (a writable overlay) died
  immediately with `make: fatal error: getcwd (bu5).`. With `--cwd /` it worked.
- **Root cause:** SVR4 `getcwd(3C)` has no kernel syscall — it walks *up* in
  userland: `lstat(".")` to save the current dir's `(st_dev, st_ino)`, then
  repeatedly `chdir("..")` + `getdents` the parent + `lstat` each entry until it
  finds the child whose `(dev,ino)` matches, prepending names. Our mount table
  presents `/work` as a *virtual* child of `/` backed by a host directory on a
  *different host filesystem* (e.g. guest `/`→/mnt/hd0_root dev 0x71f, guest
  `/work`→/tmp/asm88 dev 0x2f). The parent listing of `/` (the real host
  /mnt/hd0_root) contains **no `work` entry at all**, so the upward walk never
  finds the current directory and bails. `--cwd /` worked only because the walk
  terminates instantly when cwd is already root.
- **Fix (src/fs.zig + src/syscalls/dispatch.zig):** make mount points appear as
  ordinary child directory entries so the walk can climb across them.
  - `Fs.openDir` now records the *guest* directory path for each dir fd
    (`dir_path`/`dir_path_len`), and `sysOpen` passes the canonicalized guest
    path.
  - `Fs.mountChild(dir, i)` enumerates mount points whose parent guest dir
    equals `dir`, returning each mount's backing `host_root` + entry `name`.
  - `sysGetdents`, after the real `readdir` stream is exhausted, appends a
    synthetic dirent for each such mount point. Its `d_ino` is
    `stat(host_root).st_ino` — exactly what `lstat()` of the mount point returns
    (both stat the same backing host dir), so the walk's inode match succeeds
    and the subsequent `lstat` confirms the same `(dev,ino)`.
  - A per-fd cursor (`dir_synth_next` + `dirSynthNext/Advance/Rewind`) resumes
    synthetic emission across getdents calls / buffer boundaries.
- **Why the inode identity holds:** `lstat("/work")` and `lstat(".")` (when
  cwd=/work) both resolve through the mount table to the same host path, so they
  already agree. The only missing piece was the parent listing advertising the
  child — which the synthetic entry supplies with the matching `d_ino`.
- **Verified:** `make --cwd /work` builds default/named/`clean` targets;
  `make -f Makefile.cc` drives `/usr/ccs/bin/cc` to compile a C program → binary
  → runs → correct output. `ls /` now shows `work`; `ls /work` lists the overlay
  contents; `ls` of real directories is unchanged (no regression).
- **Files:** `src/fs.zig` (`dir_path`, `mountChild`, `canonicalGuest`,
  `dirGuestPath`, `dirSynth*`, `openDir` signature), `src/syscalls/dispatch.zig`
  (`sysGetdents` synthetic-entry pass, `sysOpen` guest-path threading).
