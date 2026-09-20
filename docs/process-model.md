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
