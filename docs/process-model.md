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

## Still to do (follow-ups)
- **`;` sequencing** and **pipelines** fault after the first child: e.g.
  `sh -c "/usr/bin/pwd; /usr/bin/true"` runs pwd then the parent faults at
  0x312c0; `pwd | cat` faults in cat. Likely post-fork parent/child state or
  fd-inheritance issues in the host-fork model — needs investigation.
- Individual external programs may hit further unimplemented syscalls
  (fail-fast reports them, e.g. it surfaced uname(135) cleanly).

The process-model plumbing (fork/exec/wait/waitsys/pipe) is wired and works for
single-command `-c`; static single-process binaries (echo/cat/ls/pwd) are
unaffected and work.
