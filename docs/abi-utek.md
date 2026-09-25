# Tektronix UTek XD88 (m88k) — User-Mode Syscall ABI

Ground truth for the UTek personality, recovered by disassembling the syscall
stubs in the guest's own `/lib/libc.a` and its `crt0.o`, and cross-checked
against a fully-linked `/bin/echo` and the **nono** hardware oracle. UTek is
Tektronix's BSD-derived Unix for the XD88 workstation (MC88100, big-endian);
the on-disk filesystem is UFS1/FFS, but the userland errno numbers and process
startup follow the AT&T/UniSoft SysV lineage.

Guest root filesystem used for recovery: `~/Documents/FUSE-utek/tekroot`.

## Platform identity

- OS: **Tektronix UTek** (XD88 workstation), MC88100, big-endian.
- Executable format: **88K BCS COFF** (`file` reports "88K BCS executable").
  filehdr magic `0x016d`. Statically linked; no dynamic linking for the CLI
  tools. (Contrast: SysV/88 and OpenBSD/m88k use ELF32-BE.)
- errno numbers: the AT&T/UniSoft SysV set (`usr/include/sys/errno.h`):
  EPERM=1, ENOENT=2, ..., ENOSYS=89. Same low range as SysV/88.

## Calling convention (`tb0 0, r0, 450`)

Recovered from 70 `libc.a` stubs (write/read/open/close/_exit/... all share the
shape) and confirmed in Ghidra + nono. The stub shape:

```
    or   r9, r0, <N>     ; syscall number -> r9   (encoded 0x6120_00NN)
    tb0  0, r0, 450      ; SYSCALL TRAP, vector 450 (0x1c2)  <- the trap
    br   err             ; instruction after the trap: the error path
    jmp  r1              ; success return (kernel skips the br to land here)
 err:
    ...                  ; -> _cerror: errno = kernel value, return -1
```

| Aspect            | Convention                                                   |
|-------------------|--------------------------------------------------------------|
| Trap instruction  | `tb0 0, r0, 450` -> **exception vector 450** (0x1c2).        |
| Syscall number    | In **r9** (`or r9, r0, <N>`). (Same register as SysV/88.)    |
| Arguments         | r2..r8 (SVR4 m88k C calling convention).                     |
| Return value      | r2. Dual-return calls put the 2nd value in r3 (getpid/getppid, getuid/geteuid, getgid/getegid, and pipe's two fds). |
| Error signalling  | Carry-based **skip-on-success**: on success the kernel advances the pipeline past the `br err` to reach `jmp r1`; on error it leaves control on `br err` (which reaches `_cerror`). The PSR carry bit (PSR_C = 0x10000000, bit 28 — from `sys/m88kbcs.h`) is set on error, cleared on success. `_cerror` stores the kernel's error value into the global `errno` and returns -1 (`or.c r2,r0,r0`). |

**Second trap vector 449** (0x1c1) is the "local"/Tektronix entry, used by
`getrlimit` (local #2), `setrlimit` (local #1), and the `sys_local`
multiplexor. The number is still in r9. **Vector 448** (0x1c0) is `sigret`.
run88k routes both 450 and 449 to the UTek dispatcher (via the runner's
`syscall_vector` and `syscall_vector2`); the dispatcher reads
`cpu.last_exception` to tell them apart.

Comparison to the other m88k personalities:

| | UTek | SysV/88 R4 | OpenBSD/NetBSD |
|-|------|------------|----------------|
| Trap vector    | **450** | 451 | 450 |
| Number register| r9      | r9  | r13 |
| Args           | r2..r8  | r2..r8 | r2..r12 |
| Return         | r2 (+r3)| r2 (+r3) | r2 (+r3) |
| Error signal   | carry / skip-on-success | same | same |
| Format         | 88K BCS COFF | ELF32-BE | ELF32-BE |
| Startup        | register handoff | register handoff | stack + ELF auxv |

## Syscall number table — RECOVERED (vector 450)

There is no `syscall.h` in the UTek tree, so the stubs are the ground truth.
A compact, UTek-specific numbering (NOT SysV/88's 1..146, NOT stock BSD):

```
 1 access    2 brk       3 chdir     4 chmod     5 lchown    6 chroot
 7 close     8 execve    9 _exit    10 fcntl    11 fork     12 fpathconf
13 fstat    14 getdents 15 getgid   16 getgroups 17 getitimer 18 getmsg
19 getpgrp  20 getpid   21 getpsr   22 getuid   23 ioctl    24 kill
25 link     26 lseek    27 memctl   28 mkdir    29 mknod    30 msgsys
31 nice     32 open     33 pathconf 34 pipe     35 plock    36 poll
37 profil   38 ptrace   39 putmsg   40 read     41 rename   42 rmdir
43 semsys   44 setgid   45 setitimer 46 setpgid 47 setpsr   48 setsid
49 setuid   50 shmsys   51 sigaction 52 sigfillset 53 sigpending
54 sigprocmask 55 sigsuspend 56 stat 57 sync    58 sysconf  59 time
60 times    61 ulimit   62 umask    63 uname    64 unlink   65 ustat
66 utime    67 waitpid  68 write
```

Encoded in `src/syscalls/table_utek.zig`.

## Process startup contract (`_start`) — RECOVERED

Recovered from `crt0.o` and the linked `/bin/echo` entry (0x2200). Identical to
SysV/88: a **register handoff**, no stack scan, no auxv.

| Register | Contents |
|----------|----------|
| r2       | **argc** |
| r3       | **argv** (`char **`, NULL-terminated) |
| r4       | **envp** (`char **`, NULL-terminated) |
| r6       | cleanup fn or 0 |
| r31      | **stack pointer** (aligned; `and r31,r31,0xfff0`) |
| r1       | return address |

Proof from `echo` entry: `st r2,r31,0; st r3,r31,4; st r4,r31,8` saves the
handoff registers, and they are reloaded (`ld r2/r3/r4`) right before the call
to `main`, so `main(argc, argv, envp) = main(r2, r3, r4)`.

`src/process.zig` `setupUtek()` builds the argv/envp strings + vectors, sets
r2/r3/r4/r6/r31/r1, and installs a UTek exit trampoline in the halt pad
(`or r9,r0,9; tb0 0,r0,450` — SYS_exit).

## struct stat (stat=56, fstat=13)

From `usr/include/sys/stat.h` + `sys/types.h` (all fields 4-byte `long`,
big-endian), total 512 bytes (trailing `st_pad[456]` zeroed):

```
st_dev@0 st_ino@4 st_mode@8 st_nlink@12 st_uid@16 st_gid@20 st_rdev@24
st_size@28 st_atime@32 st_ausec@36 st_mtime@40 st_musec@44 st_ctime@48
st_cusec@52  (then st_pad[456])
```

No st_blksize/st_blocks fields. S_IF* type bits match host Linux
(S_IFDIR=0x4000, S_IFREG=0x8000, ...).

## struct dirent + getdents (getdents=14)

`getdents(2)` fills `struct dirent { ulong d_ino; long d_off; ushort d_reclen;
char d_name[]; }` — d_ino@0, d_off@4, d_reclen@8, d_name@10, d_reclen rounded
to a 4-byte multiple. Same layout as SysV/88; backed by the host
opendir/readdir shim (`src/host_dir.c`).

## The CPU "mask level" gate (sysconf `_SC_CPUID`)

libc startup — linked into **every** BCS binary — calls
`sysconf(_SC_CPUID)` (name 33) and requires the returned value to be **>= 13**
(0xd) or it prints "Minimum CPU mask level required is 13" and aborts.
Confirmed by disassembling `/bin/cat`: `cmp r10,r25,0xd; bb1 ge,r10,ok`.
`src/syscalls/dispatch_utek.zig` returns `0x1a` for `_SC_CPUID`.

## Core fix motivated by UTek (musashi88k)

UTek's libc emits the triadic `cmp` (and other ALU/logical ops) with a nonzero
**width field** (bits 9..5) — e.g. `0xf5597d00` = `cmp r10,r25,r0` with
width=8. The MC88100 decodes these non-bit-field ops from **op6 (bits 15..10)
alone** and treats bits 9..5 as a don't-care. musashi88k originally required an
exact 11-bit match and silently dropped the instruction (leaving the comparison
result register unchanged), which made every BCS binary's null-check
mis-branch and fault. Verified on nono: `0xf5597c00` and `0xf5597d00` produce
the identical `cmp` bitstring. Fixed in `musashi88k/src/decode.zig` `group3d`
by dispatching and/and.c/or/or.c/xor/xor.c/cmp/mul/div/divu on op6 alone. See
`docs/core-fixes.md`.

## Working today

Static UTek binaries run end to end against the mounted guest root:
`/bin/echo` (multiple/empty/many args), `/bin/pwd`, `/bin/date`, `/bin/cat`
(single + multiple files). Selected with `--os utek` or auto-detected from the
BCS COFF magic. `/bin/ls` runs but currently prints only `.` (it takes an
ioctl/stat path that needs more work) — a follow-on, mirroring the analogous
open `ls` item on the SysV/88 side.

## Files

- `src/abi/utek.zig` — personality (vector 450/449, r9, carry/skip-on-success).
- `src/loaders/coff.zig` — 88K BCS COFF loader (magic 0x016d, 44-byte scnhdr
  stride, `.text`/`.data`/`.bss` by name, unrounded brk).
- `src/syscalls/table_utek.zig` — the syscall number enum.
- `src/syscalls/dispatch_utek.zig` — host-backed dispatcher (vectors 450+449).
- `src/process.zig` `setupUtek()` — register-handoff startup.
- `src/main.zig` — `--os utek`, COFF auto-detect, `cmdRunUtek`.

## Toolchain bring-up status

Driving the guest's own C toolchain (the headline goal). Set up writable
mounts for scratch: `--mount /tmp=<host tmp> --mount /work=<host work>`.

**Working:**
- `/lib/cpp` (preprocessor) — produces correct `.i`.
- `/lib/comp` (Green Hills C-88000 1.8.5 compiler) — produces correct m88k
  `.s` from a `.i` (verified `_main` with `subu r31,r31,40`, `bsr _printf`).
- `/lib/as` (the real assembler) — produces valid 88K BCS COFF `.o`
  (magic 0x016d) from a `.s`.
- `/bin/ld -r` (incremental/relocatable link) — combines objects successfully.
- `/bin/cc` driver — forks/execs the phases in order (cpp → comp → as → ld),
  printing each command with `-v`.
- `sh -c` with fork/exec/pipe, command substitution, nested shells, and the
  shebang-less shell-script utilities (basename/dirname/true/false — these have
  no `#!` line; the exec path runs them via /bin/sh).

**Syscalls added for the toolchain:** `times`(60), `ulimit`(61), `utime`(66),
`sysconf`(58, incl. `_SC_CPUID`), `pathconf`/`fpathconf`. Plus procmodel
`execve` gained COFF support (HostProcess.utek flag) and a shell-script
fallback, and a critical `waitpid` fix (dual-return pid:r2/status:r3; the libc
stub stores r3 itself, so the kernel must NOT write the status buffer).

**Full compile+link works (via direct phase invocation):**
```
/lib/cpp prog.c prog.i -Dghs
/lib/comp prog.i prog.i prog.s
/lib/as -o prog.o prog.s
/bin/ld -o prog /lib/crt0.o /lib/default.ld prog.o -lc   # cc's exact ld line
```
produces a working COFF executable that runs under run88k (e.g. a loop summing
1..10 prints `sum1..10=55`, and `hello.c` prints `hello, utek`).

### The zero-page fix (unblocked ld)

`ld`'s executable-link path faulted on a null-pointer `strcmp`
(`ld.bu r5,[r2]` at ld:0x26ad8, r2=0). Root cause (traced via Ghidra): `ld`
builds a synthetic file-node for the `/lib/default.ld` linker command file
(the `*m32.default.fil` symbol) whose name field is **legitimately NULL** by
design (ld stores 0 there at ld:0x1100c; the caller passes 0 at ld:0x179fc),
then walks the symbol list and `strcmp`s each name. On real UTek, address 0 is
a **readable zero page** (classic pre-strict-MMU Unix), so `strcmp(NULL, name)`
reads `*NULL == 0`, treats it as an empty string, and returns a mismatch — no
fault. run88k left address 0 unmapped, so the read faulted.

Fix: `process.zig` `setupUtek` maps a **read-only zero page** `[0, 0x2000)`
(below the lowest text vaddr 0x2200). Reads of low/null addresses return 0;
null *stores* still fault (so real guest bugs are still caught). This is
genuine UTek process-layout behavior, not a workaround.

### Still blocked: the `/bin/as` shell wrapper (sh allocator corruption)

`cc` drives cpp → comp → **as** → ld. The `as` phase is a `/bin/sh` script.
With the zero page, sh no longer faults but instead **infinite-loops** in a
free-list walk (`while(*p){ *p = **p; }` at sh:0x11870) after the script's
command substitutions and string building — the list becomes malformed (a
node's link is 0/self-referential) only after the *cumulative* work of the
full script. Every isolated construct works (glob, `${V:-d}`, `$$`, command
substitution incl. `basename`→`expr`, `dirname`/`basename` concat, `shift`/
`while`/`case`/`break`, the exact `SGS` logic). This points to a subtle heap/
allocator corruption in sh that only surfaces after many allocations — a
distinct bug from ld's (verified `cmp`/`bcnd` against nono; `brk` semantics
checked). Root-causing it needs a dedicated sh allocator trace.

Consequence: full `cc`/`make` are blocked only by this sh issue. The
compiler and linker themselves are proven working; a build that avoids the
`as` shell wrapper (or once the sh bug is fixed) completes.

### awk works fully (isolates the sh bug)

`/usr/bin/awk` (88K BCS) runs correctly end to end, which is a strong signal
that the emulator's memory/allocator handling is sound and the sh hang is
sh-specific:

- `awk 'BEGIN{print 2+3}'` → 5; printf `%d/%s/%.2f`; `substr`/`index`;
  arrays + `for(k in a)`; `sprintf`.
- FP: a report script computes a floating-point average (`87.5`) — exercises
  SFU1 (the FPU work from core-fixes) alongside strings and arrays.
- A `-f` script with fields (`$1`,`$2`,`NR`,`NF`), arrays, accumulation, max
  tracking, `printf`, and `END` produces correct output over a data file.
- Allocator stress: 2000 array elements + `sprintf` per element completes fine.
  (An O(n²) repeated string-concat of ~14k chars merely exhausts the 200M
  instruction budget — it is slow, not a hang; n=1500 building a 10,890-char
  string completes.)
- The `-f` syntax-error exit path is clean (prints the diagnostic, exits).

Caveats (not emulator bugs): this 1990 awk predates `toupper`; and passing an
inline program as an argv string can mangle it (use `-f file`). Redirect from a
device like `/dev/null` needs that node present in the mounted root.

This makes the sh free-list infinite-loop a genuine sh-internal data-structure
corruption specific to that program, not a general emulator heap fault.

### make works; the sh bug narrowed to fork+heap-threshold

`/bin/make` runs correctly: it executes simple rule commands by exec'ing them
directly (`/bin/echo` etc., no shell), and uses `/bin/sh` for rules containing
shell constructs (a `for` loop rule works). `make hello` drives
`cc → cpp → comp` (all fine) and then hangs exactly at the `as` phase — the same
sh bug — and make correctly reports "Error code 1" when the child times out. So
make itself is fully functional; the sole blocker for `cc`/`make` is the sh
command-substitution hang.

Minimal reproduction of the sh hang (no `as` script needed):
```
sh -c 'x=; i=0; while [ $i -lt 30 ]; do x="$x abcdefgh"; i=`expr $i + 1`; done; echo done'
```
- Sharp threshold: **n=28 completes, n=30 hangs.** Needs BOTH the parent's
  growing-string allocation (`x="$x …"`) AND the per-iteration command
  substitution (each spawns a forked, then exec'd, `expr`).
- A pure command-substitution loop with no parent string growth runs fine to
  n=20+. So it is not fork/exec count alone — it is a parent **heap-size
  threshold** combined with fork+exec.

Root-cause chain established (via --watch/--trace-all):
- The hang is sh/expr's K&R-style malloc free-list coalescing loop
  (`while(*p){ *p = **p; }`) spinning because a free-list node's next-pointer is
  0 instead of the tagged sentinel `arena_base|1`.
- The corrupting process is a **forked + exec'd command-substitution child**.
  `fork` happens before the parent finishes building its free list; the child
  then execs (which zeroes memory and reloads), re-initializes malloc, yet its
  free-list walk reaches a node whose next is 0.
- Verified NOT a general emulator fault: awk does 2000 allocations cleanly; the
  CPU primitives (`cmp` incl. width variant, `bcnd` masks 2/13) and `brk`/`sbrk`
  semantics all match nono/the libc stubs. The corruption is specific to the
  fork→exec→malloc-reinit path at a heap-size threshold.

This is the single remaining blocker for full `cc`/`make`. The minimal repro
above is the entry point for the next debugging pass (watch the exec'd child's
malloc arena init and find which write/branch leaves the free-list node at 0).
