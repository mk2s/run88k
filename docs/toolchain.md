# Toolchain (as / cc / ld) — status

All three are dynamically-linked ELF (`interpreter /usr/lib/libc.so.1`), the same
class as `date`, and they all load + run their dynamic startup.

## RESOLVED: full `cc` compile works end-to-end

`cc -o hi hi.c` compiles a real C program (cpp -> ccom -> as -> ld) to a valid
`ELF 32-bit MSB executable, Motorola m88k, dynamically linked`, and the result
RUNS under run88k (prints via printf, returns its exit code). Verified:
```
$ cc -o hi hi.c          # hi.c: printf("hello from m88k cc\n"); return 3;
$ run88k ... run hi   ->  hello from m88k cc   (exit 3)
```

Three things had to be in place (all in the syscall layer):
1. **file-backed mmap with MAP_SHARED write-back.** `as` and `ld` build their
   ELF output in a `mmap(fd, MAP_SHARED)` of the output file and rely on
   `munmap` flushing the mapped bytes back to disk. `sysMmap` now `pread`s the
   file into the region on map; MAP_SHARED file maps are tracked (with a dup'd
   fd) and `munmap` `pwrite`s the region back. Without write-back, `as`
   produced a 0-byte `.o` (this was the real cause of the old "as faults on a
   real token" symptom — after earlier fixes it stopped faulting but silently
   wrote nothing).
2. **`--cwd <guest-dir>` flag.** `cc` runs its sub-tools with output paths
   relative to the CWD (e.g. `as` writes `t.o`, not `/work/t.o`). The guest CWD
   defaults to `/` (read-only root), so relative outputs failed with "Cannot
   Open Output File". Run with `--cwd /work` (a writable mount).
3. **New syscalls:** `memcntl (131)` (advisory cache/sync, no-op success),
   `chmod (15)` + `fchmod (93)` (ld sets the output's mode; path-resolved
   through the mount table). Plus `munmap (117)`/`mprotect (116)` from the
   size/nm work.

## Verified cc capabilities
- **`-O` optimization works**: `cc -O -o hi hi.c` produces a correct binary
  (optimizer register allocation, the `optim` pass — all fine).
- **Multi-translation-unit**: `cc -O -c -o a.o a.c`, `cc -O -c -o b.o b.c`,
  `cc -o prog a.o b.o` links and runs correctly.
- Exercised: recursion (fib), `%`/loops (gcd), string.h (strcpy/strcat/strlen),
  nested-loop sort, arrays, exit codes — all correct.
- **Language level is K&R / C89** (1991 CCCS). C99isms fail with real cc
  diagnostics: no `for(int i=...)` init-decls, no mid-block declarations. Use
  old-style function defs and top-of-block declarations.

## KNOWN: `cc` without `-o` faults (PROBABLE latent cc driver bug, NOT an emulator bug)
`cc foo.c` / `cc -c foo.c` / `cc -S foo.c` / `cc -V foo.c` (any invocation with
no explicit `-o`) faults with a NULL deref inside libc `strcmp` (guest pc
0x50341c8 = libc `strcmp` vaddr 0x341c8, `ld.bu r2,r3,r5` with r3=0). Traced
entirely to cc's own `main()` (Ghidra-decompiled, program `cc`):

- In the non-option-argument case (`case 0xffffffff:`, the input filename), cc
  does `derived = setsuf(name, 'o')` (turn `foo.c` -> `foo.o`) then
  `strcmp(derived, uStack_14)` to detect an output==input collision.
- `uStack_14` is main's local at stack slot **fp+0x7c**. It is written ONLY
  inside the `-o` option handler (`case 0x6f:`, cc code at 0x213ac and 0x213ec:
  `st r2,r31,0x7c`). The function prologue never initializes it.
- With no `-o` on the command line, `case 0x6f` never runs, so `uStack_14` is
  read uninitialized. Under run88k the entire guest address space is zero-filled
  at init (`mem.zig` `@memset(buf,0)`), so the slot reads as NULL and libc
  `strcmp(derived, NULL)` dereferences address 0 -> fault.

Every syscall on the path succeeded and the CPU faithfully executed the NULL
deref cc coded. The working `-o` invocations (`cc -o hi hi.c`, `cc -o x -c x.c`)
initialize the same slot to a valid pointer and never fault — confirming the
slot is the trigger.

This is a **probable cc bug** (use of an uninitialized local), masked on real
SysV/88 hardware because the stack slot would hold stale non-NULL garbage from a
prior frame; page 0 is unmapped there too, so a genuinely-NULL slot would fault
on real hardware as well. Our zero-filled stack is arguably *more* deterministic
than the hardware, which is what surfaces the latent bug.

Per decision: **noted as a probable cc bug; no emulator action taken.**
**Workaround: always pass `-o`.** (Mapping/seeding memory to paper over it was
rejected — it would mask genuine null-deref bugs.)

Note on tooling: nothing was wrong with Ghidra's ELF loader here — it loaded
`cc` correctly (image_base 0x20034, proper .text, 259 funcs, retained .symtab)
once a stale raw-binary import of the same name was removed. When multiple
programs are open, pass `program=<name>` explicitly on every Ghidra MCP call;
the default active program is not reliably the one just switched to.

## Requirements to run the toolchain
- Mounts: `--root <hd0_root> --mount /usr=<hd0_slice3>` as usual, PLUS a
  **writable temp** at the guest's temp path (`--mount /var/tmp=/tmp/guest_vartmp`)
  AND a **writable working dir** (`--mount /work=/tmp/asm88`).
- **`--cwd /work`** so sub-tool relative output paths land in the writable dir.
- **Always pass `-o`** (see the no-`-o` cc bug above).

## Syscalls added (surfaced by the toolchain)
- **unlink (10)**, **rename (134)**, **mkdir (80)**, **rmdir (79)**,
  **creat (8)** — path-resolved through the mount table (creat delegates to
  open with O_WRONLY|O_CREAT|O_TRUNC). `as` uses unlink/rename to manage its
  temp relocation file.
- **memcntl (131)**, **chmod (15)**, **fchmod (93)**, **munmap (117)**,
  **mprotect (116)** — see the cc section above.

## RESOLVED: `as` (/usr/ccs/bin/as) — WORKS
Assembles a real `.s` (directives + instructions) to a valid m88k ELF
relocatable. The former "faults / empty .o on a real token" was the
MAP_SHARED-writeback gap, now fixed.

## RESOLVED: the `lda` core bug (was blocking as/dis/cc)

The faults below were all one root cause: the m88k `lda`/`lda.d`/`lda.h`/`lda.b`
(load-address, scaled register-index) instructions were not implemented in the
core (op6 0x0c-0x0f fell into `memRegister`'s `else` and did nothing). `lda` is
the scaled `base + index*size` address-generation op, used everywhere in the
toolchain's table/array indexing. With it a no-op, pointers came out unaligned/
garbage, cascading into absurd malloc sizes (e.g. the infamous `0x50000000` =
`20 * 0x4000000`, where 0x4000000 was an unaligned load off a bad pointer).
Fixed in `musashi88k/src/decode.zig`; see `docs/core-fixes.md` #4.

After the fix:
- **`as`** assembles real m88k instructions (`text`/`global`/`or`/`jmp`) to a
  valid ELF relocatable object.
- **`dis`** produces a full correct disassembly of a real object (crt1.o).
- **`date`** and the static utilities remain unregressed.

## `as` (/usr/ccs/bin/as) — WORKS (was PARTIALLY WORKING)
- **Empty / comment-only / whitespace-only input assembles to a valid m88k ELF
  relocatable object** (verified: `file` reports "ELF 32-bit MSB relocatable,
  Motorola m88k"). So the dynamic loader, libc, file I/O, and ELF object
  emission all work end-to-end.
- **Any input containing a real token (a label, a directive, or an
  instruction) faults**: `as` computes an out-of-bounds index into one of its
  tables and stores/loads past the end of its heap (fault at a ~0x1ffcxxx or
  ~0x4baxxx address).

### Investigation so far (not yet resolved)
The fault traces to `as` reading a packed two-halfword counter word (e.g.
`0x00010002`) with a full-word `ld` and using it as a table index (scaled ×4 in
an `lda`), producing a multi-megabyte offset. Every individual instruction on
the path was replayed through the nono MC88100 oracle and **matched**:
`ld.hu`, `st.b`, `cmp`, `lda`, `mak` all agree. A dedicated unit test confirmed
`st.b` writes the correct big-endian byte offset (an earlier "wrong offset"
reading was a difftrace artifact from reporting an *unaligned* word; difftrace
now masks the reported mem address to the aligned word).

So the divergence, if it is an emulator bug, is upstream of the fault and not
yet localized; alternatively `as` depends on some memory/syscall state we don't
reproduce faithfully. Next step is a broader lockstep diff (bulk-replay a window
of the first-token path against nono) to find the first divergent register
value, the same method that found the `ext`, register-indexed-load, and
`ld.hu`/`ld.bu` core bugs.

## cc (/usr/ccs/bin/cc) — driver runs
`cc` runs its driver and produces real diagnostics (e.g. rejects `-S -o x.s`
with "assembler output does not end in .o"), i.e. option parsing + the fork/exec
of sub-tools is exercised. A full compile currently hits a null-pointer load in
libc downstream (needs the same lockstep treatment, likely the same root cause
as `dis`).

## dis (/usr/ccs/bin/dis) — runs; faults inside a specific libc malloc path
- **Usage message and empty/`.text`-less objects work** (`dis empty.o` prints
  "no data in section .text"). ELF parsing + libc I/O are fine.
- **Disassembling an object with code (e.g. crt1.o) faults**: libc's malloc
  requests `brk(0x50060140)` — i.e. `0x50000000 (libc load bias) + 0x60140
  (the real program break)`. Our brk rejects an address in the library region,
  malloc returns NULL, and `dis` dereferences it (`ld r13,r2,0x8` with r2=0).

### Root cause (partially localized, not yet fixed)
Traced with difftrace+nono into a libc heap/`morecore` routine (unbiased vaddr
~0x33340) that `date` never reaches (`date` uses a simpler malloc path — this is
why `date` works and `dis` doesn't, on the same libc). That routine computes the
heap arena base from a register that holds **0x50000000, the library load bias**,
then adds the program break. Every individual instruction on the path matches
the nono oracle; the 0x50000000 is a *data value* that flows in, not a
miscomputation. So libc's malloc is using the library's mapping base as the heap
origin, which is wrong in our layout (libraries load at 0x5000000+0x800000*n; the
heap should grow from the executable's break).

Notes gathered:
- libc's `_end`/`_edata`/`_etext` are **SHN_ABS** and live only in libc's
  **.symtab, not .dynsym**, so the dynamic linker never sees them; and libc has
  **no named relocation** for them (they're referenced via nameless RELATIVE
  relocs). Break/malloc globals (`_nd`, `curbrk`, `sbrk`, ...) are **not in
  libc's .dynsym** either, so the `_nd` seed in dynamic.zig silently no-ops for
  this libc — libc tracks the break internally and initializes it via an
  `sbrk(0)` query (which our brk services correctly: the first `sbrk(0)`
  returned the right break 0x5a13c, and the first grow `brk(0x5e140)` was
  correct).

### Fix applied this session (correct regardless)
`dynamic.zig` `lookup()` now returns **SHN_ABS** symbol values **without adding
the object bias** (linker-defined absolute markers like `_end` must not be
biased). This did not fix `dis` (libc doesn't reach `_end` via a named lookup),
but it is correct and guards against the ABS-biasing class of bug.

### Next step for dis/cc
The remaining issue is a dynamic-layout / libc-malloc-arena interaction, not a
single-instruction core bug. Likely needs the library/heap layout to match what
libc's `morecore` assumes (heap contiguous above the executable, libraries out
of the way), or targeted correction of the arena-base value libc derives.
Substantial dynamic-linking work rather than a quick patch.
(NOTE: the dis/cc arena issue above was later resolved by the `lda` core fix —
see core-fixes.md #4 — dis now works.)

## nm / size (/usr/ccs/bin) — RESOLVED (work correctly)

`size` and `nm` now produce correct output on real ELF objects:
```
$ size crt1.o           -> 204 + 64 + 0 = 268
$ size dis              -> 80860 + 21392 + 4508 = 106760
$ nm crt1.o             -> full symbol table (Index/Value/Size/Type/Bind/Shndx/Name)
```

### Root cause (three independent gaps, all in the syscall layer)
The tools' libelf reads the object with a **file-backed `mmap`**, then prints
via buffered stdio. Three missing pieces each blocked output:

1. **File-backed `mmap` was unsupported.** `sysMmap` rejected any `mmap` with a
   real fd (returned EINVAL). libelf then fell back to a malloc+read path that
   leaves the cached Ehdr unpopulated, so `elf_getehdr` (the REAL one,
   FUN_000211e0's `bsr 0x23920`) returned NULL and the printer bailed. **Fix:**
   `sysMmap` now honors file-backed `MAP_PRIVATE`: allocate a region and `pread`
   the file bytes (at the requested offset) into it. libelf's ehdr translation
   then reads straight from the mapping.
2. **`munmap` (117) / `mprotect` (116) were unimplemented** -> fault right after
   the file was processed. **Fix:** accept and return success (we don't reclaim
   the range; `mmap_next` only grows downward, which is fine).
3. **`ioctl(TCGETA)` always returned ENOTTY** -> stdout was fully buffered, and
   `size`/`nm` `_exit` without flushing, so the buffered output was discarded.
   **Fix:** `sysIoctl` handles TCGETA/TCSETA by consulting `isatty()` on the
   mapped host fd. On a terminal it reports tty-ness (fills a plausible
   `struct termio`), so stdio line-buffers stdout and each newline is written
   immediately -> output appears. On a pipe/file it still returns ENOTTY
   (block-buffered), matching real behavior.

Note the earlier "FUN_00023868 is elf_getehdr / +0x6c cache" theory was a
misidentification: 0x23868 is an archive-member getter (`elf_getarhdr`-like);
the real `elf_getehdr` is `bsr 0x23920` inside the printer FUN_000211e0, and it
succeeds once the file is mmap'd. handle+0x6c (written only by the kind==1
archive-member parser) is legitimately 0 for a plain ELF and is not the issue.

### Verified working after the fix (whole libelf inspection family)
- `size` -> `204 + 64 + 0 = 268`
- `nm` -> full symbol table
- `dump -fh` -> ELF header + section header table
- `mcs -p` -> comment/version section
- `ar t <lib.a>` -> archive member listing (exercises the kind==1 archive path
  end-to-end)
- `m4` -> `define(x,hi)x` yields `hi`. The docs previously filed m4's no-output
  as a separate temp-file/diversion issue; it was the SAME stdout-buffering
  problem and the ioctl line-buffering fix resolved it too.

### Verified unregressed
`dis`, `date`, `echo`, `ld -V`, static utilities, single `sh -c` commands;
`zig build test` green; musashi `zig build difftest` 39/39.

Note: `lorder` is a `/bin/sh` script (not ELF), so `run88k run <hostpath>`
rejects it with "NotElf" — invoke it through the guest shell instead.

--- historical notes (pre-fix) below ---

Both run, link, parse options (getopt/optind correct), and hit the error path
cleanly (`size /nonexistent` prints "cannot open"). On a VALID ELF they read the
file but print nothing.

### Fix applied: uname(2) return value (mmap availability probe)
libelf's `_elf_inline`/mmap-availability probe (FUN_00026198) calls `uname(2)`
and treats a return `> 0` as "mmap available", `<= 0` as "use malloc+read".
Our `uname` returned 0 (Linux convention); **SysV/88 `uname(2)` returns a
positive value (1)** on success. Fixed `sysUname` to return 1. This moved
size/nm onto the mmap code path (matching what `dis` does), which is the correct
behavior — verified dis/date/sh/echo unregressed.

### Scope: shared across the libelf inspection tools
A ccs survey shows the no-output issue is a **single shared libelf root cause**,
not per-tool:
- **No output on a valid ELF (crt1.o):** `size`, `nm`, `dump`, `mcs` — all the
  tools that read section/symbol data via `elf_getehdr` + section access.
- **Works:** `dis` (uses a different/lower-level libelf path), `ld -V` (version
  banner). Usage/option-error messages print fine for ALL tools (dump, nm, ar,
  yacc, lex, strip) — so stdout/stderr and early output work; the failure is
  specifically in the libelf ehdr/section-read path.
- **Separate issue:** `m4` (not libelf) also produces no output — it routes all
  output through temp-file "diversions" (`/tmp/m4aXXXXX`) and the diversion
  write/read-back path yields nothing; distinct from the libelf family, tracked
  separately.

Fixing the one libelf ehdr-cache bug should light up size/nm/dump/mcs together.

### Still open: ELF-header cache never populated
After the mmap fix, `size`'s libelf still fails at `elf_getehdr` (FUN_00023868):
it reads the Elf handle's cached ehdr pointer at offset +0x6c, finds it 0, sets
error 0x501, and returns NULL -> "invalid file type" -> no output. The parser
that would set +0x6c (FUN_00021d28) is never reached: `elf_begin`'s recognition
sets the handle's kind (+0x4c) to 3 (ELF_K_ELF), and the parser is gated on
kind==1. The gate `cmp(kind,1)` / `bb0 #3` was verified to behave correctly
(kind=3 legitimately skips the kind==1 path). So the ehdr must get parsed by a
path we're not triggering — not yet localized to a single divergent instruction.
This differs from `dis`, which uses libelf's low-level section walk and works.
Deferred.


---

# NetBSD/luna88k toolchain — status

GCC 3.3.6, static binaries under `/usr/bin` (as/ld/cc/gcc/cpp) + `/usr/libexec/{cc1,cc1plus,cc1obj}`.

## Working
- **`/usr/bin/as`** — assembles a `.s` to a valid ELF32-BE MC88000 relocatable
  (byte-exact `.text`, correct symtab/sections) on the first try.
- **`cc -c hello.c`** — the full driver forks **cpp → cc1 → as** and produces a
  valid 888-byte ELF object (`main` FUNC + `printf` UND). Verified clean under
  host `readelf`.
- **`make`** — drives rules correctly: `@`-silenced multi-command rules,
  `cc -c` via fork/exec/wait, `rm` (clean), dependency up-to-date checks, and
  correct error propagation on failure (`*** Error code 1` / `Stop`).

Two fixes were needed for the driver to find its sub-tools:
1. **argv[0] must be the guest path.** The run target is a host path (so we can
   read the file), but GCC derives its tool-search *exec prefix* from argv[0].
   Leaving `/mnt/netbsd/usr/bin/cc` there made cc look for `cc1` at
   `/mnt/netbsd/usr/bin/cc1` (then PATH-fall-back `/bin/cc1`) and never find
   `/usr/libexec/cc1`. Fix: `fs.hostToGuest()` reverse-maps the host path
   through the mount table, and `cmdRun` rewrites argv[0] to the guest path
   (`/usr/bin/cc`). Benefits every personality's toolchain.
2. The vfork r2/r3 dual-return and `/dev/stdin` fdesc fixes (see
   `docs/abi-netbsd.md`) were prerequisites for cc's fork/exec of its phases.

## RESOLVED: full `cc -o` / `make <exe>` works end-to-end

`cc -o hello hello.c` now compiles AND links a real C program (cpp → cc1 → as →
**ld** against the static `/usr/lib/libc.a`) to a valid statically-linked
`ELF 32-bit MSB executable, Motorola m88k, for NetBSD`, and the result **runs**
under run88k (prints via printf, returns its exit code). `nm /usr/lib/libc.a`
also reads to completion, and `make <exe>` drives the whole pipeline.

### Root cause: lseek 64-bit return word order (a SYSCALL bug, not a core bug)
`lseek` returns a 64-bit `off_t`. On big-endian m88k a 64-bit value in a
register pair is **high word first**, so the kernel returns the new position as
**r2 = high word, r3 = low word**. Our `sysLseek` returned it backwards
(`returnSuccess2(lo, hi)` → r2=lo, r3=hi). For any position ≥ a few KB, libc/BFD
read the LOW word (e.g. `0xc000`) as the HIGH half of its 64-bit file position;
every subsequent seek then targeted `position << 32`, the host rejected it
(EINVAL), and BFD reported the archive as "File truncated". Fix: `sysLseek`
returns `returnSuccess2(hi, lo)` (r2=hi, r3=lo). One line; unblocked the entire
linker/`nm`/toolchain.

How it was found (the method matters for the sibling personalities): built
`tools/m88k_eval.py`, an offline evaluator that recomputes every traced
instruction's result (ALU, carry chain, bit-field, loads-vs-memory, and
store-value verification) and found **zero** CPU divergences in the whole
failing run — proving the core executed faithfully and the bad data had to enter
via a syscall return. Back-tracing the bad high word through loads/stores/adds
landed on a `tb0` (syscall) as the source register's writer: the lseek return.

The investigation write-up below is kept as historical record.

### (historical) What was traced before the fix
ld issues an `lseek` on the archive (via the indirect `__syscall`(198) gate,
real number 199) with a **64-bit `off_t` whose HIGH word is a bogus member-base

### What was traced
ld issues an `lseek` on the archive (via the indirect `__syscall`(198) gate,
real number 199) with a **64-bit `off_t` whose HIGH word is a bogus member-base
value** (e.g. `off_hi=0x192000, off_lo=0x1000`), which the host rejects
(`pos=-1`), so ld concludes the archive is truncated. Good seeks in the same run
have `off_hi=0`. The off_t register pairing is confirmed CORRECT (decoded the
lseek stub `0x9c220` → the inline `__syscall` gate `0x877a0`; after the
shift-by-2 the args are fd=arg0, pad=arg1, off_hi=arg2, off_lo=arg3,
whence=arg4). So ld is genuinely being handed a bad high word — the value flows
from ld's own 64-bit archive-offset arithmetic (`subu.co/subu.ci` then
`addu.co/addu.ci`, and a page-align `and` of an `ext`-sign-extended pair around
`ld` PC `0x89500–0x89600`). This points at a **musashi88k core divergence** in
that 64-bit sequence (candidate ops verified individually against nono —
`ext rD,rS,32<31>` and the `addu.co/.ci` carry chain each compute correctly in
isolation — so the divergence is likely an *interaction* / an upstream value,
not one of those ops alone).

### Repro + tooling for next session
- Reproduce ld directly (no cc): compile a fixed object then run ld:
  ```
  run88k --root /mnt/netbsd --mount /work=/tmp/nbwork --cwd /work \
     run /mnt/netbsd/usr/bin/cc -c hello.c
  run88k --root /mnt/netbsd --mount /work=/tmp/nbwork \
     run /mnt/netbsd/usr/bin/ld -dc -dp -e _start \
     -dynamic-linker /usr/libexec/ld.elf_so -o /work/hello \
     /usr/lib/crt0.o /usr/lib/crti.o /usr/lib/crtbegin.o -L/usr/libexec \
     /work/hello.o -lgcc -lc -lgcc /usr/lib/crtend.o /usr/lib/crtn.o
  ```
- **`difftrace` is now NetBSD-aware** (`src/difftrace.zig` auto-selects the
  NetBSD personality/vector/startup from the ELF note). Generate a JSONL trace
  over a PC window and replay against the nono oracle with
  `tools/difftrace.py` to find the first divergent instruction, e.g.:
  ```
  run88k --root /mnt/netbsd --mount /work=/tmp/nbwork \
     difftrace /mnt/netbsd/usr/bin/ld <lo> <hi> <max> <ld args, output to /work/...>
  ```
  NOTE: difftrace has no `--cwd`, so pass absolute guest output paths
  (`-o /work/hello`, `/work/hello.o`). A first attempt hit a *different* offset
  in the difftrace run than the full `cc -o` run (setup/argv differences), so
  the next step is to widen the window to cover ld's whole archive-read path and
  replay from the start to find the FIRST divergence, rather than assuming the
  page-align `and` at `0x895e8` is the fault (it computes correctly on the
  values seen in the difftrace instance).

### Session 3 reframing — likely NOT a CPU-core bug; suspect archive data
Built `tools/m88k_eval.py`, an offline m88k evaluator that recomputes each
traced instruction's result from its own pre-state + opcode (and, for loads, the
captured memory word) and flags the first mismatch vs the recorded post-state —
no per-instruction nono calls needed. Extended `src/difftrace.zig` to capture the
SECOND word of doubleword mem ops (`mpre2`/`mpost2` for `ld.d`/`st.d`).

Ran it on a much simpler repro — **`nm /usr/lib/libc.a`** also fails "File
truncated" (reads several members, then fails at a specific one). Results across
the whole failing run (637k instructions, 261k modeled):
- **Zero divergences** in: all ALU-immediate ops, triadic reg ops incl. the
  `addu.co`/`addu.ci`/`subu.co`/`subu.ci` carry chain, `and/or/xor/mask/cmp`,
  the bit-field group (`ext/extu/mak/rot/clr/set`), word `ld`, `ld.d` (both
  words vs memory), and **store verification** (`st`/`st.d` wrote the correct
  source-register value).
So run88k executes this instruction stream **faithfully** — the CPU core is not
mis-computing anything on this path.

The failing `lseek` offset is genuinely built by nm/ld as a 64-bit `off_t` with
the member file-offset (e.g. `0xd000`, `0x192000`) in the **HIGH word** and a
small delta in the low word (`{hi=0xd000, lo=0}` etc.). Traced all the way back:
that high-word value is *carried consistently* through loads/stores/adds from a
struct field in nm's memory — every step verified correct. Since real NetBSD nm
does NOT do this, the divergence must come from **input DATA**, not instruction
execution: the only thing entering the CPU from outside is what our syscalls
return. Prime suspect: the **archive `read()` content / binary armap**
(`__.SYMDEF`, big-endian 32-bit member offsets) — if nm parses a member offset
into the wrong half of a 64-bit field because the bytes it read differ from the
real file (wrong offset, short read, or a byte-order/packing mismatch in how nm
reads the armap under our environment), it would then *correctly* compute a bad
64-bit seek.

**Next step:** dump the exact bytes `read()` delivers for libc.a around the
armap and the failing member header, and diff against the real file bytes at the
same offsets. Also worth checking: whether nm/ld take a different code path based
on some earlier syscall result (e.g. an `fstat` field, `sysctl`, or `fcntl`)
that we answer differently from the real kernel, steering it into a 64-bit-offset
branch it shouldn't use. `tools/m88k_eval.py` + the dbl-word difftrace are kept
for the continued hunt.

### Session 2 notes (superseded by session 3 reframing above) — ruled out the two known prior culprits
Two fixes from the OpenBSD toolchain bring-up (commit `c3b60bb`) were the first
suspects, matching a "lseek word-order / stack-not-cleaned" memory:
- **exec-time register-file cleanup** (zero r0..r31 + clear `branch_pending` on
  exec): **RULED OUT** — running `ld` *directly* (a clean top-level process, no
  fork/exec) fails identically to the cc-forked `ld`. So it is not stale-state.
- **lseek off_t word order** (OpenBSD's was initially `off_lo=arg2/off_hi=arg3`,
  corrected to `off_hi=arg2/off_lo=arg3`): **RULED OUT** — NetBSD already uses
  the corrected order, small in-range seeks (off in the low word) succeed, and
  no hi/lo swap makes the failing seek (`hi=0x192000, lo=0x1000`) sane.

Backward dataflow from the failing `lseek` (via a full-register `difftrace` of
direct `ld`, window `0x88000–0x8a000`, 12.8k rows that reproduce the failure):
the bad 64-bit `off_t` `{hi=0x192000, lo=…}` is **carried in the high word from
very early** and merely copied/added along the chain
(`lseek arg ← r4:r5 ← r14:r15 ← st.d@0x5ab4c → ld@0x617bc → addu.co/.ci@0x617c0
→ …`). At every step checked, the arithmetic is CORRECT:
- `ext r16,r17,32<31>` (sign-extend) — matches nono for all executions.
- `addu.co`/`addu.ci` 64-bit carry chain — matches nono (verified a carry case
  on the oracle: `0xfffff000+0x2000` then `+carry` gives the right high word).
- All ALU-immediate ops recompute-check clean across the whole window.
`0x192000` itself is a **legitimate** 32-bit file offset (`0x191ffc + 4`, a real
libc.a member position) — it is only wrong in that it sits in the HIGH word.

**Current best hypothesis:** since every *register* op on the path matches the
oracle, the divergence is most likely a **load reading wrong bytes** (a
register-indexed / `.d` load from a miscomputed address, or memory corrupted by
an earlier mis-targeted store) somewhere in ld's archive **armap** (symbol
index) reading, which then seeds the swapped-looking 64-bit offset. This matches
the documented core-fix history (register-indexed load, `ld.hu`/`ld.bu` decode).
The definitive next step is a **full first-divergence replay** of the direct-`ld`
trace against nono (not spot checks): walk the trace, replay each op from its
pre-state through the oracle, and stop at the first post-state mismatch — that
pinpoints the faulting instruction. difftrace is NetBSD-aware now, so the only
missing piece is an automated per-row oracle-replay loop over the (large) trace.


## NetBSD kernel build attempt (GENERIC/luna88k)

Tried building a real NetBSD/luna88k GENERIC kernel from the host source tree
(`~/Documents/netbsd-src`, current NetBSD) using the guest 3.0.1 toolchain,
mounted as `--mount /usr/src=<tree>` plus a writable `--mount /tmp=<dir>`.

Got a long way:
- **`config GENERIC`** runs under run88k and generates the full compile
  directory (Makefile + all config `.h` headers + the `machine`/`m88k`
  symlinks).
- **`make`** drives the real kernel build: `cc -ffreestanding -O2 ... -c` on
  kernel sources, `genassym.sh` (awk) generates `assym.h`, `locore.o` (assembly
  via `cc -x assembler-with-cpp`) compiles. **5 kernel objects compiled**
  cleanly (swapnetbsd.o, devsw.o, ioconf.o, param.o) before hitting the issue
  below.

Two real run88k bugs were found and fixed doing this:
1. **`/dev/null` (and `/dev/zero`, `/dev/tty`) open support.** `config`/`make`
   open `/dev/null` constantly; we only handled `/dev/std*` + `/dev/fd/N`.
   `sysOpen` now opens the host equivalent directly for these nodes.
2. **argv entries truncated at 255 bytes.** `sysExec`'s `readStrVec` used a
   `[256]u8` per-arg buffer. The kernel build's `genassym.sh`/`m88k-move.sh`
   pass a ~1.5 KB awk program as a SINGLE argv entry; truncation cut it mid-
   program ("awk: syntax error at source line 12", empty context). Now uses a
   4 KB per-arg buffer, heap-allocated (via the procmodel gpa) to keep the exec
   stack frame small. This affects any long command line, not just the kernel.

Two environment mismatches (not run88k bugs), worked around:
- Needs a **writable `/tmp`** (`genassym.sh` writes `/tmp/$$.c`): mount one.
- **`config_file.h`**: the host `param.c` `#include`s it unconditionally, but
  the 2005-era guest `config(8)` does not emit it (version skew between the
  current source tree and the 3.0.1 config binary). A minimal stub
  `config_file.h` in the compile dir gets past it.

### Open bug: cc1 infinite loop compiling `netinet/igmp.c` (diagnosis so far)
Narrowed extensively (session 4):
- **Optimizer-only:** `-O0` compiles igmp.c fine; `-O1` and `-O2` both hang.
- **One function:** bisected the preprocessed `igmp.i` per-function — only
  **`igmp_input`** hangs; all 9 other functions compile at -O2. (igmp_input is
  the big ~240-line function with four nested `switch`es on IGMP state.)
- **Deterministic infinite loop, not slow work:** two runs stop at the
  byte-identical recent-PC ring. The hot loop is cc1 code at
  **0x19c20c–0x19c25c** repeatedly calling GCC's **`bitmap_bit_p`** (0x200d90)
  and another bitmap routine (0x201c70) — i.e. GCC's bitmap-based **dataflow**
  fixpoint never converges. The loop-head register trace shows a **cyclic**
  pattern: a pointer `r17` walks heap nodes and a counter `r24` cycles
  4→3→2→…→0x1e→4… — a data structure GCC expects to be acyclic has become
  circular.
- **CPU executes faithfully where traced:** `tools/m88k_eval.py` found ZERO
  divergences across ~1.09M modeled cc1 startup ops and the 20k-instruction loop
  window; `extu rD,rS,rS` (the bit-extract in `bitmap_bit_p`, incl. offset 31)
  matches nono. So this is the same "faithful CPU, corrupted DATA" shape as the
  lseek bug — the corrupting write happens somewhere in cc1's earlier analysis
  (buried in ~200M instructions before the visible loop) and hasn't been
  surfaced yet.
- **Red herrings:** at `-O1`, disabling almost any single pass (`-fno-gcse`,
  `-fno-thread-jumps`, …) avoids the hang, but NONE of them fix it at `-O2`
  (they just perturb the RTL). So it is not one specific pass.

**Next:** the corruption is upstream of the visible dataflow loop. Options:
(a) window-difftrace the bitmap routines themselves (0x200d90 and 0x201c70) to
verify their internal ops against nono; (b) find where the cyclic list/`r17`
chain is built and diff that construction against the oracle; (c) since cc1 for
other files works, diff igmp_input's cc1 run against a known-good short function
to bisect which analysis phase diverges. This is a large differential effort;
the CPU-faithful evidence suggests looking for a bad STORE/pointer computation
(the class the offline evaluator can't see once it's in memory), same as lseek.

Repro (isolated, no make/driver needed):
```
# preprocess once: cc ... -E -o /tmp/igmp.i ../../../../netinet/igmp.c
cc1 -fpreprocessed igmp.i -quiet -O2 -o out.s      # hangs (igmp_input)
cc1 -fpreprocessed igmp.i -quiet -O0 -o out.s      # OK
```
A ready repro is staged: `repro/igmp.i` + `tools/repro-igmp-hang.sh`.

### RESOLVED: it was the step budget, not a bug
The "hang" was **not** an infinite loop or a core divergence — the emulator's
per-process instruction budget (`default_max_steps`, formerly 200M) was simply
too small for a heavy `-O2` compile. Real NetBSD/m88k under nono full-system
needs ~83s of user CPU to compile igmp.c at -O2; an interpreting emulator runs
~50–100× slower, so the real emulated instruction count is in the **billions**,
far past 200M. run88k hit the budget mid-compile and printed
"timed out (runaway?)" with a loop-looking recent-PC ring (just a snapshot of a
long-but-finite compile). FPU was ruled out along the way (cc1 executes ZERO
SFU1/FP instructions on igmp.i).

**Fix:** `machine.Runner.default_max_steps` raised to 20e9 and made a `pub var`;
the run loop treats `max_steps == 0` as unlimited; `main.zig` adds
`--max-steps N` (0 = unlimited). With this, `cc -O2 igmp.i` completes in ~26s
(exit 0, valid 1237-line .s) and `make igmp.o` produces a 7272-byte object. The
full GENERIC kernel `make` then compiles cleanly through every file (the whole
TCP/IP stack: in.c, ip_input.c, ip_icmp.c, …) with zero errors — it's just slow
(hundreds of files × tens of seconds each under interpretation = many hours).

### RESOLVED: the final link — argv entry-count cap (256 → 1024)
The final `ld` step of the kernel link initially produced 3232 bogus "undefined
reference" errors. The `ld` command GENERIC emits lists one token per object
file — **>300 argv tokens** for GENERIC. `sysExec` capped the argv/envp vectors
at **256 entries** (`argv_store: [256][]const u8`, `alloc([4096]u8, 256)`),
silently truncating the object list; every symbol defined in a dropped object
then looked undefined. (Running the same `ld` directly with `$OBJS` gave 0
undefined; only the shell-driven `>256`-token form failed — the tell.)

Raised `ARG_MAX_COUNT` to **1024** (with `ARG_MAX_LEN` still 4 KB per arg).
`readStrVec` already bounds by `out.len`, so it picked up the new size. After
this, the GENERIC/luna88k kernel links to completion:

```
#      link  GENERIC/netbsd
ld -N -Ttext 0x20000 -e start -S -o netbsd ${SYSTEM_OBJ} ${EXTRA_OBJ} vers.o
   text	   data	    bss	    dec	    hex	filename
1410012	  67136	  84448	1561596	 17d3fc	netbsd
```

Result: a valid **1.72 MB static ELF32-BE MC88000** `netbsd` kernel, entry
`start` @ 0x20000, with `.text`/`.rodata`/`.data`/`.bss` and the expected
kernel symbols (`main`, `cpu_startup`, `version`, `copyright`). A full
NetBSD/luna88k GENERIC kernel builds and links end to end under run88k.

Build invocation (root mounted at /mnt/netbsd, source tree + writable /tmp):
```
run88k --os netbsd --root /mnt/netbsd \
  --mount /usr/src=<netbsd-src> --mount /tmp=<writable> --max-steps 0 \
  --cwd /usr/src/sys/arch/luna88k/compile/GENERIC \
  run /mnt/netbsd/usr/bin/make netbsd
```
(First: `config GENERIC`, then stub `config_file.h` — see notes above.)

Lesson: distinguish "timed out at the step budget" from "infinite loop" before
assuming a bug — bump `--max-steps` (or use 0) first. Everything below this line
is the earlier (mistaken) bug hunt, kept for the record.

### FPU ruled OUT
The nono full-system log showed the guest kernel logging `rte: SFIP.V==0 (NOT
IMPLEMENTED)` during the compile, suggesting FP exceptions — but instrumenting
run88k showed cc1 executes **zero SFU1 (FP) instructions** compiling igmp.i (at
both -O0 and -O2). Those `rte` messages are unrelated kernel background noise.
So the FPU is not involved; it's an **integer** divergence.

### Refined conclusion: a control-flow divergence the offline evaluator can't see
`tools/m88k_eval.py` verifies each instruction's *destination value*
independently (ALU, carry, bit-field, loads-vs-memory, store value, AND store/
load effective-address) and found ZERO divergences across every window traced.
But it validates each instruction **in isolation from its own recorded
pre-state** — it structurally **cannot** detect a WRONG BRANCH (a `bcnd`/`bb1`/
`bb0` condition or a delay-slot interaction computed wrong): a mis-taken branch
yields a different instruction *sequence*, yet each instruction in that (wrong)
sequence still "matches" when recomputed from its own pre-state. Basic
delay-slot mechanics are oracle-verified (see core-fixes.md), but subtle cases
(condition-mask evaluation, a delay slot that modifies the branch's condition
register, nested/back-to-back delayed branches) are not exhaustively covered.
This "faithful per-instruction, wrong sequence" shape matches the symptom (a
GCC dataflow/list structure that becomes cyclic → non-terminating loop, with all
data values individually correct).

**Next tool needed:** lockstep PC comparison against nono — replay the
instruction stream through the oracle letting NONO choose each next PC, and stop
at the first PC that diverges from run88k. That catches control-flow bugs the
value-only evaluator misses. The challenge is reaching the divergence (~200M
instructions into cc1); needs a checkpoint/fast-forward or a much smaller repro
(bisecting igmp_input's body further — `cut_d` = body through line 217 already
reproduces).

### (superseded) earlier note: cc1 runaway loop compiling `netinet/igmp.c`
With the above in place, compiling the first real networking source
(`../../../../netinet/igmp.c`) makes **cc1 spin forever** — run88k times out at
200M instructions. The recent-PC ring shows a tight ~15-instruction loop in cc1
at **0x1f2288–0x1f22e0** (back-edge `bb1` at 0x1f22e0). The loop is bit-field /
find-first-bit heavy (`ext`/`mak` and `f0a89822`/`f0a99828` which look like
`ff1`/`ff0`). Earlier files (param.c etc.) compiled fine, so cc1 works broadly;
igmp.c triggers a non-terminating loop — likely a subtle CPU-core edge case
(off-by-one in a bit-scan/`ff1`/`ext` width) that never satisfies the loop exit,
or a genuinely long computation. **Next:** difftrace that PC window
(`0x1f2280 0x1f22f0`) and replay against nono / the offline evaluator
(`tools/m88k_eval.py`) to find the first divergent instruction, same method that
cracked the lseek bug. Repro:
```
config GENERIC ; echo '/* stub */' > .../compile/GENERIC/config_file.h
make igmp.o     # (with --mount /tmp=<writable> and /usr/src=<tree>)
```
