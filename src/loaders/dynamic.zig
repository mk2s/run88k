//! Minimal ELF dynamic linker for run88k (our own ld.so, eager binding).
//!
//! SysV/88 dynamically-linked binaries (date, cc, as, ld, ~76% of userland)
//! reference an interpreter (/usr/lib/libc.so.1) and NEEDED shared libraries,
//! with a PT_DYNAMIC section and .rela.plt/.rela.bss/relative relocations.
//! Rather than run the guest's own runtime linker, we resolve everything at
//! load time:
//!   1. Load the main object (done by elf.load).
//!   2. Load each NEEDED library (recursively) at a fresh load bias, via the
//!      guest mount table (fs), collecting their exported symbols.
//!   3. Apply relocations for every object:
//!        R_88K_RELATIVE (16): *addr += bias        (base fixups in libs)
//!        R_88K_COPY     (1):  copy the symbol's bytes into the exe .bss
//!        R_88K_JMP_SLOT (2):  write the resolved function address into the GOT
//!        (data/abs relocs handled generically: *addr = sym_value + addend)
//!   Eager binding: JMP_SLOT is resolved to the final target now, so guest
//!   calls go straight through the GOT with no lazy-resolution trampoline.

const std = @import("std");
const mem = @import("../mem.zig");
const elf = @import("elf.zig");
const fsmod = @import("../fs.zig");

const rd32 = elf.rd32;

const DBG = false;
extern "c" fn dprintf(fd: c_int, fmt: [*:0]const u8, ...) c_int;
fn dbg(comptime fmt: []const u8, args: anytype) void {
    var buf: [160]u8 = undefined;
    const line = std.fmt.bufPrint(buf[0 .. buf.len - 2], fmt, args) catch return;
    buf[line.len] = '\n';
    buf[line.len + 1] = 0;
    _ = dprintf(2, "%s", @as([*:0]const u8, @ptrCast(&buf)));
}
fn dbgPreempt(name: []const u8, slot: u32, old: u32, new: u32) void {
    dbg("reloc-preempt {s}: slot={x} {x} -> {x}", .{ name, slot, old, new });
}

pub const Error = error{
    NotElf,
    NotElf32,
    NotBigEndian,
    NotM88k,
    BadProgramHeaders,
    LoadOutOfRange,
    NotExecutable,
    LibraryNotFound,
    TooManyObjects,
    UnresolvedSymbol,
    OutOfMemory,
};

// Dynamic tags.
const DT_NULL = 0;
const DT_NEEDED = 1;
const DT_PLTRELSZ = 2;
const DT_PLTGOT = 3;
const DT_HASH = 4;
const DT_STRTAB = 5;
const DT_SYMTAB = 6;
const DT_RELA = 7;
const DT_RELASZ = 8;
const DT_RELAENT = 9;
const DT_STRSZ = 10;
const DT_SYMENT = 11;
const DT_JMPREL = 23;

// m88k relocation types (authoritative: DG/UX usr/include/sys/elf_88K.h).
const R_88K_COPY = 1; // copy symbol bytes into exe .bss
const R_88K_JMP_SLOT = 2; // R_88K_GOTP_ENT: resolve fn into GOTP slot
const R_88K_BBASED_32 = 16; // *addr = value + bias   (a.k.a. our "RELATIVE")
const R_88K_BBASED_16H = 18; // *(u16)addr = (value + bias) >> 16
const R_88K_BBASED_16L = 19; // *(u16)addr = (value + bias) & 0xffff
const R_88K_32 = 32; // *addr = sym_value + addend (absolute)
// Back-compat alias for the existing code paths that referenced RELATIVE.
const R_88K_RELATIVE = R_88K_BBASED_32;

// ELF32 symbol layout: st_name(4) st_value(4) st_size(4) st_info(1) st_other(1)
// st_shndx(2) = 16 bytes.
const SYMENT = 16;
const SHN_UNDEF = 0;
const SHN_ABS = 0xfff1;

/// One loaded object (main exe or a shared lib).
const Object = struct {
    bias: u32,
    dynamic_vaddr: u32,
    // Resolved dynamic-table pointers (guest addrs, biased).
    strtab: u32 = 0,
    symtab: u32 = 0,
    strsz: u32 = 0,
    rela: u32 = 0,
    relasz: u32 = 0,
    jmprel: u32 = 0,
    pltrelsz: u32 = 0,
    hash: u32 = 0,
    nchain: u32 = 0, // number of symbols (from the hash table's nchain)
    needed: [8]u32 = @splat(0), // DT_NEEDED string offsets
    n_needed: usize = 0,

    // Host-retained .symtab/.strtab bytes (NOT loaded into guest memory — these
    // sections are non-ALLOC, so mapSegments never maps them). Kept so we can
    // resolve a library's INTERNAL data symbols (e.g. libc's __iob / _lastbuf /
    // _bufendtab), which are absent from .dynsym but are the storage libc's own
    // GOT slots point at. Owned by the linker; freed in reset(). Empty slices
    // when the object has no .symtab.
    lsym: []const u8 = &.{}, // raw .symtab bytes
    lstr: []const u8 = &.{}, // raw .strtab bytes (for .symtab)
};

const MAX_OBJECTS = 16;
const LIB_BASE_START: u32 = 0x0500_0000; // load libraries here, upward
const LIB_STRIDE: u32 = 0x0080_0000; // spacing between library load bases

pub const Linker = struct {
    memory: *mem.Memory,
    fs: *fsmod.Fs,
    gpa: ?std.mem.Allocator = null, // for freeing retained .symtab bytes
    objs: [MAX_OBJECTS]Object = undefined,
    n_objs: usize = 0,
    next_base: u32 = LIB_BASE_START,
    /// Diagnostic: last unresolved symbol name (for error reporting).
    missing: [64]u8 = @splat(0),
    /// COPY-relocation preemptions: symbols the main executable defines in its
    /// own .bss (via R_88K_COPY). Every reference — including a library's own —
    /// must resolve to the executable's copy (ELF symbol preemption). Stored as
    /// (name, exe_addr) pairs; consulted first by lookup().
    preempt_names: [32][64]u8 = undefined,
    preempt_addr: [32]u32 = @splat(0),
    n_preempt: usize = 0,

    fn addPreempt(self: *Linker, name: []const u8, addr: u32) void {
        if (self.n_preempt >= self.preempt_names.len) return;
        const n = @min(name.len, 63);
        @memcpy(self.preempt_names[self.n_preempt][0..n], name[0..n]);
        self.preempt_names[self.n_preempt][n] = 0;
        self.preempt_addr[self.n_preempt] = addr;
        self.n_preempt += 1;
    }

    fn preemptOf(self: *Linker, name: []const u8) ?u32 {
        var i: usize = 0;
        while (i < self.n_preempt) : (i += 1) {
            const stored = std.mem.sliceTo(&self.preempt_names[i], 0);
            if (std.mem.eql(u8, stored, name)) return self.preempt_addr[i];
        }
        return null;
    }

    fn readDynamic(self: *Linker, obj: *Object) void {
        // Walk the DYNAMIC array (Elf32_Dyn: d_tag(4), d_val(4)).
        var p = obj.dynamic_vaddr;
        while (true) {
            const tag = self.memory.read32(p);
            const val = self.memory.read32(p + 4);
            p += 8;
            switch (tag) {
                DT_NULL => break,
                DT_STRTAB => obj.strtab = val +% obj.bias,
                DT_SYMTAB => obj.symtab = val +% obj.bias,
                DT_STRSZ => obj.strsz = val,
                DT_RELA => obj.rela = val +% obj.bias,
                DT_RELASZ => obj.relasz = val,
                DT_JMPREL => obj.jmprel = val +% obj.bias,
                DT_PLTRELSZ => obj.pltrelsz = val,
                DT_HASH => obj.hash = val +% obj.bias,
                DT_NEEDED => {
                    if (obj.n_needed < obj.needed.len) {
                        obj.needed[obj.n_needed] = val; // string offset
                        obj.n_needed += 1;
                    }
                },
                else => {},
            }
            if (p > obj.dynamic_vaddr + 8 * 256) break; // safety
        }
        // The ELF hash table begins with nbucket, nchain; nchain == symbol count.
        if (obj.hash != 0) obj.nchain = self.memory.read32(obj.hash + 4);
    }

    /// Compare a symbol's name (by st_name offset in `obj`) to `name`.
    fn symNameEq(self: *Linker, obj: *const Object, name_off: u32, name: []const u8) bool {
        const nlen: u32 = @intCast(name.len);
        var i: u32 = 0;
        while (i < nlen) : (i += 1) {
            if (self.memory.read8(obj.strtab + name_off + i) != name[i]) return false;
        }
        return self.memory.read8(obj.strtab + name_off + nlen) == 0;
    }

    /// Look up a defined (non-UNDEF) symbol `name` across all loaded objects.
    /// Returns its biased value (address), or null.
    fn lookup(self: *Linker, name: []const u8) ?u32 {
        // A COPY-relocated symbol in the executable preempts all definitions.
        if (self.preemptOf(name)) |a| return a;
        var oi: usize = 0;
        while (oi < self.n_objs) : (oi += 1) {
            const obj = &self.objs[oi];
            if (obj.symtab == 0 or obj.nchain == 0) continue;
            var si: u32 = 1; // skip the null symbol
            while (si < obj.nchain) : (si += 1) {
                const sym = obj.symtab + si * SYMENT;
                const st_name = self.memory.read32(sym + 0);
                const st_value = self.memory.read32(sym + 4);
                const st_shndx = self.memory.read16(sym + 14);
                if (st_shndx == SHN_UNDEF) continue; // undefined here
                if (st_name == 0) continue;
                if (self.symNameEq(obj, st_name, name)) {
                    // SHN_ABS (0xfff1) symbols carry an absolute value that must
                    // NOT be biased. Linker-defined markers like _end/_edata/
                    // _etext in the executable are ABS; adding the object bias
                    // corrupts them.
                    if (st_shndx == SHN_ABS) return st_value;
                    return st_value +% obj.bias;
                }
            }
        }
        return null;
    }

    /// Read a symbol's (value, size, name_off) from an object by index.
    fn symInfo(self: *Linker, obj: *const Object, idx: u32) struct { value: u32, size: u32, name_off: u32 } {
        const sym = obj.symtab + idx * SYMENT;
        return .{
            .value = self.memory.read32(sym + 4),
            .size = self.memory.read32(sym + 8),
            .name_off = self.memory.read32(sym + 0),
        };
    }

    /// Apply one RELA table [addr, addr+size) for `obj`.
    fn applyRela(self: *Linker, obj: *Object, table: u32, size: u32) Error!void {
        var off: u32 = 0;
        while (off < size) : (off += 12) {
            const r_offset = self.memory.read32(table + off + 0) +% obj.bias;
            const r_info = self.memory.read32(table + off + 4);
            const r_addend: i32 = @bitCast(self.memory.read32(table + off + 8));
            const r_type = r_info & 0xff;
            const r_sym = r_info >> 8;

            switch (r_type) {
                R_88K_RELATIVE => {
                    // *addr += bias (the addend field is the base; use current + bias)
                    const cur = self.memory.read32(r_offset);
                    self.memory.write32(r_offset, cur +% obj.bias);
                },
                R_88K_JMP_SLOT => {
                    // Resolve the function symbol and write its final address.
                    const info = self.symInfo(obj, r_sym);
                    var name: [128]u8 = undefined;
                    const nlen = self.copyName(obj, info.name_off, &name);
                    const target = self.lookup(name[0..nlen]) orelse {
                        @memcpy(self.missing[0..@min(nlen, self.missing.len)], name[0..@min(nlen, self.missing.len)]);
                        return error.UnresolvedSymbol;
                    };
                    self.memory.write32(r_offset, target);
                },
                R_88K_BBASED_16H, R_88K_BBASED_16L => {
                    // Bias-based 16-bit halves: patch the immediate field of an
                    // instruction pair (or.u rD,r0,HI ; or rD,rD,LO) with the
                    // relocated address. The full value is symval + addend +
                    // bias; for a local (sym 0) it is addend + bias. These
                    // appear in .rela.plt (types 18/19 paired) — the PLT stub's
                    // literal load of a GOT slot address.
                    var full: u32 = undefined;
                    if (r_sym != 0) {
                        const info = self.symInfo(obj, r_sym);
                        var name: [128]u8 = undefined;
                        const nlen = self.copyName(obj, info.name_off, &name);
                        const base = self.lookup(name[0..nlen]) orelse (info.value +% obj.bias);
                        full = @bitCast(@as(i32, @bitCast(base)) +% r_addend);
                    } else {
                        full = @bitCast(@as(i32, @bitCast(obj.bias)) +% r_addend);
                    }
                    const half: u16 = if (r_type == R_88K_BBASED_16H)
                        @truncate(full >> 16)
                    else
                        @truncate(full & 0xffff);
                    self.memory.write16(r_offset, half);
                },
                R_88K_COPY => {
                    // Copy the library's initial bytes into the exe's .bss, and
                    // register the exe's address as the preemptive definition:
                    // every reference to this symbol (even the library's own)
                    // must now resolve to r_offset.
                    const info = self.symInfo(obj, r_sym);
                    var name: [128]u8 = undefined;
                    const nlen = self.copyName(obj, info.name_off, &name);
                    const src = self.lookupDefiningOther(name[0..nlen], obj) orelse {
                        @memcpy(self.missing[0..@min(nlen, self.missing.len)], name[0..@min(nlen, self.missing.len)]);
                        return error.UnresolvedSymbol;
                    };
                    var k: u32 = 0;
                    while (k < info.size) : (k += 1) {
                        self.memory.write8(r_offset + k, self.memory.read8(src + k));
                    }
                    self.addPreempt(name[0..nlen], r_offset);
                },
                else => {
                    // Generic: *addr = sym_value + addend (data/abs relocs).
                    if (r_sym != 0) {
                        const info = self.symInfo(obj, r_sym);
                        var name: [128]u8 = undefined;
                        const nlen = self.copyName(obj, info.name_off, &name);
                        const v = self.lookup(name[0..nlen]) orelse (info.value +% obj.bias);
                        self.memory.write32(r_offset, @bitCast(@as(i32, @bitCast(v)) +% r_addend));
                    } else {
                        self.memory.write32(r_offset, @bitCast(@as(i32, @bitCast(obj.bias)) +% r_addend));
                    }
                },
            }
        }
    }

    /// Point libc's stdio FILE-list head (`__first_link`) at the executable's
    /// `__iob` FILE array. This libc's `__first_link` is NOT a `struct
    /// link_map` — it is the head of the stdio flush registry that `fflush`
    /// (and exit's `_cleanup`) walk. Its layout, as fflush reads it:
    ///     [+0]  FILE*  — pointer to a FILE array (the object's iob)
    ///     [+8]  int    — number of FILEs in that array
    ///     [+0xc] next  — pointer to the next registry node (0 = end)
    /// The file image ships `[+0]=0, [+8]=NIOB (0x14), [+4]` RELATIVE-reloc'd,
    /// `[+0xc]=0`; libc's own startup would set `[+0]` to `&__iob`. Because the
    /// executable COPY-relocates `__iob` into its .bss, the ONE true FILE array
    /// is the exe's copy — so we point `[+0]` there. Without this, `[+0]` is 0
    /// (or, previously, a bogus synthesized value), fflush walks the wrong/empty
    /// table, and buffered output to a pipe/file is dropped (e.g. `tr`).
    fn initStdioRegistry(self: *Linker) Error!void {
        const first = self.lookup("__first_link") orelse return; // not this libc
        // Point [+0] at the ONE true __iob FILE array:
        //   - if the exe COPY-relocated __iob into its .bss, that copy is
        //     canonical (a library's own __iob GOT slot was redirected to it);
        //   - otherwise the exe uses libc's own __iob directly, so point there.
        // libc's __iob lives in .symtab (not .dynsym), so find it via the
        // retained host symtab of whichever library defines it.
        var iob: u32 = self.preemptOf("__iob") orelse 0;
        if (iob == 0) {
            var oi: usize = 1;
            while (oi < self.n_objs) : (oi += 1) {
                if (self.hostSymByName(&self.objs[oi], "__iob")) |s| {
                    iob = s.addr;
                    break;
                }
            }
        }
        if (iob == 0) return; // no __iob anywhere: nothing to point at
        const was = self.memory.enforce;
        self.memory.enforce = false;
        defer self.memory.enforce = was;
        // [+0] = &__iob. Leave [+4], [+8] (count), [+0xc] (next) as the file
        // image / relocations set them.
        self.memory.write32(first + 0, iob);
        if (DBG) dbg("__first_link@{x}: [+0]=&__iob={x} [+8]count={x} [+c]next={x}", .{ first, iob, self.memory.read32(first + 8), self.memory.read32(first + 12) });
    }

    /// Find a library's exported DATA symbol whose (unbiased) st_value equals
    /// `vaddr`; return its name length written to `out`, or null.
    fn dataSymAtValue(self: *Linker, obj: *const Object, vaddr: u32, out: []u8) ?usize {
        if (obj.symtab == 0 or obj.nchain == 0) return null;
        var si: u32 = 1;
        while (si < obj.nchain) : (si += 1) {
            const sym = obj.symtab + si * SYMENT;
            const st_value = self.memory.read32(sym + 4);
            const st_shndx = self.memory.read16(sym + 14);
            if (st_shndx == SHN_UNDEF) continue;
            if (st_value != vaddr) continue;
            const st_name = self.memory.read32(sym + 0);
            if (st_name == 0) continue;
            return self.copyName(obj, st_name, out);
        }
        return null;
    }

    /// Look up a symbol defined by the EXECUTABLE (obj 0) only.
    fn exeDefines(self: *Linker, name: []const u8) ?u32 {
        const exe = &self.objs[0];
        if (exe.symtab == 0 or exe.nchain == 0) return null;
        var si: u32 = 1;
        while (si < exe.nchain) : (si += 1) {
            const sym = exe.symtab + si * SYMENT;
            const st_shndx = self.memory.read16(sym + 14);
            const st_name = self.memory.read32(sym + 0);
            if (st_shndx == SHN_UNDEF or st_name == 0) continue;
            if (self.symNameEq(exe, st_name, name)) return self.memory.read32(sym + 4); // exe bias is 0
        }
        return null;
    }

    /// See the pass-3 comment in link(). For each library, redirect GOT slots
    /// whose RELATIVE reloc targets a symbol the executable also defines.
    fn preemptLibraryData(self: *Linker) void {
        var oi: usize = 1; // libraries only
        while (oi < self.n_objs) : (oi += 1) {
            const obj = &self.objs[oi];
            if (obj.rela == 0 or obj.relasz == 0) continue;
            var off: u32 = 0;
            while (off < obj.relasz) : (off += 12) {
                const r_info = self.memory.read32(obj.rela + off + 4);
                if ((r_info & 0xff) != R_88K_RELATIVE) continue;
                const slot = self.memory.read32(obj.rela + off + 0) +% obj.bias;
                // The slot now holds (unbiased target + bias) after pass 2.
                const cur = self.memory.read32(slot);
                if (cur < obj.bias) continue;
                const unbiased = cur -% obj.bias;
                var namebuf: [128]u8 = undefined;
                const nlen = self.dataSymAtValue(obj, unbiased, &namebuf) orelse continue;
                if (self.exeDefines(namebuf[0..nlen])) |exe_addr| {
                    self.memory.write32(slot, exe_addr);
                    if (DBG) dbgPreempt(namebuf[0..nlen], slot, cur, exe_addr);
                }
            }
        }
    }

    /// Look up `name` in a library's retained host-side .symtab; return its
    /// BIASED value and size, or null. Used for INTERNAL data symbols (not in
    /// .dynsym) such as libc's __iob / _lastbuf / _bufendtab.
    fn hostSymByName(self: *Linker, obj: *const Object, name: []const u8) ?struct { addr: u32, size: u32 } {
        _ = self;
        const sym = obj.lsym;
        const str = obj.lstr;
        if (sym.len == 0) return null;
        const n = sym.len / SYMENT;
        var i: usize = 1; // skip the null symbol
        while (i < n) : (i += 1) {
            const o = i * SYMENT;
            const st_name = rd32(sym, o + 0);
            const st_shndx = std.mem.readInt(u16, sym[o + 14 ..][0..2], .big);
            if (st_shndx == SHN_UNDEF or st_shndx == SHN_ABS or st_name == 0) continue;
            if (st_name >= str.len) continue;
            // Compare the strtab name to `name`.
            var k: usize = 0;
            while (k < name.len) : (k += 1) {
                if (st_name + k >= str.len or str[st_name + k] != name[k]) break;
            }
            if (k == name.len and st_name + k < str.len and str[st_name + k] == 0) {
                return .{ .addr = rd32(sym, o + 4) +% obj.bias, .size = rd32(sym, o + 8) };
            }
        }
        return null;
    }

    /// Pass 3b: for every symbol the executable COPY-relocated into its .bss
    /// (recorded in preempt_names -> exe_addr), redirect any library GOT/data
    /// slot that RELATIVE-points into that symbol's LIBRARY-side storage to the
    /// executable's copy, preserving the intra-object offset.
    ///
    /// This closes the gap preemptLibraryData can't: libc references its own
    /// __iob / _lastbuf / _bufendtab through nameless RELATIVE GOT slots, and
    /// those symbols live in libc's .symtab (not .dynsym), so name/dynsym-based
    /// preemption never matched them. Without this, libc's stdio (fflush) walks
    /// its own uninitialized FILE table instead of the exe's, and a program's
    /// buffered output to a pipe/file is silently dropped (e.g. `tr`).
    fn preemptCopyRelocRanges(self: *Linker) void {
        var pi: usize = 0;
        while (pi < self.n_preempt) : (pi += 1) {
            const name = std.mem.sliceTo(&self.preempt_names[pi], 0);
            const exe_addr = self.preempt_addr[pi];
            if (DBG) dbg("copy-preempt sym '{s}' exe_addr={x}", .{ name, exe_addr });
            // For each library, find its own copy of this symbol (addr+size).
            var oi: usize = 1; // libraries only
            while (oi < self.n_objs) : (oi += 1) {
                const obj = &self.objs[oi];
                if (DBG) dbg("  obj{d} lsym.len={d}", .{ oi, obj.lsym.len });
                const libsym = self.hostSymByName(obj, name) orelse continue;
                if (DBG) dbg("  found lib copy addr={x} size={x}", .{ libsym.addr, libsym.size });
                const lo = libsym.addr;
                const hi = libsym.addr +% libsym.size;
                if (hi <= lo) continue;
                self.redirectSlotsInRange(obj, lo, hi, exe_addr);
            }
        }
    }

    /// Rewrite every RELATIVE-relocated GOT/data slot in `obj` whose current
    /// value is in [lo, hi) to `exe_addr + (value - lo)`. Scans the object's
    /// RELA and JMPREL tables for R_88K_RELATIVE entries (the slots libc fills
    /// with pointers to its own data).
    fn redirectSlotsInRange(self: *Linker, obj: *const Object, lo: u32, hi: u32, exe_addr: u32) void {
        const tables = [_]struct { addr: u32, size: u32 }{
            .{ .addr = obj.rela, .size = obj.relasz },
            .{ .addr = obj.jmprel, .size = obj.pltrelsz },
        };
        for (tables) |t| {
            if (t.addr == 0 or t.size == 0) continue;
            var off: u32 = 0;
            while (off < t.size) : (off += 12) {
                const r_info = self.memory.read32(t.addr + off + 4);
                if ((r_info & 0xff) != R_88K_RELATIVE) continue;
                const slot = self.memory.read32(t.addr + off + 0) +% obj.bias;
                const cur = self.memory.read32(slot);
                if (cur < lo or cur >= hi) continue;
                const newv = exe_addr +% (cur -% lo);
                self.memory.write32(slot, newv);
                if (DBG) dbgPreempt("copyrange", slot, cur, newv);
            }
        }
    }

    fn copyName(self: *Linker, obj: *const Object, name_off: u32, out: []u8) usize {
        var i: usize = 0;
        while (i < out.len) : (i += 1) {
            const ch = self.memory.read8(obj.strtab + name_off + @as(u32, @intCast(i)));
            if (ch == 0) break;
            out[i] = ch;
        }
        return i;
    }

    /// Like lookup, but excludes `exclude` (used for COPY relocs: the value
    /// must come from a library, not the exe's own tentative slot).
    fn lookupDefiningOther(self: *Linker, name: []const u8, exclude: *const Object) ?u32 {
        var oi: usize = 0;
        while (oi < self.n_objs) : (oi += 1) {
            const obj = &self.objs[oi];
            if (obj == exclude) continue;
            if (obj.symtab == 0 or obj.nchain == 0) continue;
            var si: u32 = 1;
            while (si < obj.nchain) : (si += 1) {
                const sym = obj.symtab + si * SYMENT;
                const st_name = self.memory.read32(sym + 0);
                const st_shndx = self.memory.read16(sym + 14);
                if (st_shndx == SHN_UNDEF or st_name == 0) continue;
                if (self.symNameEq(obj, st_name, name)) {
                    return self.memory.read32(sym + 4) +% obj.bias;
                }
            }
        }
        return null;
    }
};

/// Public entry: link `main` (already mapped at bias 0 by elf.load), loading
/// its dependency graph and applying all relocations. Returns nothing; the
/// program is ready to run at its entry point on success.
pub fn link(
    memory: *mem.Memory,
    fs: *fsmod.Fs,
    io: std.Io,
    gpa: std.mem.Allocator,
    main_dynamic_vaddr: u32,
    main_brk: u32,
) Error!void {
    var lk = Linker{ .memory = memory, .fs = fs, .gpa = gpa };
    // Free any retained library .symtab/.strtab copies once linking is done.
    defer {
        var fi: usize = 0;
        while (fi < lk.n_objs) : (fi += 1) {
            if (lk.objs[fi].lsym.len != 0) gpa.free(@constCast(lk.objs[fi].lsym));
            if (lk.objs[fi].lstr.len != 0) gpa.free(@constCast(lk.objs[fi].lstr));
        }
    }

    // Object 0: the main executable (bias 0).
    lk.objs[0] = .{ .bias = 0, .dynamic_vaddr = main_dynamic_vaddr };
    lk.readDynamic(&lk.objs[0]);
    lk.n_objs = 1;

    // Breadth-first load of NEEDED libraries.
    var scan: usize = 0;
    while (scan < lk.n_objs) : (scan += 1) {
        // Snapshot needed list (objs may move as array; it's fixed storage).
        const n = lk.objs[scan].n_needed;
        var k: usize = 0;
        while (k < n) : (k += 1) {
            const name_off = lk.objs[scan].needed[k];
            var namebuf: [256]u8 = undefined;
            const nlen = lk.copyName(&lk.objs[scan], name_off, &namebuf);
            const libpath = namebuf[0..nlen]; // e.g. /usr/lib/libc.so.1
            // Skip if already loaded (by guest path).
            if (alreadyLoaded(&lk, libpath, io, gpa)) continue;
            try loadLibrary(&lk, libpath, io, gpa);
        }
    }

    // Pass 1: apply the EXECUTABLE's RELA first. It carries the COPY
    // relocations, which register symbol preemptions (the exe's .bss copy of
    // e.g. __iob/errno/__ctype must be THE definition for all objects). This
    // must precede every other object's relocations so their JMP_SLOT/data
    // relocs resolve those symbols to the exe's copy.
    {
        const exe = &lk.objs[0];
        if (exe.rela != 0 and exe.relasz != 0) try lk.applyRela(exe, exe.rela, exe.relasz);
    }

    // Pass 2: apply all remaining relocations for every object.
    var oi: usize = 0;
    while (oi < lk.n_objs) : (oi += 1) {
        const obj = &lk.objs[oi];
        // The exe's RELA already ran in pass 1; run libs' RELA and everyone's
        // JMPREL here.
        if (oi != 0 and obj.rela != 0 and obj.relasz != 0) try lk.applyRela(obj, obj.rela, obj.relasz);
        if (obj.jmprel != 0 and obj.pltrelsz != 0) try lk.applyRela(obj, obj.jmprel, obj.pltrelsz);
    }

    // Pass 3: preempt library data references. A library GOT slot filled by a
    // (nameless) RELATIVE reloc that targets one of the library's OWN exported
    // data symbols must instead point at the EXECUTABLE's definition, if the
    // exe exports the same symbol (ELF symbol preemption). Covers plain
    // exported globals like optind/opterr that getopt reads: date defines them,
    // so libc's getopt must use date's copies. We correlate the reloc's target
    // vaddr to a library symbol's st_value, then look the name up in the exe.
    lk.preemptLibraryData();

    // Pass 3b: redirect library GOT/data slots that RELATIVE-point at a
    // library's OWN copy of an exe-COPY-relocated symbol (e.g. libc's internal
    // __iob / _lastbuf / _bufendtab, which are in libc's .symtab, not .dynsym)
    // to the executable's copy. Without this, libc's stdio operates on its own
    // uninitialized FILE table and buffered pipe/file output is dropped.
    lk.preemptCopyRelocRanges();

    // Build the runtime-linker link_map chain and publish it where libc's
    // startup expects it. The SysV/88 shared libc (which is also the
    // interpreter) walks a chain of `struct link_map` (link.h) rooted at
    // `__first_link[0]`; e.g. fflush iterates it to flush every object's FILE
    // table. We synthesize the chain the real ld.so would have built.
    try lk.initStdioRegistry();

    // Initialize libc's break-tracking global `_nd` (the userland "current
    // break" that _sbrk/_brk read/write) to the true initial break. The real
    // ld.so seeds this; without it, _sbrk computes from 0 and malloc walks off
    // into negative addresses.
    if (lk.lookup("_nd")) |nd| {
        const was = memory.enforce;
        memory.enforce = false;
        memory.write32(nd, main_brk);
        memory.enforce = was;
    }
}

/// A crude "already loaded" check keyed on the SONAME/path is skipped for now;
/// we just avoid reloading the same path within one link by remembering paths.
var loaded_paths: [MAX_OBJECTS][256]u8 = undefined;
var loaded_path_lens: [MAX_OBJECTS]usize = @splat(0);
var loaded_count: usize = 0;

fn alreadyLoaded(lk: *Linker, path: []const u8, io: std.Io, gpa: std.mem.Allocator) bool {
    _ = lk;
    _ = io;
    _ = gpa;
    var i: usize = 0;
    while (i < loaded_count) : (i += 1) {
        if (std.mem.eql(u8, loaded_paths[i][0..loaded_path_lens[i]], path)) return true;
    }
    return false;
}

fn rememberLoaded(path: []const u8) void {
    if (loaded_count >= MAX_OBJECTS) return;
    const n = @min(path.len, 256);
    @memcpy(loaded_paths[loaded_count][0..n], path[0..n]);
    loaded_path_lens[loaded_count] = n;
    loaded_count += 1;
}

fn loadLibrary(lk: *Linker, guest_path: []const u8, io: std.Io, gpa: std.mem.Allocator) Error!void {
    if (lk.n_objs >= MAX_OBJECTS) return error.TooManyObjects;
    // Resolve the guest path to a host path via the mount table.
    var hostbuf: [2048]u8 = undefined;
    const hostpath = lk.fs.resolve(guest_path, &hostbuf) catch return error.LibraryNotFound;
    const image = std.Io.Dir.cwd().readFileAlloc(io, hostpath, gpa, .limited(32 * 1024 * 1024)) catch
        return error.LibraryNotFound;
    defer gpa.free(image);

    const bias = lk.next_base;
    lk.next_base += LIB_STRIDE;

    const obj = elf.mapSegments(lk.memory, image, bias) catch return error.LoadOutOfRange;
    if (DBG) dbg("loadLibrary {s} bias={x}", .{ guest_path, bias });
    lk.objs[lk.n_objs] = .{ .bias = bias, .dynamic_vaddr = obj.dynamic_vaddr };
    lk.readDynamic(&lk.objs[lk.n_objs]);
    // Retain the library's .symtab/.strtab (non-ALLOC, so not in guest memory)
    // so pass 3 can resolve internal data symbols (libc __iob/_lastbuf/...).
    // Best-effort: on OOM or absence, leave the slices empty.
    if (elf.findSymtab(image)) |ss| {
        if (gpa.dupe(u8, ss.sym)) |symbuf| {
            if (gpa.dupe(u8, ss.str)) |strbuf| {
                lk.objs[lk.n_objs].lsym = symbuf;
                lk.objs[lk.n_objs].lstr = strbuf;
            } else |_| gpa.free(symbuf);
        } else |_| {}
    }
    lk.n_objs += 1;
    rememberLoaded(guest_path);
}

/// Reset the module-global loaded-path memo (call before each fresh link).
pub fn reset() void {
    loaded_count = 0;
}
