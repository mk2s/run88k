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

// m88k relocation types.
const R_88K_COPY = 1;
const R_88K_JMP_SLOT = 2;
const R_88K_RELATIVE = 16;

// ELF32 symbol layout: st_name(4) st_value(4) st_size(4) st_info(1) st_other(1)
// st_shndx(2) = 16 bytes.
const SYMENT = 16;
const SHN_UNDEF = 0;

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
};

const MAX_OBJECTS = 16;
const LIB_BASE_START: u32 = 0x0500_0000; // load libraries here, upward
const LIB_STRIDE: u32 = 0x0080_0000; // spacing between library load bases
const LINKMAP_REGION: u32 = 0x0400_0000; // scratch for the synthesized link_map chain

pub const Linker = struct {
    memory: *mem.Memory,
    fs: *fsmod.Fs,
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

    /// Build the `struct link_map` chain (link.h: l_addr@0, l_name@4, l_ld@8,
    /// l_next@12, l_prev@16 — 20 bytes) for all loaded objects and publish the
    /// head into libc's `__first_link[0]`. This is the book-keeping the real
    /// ld.so leaves for libc (fflush and friends walk it via l_next@0xc).
    fn buildLinkMap(self: *Linker) Error!void {
        const first = self.lookup("__first_link") orelse return; // no such libc: nothing to do
        // Reserve a scratch region for the link_map array + object name strings.
        const LM_SIZE: u32 = 20;
        const region = LINKMAP_REGION;
        const region_len: u32 = 0x2000;
        self.memory.addRegion(region, region_len, .{ .read = true, .write = true }) catch {};
        const was = self.memory.enforce;
        self.memory.enforce = false;
        defer self.memory.enforce = was;
        self.memory.zero(region, region_len);

        var map_at = region;
        var name_at = region + LM_SIZE * @as(u32, @intCast(self.n_objs)) + 4;
        var prev: u32 = 0;
        var head: u32 = 0;
        var oi: usize = 0;
        while (oi < self.n_objs) : (oi += 1) {
            const obj = &self.objs[oi];
            const lm = map_at;
            map_at += LM_SIZE;
            if (head == 0) head = lm;
            self.memory.write32(lm + 0, obj.bias); // l_addr
            self.memory.write32(lm + 4, name_at); // l_name (short placeholder)
            self.memory.write32(lm + 8, obj.dynamic_vaddr); // l_ld
            self.memory.write32(lm + 12, 0); // l_next (filled below)
            self.memory.write32(lm + 16, prev); // l_prev
            if (prev != 0) self.memory.write32(prev + 12, lm); // prev->l_next = lm
            // A minimal name string ("obj0", "obj1", ...) is enough for fflush.
            self.memory.write8(name_at + 0, 'o');
            self.memory.write8(name_at + 1, 'b');
            self.memory.write8(name_at + 2, 'j');
            self.memory.write8(name_at + 3, '0' + @as(u8, @intCast(oi & 7)));
            self.memory.write8(name_at + 4, 0);
            name_at += 5;
            prev = lm;
        }
        // __first_link[0] = head of the chain. (offset 8 already holds the
        // entry size 20 from the file image; leave it.)
        self.memory.write32(first + 0, head);
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
    var lk = Linker{ .memory = memory, .fs = fs };

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

    // Build the runtime-linker link_map chain and publish it where libc's
    // startup expects it. The SysV/88 shared libc (which is also the
    // interpreter) walks a chain of `struct link_map` (link.h) rooted at
    // `__first_link[0]`; e.g. fflush iterates it to flush every object's FILE
    // table. We synthesize the chain the real ld.so would have built.
    try lk.buildLinkMap();

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
    lk.objs[lk.n_objs] = .{ .bias = bias, .dynamic_vaddr = obj.dynamic_vaddr };
    lk.readDynamic(&lk.objs[lk.n_objs]);
    lk.n_objs += 1;
    rememberLoaded(guest_path);
}

/// Reset the module-global loaded-path memo (call before each fresh link).
pub fn reset() void {
    loaded_count = 0;
}
