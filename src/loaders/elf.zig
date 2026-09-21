//! ELF32 big-endian (MC88000) executable loader.
//!
//! Parses a static ELF EXEC, maps each PT_LOAD segment into guest memory with
//! its permissions, zero-fills the bss tail (memsz > filesz), and reports the
//! entry point and the initial program break (highest loaded byte, page
//! rounded). This is the SysV/88 lead-platform format: ELF32-BE, statically
//! linked, e_machine = EM_88K (145).

const std = @import("std");
const mem = @import("../mem.zig");

pub const Error = error{
    NotElf,
    NotElf32,
    NotBigEndian,
    NotExecutable,
    NotM88k,
    BadProgramHeaders,
    LoadOutOfRange,
};

pub const LoadedImage = struct {
    entry: u32,
    /// Initial program break: end of the highest PT_LOAD (unrounded).
    brk: u32,
    /// Lowest and highest mapped guest addresses (for diagnostics).
    load_low: u32,
    load_high: u32,
    /// Guest vaddr of the PT_DYNAMIC segment (0 if none / static).
    dynamic_vaddr: u32 = 0,
    /// True if the executable requests an interpreter (PT_INTERP present) or
    /// has a PT_DYNAMIC — i.e. it needs dynamic linking.
    is_dynamic: bool = false,
    /// True if the object carries OpenBSD markers (a PT_OPENBSD_* program
    /// header such as OPENBSD_RANDOM/WXNEEDED/BOOTDATA). Used to auto-select
    /// the OpenBSD personality when the CLI didn't force one.
    is_openbsd: bool = false,
    /// Guest vaddr of the program header table (for the ELF aux vector's
    /// AT_PHDR). 0 if the phdrs are not covered by a PT_LOAD segment.
    phdr_vaddr: u32 = 0,
    phent: u16 = 0, // size of one program header (AT_PHENT)
    phnum: u16 = 0, // number of program headers (AT_PHNUM)
};

/// OpenBSD-specific program header types (all in the OS-specific range).
pub const PT_OPENBSD_RANDOMIZE = 0x65a3dbe6;
pub const PT_OPENBSD_WXNEEDED = 0x65a3dbe7;
pub const PT_OPENBSD_BOOTDATA = 0x65a41be6;
pub const PT_OPENBSD_NOBTCFI = 0x65a3dbe8;

/// A mapped ELF object (executable or shared library), with the metadata the
/// dynamic linker needs. Segments are already loaded into guest memory.
pub const MappedObject = struct {
    /// Load bias applied to all vaddrs (0 for a fixed-address EXEC, else the
    /// base where a relocatable object was placed).
    bias: u32,
    entry: u32, // biased entry point
    dynamic_vaddr: u32, // biased PT_DYNAMIC address (0 if none)
    load_low: u32,
    load_high: u32,
};

pub const EI_NIDENT = 16;
pub const ELFCLASS32 = 1;
pub const ELFDATA2MSB = 2; // big-endian
pub const ET_EXEC = 2;
pub const ET_DYN = 3;
pub const EM_88K = 5; // EM_88K in the ELF machine enum (Motorola 88000)
pub const PT_LOAD = 1;
pub const PT_DYNAMIC = 2;
pub const PT_INTERP = 3;
pub const PF_X = 1;
pub const PF_W = 2;
pub const PF_R = 4;
const PAGE = 0x1000;

pub fn rd16(b: []const u8, off: usize) u16 {
    return std.mem.readInt(u16, b[off..][0..2], .big);
}
pub fn rd32(b: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, b[off..][0..4], .big);
}

pub const SHT_SYMTAB = 2;
pub const SHT_STRTAB = 3;

/// Locate the (`.symtab`, its `.strtab`) section byte-ranges in a file image.
/// These are non-ALLOC sections (not mapped into guest memory), so they can
/// only be read from the raw file. Returns null when absent (e.g. a stripped
/// object). The returned slices point into `image`.
pub const SymtabSlices = struct { sym: []const u8, str: []const u8 };
pub fn findSymtab(image: []const u8) ?SymtabSlices {
    if (image.len < 0x34) return null;
    const e_shoff = rd32(image, 32);
    const e_shentsize = rd16(image, 46);
    const e_shnum = rd16(image, 48);
    if (e_shoff == 0 or e_shentsize < 40 or e_shnum == 0) return null;
    // Find SHT_SYMTAB; its sh_link is the associated string table section.
    var i: usize = 0;
    while (i < e_shnum) : (i += 1) {
        const sh = e_shoff + i * e_shentsize;
        if (sh + 40 > image.len) return null;
        if (rd32(image, sh + 4) != SHT_SYMTAB) continue;
        const sym_off = rd32(image, sh + 16);
        const sym_size = rd32(image, sh + 20);
        const sym_link = rd32(image, sh + 24); // strtab section index
        if (@as(u64, sym_off) + sym_size > image.len) return null;
        if (sym_link >= e_shnum) return null;
        const lsh = e_shoff + sym_link * e_shentsize;
        if (lsh + 40 > image.len) return null;
        const str_off = rd32(image, lsh + 16);
        const str_size = rd32(image, lsh + 20);
        if (@as(u64, str_off) + str_size > image.len) return null;
        return .{
            .sym = image[sym_off .. sym_off + sym_size],
            .str = image[str_off .. str_off + str_size],
        };
    }
    return null;
}

/// Validate the ELF header for an m88k big-endian object. Returns nothing on
/// success; the caller reads e_type etc. directly.
pub fn checkHeader(image: []const u8) Error!void {
    if (image.len < EI_NIDENT + 36) return error.NotElf;
    if (!std.mem.eql(u8, image[0..4], "\x7fELF")) return error.NotElf;
    if (image[4] != ELFCLASS32) return error.NotElf32;
    if (image[5] != ELFDATA2MSB) return error.NotBigEndian;
    if (rd16(image, 18) != EM_88K) return error.NotM88k;
}

/// Map all PT_LOAD segments of `image` into guest memory at `bias` (added to
/// each p_vaddr). Zero-fills bss tails and sets region permissions. Returns the
/// mapped-object metadata (biased entry, dynamic vaddr, load extents).
///
/// Enforcement must be off (caller manages it). For a fixed EXEC pass bias=0;
/// for a relocatable ET_DYN pass the chosen load base.
pub fn mapSegments(memory: *mem.Memory, image: []const u8, bias: u32) Error!MappedObject {
    try checkHeader(image);
    const e_entry = rd32(image, 24);
    const e_phoff = rd32(image, 28);
    const e_phentsize = rd16(image, 42);
    const e_phnum = rd16(image, 44);
    if (e_phnum == 0 or e_phentsize < 32) return error.BadProgramHeaders;

    var load_low: u32 = 0xffff_ffff;
    var load_high: u32 = 0;
    var dyn_vaddr: u32 = 0;

    var i: usize = 0;
    while (i < e_phnum) : (i += 1) {
        const ph = e_phoff + i * e_phentsize;
        if (ph + 32 > image.len) return error.BadProgramHeaders;
        const p_type = rd32(image, ph + 0);
        const p_offset = rd32(image, ph + 4);
        const p_vaddr = rd32(image, ph + 8) +% bias;
        const p_filesz = rd32(image, ph + 16);
        const p_memsz = rd32(image, ph + 20);
        const p_flags = rd32(image, ph + 24);

        if (p_type == PT_DYNAMIC) dyn_vaddr = p_vaddr;
        if (p_type != PT_LOAD) continue;

        const seg_end = p_vaddr +% p_memsz;
        if (seg_end < p_vaddr or seg_end > mem.Memory.size) return error.LoadOutOfRange;
        if (p_filesz > p_memsz) return error.BadProgramHeaders;
        if (@as(u64, p_offset) + p_filesz > image.len) return error.BadProgramHeaders;

        if (p_filesz > 0) memory.writeBytes(p_vaddr, image[p_offset .. p_offset + p_filesz]);
        if (p_memsz > p_filesz) memory.zero(p_vaddr + p_filesz, p_memsz - p_filesz);

        // Shared libraries need their data (GOT) written during relocation and
        // .plt patched; map text writable too so we can relocate freely. (We
        // don't enforce W^X for the guest.)
        memory.addRegion(p_vaddr, p_memsz, .{
            .read = (p_flags & PF_R) != 0,
            .write = true,
            .exec = (p_flags & PF_X) != 0,
        }) catch return error.LoadOutOfRange;

        if (p_vaddr < load_low) load_low = p_vaddr;
        if (seg_end > load_high) load_high = seg_end;
    }
    if (load_high == 0) return error.BadProgramHeaders;

    return .{
        .bias = bias,
        .entry = e_entry +% bias,
        .dynamic_vaddr = dyn_vaddr,
        .load_low = load_low,
        .load_high = load_high,
    };
}

/// Load `image` (raw file bytes) into `memory`. Permission enforcement is
/// disabled while writing and restored by the caller/run setup.
pub fn load(memory: *mem.Memory, image: []const u8) Error!LoadedImage {
    try checkHeader(image);
    const e_type = rd16(image, 16);
    if (e_type != ET_EXEC and e_type != ET_DYN) return error.NotExecutable;

    const was_enforce = memory.enforce;
    memory.enforce = false;
    defer memory.enforce = was_enforce;

    // Executables are fixed-address (bias 0). We only load the main object
    // here; the dynamic linker (dynamic.zig) loads NEEDED libraries and applies
    // relocations when is_dynamic is set.
    const obj = try mapSegments(memory, image, 0);

    // Detect dynamic linking (PT_INTERP or PT_DYNAMIC) and OpenBSD markers
    // (any PT_OPENBSD_* program header) in one pass over the phdrs.
    var is_dyn = obj.dynamic_vaddr != 0;
    var is_obsd = false;
    const e_phoff = rd32(image, 28);
    const e_phentsize = rd16(image, 42);
    const e_phnum = rd16(image, 44);
    var i: usize = 0;
    while (i < e_phnum) : (i += 1) {
        const ph = e_phoff + i * e_phentsize;
        if (ph + 4 > image.len) break;
        const pt = rd32(image, ph + 0);
        if (pt == PT_INTERP) is_dyn = true;
        if (pt == PT_OPENBSD_RANDOMIZE or pt == PT_OPENBSD_WXNEEDED or
            pt == PT_OPENBSD_BOOTDATA or pt == PT_OPENBSD_NOBTCFI) is_obsd = true;
    }

    // Locate the program header table in guest memory (AT_PHDR): find the
    // PT_LOAD whose file range covers e_phoff, then map the offset through.
    var phdr_vaddr: u32 = 0;
    {
        var j: usize = 0;
        while (j < e_phnum) : (j += 1) {
            const ph = e_phoff + j * e_phentsize;
            if (ph + 32 > image.len) break;
            if (rd32(image, ph + 0) != PT_LOAD) continue;
            const p_offset = rd32(image, ph + 4);
            const p_vaddr = rd32(image, ph + 8);
            const p_filesz = rd32(image, ph + 16);
            if (e_phoff >= p_offset and e_phoff + @as(u32, e_phnum) * e_phentsize <= p_offset + p_filesz) {
                phdr_vaddr = p_vaddr + (e_phoff - p_offset);
                break;
            }
        }
    }

    // The initial program break is the EXACT end of the highest loaded segment,
    // NOT page-rounded (the guest's crt/libc grows the heap from there).
    return .{
        .entry = obj.entry,
        .brk = obj.load_high,
        .load_low = obj.load_low,
        .load_high = obj.load_high,
        .dynamic_vaddr = obj.dynamic_vaddr,
        .is_dynamic = is_dyn,
        .is_openbsd = is_obsd,
        .phdr_vaddr = phdr_vaddr,
        .phent = e_phentsize,
        .phnum = e_phnum,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Build a minimal ELF32-BE m88k executable with one R-E PT_LOAD segment
/// carrying `code` at vaddr, for testing the parser without a real binary.
fn buildTinyElf(alloc: std.mem.Allocator, vaddr: u32, entry: u32, code: []const u8) ![]u8 {
    const ehsize = 52;
    const phentsize = 32;
    const phoff = ehsize;
    const dataoff = phoff + phentsize;
    var buf = try alloc.alloc(u8, dataoff + code.len);
    @memset(buf, 0);
    // e_ident
    @memcpy(buf[0..4], "\x7fELF");
    buf[4] = ELFCLASS32;
    buf[5] = ELFDATA2MSB;
    buf[6] = 1;
    std.mem.writeInt(u16, buf[16..18], ET_EXEC, .big); // e_type
    std.mem.writeInt(u16, buf[18..20], EM_88K, .big); // e_machine
    std.mem.writeInt(u32, buf[20..24], 1, .big); // e_version
    std.mem.writeInt(u32, buf[24..28], entry, .big); // e_entry
    std.mem.writeInt(u32, buf[28..32], phoff, .big); // e_phoff
    std.mem.writeInt(u16, buf[40..42], ehsize, .big); // e_ehsize
    std.mem.writeInt(u16, buf[42..44], phentsize, .big); // e_phentsize
    std.mem.writeInt(u16, buf[44..46], 1, .big); // e_phnum
    // program header
    std.mem.writeInt(u32, buf[phoff + 0 ..][0..4], PT_LOAD, .big);
    std.mem.writeInt(u32, buf[phoff + 4 ..][0..4], dataoff, .big); // p_offset
    std.mem.writeInt(u32, buf[phoff + 8 ..][0..4], vaddr, .big); // p_vaddr
    std.mem.writeInt(u32, buf[phoff + 16 ..][0..4], @intCast(code.len), .big); // p_filesz
    std.mem.writeInt(u32, buf[phoff + 20 ..][0..4], @intCast(code.len), .big); // p_memsz
    std.mem.writeInt(u32, buf[phoff + 24 ..][0..4], PF_R | PF_X, .big); // p_flags
    @memcpy(buf[dataoff..], code);
    return buf;
}

test "loads a minimal ELF32-BE m88k executable" {
    const alloc = std.testing.allocator;
    const code = [_]u8{ 0x61, 0x20, 0x00, 0x04, 0xf0, 0x00, 0xd1, 0xc3 };
    const elf = try buildTinyElf(alloc, 0x10000, 0x10000, &code);
    defer alloc.free(elf);

    var memory = try mem.Memory.init(alloc);
    defer memory.deinit();

    const img = try load(&memory, elf);
    try std.testing.expectEqual(@as(u32, 0x10000), img.entry);
    try std.testing.expectEqual(@as(u32, 0x10008), img.brk); // exact end, unrounded
    // Code landed in guest memory big-endian.
    try std.testing.expectEqual(@as(u32, 0x612000_04), memory.read32(0x10000));
    try std.testing.expectEqual(@as(u32, 0xf000d1c3), memory.read32(0x10004));
}

test "rejects little-endian and non-m88k" {
    const alloc = std.testing.allocator;
    const code = [_]u8{ 0, 0, 0, 0 };
    var elf = try buildTinyElf(alloc, 0x10000, 0x10000, &code);
    defer alloc.free(elf);
    var memory = try mem.Memory.init(alloc);
    defer memory.deinit();

    elf[5] = 1; // ELFDATA2LSB
    try std.testing.expectError(error.NotBigEndian, load(&memory, elf));
    elf[5] = ELFDATA2MSB;
    std.mem.writeInt(u16, elf[18..20], 3, .big); // e_machine = EM_386
    try std.testing.expectError(error.NotM88k, load(&memory, elf));
}
