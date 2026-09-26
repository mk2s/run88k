//! Guest filesystem for run88k: resolves guest paths through a MOUNT TABLE to
//! host paths, plus a per-process fd table.
//!
//! Unlike runupc (single chroot root), a SysV/88 guest disk is presented as
//! several host trees — e.g. guest `/` -> /mnt/hd0_root and guest `/usr` ->
//! /mnt/hd0_slice3. resolve() canonicalizes the guest path, picks the
//! longest-matching mount, and joins with that mount's host root.
//!
//! Symlink hazard: some guest symlinks point at guest-absolute paths that only
//! make sense through the mount table, e.g. `/mnt/hd0_root/bin` is a host
//! symlink `bin -> /usr/bin`. Followed on the host it dangles or points at the
//! wrong place. So resolve() walks components and, when a component is a host
//! symlink whose target is guest-absolute (starts with '/'), it RE-RESOLVES
//! that target through the mount table rather than letting the host follow it.
//!
//! Uses libc file ops directly for stable errno and to avoid the churning std
//! I/O API.

const std = @import("std");

pub const c = struct {
    pub extern "c" fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
    pub extern "c" fn close(fd: c_int) c_int;
    pub extern "c" fn readlink(path: [*:0]const u8, buf: [*]u8, bufsiz: usize) isize;
    pub extern "c" fn access(path: [*:0]const u8, mode: c_int) c_int;
    pub extern "c" fn unlink(path: [*:0]const u8) c_int;
    pub extern "c" fn rename(old: [*:0]const u8, new: [*:0]const u8) c_int;
    pub extern "c" fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
    pub extern "c" fn rmdir(path: [*:0]const u8) c_int;
    pub extern "c" fn link(oldp: [*:0]const u8, newp: [*:0]const u8) c_int;
    pub extern "c" fn ftruncate(fd: c_int, len: c_long) c_int;
    pub extern "c" fn chmod(path: [*:0]const u8, mode: c_uint) c_int;
    pub extern "c" fn fchmod(fd: c_int, mode: c_uint) c_int;
};

// Directory-stream shim (src/host_dir.c).
extern fn r88k_diropen(path: [*:0]const u8) c_int;
extern fn r88k_dirpushback(handle: c_int) void;
extern fn r88k_dirclose(handle: c_int) void;

pub const MAX_FD: usize = 64;
const MAX_SYMLINK_DEPTH: u32 = 16;

/// Expand a DG/UX `elink:` template into a concrete path, writing into `out`
/// and returning the slice. Each `${VAR:-default}` reference expands to its
/// default (we don't carry the SDE env vars, so the defaults — SDE_PATH=/usr,
/// TARGET_BINARY_INTERFACE=m88kdgux — are exactly what a stock toolchain uses).
/// A bare `${VAR}` with no default expands to empty. Non-reference text is
/// copied verbatim. Overflow truncates safely.
fn expandElink(template: []const u8, out: []u8) []const u8 {
    var o: usize = 0;
    var i: usize = 0;
    while (i < template.len and o < out.len) {
        if (template[i] == '$' and i + 1 < template.len and template[i + 1] == '{') {
            // Find the matching '}'.
            const close = std.mem.indexOfScalarPos(u8, template, i + 2, '}') orelse {
                out[o] = template[i];
                o += 1;
                i += 1;
                continue;
            };
            const inner = template[i + 2 .. close]; // e.g. "VAR:-default" or "VAR"
            const dflt: []const u8 = if (std.mem.indexOf(u8, inner, ":-")) |sep|
                inner[sep + 2 ..]
            else
                ""; // ${VAR} with no default -> empty
            const take = @min(dflt.len, out.len - o);
            @memcpy(out[o .. o + take], dflt[0..take]);
            o += take;
            i = close + 1;
        } else {
            out[o] = template[i];
            o += 1;
            i += 1;
        }
    }
    return out[0..o];
}

pub const Mount = struct {
    /// Guest path prefix, e.g. "/" or "/usr". No trailing slash except "/".
    guest_prefix: []const u8,
    /// Host directory backing it, e.g. "/mnt/hd0_root". No trailing slash.
    host_root: []const u8,
};

pub const Error = error{ BadPath, NameTooLong, NoMount };

pub const Fs = struct {
    /// Mount table. Callers add mounts; resolve() uses longest-prefix match.
    mounts: std.ArrayListUnmanaged(Mount) = .empty,
    /// Guest current working directory (guest-absolute, starts with '/').
    cwd: []u8,
    cwd_len: usize,
    host_fd: [MAX_FD]i32,
    /// Directory-stream handle per guest fd (-1 if not a directory).
    dir_handle: [MAX_FD]i32,
    /// Guest-absolute path of the directory opened on each guest fd (only
    /// meaningful when dir_handle[gfd] >= 0). Used by getdents to synthesize
    /// entries for mount points that live directly under this directory, so a
    /// userland getcwd() walk (getdents(..) + lstat) can cross mount
    /// boundaries the same way it would on a single real filesystem.
    dir_path: [MAX_FD][256]u8,
    dir_path_len: [MAX_FD]usize,
    /// Index of the next synthetic mount-point entry to emit for this dir fd
    /// once the real readdir stream is exhausted (see getdents).
    dir_synth_next: [MAX_FD]usize,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !Fs {
        var fs = Fs{
            .cwd = try allocator.alloc(u8, 1024),
            .cwd_len = 1,
            .host_fd = undefined,
            .dir_handle = undefined,
            .dir_path = undefined,
            .dir_path_len = undefined,
            .dir_synth_next = undefined,
            .allocator = allocator,
        };
        fs.cwd[0] = '/';
        for (&fs.host_fd) |*h| h.* = -1;
        for (&fs.dir_handle) |*d| d.* = -1;
        for (&fs.dir_path_len) |*l| l.* = 0;
        for (&fs.dir_synth_next) |*s| s.* = 0;
        fs.host_fd[0] = 0;
        fs.host_fd[1] = 1;
        fs.host_fd[2] = 2;
        return fs;
    }

    pub fn deinit(self: *Fs) void {
        var i: usize = 3;
        while (i < MAX_FD) : (i += 1) {
            if (self.host_fd[i] >= 0) _ = c.close(self.host_fd[i]);
        }
        self.mounts.deinit(self.allocator);
        self.allocator.free(self.cwd);
    }

    /// Register a mount. Later resolve() picks the longest matching guest prefix.
    pub fn addMount(self: *Fs, guest_prefix: []const u8, host_root: []const u8) !void {
        try self.mounts.append(self.allocator, .{ .guest_prefix = guest_prefix, .host_root = host_root });
    }

    fn cwdSlice(self: *const Fs) []const u8 {
        return self.cwd[0..self.cwd_len];
    }

    /// Public wrapper over canonicalize() for callers that need the guest-
    /// absolute, "."/".." collapsed form of a path (e.g. getdents mount-entry
    /// synthesis). Returns null on error rather than propagating.
    pub fn canonicalGuest(self: *const Fs, guest_path: []const u8, out: []u8) ?[]const u8 {
        return self.canonicalize(guest_path, out) catch null;
    }

    /// Canonicalize a (possibly relative) guest path into a guest-absolute path
    /// with "." and ".." collapsed. Writes into `out`, returns the slice.
    fn canonicalize(self: *const Fs, guest_path: []const u8, out: []u8) Error![]const u8 {
        if (guest_path.len == 0) return error.BadPath;
        var abspath: [2048]u8 = undefined;
        var n: usize = 0;
        if (guest_path[0] != '/') {
            const cw = self.cwdSlice();
            if (cw.len > abspath.len) return error.NameTooLong;
            @memcpy(abspath[0..cw.len], cw);
            n = cw.len;
            if (n == 0 or abspath[n - 1] != '/') {
                if (n + 1 > abspath.len) return error.NameTooLong;
                abspath[n] = '/';
                n += 1;
            }
        }
        if (n + guest_path.len > abspath.len) return error.NameTooLong;
        @memcpy(abspath[n .. n + guest_path.len], guest_path);
        n += guest_path.len;

        var comps: [64][]const u8 = undefined;
        var ncomp: usize = 0;
        var it = std.mem.tokenizeScalar(u8, abspath[0..n], '/');
        while (it.next()) |comp| {
            if (std.mem.eql(u8, comp, ".")) continue;
            if (std.mem.eql(u8, comp, "..")) {
                if (ncomp > 0) ncomp -= 1;
                continue;
            }
            if (ncomp >= comps.len) return error.NameTooLong;
            comps[ncomp] = comp;
            ncomp += 1;
        }

        var w: usize = 0;
        out[w] = '/';
        w = 1;
        var ci: usize = 0;
        while (ci < ncomp) : (ci += 1) {
            if (w > 1) {
                if (w + 1 > out.len) return error.NameTooLong;
                out[w] = '/';
                w += 1;
            }
            if (w + comps[ci].len > out.len) return error.NameTooLong;
            @memcpy(out[w .. w + comps[ci].len], comps[ci]);
            w += comps[ci].len;
        }
        return out[0..if (w == 1) 1 else w];
    }

    /// Longest-prefix mount lookup for a guest-absolute path. Returns the mount
    /// and the byte offset in `abs` just past the matched prefix.
    fn mountFor(self: *const Fs, abs: []const u8) ?struct { m: Mount, rest_at: usize } {
        var best: ?Mount = null;
        var best_len: usize = 0;
        var best_rest: usize = 0;
        for (self.mounts.items) |m| {
            const p = m.guest_prefix;
            const is_root = std.mem.eql(u8, p, "/");
            const matches = if (is_root)
                true
            else
                std.mem.startsWith(u8, abs, p) and (abs.len == p.len or abs[p.len] == '/');
            if (matches and p.len >= best_len) {
                best = m;
                best_len = p.len;
                best_rest = if (is_root) 1 else p.len; // skip leading '/' or the prefix
            }
        }
        if (best) |m| return .{ .m = m, .rest_at = best_rest };
        return null;
    }

    /// Join a mount's host root with the remainder of a guest-absolute path.
    fn joinHost(m: Mount, abs: []const u8, rest_at: usize, out: []u8) Error![:0]const u8 {
        var w: usize = 0;
        if (m.host_root.len + 1 > out.len) return error.NameTooLong;
        @memcpy(out[0..m.host_root.len], m.host_root);
        w = m.host_root.len;
        const rest = if (rest_at <= abs.len) abs[rest_at..] else "";
        if (rest.len > 0 and rest[0] != '/') {
            out[w] = '/';
            w += 1;
        }
        if (w + rest.len + 1 > out.len) return error.NameTooLong;
        @memcpy(out[w .. w + rest.len], rest);
        w += rest.len;
        out[w] = 0;
        return out[0..w :0];
    }

    /// Resolve a guest path to a NUL-terminated host path via the mount table,
    /// following guest-absolute symlinks through the table. Writes into `out`.
    pub fn resolve(self: *const Fs, guest_path: []const u8, out: []u8) Error![:0]const u8 {
        var abs_buf: [2048]u8 = undefined;
        const first = try self.canonicalize(guest_path, &abs_buf);
        var abs_len = first.len;
        var depth: u32 = 0;

        // Walk the guest-absolute path component by component. Build the
        // resolved guest-absolute prefix in `built`; for each component, map
        // the prefix through the mount table to a host path and readlink it. A
        // guest-absolute symlink target replaces the walked prefix (staying in
        // guest space, so the mount table applies); a relative target is
        // resolved against the current built prefix.
        walk: while (true) {
            depth += 1;
            if (depth > MAX_SYMLINK_DEPTH) return error.BadPath;
            const abs = abs_buf[0..abs_len];

            var built: [2048]u8 = undefined;
            built[0] = '/';
            var blen: usize = 1;

            var it = std.mem.tokenizeScalar(u8, abs, '/');
            while (it.next()) |comp| {
                // Append "/comp" (or just "comp" right after root) to built.
                const need_sep = blen > 1;
                const add = (if (need_sep) @as(usize, 1) else 0) + comp.len;
                if (blen + add > built.len) return error.NameTooLong;
                if (need_sep) {
                    built[blen] = '/';
                    blen += 1;
                }
                @memcpy(built[blen .. blen + comp.len], comp);
                blen += comp.len;

                // Map the built prefix through the mount table and readlink it.
                const bslice = built[0..blen];
                const hit = self.mountFor(bslice) orelse return error.NoMount;
                const host = try joinHost(hit.m, bslice, hit.rest_at, out);
                var linkbuf: [1024]u8 = undefined;
                const n = c.readlink(host.ptr, &linkbuf, linkbuf.len);
                if (n <= 0) continue; // not a symlink: keep walking
                var target: []const u8 = linkbuf[0..@intCast(n)];

                // DG/UX "environment link": the target is a literal string
                // `elink:<template>` where <template> contains `${VAR:-default}`
                // references resolved at link-follow time (used to point the
                // toolchain's /usr/lib/{crt0.o,libc.a,...} at the active SDE
                // target, e.g. /usr/sde/m88kdgux/usr/lib/...). We don't carry
                // those env vars, so expand each `${VAR:-default}` to its
                // default. The expanded path is guest-absolute.
                var elink_buf: [2048]u8 = undefined;
                if (std.mem.startsWith(u8, target, "elink:")) {
                    target = expandElink(target["elink:".len..], &elink_buf);
                }

                // Build the new guest-absolute path: (symlink target, resolved)
                // followed by the remaining unprocessed components.
                var newabs: [2048]u8 = undefined;
                var nlen: usize = 0;
                if (target[0] == '/') {
                    // Guest-absolute target replaces the built prefix.
                    @memcpy(newabs[0..target.len], target);
                    nlen = target.len;
                } else {
                    // Relative target: parent of built prefix + target.
                    var parent = blen;
                    while (parent > 1 and built[parent - 1] != '/') parent -= 1;
                    if (parent > 1) parent -= 1; // drop trailing slash
                    const par = if (parent == 0) 1 else parent;
                    @memcpy(newabs[0..par], built[0..par]);
                    nlen = par;
                    if (newabs[nlen - 1] != '/') {
                        newabs[nlen] = '/';
                        nlen += 1;
                    }
                    @memcpy(newabs[nlen .. nlen + target.len], target);
                    nlen += target.len;
                }
                // Append the rest of the original path (it.rest()).
                const rest = it.rest();
                if (rest.len > 0) {
                    if (newabs[nlen - 1] != '/') {
                        newabs[nlen] = '/';
                        nlen += 1;
                    }
                    @memcpy(newabs[nlen .. nlen + rest.len], rest);
                    nlen += rest.len;
                }
                // Canonicalize and restart the walk.
                const canon = try self.canonicalize(newabs[0..nlen], &abs_buf);
                abs_len = canon.len;
                continue :walk;
            }

            // No symlink encountered along the whole path: map it to a host path.
            const hit = self.mountFor(abs_buf[0..abs_len]) orelse return error.NoMount;
            return try joinHost(hit.m, abs_buf[0..abs_len], hit.rest_at, out);
        }
    }

    // --- fd table (lowest-free-first, like Unix) ---------------------------

    pub fn allocFd(self: *Fs, hfd: i32) ?u32 {
        return self.allocFdFrom(hfd, 0);
    }

    /// Allocate the lowest free guest fd >= `min` and map it to host fd `hfd`.
    /// This is the F_DUPFD contract (dup into a fd at or above a floor), which
    /// shells use to build their stdio redirections.
    pub fn allocFdFrom(self: *Fs, hfd: i32, min: u32) ?u32 {
        var i: usize = min;
        while (i < MAX_FD) : (i += 1) {
            if (self.host_fd[i] < 0) {
                self.host_fd[i] = hfd;
                return @intCast(i);
            }
        }
        return null;
    }

    /// Map host fd `hfd` onto a SPECIFIC guest fd `gfd` (the dup2/dup3 target).
    /// Assumes gfd was already closed by the caller. Returns false if gfd is out
    /// of range.
    pub fn allocFdAt(self: *Fs, gfd: u32, hfd: i32) bool {
        if (gfd >= MAX_FD) return false;
        self.host_fd[gfd] = hfd;
        return true;
    }

    pub fn get(self: *const Fs, gfd: u32) ?i32 {
        if (gfd >= MAX_FD) return null;
        const h = self.host_fd[gfd];
        return if (h < 0) null else h;
    }

    pub fn closeFd(self: *Fs, gfd: u32) bool {
        if (gfd >= MAX_FD) return false;
        const h = self.host_fd[gfd];
        if (h < 0) return false;
        if (self.dir_handle[gfd] >= 0) {
            r88k_dirclose(self.dir_handle[gfd]);
            self.dir_handle[gfd] = -1;
            self.dir_path_len[gfd] = 0;
            self.dir_synth_next[gfd] = 0;
        }
        // Close the underlying HOST fd whenever it is one we allocated (>= 3).
        // Guard on the *host* fd, not the guest fd: a guest may dup2 a pipe end
        // onto guest fd 0/1/2 and then replace it — if we skipped the close for
        // guest 0/1/2 the pipe end (host fd >= 3) would leak, and a downstream
        // reader would never see EOF (the `echo x | wc -w` hang). Host fds 0/1/2
        // are the emulator's own stdio and must never be closed here.
        if (h > 2) _ = c.close(h);
        self.host_fd[gfd] = -1;
        return true;
    }

    /// Try to open a directory stream for `host_path` and associate it with an
    /// allocated guest fd. `guest_path` is the guest-absolute directory path
    /// (used later to synthesize mount-point entries in getdents). Returns the
    /// guest fd on success, null if it is not a directory (caller should
    /// proceed with the regular file open).
    pub fn openDir(self: *Fs, host_path: [*:0]const u8, guest_path: []const u8, hfd: i32) ?u32 {
        const handle = r88k_diropen(host_path);
        if (handle < 0) return null;
        const gfd = self.allocFd(hfd) orelse {
            r88k_dirclose(handle);
            return null;
        };
        self.dir_handle[gfd] = handle;
        const n = @min(guest_path.len, self.dir_path[gfd].len);
        @memcpy(self.dir_path[gfd][0..n], guest_path[0..n]);
        self.dir_path_len[gfd] = n;
        self.dir_synth_next[gfd] = 0;
        return gfd;
    }

    /// Guest-absolute path of the directory opened on `gfd`, or null.
    pub fn dirGuestPath(self: *const Fs, gfd: u32) ?[]const u8 {
        if (gfd >= MAX_FD) return null;
        if (self.dir_handle[gfd] < 0) return null;
        return self.dir_path[gfd][0..self.dir_path_len[gfd]];
    }

    /// Read/advance the synthetic mount-entry cursor for a dir fd.
    pub fn dirSynthNext(self: *const Fs, gfd: u32) usize {
        if (gfd >= MAX_FD) return 0;
        return self.dir_synth_next[gfd];
    }
    pub fn dirSynthAdvance(self: *Fs, gfd: u32) void {
        if (gfd >= MAX_FD) return;
        self.dir_synth_next[gfd] += 1;
    }
    pub fn dirSynthRewind(self: *Fs, gfd: u32) void {
        if (gfd >= MAX_FD) return;
        if (self.dir_synth_next[gfd] > 0) self.dir_synth_next[gfd] -= 1;
    }

    /// For a guest-absolute directory `dir`, return the host backing path of
    /// the `index`-th mount point that lives DIRECTLY under `dir` (i.e. the
    /// mount's guest_prefix has `dir` as its parent), along with the final path
    /// component (the entry name). Returns null once `index` is out of range.
    ///
    /// This lets getdents present a mount point as a normal child directory so
    /// a userland getcwd()'s "read the parent, match inodes" walk can climb
    /// across mount boundaries.
    pub fn mountChild(self: *const Fs, dir: []const u8, index: usize) ?struct { host_root: []const u8, name: []const u8 } {
        var seen: usize = 0;
        for (self.mounts.items) |m| {
            const p = m.guest_prefix;
            if (std.mem.eql(u8, p, "/")) continue; // root is never a child
            // Split p into parent + name at the last '/'.
            var slash: usize = p.len;
            while (slash > 0 and p[slash - 1] != '/') slash -= 1;
            // parent = p[0..slash-1] (drop trailing '/'), or "/" if slash==1.
            const parent = if (slash <= 1) "/" else p[0 .. slash - 1];
            const name = p[slash..];
            if (name.len == 0) continue;
            if (!std.mem.eql(u8, parent, dir)) continue;
            if (seen == index) return .{ .host_root = m.host_root, .name = name };
            seen += 1;
        }
        return null;
    }

    /// If the guest path `dir`/`name` is itself a mount point, return the
    /// host backing root of that mount; else null. getdents uses this to
    /// report the MOUNTED directory's inode for an entry that also exists as a
    /// real (shadowed) child on the host — so a getcwd() inode-match walk sees
    /// the same inode from stat(mountpoint) and from the parent's listing.
    pub fn mountAt(self: *const Fs, dir: []const u8, name: []const u8) ?[]const u8 {
        for (self.mounts.items) |m| {
            const p = m.guest_prefix;
            if (std.mem.eql(u8, p, "/")) continue;
            var slash: usize = p.len;
            while (slash > 0 and p[slash - 1] != '/') slash -= 1;
            const parent = if (slash <= 1) "/" else p[0 .. slash - 1];
            const mname = p[slash..];
            if (mname.len == 0) continue;
            if (std.mem.eql(u8, parent, dir) and std.mem.eql(u8, mname, name)) {
                return m.host_root;
            }
        }
        return null;
    }

    pub fn dirHandleFor(self: *const Fs, gfd: u32) ?c_int {
        if (gfd >= MAX_FD) return null;
        const h = self.dir_handle[gfd];
        return if (h < 0) null else h;
    }

    pub fn dirPushback(self: *const Fs, handle: c_int) void {
        _ = self;
        r88k_dirpushback(handle);
    }

    /// Change cwd (guest-absolute canonical). Does not verify existence here.
    pub fn chdir(self: *Fs, guest_path: []const u8) Error!void {
        var buf: [2048]u8 = undefined;
        const canon = try self.canonicalize(guest_path, &buf);
        if (canon.len > self.cwd.len) return error.NameTooLong;
        @memcpy(self.cwd[0..canon.len], canon);
        self.cwd_len = canon.len;
    }

    pub fn cwdPath(self: *const Fs) []const u8 {
        return self.cwdSlice();
    }
};

// ---------------------------------------------------------------------------
// Tests (path resolution — the symlink tests need a live tree, so they are
// guarded to the mounted SysV/88 filesystem and skip if absent).
// ---------------------------------------------------------------------------

fn testFs() !Fs {
    var fs = try Fs.init(std.testing.allocator);
    try fs.addMount("/", "/mnt/hd0_root");
    try fs.addMount("/usr", "/mnt/hd0_slice3");
    return fs;
}

test "mount table longest-prefix resolution" {
    var fs = try testFs();
    defer fs.deinit();
    var out: [1024]u8 = undefined;
    // /etc -> root mount
    try std.testing.expectEqualStrings("/mnt/hd0_root/etc/passwd", try fs.resolve("/etc/passwd", &out));
    // /usr/bin -> the /usr mount (hd0_slice3), NOT /mnt/hd0_root/usr/bin
    try std.testing.expectEqualStrings("/mnt/hd0_slice3/bin/cc", try fs.resolve("/usr/bin/cc", &out));
    // /usr itself
    try std.testing.expectEqualStrings("/mnt/hd0_slice3", try fs.resolve("/usr", &out));
    // .. collapse and escape clamp
    try std.testing.expectEqualStrings("/mnt/hd0_root/x", try fs.resolve("/../../x", &out));
}

test "relative paths resolve against cwd" {
    var fs = try testFs();
    defer fs.deinit();
    var out: [1024]u8 = undefined;
    try fs.chdir("/usr/lib");
    try std.testing.expectEqualStrings("/usr/lib", fs.cwdPath());
    try std.testing.expectEqualStrings("/mnt/hd0_slice3/lib/libc.a", try fs.resolve("libc.a", &out));
}

test "guest-absolute symlink re-resolves through the mount table" {
    // Only meaningful against the real mounted tree where /bin -> /usr/bin.
    var buf: [16]u8 = undefined;
    if (c.readlink("/mnt/hd0_root/bin", &buf, buf.len) <= 0) return; // skip if not mounted
    var fs = try testFs();
    defer fs.deinit();
    var out: [1024]u8 = undefined;
    // /bin is a symlink to /usr/bin, which must land in hd0_slice3.
    const r = try fs.resolve("/bin/echo", &out);
    try std.testing.expectEqualStrings("/mnt/hd0_slice3/bin/echo", r);
}

test "fd table lowest-free-first" {
    var fs = try testFs();
    defer fs.deinit();
    try std.testing.expectEqual(@as(i32, 0), fs.get(0).?);
    const g = fs.allocFd(99).?;
    try std.testing.expectEqual(@as(u32, 3), g);
    fs.host_fd[3] = -1;
    _ = fs.closeFd(1);
    try std.testing.expectEqual(@as(u32, 1), fs.allocFd(77).?);
}

test "allocFdFrom honors a floor (F_DUPFD contract)" {
    var fs = try testFs();
    defer fs.deinit();
    // fds 0,1,2 are open by default. Duplicating with a floor of 5 must skip
    // to fd 5 even though 3 and 4 are free — this is what a shell relies on
    // when it moves a pipe end above the stdio range.
    try std.testing.expectEqual(@as(u32, 5), fs.allocFdFrom(88, 5).?);
    // The lowest-free path (floor 0) still fills the gap at 3 first.
    try std.testing.expectEqual(@as(u32, 3), fs.allocFdFrom(89, 0).?);
    // After closing stdout, a floor of 1 reuses fd 1 (the dup2(x,1) case).
    _ = fs.closeFd(1);
    try std.testing.expectEqual(@as(u32, 1), fs.allocFdFrom(90, 1).?);
}

// ---------------------------------------------------------------------------
// getcwd / mount-boundary regression guards.
//
// A userland getcwd() (SVR4 has no getcwd syscall) walks up via
// getdents("..") + lstat, matching (dev,ino). A virtual mount overlay (e.g.
// /work on a different host fs than guest /) has no real entry in its parent's
// on-disk listing, so the walk fails ("getcwd (bu5)" in make). The fix makes
// getdents synthesize a child entry for each mount point whose parent is the
// directory being listed; mountChild() is the enumeration that drives it.
// These guard the pure logic; the getdents synthesis itself is exercised
// end-to-end by running make against a mounted tree.

test "mountChild enumerates mounts directly under a directory" {
    var fs = try Fs.init(std.testing.allocator);
    defer fs.deinit();
    try fs.addMount("/", "/mnt/hd0_root");
    try fs.addMount("/usr", "/mnt/hd0_slice3");
    try fs.addMount("/work", "/tmp/asm88");
    try fs.addMount("/var/tmp", "/tmp/guest_vartmp");

    // Children of "/": usr and work (root itself is never a child; /var/tmp is
    // nested under /var, not /).
    const c0 = fs.mountChild("/", 0).?;
    try std.testing.expectEqualStrings("usr", c0.name);
    try std.testing.expectEqualStrings("/mnt/hd0_slice3", c0.host_root);
    const c1 = fs.mountChild("/", 1).?;
    try std.testing.expectEqualStrings("work", c1.name);
    try std.testing.expectEqualStrings("/tmp/asm88", c1.host_root);
    // Only two children of "/": index 2 is past the end.
    try std.testing.expect(fs.mountChild("/", 2) == null);

    // Nested mount: /var/tmp appears as child "tmp" of "/var", NOT of "/".
    const v = fs.mountChild("/var", 0).?;
    try std.testing.expectEqualStrings("tmp", v.name);
    try std.testing.expectEqualStrings("/tmp/guest_vartmp", v.host_root);
    try std.testing.expect(fs.mountChild("/var", 1) == null);

    // A directory with no mount children yields nothing.
    try std.testing.expect(fs.mountChild("/usr", 0) == null);
    try std.testing.expect(fs.mountChild("/nonexistent", 0) == null);
}

test "canonicalGuest collapses . and .. for dir-entry synthesis" {
    var fs = try testFs();
    defer fs.deinit();
    var out: [256]u8 = undefined;
    try std.testing.expectEqualStrings("/work", fs.canonicalGuest("/work", &out).?);
    try std.testing.expectEqualStrings("/work", fs.canonicalGuest("/usr/../work", &out).?);
    try std.testing.expectEqualStrings("/", fs.canonicalGuest("/", &out).?);
    // Relative resolves against cwd.
    try fs.chdir("/usr/lib");
    try std.testing.expectEqualStrings("/usr/lib", fs.canonicalGuest(".", &out).?);
    try std.testing.expectEqualStrings("/usr", fs.canonicalGuest("..", &out).?);
}

test "dir synth cursor advances and rewinds per fd" {
    var fs = try testFs();
    defer fs.deinit();
    // The cursor lets getdents resume synthetic-entry emission across calls /
    // buffer boundaries. Exercise the accessor contract directly.
    const gfd: u32 = 7;
    try std.testing.expectEqual(@as(usize, 0), fs.dirSynthNext(gfd));
    fs.dirSynthAdvance(gfd);
    fs.dirSynthAdvance(gfd);
    try std.testing.expectEqual(@as(usize, 2), fs.dirSynthNext(gfd));
    fs.dirSynthRewind(gfd);
    try std.testing.expectEqual(@as(usize, 1), fs.dirSynthNext(gfd));
    // Rewind never underflows below 0.
    fs.dirSynthRewind(gfd);
    fs.dirSynthRewind(gfd);
    try std.testing.expectEqual(@as(usize, 0), fs.dirSynthNext(gfd));
}
