const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The musashi88k CPU core. Its build.zig does not export a public module
    // (it only builds C libraries), so we consume its native Zig API by
    // creating a module directly from the dependency's src/root.zig. root.zig
    // re-exports cpu.Cpu, cpu.MemoryBus, and decode.step for embedding.
    const musashi_dep = b.dependency("musashi88k", .{});
    const m88k_mod = b.createModule(.{
        .root_source_file = musashi_dep.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ---- run88k emulator executable ---------------------------------------
    const root = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    root.addImport("m88k", m88k_mod);
    root.link_libc = true; // libc externs (write, stat shim) for host-backed syscalls
    root.addCSourceFile(.{ .file = b.path("src/host_stat.c"), .flags = &.{"-std=gnu11"} });

    const exe = b.addExecutable(.{
        .name = "run88k",
        .root_module = root,
    });

    // Install per-target so cross-builds don't clobber each other:
    //   zig-out/bin/<arch>-<os>/run88k
    const res = target.result;
    const exe_name = if (res.os.tag == .windows) "run88k.exe" else "run88k";
    const dest_sub_path = b.fmt("{s}-{s}/{s}", .{ @tagName(res.cpu.arch), @tagName(res.os.tag), exe_name });
    const install_exe = b.addInstallArtifact(exe, .{
        .dest_sub_path = dest_sub_path,
        .pdb_dir = .disabled,
    });
    b.getInstallStep().dependOn(&install_exe.step);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(&install_exe.step);
    if (@hasField(std.Build, "args")) {
        if (@field(b, "args")) |args| run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the emulator");
    run_step.dependOn(&run_cmd.step);

    // ---- Unit tests -------------------------------------------------------
    const test_step = b.step("test", "Run unit tests");

    // A single test aggregator rooted at src/tests.zig so every module's
    // relative imports (loaders/, abi/, syscalls/) resolve. libc is linked for
    // the host-backed syscalls; the m88k core module is available.
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addImport("m88k", m88k_mod);
    test_mod.link_libc = true;
    test_mod.addCSourceFile(.{ .file = b.path("src/host_stat.c"), .flags = &.{"-std=gnu11"} });
    const unit_tests = b.addTest(.{ .root_module = test_mod });
    test_step.dependOn(&b.addRunArtifact(unit_tests).step);
}
