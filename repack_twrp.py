#!/usr/bin/env python3
import argparse
from datetime import datetime
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from vendor_boot import repack_vendor_boot
from patch_goodix_scp import patch_module as patch_goodix_scp
from remove_scp_symbols import main as remove_scp_symbols_main
from patch_scp_init import patch_scp_init

ROOT = Path(__file__).resolve().parent
DEFAULT_TWRP_SOURCE = ROOT.parent
WORK = ROOT / ".work"

BIONIC_LIBRARIES = {
    "libc.so",
    "libm.so",
    "libdl.so",
    "ld-android.so",
}

LK_MB_RAMDISK_BYTES = 0x04000000  # 64 MiB fixed MediaTek LK mb_ramdisk pool
INIT_BOOT_RAMDISK_RESERVE = 3 * 1024 * 1024  # 3 MiB reserve for stock/KSU init_boot ramdisk
MAX_VENDOR_RAMDISK_BYTES = LK_MB_RAMDISK_BYTES - INIT_BOOT_RAMDISK_RESERVE  # 63,963,136 bytes

MINADBD_BASE_LIBRARIES = """
libbinder.so
libbinder_ndk.so
""".split()

STOCK_RECOVERY_FILES = """
first_stage_ramdisk/fstab.emmc
odm_property_contexts
plat_property_contexts
product_property_contexts
sepolicy
system/bin/hw/android.hardware.fastboot-service.example_recovery
system/etc/init/android.hardware.fastboot-service.example_recovery.rc
system/etc/vintf/manifest/android.hardware.fastboot-service.example.xml
system_ext_property_contexts
vendor_file_contexts
vendor_property_contexts
vendor_service_contexts
""".split()

TWRP_FILES = """
default.prop
init
init.recovery.mt6991.rc
init.recovery.project.rc
sbin/sh
system/bin/fastbootd
system/bin/keystore2
system/bin/minadbd
system/bin/recovery
system/bin/se_omapi
system/bin/twrp
system/etc/init/keystore2.rc
system/etc/init/logd.rc
system/etc/init/se_omapi.rc
system/etc/ld.config.txt
system/etc/mkshrc
system/etc/recovery.fstab
system/etc/selinux/plat_keystore2_key_contexts
system/etc/ueventd.rc
system/etc/vintf/manifest/android.system.keystore2-service.xml
vendor/etc/ueventd.rc
""".split()

OPTIONAL_TWRP_FILES = """
system/bin/awk
system/bin/bash
system/bin/bc
system/bin/bootctl
system/bin/bu
system/bin/dmctl
system/bin/dmuserd
system/bin/dump_image
system/bin/e2fsck
system/bin/egrep
system/bin/erase_image
system/bin/fatlabel
system/bin/fgrep
system/bin/flash_image
system/bin/fox
system/bin/fsck.erofs
system/bin/fsck.f2fs
system/bin/fsck.fat
system/bin/grep
system/bin/lptools
system/bin/lpunpack
system/bin/lz4
system/bin/lzma
system/bin/magiskboot
system/bin/me.twrp.twrpapp.apk
system/bin/mkfs.fat
system/bin/pigz
system/bin/privapp-permissions-twrpapp.xml
system/bin/resetprop
system/bin/resize2fs
system/bin/sgdisk
system/bin/simg2img
system/bin/tune2fs
system/bin/unpigz
system/bin/vold_prepare_subdirs
system/bin/xz
system/bin/zip
system/etc/bash/bashrc
system/etc/bash.bashrc
system/lib64/hw/android.hardware.health@2.0-impl-2.1.so
""".split()

# Klimt-specific: touch userspace components and SE HAL (goes to recovery ramdisk)
# Touch kernel modules (.ko) are added to platform ramdisk instead - see add_touch_modules_to_platform()
# Note: vendor.xiaomi.hw.touchfeature-service is NOT included here - it runs from
# mounted stock odm partition via touch_init.sh (see THP userspace stack)
STOCK_PARTITION_FILES = {
    "system/lib64/android.hardware.secure_element-V1-ndk.so": "partitions/vendor/lib64/android.hardware.secure_element-V1-ndk.so",
    "system/lib64/android.se.omapi-V1-ndk.so": "partitions/vendor/lib64/android.se.omapi-V1-ndk.so",
    "system/lib64/stock-vendor-hal/android.hardware.secure_element-V1-ndk.so": "partitions/vendor/lib64/android.hardware.secure_element-V1-ndk.so",
    "system/lib64/stock-vendor-hal/libbinder.so": "vendor_boot/platform/system/lib64/libbinder.so",
    "system/lib64/stock-vendor-hal/libbinder_ndk.so": "vendor_boot/platform/system/lib64/libbinder_ndk.so",
}

# Touch kernel modules to add to platform ramdisk (ramdisk00)
# These are loaded manually via insmod in init.recovery.project.rc
# scp.ko is loaded first to provide symbols for goodix_core_dali.ko
TOUCH_MODULES = [
    "scp.ko",                   # Must load before goodix_core_dali
    "mtk_ioctl_touch_boost.ko",
    "touch_boost.ko",
    "xiaomi_touch_dali.ko",
    "goodix_core_dali.ko",
    "si_haptic.ko",
]

# Module dependencies for modules.dep
TOUCH_MODULE_DEPS = {
    "scp.ko": ["/lib/modules/mtk_tinysys_ipi.ko", "/lib/modules/mtk-mbox.ko", "/lib/modules/clk-common.ko", "/lib/modules/mtk-afe-external.ko", "/lib/modules/aee_aed.ko"],
    "mtk_ioctl_touch_boost.ko": [],
    "touch_boost.ko": ["/lib/modules/mtk_ioctl_touch_boost.ko"],
    "xiaomi_touch_dali.ko": ["/lib/modules/mediatek-drm.ko", "/lib/modules/miev.ko"],
    "goodix_core_dali.ko": ["/lib/modules/xiaomi_touch_dali.ko", "/lib/modules/scp.ko", "/lib/modules/mtk_tinysys_ipi.ko"],
    "si_haptic.ko": ["/lib/modules/miev.ko"],
}

# Klimt Goodix & haptic firmware
for name in ("goodix_cfg_group_klimt.bin", "goodix_firmware_klimt.bin", "klimt_gtp_thp_config.ini"):
    STOCK_PARTITION_FILES[f"ram/firmware/{name}"] = f"partitions/odm/firmware/{name}"
for name in ("aw8697_haptic.bin", "haptic_config.bin"):
    STOCK_PARTITION_FILES[f"ram/firmware/{name}"] = f"partitions/vendor/firmware/{name}"

# Klimt touch config files (from odm/etc/touch)
for name in ("dynamicrate.json", "gameturbotool-fastinput.json", "gameturbotool-control.json", "gameturbotool.json"):
    STOCK_PARTITION_FILES[f"ram/etc/touch/{name}"] = f"partitions/odm/etc/touch/{name}"

TOUCH_PATH_REPLACEMENTS = (
    (b"/odm/lib64/", b"/ram/lib64/"),
    (b"/odm/firmware", b"/ram/firmware"),
    (b"odm/firmware", b"ram/firmware"),
    (b"/odm/etc/", b"/ram/etc/"),
    (b"odm/etc/", b"ram/etc/"),
)

STOCK_VENDOR_MANIFESTS = """
android.hardware.gatekeeper-service.mitee.xml
android.hardware.security.keymint-service.mitee.xml
android.hardware.security.secureclock-service.mitee.xml
android.hardware.security.sharedsecret-service.mitee.xml
android.hardware.weaver-service.nxp.xml
""".split()


def copy_path(source: Path, target: Path) -> None:
    if not source.is_file() and not source.is_symlink():
        raise FileNotFoundError(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    if source.is_symlink():
        target.symlink_to(os.readlink(source))
    else:
        shutil.copy2(source, target)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def patch_touch_paths(path: Path) -> None:
    data = path.read_bytes()
    for old, new in TOUCH_PATH_REPLACEMENTS:
        if len(old) != len(new):
            raise RuntimeError("touch path replacement changes binary size")
        data = data.replace(old, new)
    if b"/odm/" in data or b"odm/firmware" in data:
        raise SystemExit(f"touch library still references ODM: {path.name}")
    path.write_bytes(data)


def patch_goodix_module(work: Path) -> Path:
    """Binary-patch goodix_core_dali.ko to remove SCP dependency.
    
    Returns path to the patched module.
    """
    source = work / "partitions/vendor_dlkm/lib/modules/goodix_core_dali.ko"
    if not source.is_file():
        raise SystemExit(f"goodix_core_dali.ko not found at {source}")
    
    patched = work / "goodix_core_dali_patched.ko"
    final = work / "goodix_core_dali_final.ko"
    
    print("Patching goodix_core_dali.ko to remove SCP dependency...")
    
    # Step 1: Stub SCP functions
    if not patch_goodix_scp(str(source), str(patched)):
        raise SystemExit("Failed to patch goodix_core_dali.ko SCP functions")
    
    # Step 2: Remove SCP symbol references from ELF
    # remove_scp_symbols_main uses sys.argv
    old_argv = sys.argv
    sys.argv = ["remove_scp_symbols.py", str(patched), str(final)]
    try:
        remove_scp_symbols_main()
    finally:
        sys.argv = old_argv
    
    if not final.is_file():
        raise SystemExit("Failed to remove SCP symbols from goodix_core_dali.ko")
    
    print(f"Patched goodix module: {final}")
    return final


def add_touch_modules_to_platform(platform_tree: Path, work: Path) -> None:
    """Add touch kernel modules to platform ramdisk (ramdisk00).
    
    Modules are placed in lib/modules/ but NOT added to modules.load.recovery.
    They will be loaded manually via insmod in init.recovery.project.rc during
    second-stage init (not first-stage). This avoids kernel panics from loading
    touch drivers too early before hardware is ready.
    
    Uses patched scp.ko (init returns 0 immediately) to provide SCP symbols
    for goodix_core_dali.ko without initializing hardware.
    """
    modules_dir = platform_tree / "lib/modules"
    if not modules_dir.is_dir():
        raise SystemExit(f"Platform modules directory not found: {modules_dir}")
    
    vendor_dlkm = work / "partitions/vendor_dlkm/lib/modules"
    
    # Patch scp.ko to not initialize hardware
    scp_source = vendor_dlkm / "scp.ko"
    scp_patched = work / "scp_patched.ko"
    print("Patching scp.ko init function...")
    patch_scp_init(str(scp_source), str(scp_patched))
    
    print("Adding touch modules to platform ramdisk...")
    for mod_name in TOUCH_MODULES:
        if mod_name == "scp.ko":
            source = scp_patched
        else:
            source = vendor_dlkm / mod_name
        
        if not source.is_file():
            print(f"  Warning: module not found: {source}")
            continue
        
        target = modules_dir / mod_name
        shutil.copy2(source, target)
        print(f"  Added: {mod_name}")
    
    # Do NOT add to modules.load.recovery - modules will be loaded via insmod
    # in init.recovery.project.rc during second-stage init
    
    # Update modules.dep for dependency resolution
    dep_file = modules_dir / "modules.dep"
    with dep_file.open("a") as f:
        for mod_name, deps in TOUCH_MODULE_DEPS.items():
            if deps:
                dep_str = " ".join(deps)
                f.write(f"/lib/modules/{mod_name}: {dep_str}\n")
            else:
                f.write(f"/lib/modules/{mod_name}:\n")
    
    print(f"Added {len(TOUCH_MODULES)} touch modules to platform ramdisk (not auto-loaded)")


def elf_needed(path: Path) -> set[str] | None:
    result = subprocess.run(["readelf", "-d", str(path)], text=True, capture_output=True, env={"LC_ALL": "C"})
    if result.returncode != 0:
        return None
    needed = set()
    marker = "Shared library: ["
    for line in result.stdout.splitlines():
        if marker in line:
            needed.add(line.split(marker, 1)[1].split("]", 1)[0])
    return needed


def isolate_build_libraries(
    build: Path, platform_tree: Path, recovery_tree: Path, twrp_source: Path
) -> set[Path]:
    """Isolate all non-Bionic A14 shared libraries into /system/lib64/twrp/.

    Returns the set of ELF binaries in recovery_tree that had DT_RUNPATH patched
    (so later UPX steps skip them cleanly without hitting CantPackException).
    """
    patchelf_bin = shutil.which("patchelf") or str(Path.home() / ".local/bin/patchelf")
    if not Path(patchelf_bin).is_file():
        raise SystemExit(f"patchelf not found (looked in PATH and {patchelf_bin})")

    clang_dirs = sorted(twrp_source.glob("prebuilts/clang/host/linux-x86/clang-r*"))
    llvm_objcopy = clang_dirs[-1] / "bin/llvm-objcopy" if clang_dirs else None
    llvm_strip = clang_dirs[-1] / "bin/llvm-strip" if clang_dirs else None

    stock_bins = {"se_omapi", "touch_report_debug"}
    pending: list[str] = []
    patchelf_targets: list[Path] = []

    bin_dir = recovery_tree / "system/bin"
    if bin_dir.is_dir():
        for entry in sorted(bin_dir.iterdir()):
            if not entry.is_file() or entry.is_symlink() or entry.name in stock_bins:
                continue
            needed = elf_needed(entry)
            if needed is None:
                continue
            if needed - BIONIC_LIBRARIES:
                pending.extend(needed)
                patchelf_targets.append(entry)

    hw_dir = recovery_tree / "system/lib64/hw"
    if hw_dir.is_dir():
        for so in sorted(hw_dir.glob("*.so")):
            if so.is_file() and not so.is_symlink():
                needed = elf_needed(so)
                if needed is not None:
                    pending.extend(needed)
                    patchelf_targets.append(so)

    twrp_lib_dir = recovery_tree / "system/lib64/twrp"
    twrp_lib_dir.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    while pending:
        name = pending.pop()
        if name in seen or name in BIONIC_LIBRARIES:
            continue
        seen.add(name)
        src = build / "system/lib64" / name
        if not src.is_file() and not src.is_symlink():
            raise SystemExit(f"missing A14 library dependency in build: {name}")
        needed = elf_needed(src)
        if needed is not None:
            pending.extend(needed)
        dst = twrp_lib_dir / name
        if dst.exists() or dst.is_symlink():
            dst.unlink()
        copy_path(src, dst)
        if dst.is_file() and not dst.is_symlink():
            if llvm_objcopy and llvm_objcopy.is_file():
                subprocess.run([str(llvm_objcopy), "--remove-section=.gnu_debugdata", str(dst)], check=False, stderr=subprocess.DEVNULL)
            if llvm_strip and llvm_strip.is_file():
                subprocess.run([str(llvm_strip), "--strip-unneeded", str(dst)], check=False, stderr=subprocess.DEVNULL)
            if needed and (needed - BIONIC_LIBRARIES):
                patchelf_targets.append(dst)

    rpath = "/system/lib64/twrp:/system/lib64"
    for target in patchelf_targets:
        if target.parent == bin_dir:
            if llvm_objcopy and llvm_objcopy.is_file():
                subprocess.run([str(llvm_objcopy), "--remove-section=.gnu_debugdata", str(target)], check=False, stderr=subprocess.DEVNULL)
            if llvm_strip and llvm_strip.is_file():
                subprocess.run([str(llvm_strip), "--strip-unneeded", str(target)], check=False, stderr=subprocess.DEVNULL)
        subprocess.run([patchelf_bin, "--set-rpath", rpath, str(target)], check=True)

    # Expose non-colliding libraries (such as libvndksupport.so, libdl_android.so,
    # libandroidicu.so) via /system/lib64/<name> -> twrp/<name> symlinks so stock
    # vendor HALs and touch_init can resolve them without touching colliding A16 libs.
    rec_lib_dir = recovery_tree / "system/lib64"
    plat_lib_dir = platform_tree / "system/lib64"
    exposed = 0
    for so_name in sorted(seen):
        rec_entry = rec_lib_dir / so_name
        plat_entry = plat_lib_dir / so_name
        if not rec_entry.exists() and not rec_entry.is_symlink() and not plat_entry.exists() and not plat_entry.is_symlink():
            rec_entry.symlink_to(f"twrp/{so_name}")
            exposed += 1

    print(f"Isolated {len(seen)} A14 libraries into /system/lib64/twrp/ (exposed {exposed} non-colliding symlinks) and set RUNPATH on {len(patchelf_targets)} ELFs")
    return set(patchelf_targets)


def pack_tree(tree: Path, output: Path, twrp_source: Path) -> None:
    mkbootfs = twrp_source / "out/host/linux-x86/bin/mkbootfs"
    lz4 = twrp_source / "out/host/linux-x86/bin/lz4"
    cpio = output.with_suffix(".cpio")
    with cpio.open("xb") as stream:
        subprocess.run([str(mkbootfs), "-d", str(twrp_source / "out/target/product/klimt"), str(tree)], check=True, stdout=stream)
    subprocess.run([str(lz4), "-l", "-12", "--favor-decSpeed", str(cpio), str(output)], check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--twrp-source", type=Path, default=DEFAULT_TWRP_SOURCE
    )
    parser.add_argument(
        "--security-patch", required=True, metavar="YYYY-MM-DD"
    )
    args = parser.parse_args()
    try:
        datetime.strptime(args.security_patch, "%Y-%m-%d")
    except ValueError:
        parser.error("--security-patch must use YYYY-MM-DD")
    twrp_source = args.twrp_source.resolve()
    host_bin = twrp_source / "out/host/linux-x86/bin"
    if host_bin.is_dir():
        os.environ["PATH"] = f"{host_bin}:{os.environ.get('PATH', '')}"
    build = (twrp_source / "out/target/product/klimt/recovery/root").resolve()

    if not (WORK / "state.json").is_file():
        raise SystemExit("firmware is not prepared; run unpack_stock.py first")
    if not build.is_dir():
        raise SystemExit(f"missing recovery staging directory: {build}")
    build_time = datetime.now()
    run_id = build_time.strftime("%Y%m%d-%H%M%S")
    output_dir = ROOT / "output" / run_id
    output = output_dir / f"klimt-{build_time.strftime('%Y%m%d')}-vendor_boot.img"
    if output_dir.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output_dir}")

    minadbd_needed = elf_needed(build / "system/bin/minadbd")
    if minadbd_needed is None:
        raise SystemExit("cannot read minadbd ELF dependencies")
    minadbd_libraries = sorted(
        {
            *MINADBD_BASE_LIBRARIES,
            *(
                name
                for name in minadbd_needed
                if name.startswith("android.hardware.health-V") and name.endswith("-ndk.so")
            ),
        }
    )

    required_build = [
        *TWRP_FILES,
        *(f"system/lib64/{name}" for name in minadbd_libraries),
    ]
    missing = [path for path in required_build if not (build / path).is_file() and not (build / path).is_symlink()]
    if missing:
        raise SystemExit("recovery build is incomplete:\n  " + "\n  ".join(missing))
    run = Path(tempfile.mkdtemp(prefix=f"repack-{run_id}-", dir=WORK))

    stock_platform = WORK / "vendor_boot/platform"
    stock_recovery = WORK / "vendor_boot/recovery"
    partitions = WORK / "partitions"
    platform_tree = run / "platform-tree"
    recovery_tree = run / "recovery-tree"

    shutil.copytree(
        stock_platform,
        platform_tree,
        symlinks=True,
        ignore=lambda directory, names: {
            name for name in names
            if str((Path(directory) / name).relative_to(stock_platform)) in ("system/bin/recovery", "system/bin/fastbootd")
        },
    )
    # NOTE: mtu3 patch is dash-specific. Skip for klimt unless needed.
    # from mtu3_patch import MTU3_MODULE, verify_patched_mtu3
    # verify_patched_mtu3(platform_tree / MTU3_MODULE)
    init_rc = platform_tree / "system/etc/init/hw/init.rc"
    init_text = init_rc.read_text()
    marker = "    user root\n\nservice adbd "
    if init_text.count(marker) != 1:
        raise SystemExit("unexpected factory type-1 init.rc recovery service")
    # Keep init.rc free of LD_LIBRARY_PATH so recovery does not poison stock
    # A16 child tools (toybox chmod/find/sh); A14 binaries use DT_RUNPATH instead.

    # Add touch modules to platform ramdisk (degas/chagall approach)
    add_touch_modules_to_platform(platform_tree, WORK)

    recovery_tree.mkdir()
    for relative in STOCK_RECOVERY_FILES:
        copy_path(stock_recovery / relative, recovery_tree / relative)
    stock_prop = stock_recovery / "prop.default"
    prop_text = stock_prop.read_text()
    for old, new in (("ro.secure=1", "ro.secure=0"), ("ro.debuggable=0", "ro.debuggable=1")):
        if prop_text.count(old) != 1:
            raise SystemExit(f"expected exactly one {old!r} in factory prop.default")
        prop_text = prop_text.replace(old, new)
    release_lines = [line for line in prop_text.splitlines() if line.startswith("ro.build.version.release=")]
    if len(release_lines) != 1:
        raise SystemExit("expected one ro.build.version.release property in factory prop.default")
    prop_text = prop_text.replace(release_lines[0], "ro.build.version.release=17")
    patch_lines = [line for line in prop_text.splitlines() if line.startswith("ro.build.version.security_patch=")]
    if len(patch_lines) != 1:
        raise SystemExit("expected one ro.build.version.security_patch property in factory prop.default")
    prop_text = prop_text.replace(
        patch_lines[0], f"ro.build.version.security_patch={args.security_patch}"
    )
    (recovery_tree / "prop.default").write_text(prop_text)

    for relative in TWRP_FILES:
        copy_path(build / relative, recovery_tree / relative)
    # Start keystore2 and se_omapi from init.recovery.project.rc after touch_init
    # stabilizes servicemanager and tee-ready-delay finishes.
    (recovery_tree / "system/etc/init/keystore2.rc").write_text(
        "service keystore2 /system/bin/keystore2 /tmp/misc/keystore\n"
        "    class early_hal\n"
        "    user root\n"
        "    group keystore readproc log\n"
        "    writepid /dev/cpuset/foreground/tasks\n"
        "    seclabel u:r:recovery:s0\n"
        "    disabled\n"
    )
    (recovery_tree / "system/etc/init/se_omapi.rc").write_text(
        "service se_omapi /system/bin/se_omapi\n"
        "    class hal\n"
        "    user root\n"
        "    group root\n"
        "    interface aidl android.se.omapi.ISecureElementService/default\n"
        "    seclabel u:r:recovery:s0\n"
        "    disabled\n"
    )
    task_profiles_src = build / "system/etc/task_profiles.json"
    if not task_profiles_src.is_file():
        task_profiles_src = twrp_source / "system/core/libprocessgroup/profiles/task_profiles.json"
    if task_profiles_src.is_file():
        copy_path(task_profiles_src, recovery_tree / "system/etc/task_profiles.json")
    for se_xml_rel in ("system/etc/vintf/manifest/se_omapi.xml", "vendor/etc/vintf/manifest/se_omapi.xml"):
        if (build / se_xml_rel).is_file():
            copy_path(build / se_xml_rel, recovery_tree / "system/etc/vintf/manifest/se_omapi.xml")
            copy_path(build / se_xml_rel, recovery_tree / "vendor/etc/vintf/manifest/se_omapi.xml")
            break
    else:
        raise SystemExit("missing se_omapi.xml in recovery build")
    for relative in OPTIONAL_TWRP_FILES:
        src = build / relative
        if src.is_file() or src.is_symlink():
            copy_path(src, recovery_tree / relative)
    if (build / "FFiles").is_dir():
        shutil.copytree(build / "FFiles", recovery_tree / "FFiles", symlinks=True)
    if (build / "sbin").is_dir():
        for entry in sorted((build / "sbin").iterdir()):
            if entry.name == "adbd":
                continue
            target = recovery_tree / "sbin" / entry.name
            if entry.is_symlink():
                if not target.exists() and not target.is_symlink():
                    copy_path(entry, target)
                link_target = Path(os.readlink(entry))
                if str(link_target).startswith("/system/bin/"):
                    bin_rel = Path("system/bin") / link_target.name
                    src_bin = build / bin_rel
                    dst_bin = recovery_tree / bin_rel
                    if (src_bin.is_file() or src_bin.is_symlink()) and not dst_bin.exists() and not dst_bin.is_symlink():
                        copy_path(src_bin, dst_bin)
            elif entry.is_file():
                # mkbootfs fs_config assigns unknown /sbin files mode 0644.
                # Place regular files in /system/bin (0755) and symlink from /sbin.
                dst_bin = recovery_tree / "system/bin" / entry.name
                if dst_bin.exists() or dst_bin.is_symlink():
                    dst_bin.unlink()
                copy_path(entry, dst_bin)
                if target.exists() or target.is_symlink():
                    target.unlink()
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(f"/system/bin/{entry.name}")
    # Override init.recovery.project.rc with device tree version (has scp_stub + touch insmod)
    device_rc = ROOT.parent / "device_xiaomi_klimt_twrp/rootdir/init.recovery.project.rc"
    if device_rc.is_file():
        shutil.copy2(device_rc, recovery_tree / "init.recovery.project.rc")
        print(f"Overrode init.recovery.project.rc from device tree")
    shutil.copytree(build / "twres", recovery_tree / "twres", symlinks=True)
    lang_dir = recovery_tree / "twres/languages"
    if lang_dir.is_dir():
        for lang_xml in sorted(lang_dir.glob("*.xml")):
            if lang_xml.name not in ("en.xml", "vi_VN.xml"):
                lang_xml.unlink()
    fonts_dir = recovery_tree / "twres/fonts"
    if fonts_dir.is_dir():
        keep_fonts = {
            "EuclidFlex-Regular.ttf",
            "EuclidFlex-Medium.ttf",
            "Roboto-Regular.ttf",
            "Roboto-Medium.ttf",
        }
        for font_file in sorted(fonts_dir.iterdir()):
            if font_file.name in keep_fonts:
                continue
            target_font = (
                "EuclidFlex-Regular.ttf"
                if "Regular" in font_file.name or font_file.name in ("Chococooky.ttf", "RobotoSlab.ttf")
                else "EuclidFlex-Medium.ttf"
            )
            if (fonts_dir / target_font).exists():
                font_file.unlink()
                font_file.symlink_to(target_font)
        misans = fonts_dir / "MiSans.ttf"
        if not misans.exists() and not misans.is_symlink() and (fonts_dir / "Roboto-Regular.ttf").exists():
            misans.symlink_to("Roboto-Regular.ttf")
    for target, source in STOCK_PARTITION_FILES.items():
        copy_path(WORK / source, recovery_tree / target)
    
    # THP userspace stack: cross-compile shims and install touch_init.sh
    thp_dir = recovery_tree / "thp"
    thp_dir.mkdir(exist_ok=True)
    device_tree = Path(__file__).parent.parent / "device_xiaomi_klimt_twrp"
    shims_src = device_tree / "recovery_userspace" / "shims"
    
    # Find clang compiler from TWRP/OrangeFox prebuilts
    clang_candidates = list(twrp_source.glob("prebuilts/clang/host/linux-x86/clang-r*/bin/clang"))
    if not clang_candidates:
        raise SystemExit(f"Cannot find clang in {twrp_source}/prebuilts")
    clang = sorted(clang_candidates)[-1]  # Use latest version
    print(f"Using clang: {clang}")
    
    # Cross-compile shims
    for shim in ("sm_stab3.c", "touch_shim.c"):
        shim_src = shims_src / shim
        shim_so = thp_dir / shim.replace(".c", ".so")
        print(f"Cross-compiling {shim}...")
        subprocess.run([
            str(clang), "--target=aarch64-linux-gnu", "-shared", "-fPIC", "-nostdlib", "-O0", "-std=c11",
            "-o", str(shim_so), str(shim_src)
        ], check=True)
    
    # Copy touch_init.sh
    touch_init_src = device_tree / "recovery_userspace" / "touch_init.sh"
    copy_path(touch_init_src, thp_dir / "touch_init.sh")
    for name in STOCK_VENDOR_MANIFESTS:
        source = partitions / "vendor/etc/vintf/manifest" / name
        copy_path(source, recovery_tree / "vendor/etc/vintf/manifest" / name)
        copy_path(source, recovery_tree / "system/etc/vintf/manifest" / name)
    mtd_manifest = partitions / "odm/etc/vintf/manifest/manifest_vendor.xiaomi.hardware.aidl.mtdservice.xml"
    if mtd_manifest.is_file():
        copy_path(mtd_manifest, recovery_tree / "odm/etc/vintf/manifest/manifest_vendor.xiaomi.hardware.aidl.mtdservice.xml")
        copy_path(mtd_manifest, recovery_tree / "system/etc/vintf/manifest/manifest_vendor.xiaomi.hardware.aidl.mtdservice.xml")
    ese_manifest = recovery_tree / "system/etc/vintf/manifest/android.hardware.secure_element-eSE1.xml"
    ese_manifest.parent.mkdir(parents=True, exist_ok=True)
    ese_manifest.write_text(
        '<manifest version="1.0" type="device">\n'
        '    <hal format="aidl">\n'
        '        <name>android.hardware.secure_element</name>\n'
        '        <version>1</version>\n'
        '        <fqname>ISecureElement/eSE1</fqname>\n'
        '    </hal>\n'
        '</manifest>\n'
    )
    for relative in ("apex", "config", "linkerconfig", "sdcard", "tmp"):
        (recovery_tree / relative).mkdir()
    patchelf_targets = isolate_build_libraries(build, platform_tree, recovery_tree, twrp_source)
    # Symlink minadbd private libs -> ../twrp/ and stock-vendor-hal -> ../ to save ramdisk space
    minadbd_dir = recovery_tree / "system/lib64/minadbd"
    minadbd_dir.mkdir(parents=True, exist_ok=True)
    for name in minadbd_libraries:
        link = minadbd_dir / name
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(f"../twrp/{name}")
    stock_hal_dir = recovery_tree / "system/lib64/stock-vendor-hal"
    if stock_hal_dir.is_dir():
        for entry in sorted(stock_hal_dir.iterdir()):
            name = entry.name
            if (recovery_tree / "system/lib64" / name).exists() or (platform_tree / "system/lib64" / name).exists():
                entry.unlink()
                entry.symlink_to(f"../{name}")

    # Compress static/Bionic-only recovery binaries with UPX to stay safely within
    # MediaTek LK's 64 MiB mb_ramdisk pool (vendor_boot ramdisks + init_boot ramdisk).
    upx_bin = twrp_source / "vendor/recovery/tools/upx"
    if upx_bin.is_file():
        skip_upx = {"init", "linker64", "adbd", "magiskboot", "touch_report_debug", "fastbootd", "se_omapi"}
        skip_upx.discard("magiskboot")
        for bin_dir in (recovery_tree / "system/bin", recovery_tree / "sbin"):
            if not bin_dir.is_dir():
                continue
            for bin_path in sorted(bin_dir.iterdir()):
                if bin_path.is_file() and not bin_path.is_symlink() and bin_path.name not in skip_upx and bin_path not in patchelf_targets:
                    if elf_needed(bin_path) is not None:
                        res = subprocess.run([str(upx_bin), "-q", "--lzma", str(bin_path)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        if res.returncode == 0:
                            subprocess.run([str(upx_bin), "-q", "-t", str(bin_path)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    platform_fragment = run / "platform.lz4"
    recovery_fragment = run / "recovery.lz4"
    pack_tree(platform_tree, platform_fragment, twrp_source)
    pack_tree(recovery_tree, recovery_fragment, twrp_source)

    from vendor_boot import avb_max_serialized_size, avb_metadata, parse_container, serialized_size_multi
    template_bytes = (WORK / "images/vendor_boot.img").read_bytes()
    container_info = parse_container(template_bytes)
    avb_meta = avb_metadata(template_bytes)
    max_ser = avb_max_serialized_size(len(template_bytes), avb_meta)
    p_sz = platform_fragment.stat().st_size
    r_sz = recovery_fragment.stat().st_size
    cur_ser = serialized_size_multi(container_info, {0: p_sz, 1: r_sz})
    ramdisk_sum = p_sz + r_sz
    print(f"Ramdisk sizes: platform={p_sz}, recovery={r_sz}, sum={ramdisk_sum} / LK max={MAX_VENDOR_RAMDISK_BYTES}")
    if ramdisk_sum > MAX_VENDOR_RAMDISK_BYTES:
        raise SystemExit(
            f"Combined ramdisk size {ramdisk_sum} exceeds LK mb_ramdisk safe limit {MAX_VENDOR_RAMDISK_BYTES} "
            f"(pool={LK_MB_RAMDISK_BYTES}, init_boot reserve={INIT_BOOT_RAMDISK_RESERVE})"
        )
    if cur_ser > max_ser:
        raise SystemExit(f"Serialized size {cur_ser} still exceeds AVB max {max_ser}")
    report = output_dir / "repack-report.json"
    budget = output_dir / "size-budget.json"
    result = repack_vendor_boot(
        WORK / "images/vendor_boot.img",
        [
            {"name": "", "type": 1, "path": platform_fragment},
            {"name": "recovery", "type": 2, "path": recovery_fragment},
        ],
        output,
        report,
        budget,
    )
    if result["status"] != "PACKAGING_VALID" or not result["checks"]["dtb_preserved"]:
        raise SystemExit("container validation failed")
    shutil.rmtree(run)
    print(f"system security patch: {args.security_patch}")
    print(f"created: {output}")
    print(f"sha256: {sha256(output)}")


if __name__ == "__main__":
    main()
