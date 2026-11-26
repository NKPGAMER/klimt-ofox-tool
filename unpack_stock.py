#!/usr/bin/env python3
import argparse
import json
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEFAULT_TWRP_SOURCE = ROOT.parent
WORK = ROOT / ".work"
IMAGE_NAMES = ("vendor_boot.img", "vendor.img", "odm.img", "vendor_dlkm.img")


def extract_cpio(
    fragment: Path, destination: Path, name: str, twrp_source: Path
) -> None:
    lz4 = twrp_source / "out/host/linux-x86/bin/lz4"
    cpio = destination.parent / f"{name}.cpio"
    destination.mkdir()
    with cpio.open("xb") as stream:
        subprocess.run([str(lz4), "-dc", str(fragment)], check=True, stdout=stream)
    with cpio.open("rb") as stream:
        subprocess.run(
            ["cpio", "--no-absolute-filenames", "-idm", "--quiet"],
            cwd=destination,
            check=True,
            stdin=stream,
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_dir", nargs="?", type=Path, default=ROOT / "input")
    parser.add_argument(
        "--twrp-source", type=Path, default=DEFAULT_TWRP_SOURCE
    )
    args = parser.parse_args()
    input_dir = args.input_dir.resolve()
    twrp_source = args.twrp_source.resolve()

    missing = [name for name in IMAGE_NAMES if not (input_dir / name).is_file()]
    if missing:
        raise SystemExit("missing firmware images:\n  " + "\n  ".join(missing))
    if WORK.exists():
        raise SystemExit(f"refusing to overwrite existing work directory: {WORK}")

    unpacker = twrp_source / "system/tools/mkbootimg/unpack_bootimg.py"
    lz4 = twrp_source / "out/host/linux-x86/bin/lz4"
    for tool in (unpacker, lz4):
        if not tool.is_file():
            raise SystemExit(f"missing build tool: {tool}")
    if shutil.which("fsck.erofs") is None:
        raise SystemExit("missing host tool: fsck.erofs")

    images = WORK / "images"
    boot = WORK / "vendor_boot"
    unpacked = boot / "unpacked"
    partitions = WORK / "partitions"
    images.mkdir(parents=True)
    unpacked.mkdir(parents=True)
    partitions.mkdir()

    for name in IMAGE_NAMES:
        (images / name).symlink_to(input_dir / name)
    subprocess.run(
        ["python3", str(unpacker), "--boot_img", str(images / "vendor_boot.img"), "--out", str(unpacked)],
        check=True,
    )
    for fragment in ("vendor_ramdisk00", "vendor_ramdisk01", "dtb"):
        if not (unpacked / fragment).is_file():
            raise SystemExit(f"vendor_boot is missing {fragment}")
    extract_cpio(
        unpacked / "vendor_ramdisk00", boot / "platform", "platform", twrp_source
    )
    extract_cpio(
        unpacked / "vendor_ramdisk01", boot / "recovery", "recovery", twrp_source
    )
    # NOTE: mtu3 patch is dash-specific. Klimt may need a different patch or none at all.
    # Uncomment and adjust if OTG host mode needs patching on klimt:
    # from mtu3_patch import MTU3_MODULE, patch_mtu3_otg_host
    # patch_mtu3_otg_host(boot / "platform" / MTU3_MODULE)

    for name in ("vendor", "odm", "vendor_dlkm"):
        destination = partitions / name
        destination.mkdir()
        subprocess.run(
            ["fsck.erofs", f"--extract={destination}", "--no-preserve-owner", str(images / f"{name}.img")],
            check=True,
            stdout=subprocess.DEVNULL,
        )

    # Klimt-specific required files
    required = (
        "partitions/vendor/lib64/android.hardware.secure_element-V1-ndk.so",
        "partitions/vendor/lib64/android.se.omapi-V1-ndk.so",
        "partitions/odm/bin/touch_report_debug",
        "partitions/vendor_dlkm/lib/modules/scp.ko",
        "partitions/vendor_dlkm/lib/modules/si_haptic.ko",
        "partitions/vendor_dlkm/lib/modules/xiaomi_touch_dali.ko",
        "partitions/vendor_dlkm/lib/modules/goodix_core_dali.ko",
    )
    absent = [path for path in required if not (WORK / path).is_file()]
    if absent:
        raise SystemExit("firmware set is incomplete:\n  " + "\n  ".join(absent))
    (WORK / "state.json").write_text(
        json.dumps({"input_dir": str(input_dir), "images": list(IMAGE_NAMES)}, indent=2) + "\n"
    )
    print(f"firmware prepared: {WORK}")


if __name__ == "__main__":
    main()
