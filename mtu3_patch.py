import hashlib
from pathlib import Path


MTU3_MODULE = Path("lib/modules/mtu3.ko")
MTU3_STOCK_SHA256 = "0e13a0d2dfcc9ace79ed3c4be0773a0acf397815c878626848d397ce83c620fb"
MTU3_PATCHED_SHA256 = "3c4e027d4ebac0652a3351b8d0492350c7120c83ef0efaa073c85dd6cec1d3f5"
MTU3_OTG_PATCH_OFFSET = 0x10B98
MTU3_OTG_PATCH_FROM = bytes.fromhex("28 05 00 b4")
MTU3_OTG_PATCH_TO = bytes.fromhex("28 00 00 b4")


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def patch_mtu3_otg_host(path: Path) -> None:
    data = path.read_bytes()
    source_hash = hashlib.sha256(data).hexdigest()
    if source_hash != MTU3_STOCK_SHA256:
        raise SystemExit(
            f"unsupported stock mtu3.ko: expected {MTU3_STOCK_SHA256}, got {source_hash}"
        )
    end = MTU3_OTG_PATCH_OFFSET + len(MTU3_OTG_PATCH_FROM)
    actual = data[MTU3_OTG_PATCH_OFFSET:end]
    if actual != MTU3_OTG_PATCH_FROM:
        raise SystemExit(
            f"unexpected mtu3.ko instruction at 0x{MTU3_OTG_PATCH_OFFSET:x}: "
            f"expected {MTU3_OTG_PATCH_FROM.hex()}, got {actual.hex()}"
        )
    path.write_bytes(
        data[:MTU3_OTG_PATCH_OFFSET] + MTU3_OTG_PATCH_TO + data[end:]
    )
    verify_patched_mtu3(path)
    print(f"patched recovery OTG host gate: {MTU3_MODULE} ({MTU3_PATCHED_SHA256})")


def verify_patched_mtu3(path: Path) -> None:
    actual_hash = file_sha256(path)
    if actual_hash != MTU3_PATCHED_SHA256:
        raise SystemExit(
            "prepared mtu3.ko is not OTG-patched; rerun unpack_stock.py: "
            f"expected {MTU3_PATCHED_SHA256}, got {actual_hash}"
        )
