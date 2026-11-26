#!/usr/bin/env python3
"""Read and rebuild Android vendor_boot images."""

import hashlib
import json
import math
import os
from pathlib import Path
import struct
import subprocess


HEADER_SIZE_V4 = 2128
ENTRY_SIZE_V4 = 108
AVB_FOOTER_SIZE = 64
AVB_VBMETA_HEADER_SIZE = 256


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def sha256(data) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_c_string(data: bytes) -> str:
    return data.split(b"\0", 1)[0].decode("utf-8")


def parse_vbmeta_blob(blob: bytes) -> dict:
    if len(blob) < AVB_VBMETA_HEADER_SIZE:
        raise ValueError("vbmeta blob is too small")
    fmt = ">4sIIQQI" + "Q" * 11 + "II48s80s"
    values = struct.unpack_from(fmt, blob, 0)
    if values[0] != b"AVB0":
        raise ValueError("invalid vbmeta magic")
    auth_size = values[3]
    aux_size = values[4]
    algorithm_type = values[5]
    descriptors_offset = values[14]
    descriptors_size = values[15]
    release_string = decode_c_string(values[19])
    expected_size = AVB_VBMETA_HEADER_SIZE + auth_size + aux_size
    if expected_size > len(blob):
        raise ValueError("vbmeta blocks exceed blob size")
    desc_start = AVB_VBMETA_HEADER_SIZE + auth_size + descriptors_offset
    desc_end = desc_start + descriptors_size
    if desc_end > expected_size:
        raise ValueError("vbmeta descriptors exceed auxiliary block")

    descriptors = []
    cursor = desc_start
    while cursor < desc_end:
        if cursor + 16 > desc_end:
            raise ValueError("truncated AVB descriptor header")
        tag, following = struct.unpack_from(">QQ", blob, cursor)
        total = 16 + following
        if total < 16 or cursor + total > desc_end:
            raise ValueError("invalid AVB descriptor size")
        descriptor = {"tag": tag, "size": total}
        if tag == 0:
            if total < 32:
                raise ValueError("truncated AVB property descriptor")
            _, _, key_len, value_len = struct.unpack_from(">QQQQ", blob, cursor)
            variable = cursor + 32
            key_end = variable + key_len
            value_start = key_end + 1
            value_end = value_start + value_len
            if value_end + 1 > cursor + total:
                raise ValueError("AVB property strings exceed descriptor")
            if blob[key_end] != 0 or blob[value_end] != 0:
                raise ValueError("AVB property strings are not NUL-terminated")
            descriptor.update(
                {
                    "kind": "property",
                    "key": blob[variable:key_end].decode("utf-8"),
                    "value": blob[value_start:value_end].decode("utf-8"),
                }
            )
        elif tag == 2:
            if total < 132:
                raise ValueError("truncated AVB hash descriptor")
            unpacked = struct.unpack_from(">QQQ32sIIII60s", blob, cursor)
            image_size = unpacked[2]
            algorithm = decode_c_string(unpacked[3])
            name_len, salt_len, digest_len, flags = unpacked[4:8]
            variable = cursor + 132
            required = variable + name_len + salt_len + digest_len
            if required > cursor + total:
                raise ValueError("AVB hash descriptor strings exceed descriptor")
            name = blob[variable : variable + name_len].decode("utf-8")
            variable += name_len
            salt = blob[variable : variable + salt_len]
            variable += salt_len
            digest = blob[variable : variable + digest_len]
            descriptor.update(
                {
                    "kind": "hash",
                    "image_size": image_size,
                    "hash_algorithm": algorithm,
                    "partition_name": name,
                    "salt": salt.hex(),
                    "digest": digest.hex(),
                    "flags": flags,
                }
            )
        elif tag == 4:
            if total < 92:
                raise ValueError("truncated AVB chain descriptor")
            unpacked = struct.unpack_from(">QQIIII60s", blob, cursor)
            rollback_location, name_len, key_len, flags = unpacked[2:6]
            variable = cursor + 92
            if variable + name_len + key_len > cursor + total:
                raise ValueError("AVB chain descriptor strings exceed descriptor")
            descriptor.update(
                {
                    "kind": "chain_partition",
                    "partition_name": blob[variable : variable + name_len].decode("utf-8"),
                    "rollback_index_location": rollback_location,
                    "public_key_size": key_len,
                    "flags": flags,
                }
            )
        else:
            descriptor["kind"] = {1: "hashtree", 3: "kernel_cmdline"}.get(
                tag, "unknown"
            )
        descriptors.append(descriptor)
        cursor += total
    if cursor != desc_end:
        raise ValueError("AVB descriptor traversal did not end exactly")
    return {
        "algorithm": {
            0: "NONE",
            1: "SHA256_RSA2048",
            2: "SHA256_RSA4096",
            3: "SHA256_RSA8192",
            4: "SHA512_RSA2048",
            5: "SHA512_RSA4096",
            6: "SHA512_RSA8192",
        }.get(algorithm_type, f"UNKNOWN_{algorithm_type}"),
        "rollback_index": values[16],
        "flags": values[17],
        "rollback_index_location": values[18],
        "release_string": release_string,
        "descriptors": descriptors,
    }


def parse_footer(image: bytes) -> dict:
    if len(image) < AVB_FOOTER_SIZE:
        raise ValueError("image is too small for AVB footer")
    magic, major, minor, original_size, vbmeta_offset, vbmeta_size = struct.unpack_from(
        ">4sIIQQQ28x", image, len(image) - AVB_FOOTER_SIZE
    )
    if magic != b"AVBf":
        raise ValueError("invalid AVB footer magic")
    if original_size > vbmeta_offset or vbmeta_offset + vbmeta_size > len(image) - AVB_FOOTER_SIZE:
        raise ValueError("invalid AVB footer ranges")
    return {
        "version": f"{major}.{minor}",
        "original_image_size": original_size,
        "vbmeta_offset": vbmeta_offset,
        "vbmeta_size": vbmeta_size,
    }


def find_hash_descriptor(vbmeta: dict, partition: str) -> dict:
    matches = [
        descriptor
        for descriptor in vbmeta["descriptors"]
        if descriptor.get("kind") == "hash"
        and descriptor.get("partition_name") == partition
    ]
    if len(matches) != 1:
        raise ValueError(f"expected one hash descriptor for {partition}, got {len(matches)}")
    result = dict(matches[0])
    for key in ("tag", "kind", "size"):
        result.pop(key, None)
    return result


def verify_hash_descriptor(descriptor: dict, image: bytes) -> bool:
    if descriptor["image_size"] > len(image):
        return False
    digest = hashlib.new(descriptor["hash_algorithm"])
    digest.update(bytes.fromhex(descriptor["salt"]))
    digest.update(memoryview(image)[: descriptor["image_size"]])
    return digest.hexdigest() == descriptor["digest"]


def parse_container(image: bytes) -> dict:
    if image[:8] != b"VNDRBOOT":
        raise ValueError("template is not a vendor_boot image")
    version, page_size, _, _, ramdisk_size = struct.unpack_from("<IIIII", image, 8)
    header_size, dtb_size = struct.unpack_from("<II", image, 2096)
    table_size, entry_count, entry_size, bootconfig_size = struct.unpack_from("<IIII", image, 2112)
    if version != 4 or header_size != HEADER_SIZE_V4:
        raise ValueError(f"unsupported vendor_boot header v{version} size {header_size}")
    if page_size == 0 or page_size & (page_size - 1):
        raise ValueError("invalid page size")
    if entry_size < ENTRY_SIZE_V4 or table_size != entry_count * entry_size:
        raise ValueError("invalid vendor ramdisk table")
    ramdisk_offset = align(header_size, page_size)
    ramdisk_end = ramdisk_offset + ramdisk_size
    dtb_offset = align(ramdisk_end, page_size)
    dtb_end = dtb_offset + dtb_size
    table_offset = align(dtb_end, page_size)
    table_end = table_offset + table_size
    bootconfig_offset = align(table_end, page_size)
    bootconfig_end = bootconfig_offset + bootconfig_size
    entries = []
    expected_offset = 0
    for index in range(entry_count):
        table_entry_offset = table_offset + index * entry_size
        size, offset, ramdisk_type = struct.unpack_from("<III", image, table_entry_offset)
        if offset != expected_offset or offset + size > ramdisk_size:
            raise ValueError(f"invalid fragment range for entry {index}")
        name = decode_c_string(image[table_entry_offset + 12 : table_entry_offset + 44])
        board_id = list(struct.unpack_from("<16I", image, table_entry_offset + 44))
        payload = image[ramdisk_offset + offset : ramdisk_offset + offset + size]
        entries.append(
            {
                "index": index,
                "size": size,
                "offset": offset,
                "type": ramdisk_type,
                "name": name,
                "board_id": board_id,
                "payload": payload,
                "raw_table_entry": image[table_entry_offset : table_entry_offset + entry_size],
            }
        )
        expected_offset += size
    if expected_offset != ramdisk_size:
        raise ValueError("fragment total does not match vendor ramdisk size")
    return {
        "version": version,
        "page_size": page_size,
        "header_size": header_size,
        "ramdisk_size": ramdisk_size,
        "ramdisk_offset": ramdisk_offset,
        "ramdisk_end": ramdisk_end,
        "dtb_size": dtb_size,
        "dtb_offset": dtb_offset,
        "dtb_end": dtb_end,
        "table_size": table_size,
        "table_offset": table_offset,
        "table_end": table_end,
        "entry_count": entry_count,
        "entry_size": entry_size,
        "bootconfig_size": bootconfig_size,
        "bootconfig_offset": bootconfig_offset,
        "bootconfig_end": bootconfig_end,
        "entries": entries,
    }


def avb_metadata(template: bytes) -> dict:
    footer = parse_footer(template)
    local_blob = template[footer["vbmeta_offset"] : footer["vbmeta_offset"] + footer["vbmeta_size"]]
    local_vbmeta = parse_vbmeta_blob(local_blob)
    if local_vbmeta["algorithm"] != "NONE":
        raise ValueError("stock local vendor_boot vbmeta is signed; private-key rebuild is unavailable")
    local_hash = find_hash_descriptor(local_vbmeta, "vendor_boot")
    if not verify_hash_descriptor(local_hash, template):
        raise ValueError("stock local hash descriptor does not verify")
    properties = [
        {"key": item["key"], "value": item["value"]}
        for item in local_vbmeta["descriptors"]
        if item.get("kind") == "property"
    ]
    unsupported = [
        item["kind"]
        for item in local_vbmeta["descriptors"]
        if item.get("kind") not in {"hash", "property"}
    ]
    if unsupported:
        raise ValueError(f"unsupported local AVB descriptors: {unsupported}")
    return {
        "footer": footer,
        "local_vbmeta": local_vbmeta,
        "local_hash": local_hash,
        "properties": properties,
    }


def avb_common_args(template_size: int, metadata: dict) -> list[str]:
    descriptor = metadata["local_hash"]
    vbmeta = metadata["local_vbmeta"]
    args = [
        "--partition_size",
        str(template_size),
        "--partition_name",
        descriptor["partition_name"],
        "--hash_algorithm",
        descriptor["hash_algorithm"],
        "--salt",
        descriptor["salt"],
        "--algorithm",
        vbmeta["algorithm"],
        "--rollback_index",
        str(vbmeta["rollback_index"]),
        "--rollback_index_location",
        str(vbmeta["rollback_index_location"]),
        "--flags",
        str(vbmeta["flags"]),
    ]
    if descriptor["flags"] & 1:
        args.append("--do_not_use_ab")
    if descriptor["flags"] & ~1:
        raise ValueError(f"unsupported hash descriptor flags: {descriptor['flags']}")
    for prop in metadata["properties"]:
        args.extend(["--prop", f"{prop['key']}:{prop['value']}"])
    return args


def serialized_size_multi(container: dict, replacement_sizes: dict[int, int]) -> int:
    ramdisk_size = sum(
        replacement_sizes.get(entry["index"], entry["size"])
        for entry in container["entries"]
    )
    page = container["page_size"]
    result = align(container["header_size"], page)
    result += align(ramdisk_size, page)
    result += align(container["dtb_size"], page)
    result += align(container["table_size"], page)
    result += align(container["bootconfig_size"], page)
    return result


def avb_max_serialized_size(template_size: int, metadata: dict) -> int:
    command = ["avbtool", "add_hash_footer", *avb_common_args(template_size, metadata), "--calc_max_image_size"]
    return int(subprocess.run(command, check=True, text=True, stdout=subprocess.PIPE).stdout.strip())


def calculate_multi_budget(
    container: dict, template_size: int, metadata: dict, replacements: dict[int, bytes]
) -> dict:
    max_serialized_size = avb_max_serialized_size(template_size, metadata)
    replacement_sizes = {index: len(payload) for index, payload in replacements.items()}
    new_serialized_size = serialized_size_multi(container, replacement_sizes)
    target_budgets = []
    for index, new_size in sorted(replacement_sizes.items()):
        other_sizes = dict(replacement_sizes)
        low, high = 0, template_size
        while low < high:
            middle = (low + high + 1) // 2
            other_sizes[index] = middle
            if serialized_size_multi(container, other_sizes) <= max_serialized_size:
                low = middle
            else:
                high = middle - 1
        hard_max = low
        reserve = max(1024 * 1024, math.ceil(hard_max * 0.05))
        safe_max = hard_max - reserve
        stock_size = container["entries"][index]["size"]
        grew = new_size > stock_size
        target_gate = (
            "NOT_GROWN"
            if not grew
            else "PASS"
            if new_size <= safe_max
            else "NEAR_LIMIT"
            if new_size <= hard_max
            else "EXCEEDS_LIMIT"
        )
        target_budgets.append(
            {
                "index": index,
                "stock_size": stock_size,
                "new_size": new_size,
                "grew": grew,
                "hard_max_with_other_replacements_fixed": hard_max,
                "safe_reserve": reserve,
                "safe_max_with_other_replacements_fixed": safe_max,
                "size_gate": target_gate,
            }
        )
    growth_gates = [item["size_gate"] for item in target_budgets if item["grew"]]
    gate = (
        "EXCEEDS_LIMIT"
        if new_serialized_size > max_serialized_size or "EXCEEDS_LIMIT" in growth_gates
        else "NEAR_LIMIT"
        if "NEAR_LIMIT" in growth_gates
        else "PASS"
    )
    return {
        "partition_size": template_size,
        "avb_max_serialized_image_size": max_serialized_size,
        "avb_footer_and_metadata_reserve": template_size - max_serialized_size,
        "new_serialized_image_size": new_serialized_size,
        "hard_serialized_headroom": max_serialized_size - new_serialized_size,
        "replacement_fragment_sizes": {
            str(index): size for index, size in sorted(replacement_sizes.items())
        },
        "target_budgets": target_budgets,
        "size_gate": gate,
        "formula": (
            "for each grown fragment, hold all other final replacements fixed; "
            "SAFE_MAX = HARD_MAX - max(1 MiB, ceil(HARD_MAX * 5%))"
        ),
    }


def serialize_base(
    template: bytes, container: dict, replacements: dict[int, bytes]
) -> tuple[bytes, list[dict]]:
    payloads = []
    entries_after = []
    next_offset = 0
    for entry in container["entries"]:
        payload = replacements.get(entry["index"], entry["payload"])
        payloads.append(payload)
        entries_after.append(
            {
                "index": entry["index"],
                "size": len(payload),
                "offset": next_offset,
                "type": entry["type"],
                "name": entry["name"],
                "board_id": entry["board_id"],
                "sha256": sha256(payload),
            }
        )
        next_offset += len(payload)

    page = container["page_size"]
    header = bytearray(template[: container["header_size"]])
    struct.pack_into("<I", header, 24, next_offset)
    table = bytearray(template[container["table_offset"] : container["table_end"]])
    for entry in entries_after:
        offset = entry["index"] * container["entry_size"]
        struct.pack_into("<II", table, offset, entry["size"], entry["offset"])

    result = bytearray(header)
    result.extend(b"\0" * (align(len(result), page) - len(result)))
    for payload in payloads:
        result.extend(payload)
    result.extend(b"\0" * (align(len(result), page) - len(result)))
    result.extend(template[container["dtb_offset"] : container["dtb_end"]])
    result.extend(b"\0" * (align(len(result), page) - len(result)))
    result.extend(table)
    result.extend(b"\0" * (align(len(result), page) - len(result)))
    result.extend(template[container["bootconfig_offset"] : container["bootconfig_end"]])
    result.extend(b"\0" * (align(len(result), page) - len(result)))
    return bytes(result), entries_after


def repack_vendor_boot(
    template_path: Path,
    replacement_specs: list[dict],
    output_path: Path,
    report_path: Path,
    budget_path: Path,
) -> dict:
    if output_path.exists():
        raise FileExistsError(f"refusing to overwrite {output_path}")
    template = template_path.read_bytes()
    container = parse_container(template)
    metadata = avb_metadata(template)
    if metadata["footer"]["original_image_size"] != align(container["bootconfig_end"], container["page_size"]):
        raise ValueError("template layout does not equal AVB original image size")
    replacements = {}
    replacement_reports = []
    for spec in replacement_specs:
        targets = [
            entry
            for entry in container["entries"]
            if entry["name"] == spec["name"] and entry["type"] == spec["type"]
        ]
        if len(targets) != 1:
            raise ValueError(
                f"expected one target fragment for name={spec['name']!r} type={spec['type']}, "
                f"found {len(targets)}"
            )
        target = targets[0]
        if target["index"] in replacements:
            raise ValueError(f"duplicate replacement for fragment index {target['index']}")
        payload = spec["path"].read_bytes()
        replacements[target["index"]] = payload
        replacement_reports.append(
            {
                "path": str(spec["path"]),
                "size": len(payload),
                "sha256": sha256(payload),
                "target_index": target["index"],
                "target_name": target["name"],
                "target_type": target["type"],
            }
        )
    budget = calculate_multi_budget(container, len(template), metadata, replacements)
    if budget["size_gate"] == "EXCEEDS_LIMIT":
        raise ValueError("replacement exceeds hard size limit")

    base, entries_after = serialize_base(template, container, replacements)
    if len(base) != budget["new_serialized_image_size"]:
        raise ValueError("serializer size disagrees with budget calculation")
    stock_base = template[: metadata["footer"]["original_image_size"]]
    identity_input = all(
        payload == container["entries"][index]["payload"]
        for index, payload in replacements.items()
    )
    if identity_input and base != stock_base:
        raise ValueError("identity serialization changed stock pre-AVB bytes")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("xb") as stream:
            stream.write(base)
        command = [
            "avbtool",
            "add_hash_footer",
            "--image",
            str(output_path),
            *avb_common_args(len(template), metadata),
        ]
        subprocess.run(command, check=True)
        output = output_path.read_bytes()
        if len(output) != len(template):
            raise ValueError("repacked image does not match partition size")
        output_footer = parse_footer(output)
        output_blob = output[output_footer["vbmeta_offset"] : output_footer["vbmeta_offset"] + output_footer["vbmeta_size"]]
        output_vbmeta = parse_vbmeta_blob(output_blob)
        output_hash = find_hash_descriptor(output_vbmeta, "vendor_boot")
        if not verify_hash_descriptor(output_hash, output):
            raise ValueError("rebuilt local AVB descriptor does not verify")
        output_container = parse_container(output)
        dtb_preserved = (
            template[container["dtb_offset"] : container["dtb_end"]]
            == output[
                output_container["dtb_offset"] : output_container["dtb_end"]
            ]
        )
        bootconfig_preserved = (
            template[container["bootconfig_offset"] : container["bootconfig_end"]]
            == output[
                output_container["bootconfig_offset"] : output_container["bootconfig_end"]
            ]
        )
        template_header = template[: container["header_size"]]
        output_header = output[: output_container["header_size"]]
        header_preserved = (
            template_header[:24] == output_header[:24]
            and template_header[28:] == output_header[28:]
        )
        preservation_checks = {
            "dtb_preserved": dtb_preserved,
            "cmdline_and_header_preserved_except_total_ramdisk_size": header_preserved,
            "bootconfig_preserved": bootconfig_preserved,
        }
        failed_preservation_checks = [
            name for name, passed in preservation_checks.items() if not passed
        ]
        if failed_preservation_checks:
            raise ValueError(
                "repack changed protected container fields: "
                + ", ".join(failed_preservation_checks)
            )
    except Exception:
        if output_path.exists():
            os.unlink(output_path)
        raise

    before_entries = [
        {
            "index": entry["index"],
            "size": entry["size"],
            "offset": entry["offset"],
            "type": entry["type"],
            "name": entry["name"],
            "board_id": entry["board_id"],
            "sha256": sha256(entry["payload"]),
        }
        for entry in container["entries"]
    ]
    report = {
        "status": "IDENTITY_REPLACEMENT_VALID" if identity_input and output == template else "PACKAGING_VALID",
        "template": {"path": str(template_path), "size": len(template), "sha256": sha256(template)},
        "replacements": replacement_reports,
        "output": {"path": str(output_path), "size": len(output), "sha256": sha256(output), "byte_identical_to_template": output == template},
        "target_indices": sorted(replacements),
        "entries_before": before_entries,
        "entries_after": entries_after,
        "checks": {
            "non_target_payloads_preserved": all(
                before_entries[index]["sha256"] == entries_after[index]["sha256"]
                for index in range(len(before_entries))
                if index not in replacements
            ),
            "entry_metadata_preserved": all(
                before_entries[index][key] == entries_after[index][key]
                for index in range(len(before_entries))
                for key in ("type", "name", "board_id")
            ),
            **preservation_checks,
            "local_avb_descriptor_valid": True,
        },
        "size_budget": budget,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    budget_path.parent.mkdir(parents=True, exist_ok=True)
    budget_path.write_text(json.dumps(budget, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report
