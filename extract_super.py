#!/usr/bin/env python3
"""Extract logical partitions from Android super.img"""
import argparse
import struct
import sys
from pathlib import Path


def find_lp_metadata(f):
    """Find LP metadata offset in super.img"""
    f.seek(0)
    data = f.read(0x10000)  # Search first 64KB
    # Look for "0PLA" magic (ALP0 in little-endian)
    offset = data.find(b'0PLA')
    if offset == -1:
        raise ValueError("LP metadata not found in first 64KB")
    return offset


def read_super_metadata(f):
    """Read LP metadata from super.img"""
    # Find LP metadata offset
    lp_offset = find_lp_metadata(f)
    f.seek(lp_offset)
    
    # Read LP metadata header
    magic = f.read(4)
    if magic != b'0PLA':
        raise ValueError(f"Invalid LP magic: {magic}")
    
    major_version = struct.unpack('<I', f.read(4))[0]
    minor_version = struct.unpack('<I', f.read(4))[0]
    header_size = struct.unpack('<I', f.read(4))[0]
    header_checksum = f.read(32)  # SHA256
    tables_size = struct.unpack('<Q', f.read(8))[0]
    tables_checksum = f.read(32)  # SHA256
    partitions_offset = struct.unpack('<Q', f.read(8))[0]
    partitions_size = struct.unpack('<Q', f.read(8))[0]
    partitions_checksum = f.read(32)  # SHA256
    extents_offset = struct.unpack('<Q', f.read(8))[0]
    extents_size = struct.unpack('<Q', f.read(8))[0]
    extents_checksum = f.read(32)  # SHA256
    groups_offset = struct.unpack('<Q', f.read(8))[0]
    groups_size = struct.unpack('<Q', f.read(8))[0]
    groups_checksum = f.read(32)  # SHA256
    block_devices_offset = struct.unpack('<Q', f.read(8))[0]
    block_devices_size = struct.unpack('<Q', f.read(8))[0]
    block_devices_checksum = f.read(32)  # SHA256
    flags = struct.unpack('<I', f.read(4))[0]
    reserved = f.read(52)
    
    return {
        'major_version': major_version,
        'minor_version': minor_version,
        'header_size': header_size,
        'tables_size': tables_size,
        'partitions_offset': partitions_offset,
        'partitions_size': partitions_size,
        'extents_offset': extents_offset,
        'extents_size': extents_size,
        'groups_offset': groups_offset,
        'groups_size': groups_size,
        'block_devices_offset': block_devices_offset,
        'block_devices_size': block_devices_size,
    }


def read_partitions(f, metadata):
    """Read partition entries"""
    partitions = []
    f.seek(metadata['header_size'] + metadata['partitions_offset'])
    
    while f.tell() < metadata['header_size'] + metadata['partitions_offset'] + metadata['partitions_size']:
        name = f.read(36).decode('utf-8').rstrip('\0')
        if not name:
            break
        attr = struct.unpack('<I', f.read(4))[0]
        first_extent_index = struct.unpack('<I', f.read(4))[0]
        num_extents = struct.unpack('<I', f.read(4))[0]
        group_index = struct.unpack('<I', f.read(4))[0]
        
        partitions.append({
            'name': name,
            'attr': attr,
            'first_extent_index': first_extent_index,
            'num_extents': num_extents,
            'group_index': group_index,
        })
    
    return partitions


def read_extents(f, metadata):
    """Read extent entries"""
    extents = []
    f.seek(metadata['header_size'] + metadata['extents_offset'])
    
    while f.tell() < metadata['header_size'] + metadata['extents_offset'] + metadata['extents_size']:
        num_sectors = struct.unpack('<Q', f.read(8))[0]
        target_type = struct.unpack('<I', f.read(4))[0]
        target_data = struct.unpack('<Q', f.read(8))[0]
        
        extents.append({
            'num_sectors': num_sectors,
            'target_type': target_type,
            'target_data': target_data,
        })
    
    return extents


def extract_partition(f, partition, extents, output_path, block_size=512):
    """Extract a single partition to a file"""
    with open(output_path, 'wb') as out:
        for i in range(partition['first_extent_index'], 
                      partition['first_extent_index'] + partition['num_extents']):
            extent = extents[i]
            if extent['target_type'] == 0:  # LINEAR
                offset = extent['target_data'] * block_size
                size = extent['num_sectors'] * block_size
                f.seek(offset)
                data = f.read(size)
                out.write(data)
            else:
                print(f"  Warning: Unsupported extent type {extent['target_type']}")


def main():
    parser = argparse.ArgumentParser(description='Extract partitions from super.img')
    parser.add_argument('super_img', help='Path to super.img')
    parser.add_argument('output_dir', help='Output directory')
    parser.add_argument('--partitions', nargs='+', default=['vendor', 'odm', 'vendor_dlkm'],
                       help='Partitions to extract (default: vendor odm vendor_dlkm)')
    args = parser.parse_args()
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Reading {args.super_img}...")
    with open(args.super_img, 'rb') as f:
        metadata = read_super_metadata(f)
        print(f"LP version: {metadata['major_version']}.{metadata['minor_version']}")
        
        partitions = read_partitions(f, metadata)
        print(f"Found {len(partitions)} partitions:")
        for p in partitions:
            print(f"  - {p['name']}")
        
        extents = read_extents(f, metadata)
        print(f"Found {len(extents)} extents")
        
        for target_name in args.partitions:
            found = False
            for p in partitions:
                if p['name'] == target_name:
                    output_path = output_dir / f"{target_name}.img"
                    print(f"Extracting {target_name}...")
                    extract_partition(f, p, extents, output_path)
                    size = output_path.stat().st_size
                    print(f"  -> {output_path} ({size} bytes)")
                    found = True
                    break
            if not found:
                print(f"Warning: Partition '{target_name}' not found")


if __name__ == '__main__':
    main()
