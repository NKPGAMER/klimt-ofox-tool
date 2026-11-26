#!/bin/bash
# Extract vendor, odm, vendor_dlkm from super.img
# Usage: ./extract_super.sh /path/to/super.img

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 /path/to/super.img"
    exit 1
fi

SUPER_IMG="$1"
WORK_DIR="$(dirname "$0")/.work"
PARTITIONS_DIR="$WORK_DIR/partitions"

if [ -d "$WORK_DIR" ]; then
    echo "Error: .work directory already exists. Remove it first."
    exit 1
fi

mkdir -p "$WORK_DIR/super" "$PARTITIONS_DIR"

echo "=== Converting sparse super.img to raw ==="
simg2img "$SUPER_IMG" "$WORK_DIR/super/super.raw"

echo "=== Extracting partitions from super.raw ==="
# Try lpunpack first
if command -v lpunpack &> /dev/null; then
    lpunpack "$WORK_DIR/super/super.raw" "$WORK_DIR/super/extracted/"
else
    echo "lpunpack not found, trying alternative method..."
    # Use Python to parse super partition
    python3 - "$WORK_DIR/super/super.raw" "$WORK_DIR/super/extracted/" << 'PYTHON_SCRIPT'
import sys
import struct
from pathlib import Path

def read_super_metadata(raw_path, output_dir):
    """Extract logical partitions from super.img"""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    with open(raw_path, 'rb') as f:
        # Read super partition metadata
        # This is a simplified version - may need adjustment for actual super.img format
        data = f.read()
        
        # Look for partition names
        partitions = ['vendor', 'odm', 'vendor_dlkm']
        
        for part_name in partitions:
            # Find partition in super.img
            # This is placeholder - actual implementation depends on super.img format
            print(f"Looking for {part_name} partition...")
            
    print("Note: Manual extraction may be needed")
    print("Use: lpunpack super.raw output_dir/")

PYTHON_SCRIPT
fi

echo ""
echo "=== Next steps ==="
echo "1. If lpunpack worked, check $WORK_DIR/super/extracted/"
echo "2. Copy vendor.img, odm.img, vendor_dlkm.img to input/"
echo "3. Run: python3 unpack_stock.py"
