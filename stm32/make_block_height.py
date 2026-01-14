#!/usr/bin/env python3
#
# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Capture current (mainnet) block height for SSSP/CCC features
#
import sys, time, datetime
import urllib.request


FILE_NAME = "../shared/block_height.py"


def _get_block_height(url):
    with urllib.request.urlopen(url) as response:
        height_data = response.read().decode().strip()
        return int(height_data)


def get_block_height(url):
    try:
        return _get_block_height(url)
    except:
        time.sleep(2)
        return _get_block_height(url)


def parse_block_height_file():
    with open(FILE_NAME, "r") as f:
        for l in f.readlines():
            if l.startswith("BLOCK_HEIGHT ="):
                return int(l.split("=")[-1].strip())

    return None


def write_block_height_file(block_height):
    now = datetime.datetime.now(datetime.timezone.utc)
    with open(FILE_NAME, "wt") as f:
        f.write('''\
# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# AUTO-generated.
#

# As of %s UTC
BLOCK_HEIGHT = %d

# EOF
''' % (now.strftime("%Y-%m-%d %H:%M:%S"), block_height))


def main():
    current_height = None
    for _ in range(2):
        bh_a = get_block_height("https://mempool.space/api/blocks/tip/height")
        bh_b = get_block_height("https://blockstream.info/api/blocks/tip/height")
        if bh_a == bh_b:
            current_height = bh_a
            break

        time.sleep(5)

    if current_height is None:
        raise RuntimeError("Could not get current block height")

    file_block_height = parse_block_height_file()
    if file_block_height is None:
        raise RuntimeError("Could not parse block height from file")

    if current_height > file_block_height:
        write_block_height_file(current_height)
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()

# EOF
