#!/usr/bin/env python3
"""
DFU Binary Extractor - Firmware Liberation Tool
Extract raw firmware from DFU containers for reverse engineering (Made for Flipper Zero)
"""

import struct
import sys
import argparse
import time
import random
from typing import List, Tuple

# DFU file structure constants
DFU_SUFFIX_LENGTH = 16
DFU_PREFIX_LENGTH = 11


# ANSI color codes for terminal styling
class Colors:
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    DARKCYAN = "\033[36m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"


def print_banner():

    banner = f"""{Colors.CYAN}
   ██████╗  ██████╗  ██████╗██╗  ██╗███████╗████████╗ ██████╗  ██████╗ ██████╗ 
   ██╔══██╗██╔═══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔════╝ ██╔═══██╗██╔══██╗
   ██████╔╝██║   ██║██║     █████╔╝ █████╗     ██║   ██║  ███╗██║   ██║██║  ██║
   ██╔══██╗██║   ██║██║     ██╔═██╗ ██╔══╝     ██║   ██║   ██║██║   ██║██║  ██║
   ██║  ██║╚██████╔╝╚██████╗██║  ██╗███████╗   ██║   ╚██████╔╝╚██████╔╝██████╔╝
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═════╝ 
   {Colors.PURPLE}                    ╔═╗╦╦═╗╔╦╗╦ ╦╔═╗╦═╗╔═╗  ╔═╗═╗ ╦╔╦╗╦═╗╔═╗╔═╗╔╦╗╔═╗╦═╗
                       ╠╣ ║╠╦╝║║║║║║╠═╣╠╦╝║╣   ║╣ ╔╩╦╝ ║ ╠╦╝╠═╣║   ║ ║ ║╠╦╝
                       ╚  ╩╩╚═╩ ╩╚╩╝╩ ╩╩╚═╚═╝  ╚═╝╩ ╚═ ╩ ╩╚═╩ ╩╚═╝ ╩ ╚═╝╩╚═
   {Colors.GREEN}═══════════════════════════════════════════════════════════════════════════════
   {Colors.YELLOW}    → {Colors.CYAN}https://betaskynet.com {Colors.YELLOW}← → {Colors.PURPLE}http://discord.gg/thepirates {Colors.YELLOW}←
   {Colors.GREEN}═══════════════════════════════════════════════════════════════════════════════{Colors.END}
   """
    print(banner)


def loading_animation(message, duration=0.5):
    """Display a cool loading animation"""
    chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        print(
            f"\r{Colors.GREEN}[{chars[i % len(chars)]}] {message}{Colors.END}",
            end="",
            flush=True,
        )
        time.sleep(0.1)
        i += 1
    print(f"\r{Colors.GREEN}[✓] {message}{Colors.END}")


def print_hex_preview(data, max_bytes=32):
    """Print a hex preview of the data"""
    preview = data[: min(len(data), max_bytes)]
    hex_str = " ".join(f"{b:02X}" for b in preview)
    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in preview)

    print(
        f"{Colors.DARKCYAN}┌─ HEX PREVIEW ─────────────────────────────────────────────────────────────────────────────────────────────────┐{Colors.END}"
    )
    print(f"{Colors.DARKCYAN}│ {Colors.CYAN}{hex_str}{Colors.END}")
    print(f"{Colors.DARKCYAN}│ {Colors.PURPLE}{ascii_str}{Colors.END}")
    print(
        f"{Colors.DARKCYAN}└───────────────────────────────────────────────────────────────────────────────────────────────────────────────┘{Colors.END}"
    )


class DFUParser:
    def __init__(self, dfu_data: bytes):
        self.dfu_data = dfu_data
        self.targets = []

    def parse_suffix(self) -> dict:
        """Parse the DFU suffix (last 16 bytes)"""
        if len(self.dfu_data) < DFU_SUFFIX_LENGTH:
            raise ValueError("File too small to contain DFU suffix")

        suffix_data = self.dfu_data[-DFU_SUFFIX_LENGTH:]

        suffix = {
            "bcdDevice": struct.unpack("<H", suffix_data[0:2])[0],
            "idProduct": struct.unpack("<H", suffix_data[2:4])[0],
            "idVendor": struct.unpack("<H", suffix_data[4:6])[0],
            "bcdDFU": struct.unpack("<H", suffix_data[6:8])[0],
            "ucDfuSignature": suffix_data[8:11],
            "bLength": suffix_data[11],
            "dwCRC": struct.unpack("<I", suffix_data[12:16])[0],
        }

        if suffix["ucDfuSignature"] != b"UFD":
            raise ValueError("Invalid DFU signature")

        return suffix

    def parse_prefix(self) -> dict:
        """Parse the DFU prefix"""
        if len(self.dfu_data) < DFU_PREFIX_LENGTH + DFU_SUFFIX_LENGTH:
            raise ValueError("File too small to contain DFU prefix")

        prefix_data = self.dfu_data[:DFU_PREFIX_LENGTH]

        prefix = {
            "szSignature": prefix_data[0:5],
            "bVersion": prefix_data[5],
            "dwImageSize": struct.unpack("<I", prefix_data[6:10])[0],
            "bTargets": prefix_data[10],
        }

        if prefix["szSignature"] != b"DfuSe":
            return None

        return prefix

    def extract_raw_binary(self) -> bytes:
        """Extract raw binary (DFU without DfuSe extensions)"""
        return self.dfu_data[:-DFU_SUFFIX_LENGTH]

    def extract_dfuse_targets(self) -> List[Tuple[int, bytes]]:
        """Extract targets from DfuSe format"""
        targets = []
        offset = DFU_PREFIX_LENGTH

        prefix = self.parse_prefix()
        if not prefix:
            return []

        for i in range(prefix["bTargets"]):
            target_prefix = self.dfu_data[offset : offset + 274]

            signature = target_prefix[0:6]
            if signature != b"Target":
                raise ValueError(f"Invalid target signature at offset {offset}")

            alternate_setting = target_prefix[6]
            target_name = target_prefix[11:266].rstrip(b"\x00")
            target_size = struct.unpack("<I", target_prefix[266:270])[0]
            nb_elements = struct.unpack("<I", target_prefix[270:274])[0]

            offset += 274

            element_data = bytearray()
            for j in range(nb_elements):
                element_addr = struct.unpack("<I", self.dfu_data[offset : offset + 4])[
                    0
                ]
                element_size = struct.unpack(
                    "<I", self.dfu_data[offset + 4 : offset + 8]
                )[0]
                offset += 8

                data = self.dfu_data[offset : offset + element_size]
                element_data.extend(data)
                offset += element_size

                targets.append((element_addr, bytes(data)))

        return targets

    def extract(self) -> List[Tuple[int, bytes]]:
        """Extract firmware from DFU file"""
        if self.dfu_data[:5] == b"DfuSe":
            return self.extract_dfuse_targets()
        else:
            return [(0, self.extract_raw_binary())]


def save_binaries(targets: List[Tuple[int, bytes]], output_prefix: str):
    """Save extracted binaries to files"""
    print(f"\n{Colors.YELLOW}[*] EXTRACTING FIRMWARE...{Colors.END}")

    if len(targets) == 1:
        addr, data = targets[0]
        filename = f"{output_prefix}.bin"

        loading_animation("Liberating firmware from DFU container", 2.0)

        with open(filename, "wb") as f:
            f.write(data)

        print(f"{Colors.GREEN}[+] EXTRACTION SUCCESSFUL!{Colors.END}")
        print(f"{Colors.CYAN}    → Filename: {Colors.BOLD}{filename}{Colors.END}")
        print(f"{Colors.CYAN}    → Size: {Colors.BOLD}{len(data):,} bytes{Colors.END}")
        if addr != 0:
            print(
                f"{Colors.CYAN}    → Load Address: {Colors.BOLD}0x{addr:08X}{Colors.END}"
            )

        print_hex_preview(data)
    else:
        for i, (addr, data) in enumerate(targets):
            filename = f"{output_prefix}_{i}.bin"

            loading_animation(f"Extracting target {i+1}/{len(targets)}", 2.0)

            with open(filename, "wb") as f:
                f.write(data)

            print(f"{Colors.GREEN}[+] TARGET {i+1} EXTRACTED!{Colors.END}")
            print(f"{Colors.CYAN}    → Filename: {Colors.BOLD}{filename}{Colors.END}")
            print(
                f"{Colors.CYAN}    → Size: {Colors.BOLD}{len(data):,} bytes{Colors.END}"
            )
            print(
                f"{Colors.CYAN}    → Load Address: {Colors.BOLD}0x{addr:08X}{Colors.END}"
            )

            if i == 0:
                print_hex_preview(data)


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Extract binary from DFU file for Ghidra analysis"
    )
    parser.add_argument("input", help="Input DFU file")
    parser.add_argument(
        "-o",
        "--output",
        help="Output file prefix (default: input filename without extension)",
    )
    parser.add_argument(
        "-i", "--info", action="store_true", help="Show DFU file information"
    )

    args = parser.parse_args()

    print(f"{Colors.YELLOW}[*] INITIALIZING DFU EXTRACTOR...{Colors.END}")
    loading_animation("Loading DFU parser modules", 2.0)

    try:
        print(
            f"{Colors.YELLOW}[*] READING TARGET FILE: {Colors.BOLD}{args.input}{Colors.END}"
        )
        with open(args.input, "rb") as f:
            dfu_data = f.read()
        loading_animation("File loaded into memory", 2.0)
        print(f"{Colors.GREEN}[+] File size: {len(dfu_data):,} bytes{Colors.END}")
    except IOError as e:
        print(
            f"{Colors.RED}[!] ERROR: Failed to read file - {e}{Colors.END}",
            file=sys.stderr,
        )
        return 1

    try:
        dfu_parser = DFUParser(dfu_data)

        if args.info:
            print(f"\n{Colors.YELLOW}[*] ANALYZING DFU STRUCTURE...{Colors.END}")
            loading_animation("Parsing DFU headers", 2.0)

            suffix = dfu_parser.parse_suffix()
            print(f"\n{Colors.PURPLE}╔═══ DFU FILE INTELLIGENCE ═══╗{Colors.END}")
            print(
                f"{Colors.CYAN}  Vendor ID:      {Colors.GREEN}0x{suffix['idVendor']:04X}{Colors.END}"
            )
            print(
                f"{Colors.CYAN}  Product ID:     {Colors.GREEN}0x{suffix['idProduct']:04X}{Colors.END}"
            )
            print(
                f"{Colors.CYAN}  Device Version: {Colors.GREEN}0x{suffix['bcdDevice']:04X}{Colors.END}"
            )
            print(
                f"{Colors.CYAN}  DFU Version:    {Colors.GREEN}0x{suffix['bcdDFU']:04X}{Colors.END}"
            )

            prefix = dfu_parser.parse_prefix()
            if prefix:
                print(
                    f"{Colors.CYAN}  Format:         {Colors.GREEN}DfuSe (ST Extensions){Colors.END}"
                )
                print(
                    f"{Colors.CYAN}  Targets:        {Colors.GREEN}{prefix['bTargets']}{Colors.END}"
                )
            else:
                print(
                    f"{Colors.CYAN}  Format:         {Colors.GREEN}Raw DFU{Colors.END}"
                )
            print(f"{Colors.PURPLE}╚════════════════════════════╝{Colors.END}")

        targets = dfu_parser.extract()

        if args.output:
            output_prefix = args.output
        else:
            output_prefix = args.input.rsplit(".", 1)[0]

        save_binaries(targets, output_prefix)

        print(
            f"\n{Colors.GREEN}╔═══════════════ GHIDRA INTEGRATION GUIDE ═══════════════╗{Colors.END}"
        )
        print(f"{Colors.CYAN}  1. Create new project → Import .bin file(s){Colors.END}")
        print(
            f"{Colors.CYAN}  2. Select processor architecture (ARM/STM32/etc){Colors.END}"
        )
        print(f"{Colors.CYAN}  3. Set base address if shown above{Colors.END}")
        print(f"{Colors.CYAN}  4. Run auto-analysis → Start reversing!{Colors.END}")
        print(
            f"{Colors.GREEN}╚═══════════════════════════════════════════════════════╝{Colors.END}"
        )

        print(
            f"\n{Colors.PURPLE}[✓] FIRMWARE EXTRACTION COMPLETE - HAPPY REVERSING!{Colors.END}"
        )
        print(
            f"{Colors.YELLOW}[>] Join us at {Colors.CYAN}http://discord.gg/thepirates{Colors.END}"
        )

    except Exception as e:
        print(f"{Colors.RED}[!] CRITICAL ERROR: {e}{Colors.END}", file=sys.stderr)
        print(
            f"{Colors.RED}[!] DFU parsing failed - file may be corrupted or unsupported{Colors.END}"
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
