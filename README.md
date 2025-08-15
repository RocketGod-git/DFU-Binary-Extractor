# DFU Binary Extractor - Firmware Liberation Tool
## A Python tool for extracting raw firmware binaries from DFU (Device Firmware Update) containers, optimized for reverse engineering with Ghidra. Perfect for analyzing Flipper Zero and other embedded device firmware.

<img width="800" height="557" alt="image" src="https://github.com/user-attachments/assets/cb500db1-da4a-4ca8-bf21-5f83762c254b" />

## 🚀 Features

DFU Format Support: Handles both standard DFU and DfuSe (ST Microelectronics) formats
Multi-Target Extraction: Automatically extracts all firmware targets from DfuSe files
Ghidra-Ready: Outputs raw binaries ready for import into Ghidra or other RE tools

## 📋 Requirements

No external dependencies (uses only Python standard library)

## 💻 Usage

Extract firmware from DFU file:
```
python dfu-bin-extractor.py firmware.dfu
```

# Specify custom output prefix
```
python dfu-bin-extractor.py firmware.dfu -o extracted_firmware
```

# Show DFU file information without extraction
```
python dfu-bin-extractor.py firmware.dfu -i
```

Command Line Options
positional arguments:
  input                 Input DFU file

optional arguments:
  -h, --help            Show help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file prefix (default: input filename without extension)
  -i, --info            Show DFU file information without extracting
  
## 🔍 Ghidra Integration

After extracting your firmware:

Create New Project: File → New Project → Non-Shared Project
Import Binary: File → Import File → Select your .bin file
Configure Import:

Format: Raw Binary
Language: ARM Cortex (for STM32) or appropriate architecture (Flipper Zero use little endian)
Base Address: Use the address shown by the extractor (e.g., 0x08000000)

Analyze: Analysis → Auto Analyze → Select all analyzers → Analyze

## 🎯 Use Cases

Flipper Zero Development: Extract and analyze Flipper Zero firmware updates

Research: Reverse engineer closed source firmware

<img width="1500" height="1000" alt="rocketgod_logo_transparent" src="https://github.com/user-attachments/assets/2bce4728-59e8-4ec1-b628-00366e2cb271" />
