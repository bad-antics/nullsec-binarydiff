# NullSec BinaryDiff

**Binary Comparison Tool**

A comprehensive binary diff and analysis tool written in Swift, demonstrating protocol-oriented programming for security-focused binary comparison.

![Swift](https://img.shields.io/badge/Swift-FA7343?style=for-the-badge&logo=swift&logoColor=white)
![Security](https://img.shields.io/badge/Security-Tool-red?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-1.0.0-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

## 🎯 Overview

NullSec BinaryDiff compares binary files to identify changes in sections, functions, imports, and exports. It highlights security-sensitive modifications and calculates similarity scores for patch analysis and malware research.

## ✨ Features

- **Section Comparison** - Detect changes in .text, .data, .bss sections
- **Function Diffing** - Track function additions, removals, modifications
- **Import/Export Analysis** - Monitor library dependencies
- **Security Highlighting** - Flag changes to sensitive functions
- **Similarity Scoring** - Calculate binary similarity percentage
- **Complexity Tracking** - Monitor cyclomatic complexity changes

## 🔍 Analysis Types

| Type | Description | Severity |
|------|-------------|----------|
| .text Modified | Code section changed | High |
| Security Func Changed | auth/crypto function modified | High |
| Section Added | New section in binary | Low |
| Function Removed | Function deleted | Medium |
| Import Added | New library dependency | Info |

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/bad-antics/nullsec-binarydiff
cd nullsec-binarydiff

# Compile with swiftc
swiftc -O binarydiff.swift -o binarydiff

# Or run directly
swift binarydiff.swift
```

## 🚀 Usage

```bash
# Compare two binaries
./binarydiff app_v1 app_v2

# Function-level diff only
./binarydiff -f old.so new.so

# Section-level diff only
./binarydiff -s binary1 binary2

# JSON output
./binarydiff -j old new

# Run demo mode
./binarydiff
```

## 💻 Example Output

```
╔══════════════════════════════════════════════════════════════════╗
║            NullSec BinaryDiff - Binary Comparison Tool           ║
╚══════════════════════════════════════════════════════════════════╝

[Demo Mode]

Comparing sample binaries...

  Section Differences:

  [~] .text
    Type:   MODIFIED
    Reason: Section content changed

  [~] .data
    Type:   MODIFIED
    Reason: Section content changed

  [+] .plt
    Type:   ADDED
    Reason: New section added

  Function Differences:

  [HIGH] ~ auth_user 🔒
    • Size: 200 → 350
    • Complexity: 8 → 12

  [MEDIUM] ~ main
    • Size: 500 → 600
    • Complexity: 15 → 18

  [HIGH] - unsafe_strcpy 🔒
    • Function removed

  [INFO] + new_feature
    • New function

  Import Changes:
    [-] libssl.so.1.1
    [+] libssl.so.3
    [+] libpthread.so.0

═══════════════════════════════════════════

  Summary:
    Old Binary:  /usr/bin/app_v1.0
    New Binary:  /usr/bin/app_v2.0
    Similarity:  20.0%

  Changes:
    Sections:    4
    Functions:   5
    Imports:     3
    Exports:     1

  Security-Sensitive Changes: 2
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Binary Parser                              │
│           ELF | Mach-O | PE Format Support                  │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Binary Info Extraction                          │
│    Sections | Functions | Imports | Exports | Hashes        │
└─────────────────────────────────────────────────────────────┘
                           │
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
     ┌──────────┐   ┌──────────┐   ┌──────────┐
     │ Section  │   │ Function │   │  Symbol  │
     │ Compare  │   │ Compare  │   │ Compare  │
     └──────────┘   └──────────┘   └──────────┘
           │               │               │
           └───────────────┼───────────────┘
                           ▼
                   ┌──────────────┐
                   │ DiffAnalysis │
                   │   Result     │
                   └──────────────┘
```

## 🦅 Swift Features Demonstrated

- **Enums with Associated Values** - `DiffType`, `Severity`
- **Structs** - Value types for `Section`, `FunctionEntry`, `BinaryInfo`
- **Computed Properties** - `Severity.color`
- **Protocol Extensions** - `CaseIterable`
- **Optionals** - Safe handling of missing data
- **Higher-Order Functions** - `filter`, `map`, `contains`
- **Set Operations** - `subtracting` for diff calculation
- **String Interpolation** - Clean output formatting

## 🔧 Data Structures

```swift
struct BinaryInfo {
    let path: String
    let size: UInt64
    let hash: String
    let sections: [Section]
    let functions: [FunctionEntry]
    let imports: [String]
    let exports: [String]
}

struct FunctionDiff {
    let diffType: DiffType
    let oldFunc: FunctionEntry?
    let newFunc: FunctionEntry?
    let severity: Severity
    let changes: [String]
}
```

## 🔐 Security-Sensitive Functions

The tool flags changes to these function patterns:
- **Memory**: `strcpy`, `memcpy`, `malloc`, `free`
- **System**: `system`, `exec`, `popen`, `fork`
- **Network**: `connect`, `bind`, `recv`, `send`
- **Crypto**: `crypt`, `encrypt`, `decrypt`
- **Auth**: `auth`, `login`, `verify`, `validate`

## 🛡️ Security Use Cases

- **Patch Analysis** - Understand security patch changes
- **Malware Research** - Compare malware variants
- **Supply Chain** - Verify binary integrity
- **Forensics** - Identify unauthorized modifications
- **Vulnerability Research** - Track function changes

## ⚠️ Legal Disclaimer

This tool is intended for:
- ✅ Authorized security research
- ✅ Malware analysis (authorized samples)
- ✅ Patch verification
- ✅ Educational purposes

**Only analyze binaries you're authorized to examine.**

## 🔗 Links

- **Portal**: [bad-antics.github.io](https://bad-antics.github.io)
- **Discord**: [discord.gg/killers](https://discord.gg/killers)
- **GitHub**: [github.com/bad-antics](https://github.com/bad-antics)

## 📄 License

MIT License - See LICENSE file for details.

## 🏷️ Version History

- **v1.0.0** - Initial release with binary comparison and security analysis

---

*Part of the NullSec Security Toolkit*
