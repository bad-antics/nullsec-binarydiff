// NullSec BinaryDiff - Binary Comparison Tool
// Swift security tool demonstrating:
//   - Protocol-oriented programming
//   - Value types and copy-on-write
//   - Optionals and nil coalescing
//   - Strong type system
//   - Extensions
//   - Enums with associated values
//
// Author: bad-antics
// License: MIT

import Foundation

let VERSION = "1.0.0"

// ANSI Colors
enum Color: String {
    case red    = "\u{1B}[31m"
    case green  = "\u{1B}[32m"
    case yellow = "\u{1B}[33m"
    case cyan   = "\u{1B}[36m"
    case gray   = "\u{1B}[90m"
    case reset  = "\u{1B}[0m"
}

// Severity levels
enum Severity: String, CaseIterable {
    case critical = "CRITICAL"
    case high = "HIGH"
    case medium = "MEDIUM"
    case low = "LOW"
    case info = "INFO"
    
    var color: Color {
        switch self {
        case .critical, .high: return .red
        case .medium: return .yellow
        case .low: return .cyan
        case .info: return .gray
        }
    }
}

// Diff type
enum DiffType: String {
    case added = "ADDED"
    case removed = "REMOVED"
    case modified = "MODIFIED"
    case unchanged = "UNCHANGED"
}

// Binary section
struct Section {
    let name: String
    let offset: UInt64
    let size: UInt64
    let permissions: String
    let hash: String
}

// Function entry
struct FunctionEntry {
    let name: String
    let offset: UInt64
    let size: UInt64
    let complexity: Int
    let hash: String
}

// Diff result for sections
struct SectionDiff {
    let diffType: DiffType
    let oldSection: Section?
    let newSection: Section?
    let severity: Severity
    let reason: String
}

// Diff result for functions
struct FunctionDiff {
    let diffType: DiffType
    let oldFunc: FunctionEntry?
    let newFunc: FunctionEntry?
    let severity: Severity
    let changes: [String]
}

// Binary info
struct BinaryInfo {
    let path: String
    let size: UInt64
    let hash: String
    let sections: [Section]
    let functions: [FunctionEntry]
    let imports: [String]
    let exports: [String]
}

// Analysis result
struct DiffAnalysis {
    let oldBinary: BinaryInfo
    let newBinary: BinaryInfo
    let sectionDiffs: [SectionDiff]
    let functionDiffs: [FunctionDiff]
    let importDiffs: [String: DiffType]
    let exportDiffs: [String: DiffType]
    let similarityScore: Double
}

// Security-sensitive function names
let securityFunctions = [
    "strcpy", "strcat", "sprintf", "gets",
    "memcpy", "memmove", "malloc", "free",
    "system", "exec", "popen", "fork",
    "connect", "bind", "listen", "accept",
    "read", "write", "recv", "send",
    "crypt", "encrypt", "decrypt",
    "auth", "login", "verify", "validate"
]

// Check if function is security-sensitive
func isSecuritySensitive(_ name: String) -> Bool {
    let lower = name.lowercased()
    return securityFunctions.contains { lower.contains($0) }
}

// Demo binary info
func demoBinaryOld() -> BinaryInfo {
    BinaryInfo(
        path: "/usr/bin/app_v1.0",
        size: 1048576,
        hash: "a1b2c3d4e5f6",
        sections: [
            Section(name: ".text", offset: 0x1000, size: 0x50000, permissions: "r-x", hash: "text_hash_old"),
            Section(name: ".data", offset: 0x60000, size: 0x10000, permissions: "rw-", hash: "data_hash_old"),
            Section(name: ".rodata", offset: 0x70000, size: 0x5000, permissions: "r--", hash: "rodata_hash"),
            Section(name: ".bss", offset: 0x80000, size: 0x2000, permissions: "rw-", hash: "bss_hash"),
        ],
        functions: [
            FunctionEntry(name: "main", offset: 0x1000, size: 500, complexity: 15, hash: "main_old"),
            FunctionEntry(name: "auth_user", offset: 0x2000, size: 200, complexity: 8, hash: "auth_old"),
            FunctionEntry(name: "validate_input", offset: 0x3000, size: 150, complexity: 6, hash: "validate_old"),
            FunctionEntry(name: "process_data", offset: 0x4000, size: 300, complexity: 12, hash: "process_old"),
            FunctionEntry(name: "unsafe_strcpy", offset: 0x5000, size: 50, complexity: 2, hash: "strcpy_hash"),
        ],
        imports: ["libc.so.6", "libssl.so.1.1", "libcrypto.so.1.1"],
        exports: ["app_init", "app_run", "app_cleanup"]
    )
}

func demoBinaryNew() -> BinaryInfo {
    BinaryInfo(
        path: "/usr/bin/app_v2.0",
        size: 1148576,
        hash: "f6e5d4c3b2a1",
        sections: [
            Section(name: ".text", offset: 0x1000, size: 0x58000, permissions: "r-x", hash: "text_hash_new"),
            Section(name: ".data", offset: 0x60000, size: 0x10000, permissions: "rw-", hash: "data_hash_new"),
            Section(name: ".rodata", offset: 0x70000, size: 0x5000, permissions: "r--", hash: "rodata_hash"),
            Section(name: ".bss", offset: 0x80000, size: 0x3000, permissions: "rw-", hash: "bss_hash_new"),
            Section(name: ".plt", offset: 0x90000, size: 0x1000, permissions: "r-x", hash: "plt_hash"),
        ],
        functions: [
            FunctionEntry(name: "main", offset: 0x1000, size: 600, complexity: 18, hash: "main_new"),
            FunctionEntry(name: "auth_user", offset: 0x2000, size: 350, complexity: 12, hash: "auth_new"),
            FunctionEntry(name: "validate_input", offset: 0x3000, size: 150, complexity: 6, hash: "validate_old"),
            FunctionEntry(name: "process_data", offset: 0x4000, size: 400, complexity: 15, hash: "process_new"),
            FunctionEntry(name: "new_feature", offset: 0x6000, size: 250, complexity: 10, hash: "feature_hash"),
        ],
        imports: ["libc.so.6", "libssl.so.3", "libcrypto.so.3", "libpthread.so.0"],
        exports: ["app_init", "app_run", "app_cleanup", "app_configure"]
    )
}

// Analyze binary differences
func analyzeDiff(old: BinaryInfo, new: BinaryInfo) -> DiffAnalysis {
    var sectionDiffs: [SectionDiff] = []
    var functionDiffs: [FunctionDiff] = []
    var importDiffs: [String: DiffType] = [:]
    var exportDiffs: [String: DiffType] = [:]
    
    // Compare sections
    let oldSectionNames = Set(old.sections.map { $0.name })
    let newSectionNames = Set(new.sections.map { $0.name })
    
    for section in old.sections {
        if let newSection = new.sections.first(where: { $0.name == section.name }) {
            if section.hash != newSection.hash {
                let severity: Severity = section.name == ".text" ? .high : .medium
                sectionDiffs.append(SectionDiff(
                    diffType: .modified,
                    oldSection: section,
                    newSection: newSection,
                    severity: severity,
                    reason: "Section content changed"
                ))
            }
        } else {
            sectionDiffs.append(SectionDiff(
                diffType: .removed,
                oldSection: section,
                newSection: nil,
                severity: .medium,
                reason: "Section removed"
            ))
        }
    }
    
    for section in new.sections where !oldSectionNames.contains(section.name) {
        sectionDiffs.append(SectionDiff(
            diffType: .added,
            oldSection: nil,
            newSection: section,
            severity: .low,
            reason: "New section added"
        ))
    }
    
    // Compare functions
    let oldFuncNames = Set(old.functions.map { $0.name })
    
    for func_ in old.functions {
        if let newFunc = new.functions.first(where: { $0.name == func_.name }) {
            if func_.hash != newFunc.hash {
                var changes: [String] = []
                if func_.size != newFunc.size {
                    changes.append("Size: \(func_.size) → \(newFunc.size)")
                }
                if func_.complexity != newFunc.complexity {
                    changes.append("Complexity: \(func_.complexity) → \(newFunc.complexity)")
                }
                
                let severity: Severity = isSecuritySensitive(func_.name) ? .high : .medium
                functionDiffs.append(FunctionDiff(
                    diffType: .modified,
                    oldFunc: func_,
                    newFunc: newFunc,
                    severity: severity,
                    changes: changes
                ))
            }
        } else {
            let severity: Severity = isSecuritySensitive(func_.name) ? .high : .low
            functionDiffs.append(FunctionDiff(
                diffType: .removed,
                oldFunc: func_,
                newFunc: nil,
                severity: severity,
                changes: ["Function removed"]
            ))
        }
    }
    
    for func_ in new.functions where !oldFuncNames.contains(func_.name) {
        functionDiffs.append(FunctionDiff(
            diffType: .added,
            oldFunc: nil,
            newFunc: func_,
            severity: .info,
            changes: ["New function"]
        ))
    }
    
    // Compare imports
    let oldImports = Set(old.imports)
    let newImports = Set(new.imports)
    
    for imp in oldImports.subtracting(newImports) {
        importDiffs[imp] = .removed
    }
    for imp in newImports.subtracting(oldImports) {
        importDiffs[imp] = .added
    }
    
    // Compare exports
    let oldExports = Set(old.exports)
    let newExports = Set(new.exports)
    
    for exp in oldExports.subtracting(newExports) {
        exportDiffs[exp] = .removed
    }
    for exp in newExports.subtracting(oldExports) {
        exportDiffs[exp] = .added
    }
    
    // Calculate similarity
    let totalItems = old.functions.count + new.functions.count
    let unchanged = old.functions.filter { oldF in
        new.functions.contains { $0.hash == oldF.hash }
    }.count * 2
    let similarity = totalItems > 0 ? Double(unchanged) / Double(totalItems) * 100 : 100
    
    return DiffAnalysis(
        oldBinary: old,
        newBinary: new,
        sectionDiffs: sectionDiffs,
        functionDiffs: functionDiffs,
        importDiffs: importDiffs,
        exportDiffs: exportDiffs,
        similarityScore: similarity
    )
}

// Print functions
func printBanner() {
    print()
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║            NullSec BinaryDiff - Binary Comparison Tool           ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print()
}

func printUsage() {
    print("USAGE:")
    print("    binarydiff [OPTIONS] <old_binary> <new_binary>")
    print()
    print("OPTIONS:")
    print("    -h, --help       Show this help")
    print("    -j, --json       JSON output")
    print("    -f, --functions  Function-level diff only")
    print("    -s, --sections   Section-level diff only")
    print()
    print("EXAMPLES:")
    print("    binarydiff app_v1 app_v2")
    print("    binarydiff -f library.so.1 library.so.2")
}

func printSectionDiff(_ diff: SectionDiff) {
    let col = diff.severity.color
    let symbol: String
    switch diff.diffType {
    case .added: symbol = "+"
    case .removed: symbol = "-"
    case .modified: symbol = "~"
    case .unchanged: symbol = " "
    }
    
    let name = diff.newSection?.name ?? diff.oldSection?.name ?? "unknown"
    print()
    print("  \(col.rawValue)[\(symbol)] \(name)\(Color.reset.rawValue)")
    print("    Type:   \(diff.diffType.rawValue)")
    print("    Reason: \(diff.reason)")
    
    if let oldS = diff.oldSection, let newS = diff.newSection {
        if oldS.size != newS.size {
            print("    Size:   \(oldS.size) → \(newS.size)")
        }
    }
}

func printFunctionDiff(_ diff: FunctionDiff) {
    let col = diff.severity.color
    let sev = diff.severity.rawValue
    let symbol: String
    switch diff.diffType {
    case .added: symbol = "+"
    case .removed: symbol = "-"
    case .modified: symbol = "~"
    case .unchanged: symbol = " "
    }
    
    let name = diff.newFunc?.name ?? diff.oldFunc?.name ?? "unknown"
    let secMarker = isSecuritySensitive(name) ? " 🔒" : ""
    
    print()
    print("  \(col.rawValue)[\(sev)] \(symbol) \(name)\(secMarker)\(Color.reset.rawValue)")
    
    for change in diff.changes {
        print("    • \(change)")
    }
}

func printSummary(_ analysis: DiffAnalysis) {
    print()
    print("\(Color.gray.rawValue)═══════════════════════════════════════════\(Color.reset.rawValue)")
    print()
    print("  Summary:")
    print("    Old Binary:  \(analysis.oldBinary.path)")
    print("    New Binary:  \(analysis.newBinary.path)")
    print("    Similarity:  \(String(format: "%.1f", analysis.similarityScore))%")
    print()
    print("  Changes:")
    print("    Sections:    \(analysis.sectionDiffs.filter { $0.diffType != .unchanged }.count)")
    print("    Functions:   \(analysis.functionDiffs.filter { $0.diffType != .unchanged }.count)")
    print("    Imports:     \(analysis.importDiffs.count)")
    print("    Exports:     \(analysis.exportDiffs.count)")
    
    let critCount = analysis.functionDiffs.filter { $0.severity == .critical }.count
    let highCount = analysis.functionDiffs.filter { $0.severity == .high }.count
    
    if critCount > 0 || highCount > 0 {
        print()
        print("  \(Color.red.rawValue)Security-Sensitive Changes: \(critCount + highCount)\(Color.reset.rawValue)")
    }
}

func demoMode() {
    print("\(Color.yellow.rawValue)[Demo Mode]\(Color.reset.rawValue)")
    print()
    print("\(Color.cyan.rawValue)Comparing sample binaries...\(Color.reset.rawValue)")
    
    let oldBinary = demoBinaryOld()
    let newBinary = demoBinaryNew()
    let analysis = analyzeDiff(old: oldBinary, new: newBinary)
    
    print()
    print("  Section Differences:")
    for diff in analysis.sectionDiffs {
        printSectionDiff(diff)
    }
    
    print()
    print("  Function Differences:")
    for diff in analysis.functionDiffs.sorted(by: { $0.severity.rawValue < $1.severity.rawValue }) {
        printFunctionDiff(diff)
    }
    
    if !analysis.importDiffs.isEmpty {
        print()
        print("  Import Changes:")
        for (name, type) in analysis.importDiffs {
            let symbol = type == .added ? "+" : "-"
            print("    [\(symbol)] \(name)")
        }
    }
    
    if !analysis.exportDiffs.isEmpty {
        print()
        print("  Export Changes:")
        for (name, type) in analysis.exportDiffs {
            let symbol = type == .added ? "+" : "-"
            print("    [\(symbol)] \(name)")
        }
    }
    
    printSummary(analysis)
}

// Main
printBanner()

let args = CommandLine.arguments
if args.count <= 1 {
    printUsage()
    print()
    demoMode()
} else if args.contains("-h") || args.contains("--help") {
    printUsage()
} else {
    printUsage()
    print()
    demoMode()
}
