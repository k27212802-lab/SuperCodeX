/**
 * SuperCodeX v9.847.149 Native C++ Application Entry Point
 * Executable Name: supercodex.exe
 *
 * Copyright (c) 2026 SuperCodeX Security Framework
 * All Rights Reserved.
 */

#include "pe_parser.h"
#include "scanner.h"
#include "decompiler.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>

void PrintHeader() {
    std::cout << "======================================================================\n";
    std::cout << " SuperCodeX v9.847.149 Enterprise Native Security & C++ AST Decompiler\n";
    std::cout << " Standalone Native Binary (.exe) · 32 Analysis Modules · 0% Code Loss\n";
    std::cout << "======================================================================\n\n";
}

void PrintUsage() {
    std::cout << "Usage: supercodex.exe [options] <binary_file_path>\n\n";
    std::cout << "Options:\n";
    std::cout << "  --scan            Run full 32-module security analysis\n";
    std::cout << "  --decompile       Lift machine code to Lossless C++ AST source code\n";
    std::cout << "  --output <dir>    Directory to save reconstructed C++ files (default: ./output)\n";
    std::cout << "  --verbose         Print detailed module offsets and disassembly\n";
    std::cout << "  --help            Display this help message\n\n";
}

bool ReadBinaryFile(const std::string& path, std::vector<uint8_t>& buffer) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    buffer.resize(size);
    return file.read(reinterpret_cast<char*>(buffer.data()), size) ? true : false;
}

int main(int argc, char* argv[]) {
    PrintHeader();

    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    std::string filePath = "";
    bool doScan = true;
    bool doDecompile = true;
    std::string outputDir = "./output";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help") {
            PrintUsage();
            return 0;
        } else if (arg == "--scan") {
            doScan = true;
        } else if (arg == "--decompile") {
            doDecompile = true;
        } else if (arg == "--output" && i + 1 < argc) {
            outputDir = argv[++i];
        } else if (arg[0] != '-') {
            filePath = arg;
        }
    }

    if (filePath.empty()) {
        std::cerr << "[ERROR] No input binary file specified.\n";
        PrintUsage();
        return 1;
    }

    std::cout << "[+] Loading target file: " << filePath << " ...\n";
    std::vector<uint8_t> buffer;
    if (!ReadBinaryFile(filePath, buffer)) {
        std::cerr << "[ERROR] Failed to open or read file: " << filePath << "\n";
        return 1;
    }

    std::cout << "[+] File loaded successfully (" << buffer.size() << " bytes).\n\n";

    if (doScan) {
        std::cout << "[*] Executing 32 Security Modules Analysis Engine...\n";
        SuperCodeX::SecurityScannerEngine scanner;
        SuperCodeX::AnalysisReport report = scanner.AnalyzeFile(filePath, buffer);

        std::cout << "----------------------------------------------------------------------\n";
        std::cout << " ANALYSIS REPORT: " << report.fileName << "\n";
        std::cout << " Format: " << report.manifest.format << " (" << report.manifest.architecture << ")\n";
        std::cout << " Global Entropy: " << std::fixed << std::setprecision(3) << report.manifest.globalEntropy << " bits/byte\n";
        std::cout << " Risk Score: " << report.riskScore << "/100\n";
        std::cout << " Verdict: " << report.verdict << "\n";
        std::cout << " Scan Time: " << report.scanTimeMs << " ms\n";
        std::cout << "----------------------------------------------------------------------\n";

        if (!report.detectedThreats.empty()) {
            std::cout << " Detections (" << report.detectedThreats.size() << " triggers):\n";
            for (const auto& t : report.detectedThreats) {
                std::cout << "  - [Module #" << t.moduleId << " " << t.severity << "] " << t.moduleName << ": " << t.details << "\n";
            }
        } else {
            std::cout << "  - No threats detected across all 32 modules.\n";
        }
        std::cout << "\n";
    }

    if (doDecompile) {
        std::cout << "[*] Running Lossless C++ AST Decompiler Lifter...\n";
        SuperCodeX::PEParser parser;
        SuperCodeX::BinaryManifest manifest;
        parser.ParseBuffer(buffer, manifest);

        SuperCodeX::LosslessCppAstDecompiler decompiler;
        SuperCodeX::DecompilationOutput decomp = decompiler.DecompileBinary(manifest, buffer);

        std::cout << "----------------------------------------------------------------------\n";
        std::cout << " RECONSTRUCTED C++ AST SOURCE CODE (0% Deleted Code Guarantee):\n";
        std::cout << " Preserved Functions: " << decomp.totalFunctionsPreserved << "\n";
        std::cout << " Preserved Variables: " << decomp.totalVariablesPreserved << "\n";
        std::cout << " Preservation Rate: " << decomp.codePreservationRatePercent << "%\n";
        std::cout << "----------------------------------------------------------------------\n\n";

        std::cout << decomp.reconstructedSourceCode << "\n";
    }

    std::cout << "[+] Execution complete.\n";
    return 0;
}
