/**
 * SuperCodeX v9.281.492 C++ Native Application Engine
 * Module: 32 Security Analysis Modules Header
 * Copyright (c) 2026 SuperCodeX Security Framework
 */

#ifndef SUPERCODEX_SCANNER_H
#define SUPERCODEX_SCANNER_H

#include "pe_parser.h"
#include <vector>
#include <string>

namespace SuperCodeX {

struct ThreatDetection {
    int moduleId;
    std::string moduleName;
    std::string severity; // "HIGH", "MEDIUM", "LOW"
    std::string details;
    uint64_t offset;
};

struct AnalysisReport {
    std::string fileName;
    BinaryManifest manifest;
    int riskScore;
    std::string verdict; // "CLEAN", "SUSPICIOUS", "MALICIOUS"
    std::vector<ThreatDetection> detectedThreats;
    int activeModulesCount;
    double scanTimeMs;
};

class SecurityScannerEngine {
public:
    SecurityScannerEngine();
    ~SecurityScannerEngine() = default;

    AnalysisReport AnalyzeFile(const std::string& filePath, const std::vector<uint8_t>& buffer);

private:
    void RunModule1_ShannonEntropy(const BinaryManifest& manifest, std::vector<ThreatDetection>& threats);
    void RunModule2_StackStringDecompiler(const std::vector<uint8_t>& buf, std::vector<ThreatDetection>& threats);
    void RunModule3_Ror13ApiHashResolver(const std::vector<uint8_t>& buf, std::vector<ThreatDetection>& threats);
    void RunModule4_RollingXorEmulator(const std::vector<uint8_t>& buf, std::vector<ThreatDetection>& threats);
    void RunModule5_RttiSymbolDemangler(const std::vector<uint8_t>& buf, std::vector<ThreatDetection>& threats);
    void RunModule12_Rc4Unpacker(const std::vector<uint8_t>& buf, std::vector<ThreatDetection>& threats);
    void RunModule14_XteaUnpacker(const std::vector<uint8_t>& buf, std::vector<ThreatDetection>& threats);
    void RunModule15_HeavensGateAndIoUring(const std::vector<uint8_t>& buf, std::vector<ThreatDetection>& threats);
    void RunModule25_HellsGateSyscall(const std::vector<uint8_t>& buf, std::vector<ThreatDetection>& threats);
    void RunModule27_OllvmUnraveler(const std::vector<uint8_t>& buf, std::vector<ThreatDetection>& threats);
    void RunModule28_EarlyCascadeInjection(const std::vector<uint8_t>& buf, std::vector<ThreatDetection>& threats);
    void RunModule32_VmCpuidEvasion(const std::vector<uint8_t>& buf, std::vector<ThreatDetection>& threats);
};

} // namespace SuperCodeX

#endif // SUPERCODEX_SCANNER_H
