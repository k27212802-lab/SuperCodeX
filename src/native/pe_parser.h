/**
 * SuperCodeX v9.281.492 C++ Native Application Engine
 * Module: PE / ELF / Mach-O Binary File Parser Header
 * Copyright (c) 2026 SuperCodeX Security Framework
 */

#ifndef SUPERCODEX_PE_PARSER_H
#ifndef SUPERCODEX_PE_PARSER_H
#define SUPERCODEX_PE_PARSER_H

#include <vector>
#include <string>
#include <cstdint>
#include <memory>

namespace SuperCodeX {

struct ImageSection {
    std::string name;
    uint32_t virtualAddress;
    uint32_t virtualSize;
    uint32_t rawDataAddress;
    uint32_t rawDataSize;
    uint32_t characteristics;
    bool isExecutable;
    bool isWritable;
    bool isReadable;
    double entropy;
};

struct ImportFunction {
    std::string libraryName;
    std::string functionName;
    uint16_t ordinal;
    uint64_t address;
};

struct BinaryManifest {
    std::string format; // "PE64", "PE32", "ELF64", "Mach-O", "DEX", "WASM"
    std::string architecture; // "x86_64", "ARM64", "Dalvik", "CIL", "Wasm"
    uint64_t entryPoint;
    uint64_t imageBase;
    size_t fileSize;
    double globalEntropy;
    bool hasTlsCallback;
    bool hasForgedRichHeader;
    bool hasRttiSymbols;
    std::vector<ImageSection> sections;
    std::vector<ImportFunction> imports;
    std::vector<std::string> rttiClasses;
};

class PEParser {
public:
    PEParser() = default;
    ~PEParser() = default;

    bool ParseBuffer(const std::vector<uint8_t>& buffer, BinaryManifest& outManifest);
    static double CalculateEntropy(const uint8_t* data, size_t size);

private:
    bool ParseDOSHeader(const uint8_t* buffer, size_t size, uint32_t& peOffset);
    bool ParseNTHeader(const uint8_t* buffer, size_t size, uint32_t peOffset, BinaryManifest& outManifest);
};

} // namespace SuperCodeX

#endif // SUPERCODEX_PE_PARSER_H
