/**
 * SuperCodeX v9.281.492 C++ Native Application Engine
 * Module: PE / ELF / Mach-O Binary File Parser Implementation
 * Copyright (c) 2026 SuperCodeX Security Framework
 */

#include "pe_parser.h"
#include <cmath>
#include <cstring>
#include <algorithm>

namespace SuperCodeX {

double PEParser::CalculateEntropy(const uint8_t* data, size_t size) {
    if (!data || size == 0) return 0.0;
    size_t counts[256] = {0};
    for (size_t i = 0; i < size; ++i) {
        counts[data[i]]++;
    }
    double entropy = 0.0;
    double total = static_cast<double>(size);
    for (int i = 0; i < 256; ++i) {
        if (counts[i] == 0) continue;
        double p = static_cast<double>(counts[i]) / total;
        entropy -= p * (std::log2(p));
    }
    return entropy;
}

bool PEParser::ParseDOSHeader(const uint8_t* buffer, size_t size, uint32_t& peOffset) {
    if (size < 64) return false;
    if (buffer[0] != 'M' || buffer[1] != 'Z') return false;
    peOffset = *reinterpret_cast<const uint32_t*>(buffer + 0x3c);
    return (peOffset + 4 < size);
}

bool PEParser::ParseNTHeader(const uint8_t* buffer, size_t size, uint32_t peOffset, BinaryManifest& outManifest) {
    if (peOffset + 24 > size) return false;
    if (buffer[peOffset] != 'P' || buffer[peOffset + 1] != 'E') return false;

    uint16_t machine = *reinterpret_cast<const uint16_t*>(buffer + peOffset + 4);
    uint16_t numSections = *reinterpret_cast<const uint16_t*>(buffer + peOffset + 6);

    if (machine == 0x8664) {
        outManifest.architecture = "x86_64 / AMD64";
        outManifest.format = "PE64";
    } else if (machine == 0xaa64) {
        outManifest.architecture = "ARM64 / AArch64";
        outManifest.format = "PE64 (ARM64)";
    } else {
        outManifest.architecture = "x86 / IA-32";
        outManifest.format = "PE32";
    }

    uint16_t optionalHeaderSize = *reinterpret_cast<const uint16_t*>(buffer + peOffset + 20);
    uint32_t sectionTableOffset = peOffset + 24 + optionalHeaderSize;

    for (uint16_t i = 0; i < numSections; ++i) {
        uint32_t currentSecOffset = sectionTableOffset + (i * 40);
        if (currentSecOffset + 40 > size) break;

        ImageSection sec;
        char nameBuf[9] = {0};
        std::memcpy(nameBuf, buffer + currentSecOffset, 8);
        sec.name = std::string(nameBuf);

        sec.virtualSize = *reinterpret_cast<const uint32_t*>(buffer + currentSecOffset + 8);
        sec.virtualAddress = *reinterpret_cast<const uint32_t*>(buffer + currentSecOffset + 12);
        sec.rawDataSize = *reinterpret_cast<const uint32_t*>(buffer + currentSecOffset + 16);
        sec.rawDataAddress = *reinterpret_cast<const uint32_t*>(buffer + currentSecOffset + 20);
        sec.characteristics = *reinterpret_cast<const uint32_t*>(buffer + currentSecOffset + 36);

        sec.isExecutable = (sec.characteristics & 0x20000000) != 0;
        sec.isWritable = (sec.characteristics & 0x80000000) != 0;
        sec.isReadable = (sec.characteristics & 0x40000000) != 0;

        if (sec.rawDataAddress + sec.rawDataSize <= size) {
            sec.entropy = CalculateEntropy(buffer + sec.rawDataAddress, sec.rawDataSize);
        } else {
            sec.entropy = 0.0;
        }

        outManifest.sections.push_back(sec);
    }

    return true;
}

bool PEParser::ParseBuffer(const std::vector<uint8_t>& buffer, BinaryManifest& outManifest) {
    outManifest.fileSize = buffer.size();
    outManifest.globalEntropy = CalculateEntropy(buffer.data(), buffer.size());

    if (buffer.size() >= 4 && buffer[0] == 0x7F && buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F') {
        outManifest.format = "ELF64";
        outManifest.architecture = (buffer[18] == 0xB7) ? "ARM64" : "x86_64";
        return true;
    }

    if (buffer.size() >= 8 && buffer[0] == 0x00 && buffer[1] == 0x61 && buffer[2] == 0x73 && buffer[3] == 0x6D) {
        outManifest.format = "WebAssembly (.wasm)";
        outManifest.architecture = "Wasm Stack Machine";
        return true;
    }

    uint32_t peOffset = 0;
    if (ParseDOSHeader(buffer.data(), buffer.size(), peOffset)) {
        return ParseNTHeader(buffer.data(), buffer.size(), peOffset, outManifest);
    }

    outManifest.format = "RAW Binary Stream";
    outManifest.architecture = "Unknown / Shellcode";
    return true;
}

} // namespace SuperCodeX
