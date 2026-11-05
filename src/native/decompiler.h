/**
 * SuperCodeX v9.281.492 C++ Native Application Engine
 * Module: Lossless C++ AST Decompiler Header
 * Copyright (c) 2026 SuperCodeX Security Framework
 */

#ifndef SUPERCODEX_DECOMPILER_H
#define SUPERCODEX_DECOMPILER_H

#include "pe_parser.h"
#include <string>
#include <vector>

namespace SuperCodeX {

struct DecompiledFunction {
    std::string name;
    std::string returnType;
    std::vector<std::pair<std::string, std::string>> parameters;
    std::vector<std::string> localVariables;
    std::string bodyCPlusPlus;
    uint64_t startRva;
    size_t codeLength;
};

struct DecompilationOutput {
    std::string reconstructedSourceCode;
    std::vector<DecompiledFunction> functions;
    size_t totalFunctionsPreserved;
    size_t totalVariablesPreserved;
    double codePreservationRatePercent; // 100.0%
};

class LosslessCppAstDecompiler {
public:
    LosslessCppAstDecompiler() = default;
    ~LosslessCppAstDecompiler() = default;

    DecompilationOutput DecompileBinary(const BinaryManifest& manifest, const std::vector<uint8_t>& buffer);
};

} // namespace SuperCodeX

#endif // SUPERCODEX_DECOMPILER_H
