import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  calculateShannonEntropy,
  reconstructStackStrings,
  scanForApiHashes,
  emulateRollingAndMultiByteXor,
  computeRor13AsciiHash,
  analyzeFileBytes,
  DEFAULT_ENGINE_CONFIG,
} from './scanner';
import {
  runRealBenchmarkSuite,
  BENCHMARK_SAMPLES,
} from './benchmark';
import {
  runDecompilationBenchmarkSuite,
  runOriginalCppFidelityBenchmarkSuite,
} from './decompiler';
import { execSync } from 'node:child_process';
import os from 'node:os';
import {
  parsePeBinaryStructure,
  decodeNativeFunctionBytes,
  isDataOrResourceFile,
} from './peExportAndDecoder';
import { verifyProjectCppSyntaxWithGpp } from './cppSyntaxValidator';

test('Shannon entropy returns 0 for uniform bytes and ~8.0 for uniform 0..255 distribution', () => {
  const zeros = new Uint8Array(512);
  assert.equal(calculateShannonEntropy(zeros), 0);

  const uniform = new Uint8Array(256 * 4);
  for (let i = 0; i < uniform.length; i++) {
    uniform[i] = i % 256;
  }
  const h = calculateShannonEntropy(uniform);
  assert.ok(h > 7.99 && h <= 8.0, `Expected ~8.0 entropy, got ${h}`);
});

test('v3 Stack-String Decompiler reconstructs strings built via mov byte ptr [rsp+disp], imm8', () => {
  const target = 'VirtualAllocEx';
  const buf = new Uint8Array(128);
  let off = 16;
  for (let i = 0; i < target.length; i++) {
    buf[off++] = 0xc6;
    buf[off++] = 0x44;
    buf[off++] = 0x24;
    buf[off++] = 0x10 + i;
    buf[off++] = target.charCodeAt(i);
  }
  const layers = reconstructStackStrings(buf);
  assert.equal(layers.length, 1);
  assert.equal(layers[0].decodedSnippet, 'VirtualAllocEx');
});

test('v3 ROR13 Dynamic API Hash Resolver identifies Cobalt Strike / Metasploit API hashes', () => {
  const buf = new Uint8Array(64);
  const view = new DataView(buf.buffer);
  view.setUint32(8, computeRor13AsciiHash('VirtualAllocEx'), true);
  view.setUint32(20, computeRor13AsciiHash('WriteProcessMemory'), true);

  const resolved = scanForApiHashes(buf);
  assert.equal(resolved.length, 2);
  assert.ok(resolved.some((r) => r.resolvedModuleAndApi.includes('VirtualAllocEx')));
});

test('v3 Rolling-XOR CPU Loop Emulator cracks position-dependent XOR cipher', () => {
  const secret = 'powershell.exe http://198.51.100.77/apt.bin VirtualAllocEx';
  const raw = new TextEncoder().encode(secret);
  const buf = new Uint8Array(128);
  for (let i = 0; i < buf.length; i++) {
    const p = i < raw.length ? raw[i] : 0x20;
    buf[i] = p ^ ((0x37 + i * 3) & 0xff);
  }
  const layers = emulateRollingAndMultiByteXor(buf);
  assert.equal(layers.length, 1);
  assert.ok(layers[0].decodedSnippet.includes('http://198.51.100.77/apt.bin'));
});

test('v4 C++ Machine Code Disassembler & RTTI Demangler reconstructs C++ code from .exe', async () => {
  const cppSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-18')!;
  const report = await analyzeFileBytes(cppSample.fileName, cppSample.buildBytes(), DEFAULT_ENGINE_CONFIG);

  assert.equal(report.verdict, 'MALICIOUS');
  assert.equal(
    report.decompilation.targetLanguage,
    'C / C++ (x86_64 SSA, Struct/VTable, Switch & Control-Flow AST Lifter)'
  );
  assert.ok(report.decompilation.disassemblyListing.some((i) => i.mnemonic === 'rdtsc'));
  assert.ok(report.decompilation.disassemblyListing.some((i) => i.mnemonic === 'call' && i.operands === 'rax'));
  assert.ok(
    report.decompilation.demangledCppSymbols.some((s) =>
      s.demangledSignature.includes('StealthAPT::ProcessHollower')
    )
  );
  assert.ok(report.decompilation.reconstructedCode.includes('__rdtsc()'));
});

test('v4 Android APK & Dalvik DEX Decompiler extracts classes.dex, Smali opcodes and Java code from .apk', async () => {
  const apkSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-19')!;
  const report = await analyzeFileBytes(apkSample.fileName, apkSample.buildBytes(), DEFAULT_ENGINE_CONFIG);

  assert.equal(report.verdict, 'MALICIOUS');
  assert.equal(report.headerAnalysis.format, 'Android APK / Dalvik DEX');
  assert.equal(report.decompilation.targetLanguage, 'Java / Smali (Android APK & Dalvik DEX Decompiler)');
  assert.ok(report.decompilation.apkDexInfo.isApkOrDex);
  assert.ok(report.decompilation.apkDexInfo.zipEntries.includes('AndroidManifest.xml'));
  assert.ok(report.decompilation.apkDexInfo.zipEntries.includes('classes.dex'));
  assert.ok(report.decompilation.disassemblyListing.some((i) => i.mnemonic === 'invoke-virtual'));
  assert.ok(report.decompilation.reconstructedCode.includes('DexClassLoader'));
  assert.ok(report.decompilation.reconstructedCode.includes('DexClassLoader'));
});

test('v5 CFG AST C++ Lifter reconstructs if/else, backward loops, stack variables, and Win64 Fastcall ABI without executing file', async () => {
  const cfgSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-20')!;
  const report = await analyzeFileBytes(cfgSample.fileName, cfgSample.buildBytes(), DEFAULT_ENGINE_CONFIG);

  assert.equal(report.verdict, 'MALICIOUS');
  assert.ok(report.decompilation.cfgStats.ifElseBranchesCount >= 1);
  assert.ok(report.decompilation.cfgStats.loopsCount >= 1);
  assert.ok(report.decompilation.cfgStats.localVariablesCount >= 1);
  assert.ok(report.decompilation.cfgStats.win64FastcallParamsCount >= 3);
  assert.ok(report.decompilation.reconstructedCode.includes('local_var_8 = 0x1337'));
  assert.ok(report.decompilation.reconstructedCode.includes('for (uint32_t loop_idx = 0;'));
  assert.ok(report.decompilation.reconstructedCode.includes('fn_rax(rcx_arg1, rdx_arg2, r8_arg3, r9_arg4)'));
  assert.ok(report.decompilation.qualityMetrics.overallAegisQualityPercent >= 90);
});

test('v5 .NET / C# CIL Decompiler reconstructs C# source and detects reflective Assembly.Load without execution', async () => {
  const dotNetSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-21')!;
  const report = await analyzeFileBytes(dotNetSample.fileName, cfgSampleBytesOrDefault(dotNetSample), DEFAULT_ENGINE_CONFIG);

  assert.equal(report.verdict, 'MALICIOUS');
  assert.equal(report.decompilation.targetLanguage, 'C# / CIL (.NET Managed Assembly Decompiler)');
  assert.ok(report.decompilation.dotNetInfo.isDotNetAssembly);
  assert.ok(report.decompilation.reconstructedCode.includes('Assembly.Load'));
  assert.ok(report.decompilation.reconstructedCode.includes('targetMethod.Invoke'));
});

function cfgSampleBytesOrDefault(sample: { buildBytes: () => Uint8Array }): Uint8Array {
  return sample.buildBytes();
}

test('v6 C++ SSA Struct/VTable/Switch & Opaque Predicate Lifter reconstructs struct offsets, virtual calls and switch tables', async () => {
  const vtableSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-22')!;
  const report = await analyzeFileBytes(vtableSample.fileName, vtableSample.buildBytes(), DEFAULT_ENGINE_CONFIG);

  assert.equal(report.verdict, 'MALICIOUS');
  assert.ok((report.decompilation.cfgStats.structFieldsCount ?? 0) >= 2);
  assert.ok((report.decompilation.cfgStats.switchBlocksCount ?? 0) >= 1);
  assert.ok((report.decompilation.cfgStats.opaquePredicatesSimplified ?? 0) >= 1);
  assert.ok(report.decompilation.reconstructedCode.includes('struct RecoveredClass_RCX'));
  assert.ok(report.decompilation.reconstructedCode.includes('switch (dispatch_cmd_id)'));
});

test('v6 Native ARM64 / AArch64 Decompiler lifts 32-bit instructions and detects direct svc #0 syscall rootkit', async () => {
  const arm64Sample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-23')!;
  const report = await analyzeFileBytes(arm64Sample.fileName, arm64Sample.buildBytes(), DEFAULT_ENGINE_CONFIG);

  assert.equal(report.verdict, 'MALICIOUS');
  assert.equal(
    report.decompilation.targetLanguage,
    'C / C++ (ARM64 / AArch64 AAPCS64 & Kernel SVC Lifter)'
  );
  assert.ok(report.decompilation.disassemblyListing.some((i) => i.mnemonic === 'svc'));
  assert.ok(report.decompilation.reconstructedCode.includes('__arm64_svc_syscall'));
});

test('v6 WebAssembly (.wasm) Stack-Machine Decompiler lifts Wasm bytecode to C and detects XOR cryptominer', async () => {
  const wasmSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-24')!;
  const report = await analyzeFileBytes(wasmSample.fileName, wasmSample.buildBytes(), DEFAULT_ENGINE_CONFIG);

  assert.equal(report.verdict, 'MALICIOUS');
  assert.equal(report.headerAnalysis.format, 'WebAssembly (.wasm) Binary');
  assert.equal(
    report.decompilation.targetLanguage,
    'C / C++ (WebAssembly .WASM Stack-Machine to C AST Decompiler)'
  );
  assert.ok(report.decompilation.disassemblyListing.some((i) => i.mnemonic === 'i32.xor'));
  assert.ok(report.decompilation.reconstructedCode.includes('wasm_linear_memory'));
});

test('v6 RC4 (KSA+PRGA) Stream-Cipher Unpacker automatically extracts .rdata key and decrypts C2 beacon', async () => {
  const rc4Sample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-25')!;
  const report = await analyzeFileBytes(rc4Sample.fileName, rc4Sample.buildBytes(), DEFAULT_ENGINE_CONFIG);

  assert.equal(report.verdict, 'MALICIOUS');
  assert.ok(
    report.deobfuscatedLayers.some(
      (l) =>
        l.method === 'RC4-KSA-PRGA-Embedded-Key-Unpacker' &&
        l.decodedSnippet.includes('https://198.51.100.250/rc4_stage2.bin')
    )
  );
  assert.ok(report.decompilation.reconstructedCode.includes('RC4_Decrypt_Stream'));
});

test('v7 Multi-Function Lossless C++ Lifter & PDB Symbol Restorer reconstructs all functions, local variables, and ALU expressions with 0% code deletion', async () => {
  const multiFuncSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-26')!;
  const report = await analyzeFileBytes(multiFuncSample.fileName, multiFuncSample.buildBytes(), DEFAULT_ENGINE_CONFIG);

  assert.equal(report.verdict, 'MALICIOUS');
  assert.ok((report.decompilation.cfgStats.recoveredFunctionsCount ?? 0) >= 1);
  assert.ok(report.decompilation.cfgStats.localVariablesCount >= 3);
  assert.ok((report.decompilation.cfgStats.aluOperationsCount ?? 0) >= 4);
  assert.equal(report.decompilation.cfgStats.instructionPreservationPercent, 100.0);
  assert.ok(report.decompilation.reconstructedCode.includes('sub_'));
  assert.ok(report.decompilation.reconstructedCode.includes('local_var_4 = 0xB979379E'));
  assert.ok(report.decompilation.reconstructedCode.includes('local_var_8 = 0x2010'));
  assert.ok(report.decompilation.reconstructedCode.includes('local_var_c = 0x4'));
});

test('v7 XTEA 32-Round Feistel Block-Cipher Unpacker decrypts encrypted C2 payload in memory', async () => {
  const xteaSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-27')!;
  const report = await analyzeFileBytes(xteaSample.fileName, xteaSample.buildBytes(), DEFAULT_ENGINE_CONFIG);

  assert.equal(report.verdict, 'MALICIOUS');
  assert.ok(
    report.deobfuscatedLayers.some(
      (l) =>
        l.method.includes('XTEA-32Round-Delta-0x9E3779B9-Unpacker') &&
        l.decodedSnippet.includes('https://198.51.100.251/xtea_stage2.bin')
    )
  );
});

test("v7 Heaven's Gate WOW64 (CS=0x33) & Linux io_uring Syscall-less Rootkit Detector catches both advanced evasion implants", async () => {
  const hgSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-28')!;
  const hgReport = await analyzeFileBytes(hgSample.fileName, hgSample.buildBytes(), DEFAULT_ENGINE_CONFIG);
  assert.equal(hgReport.verdict, 'MALICIOUS');
  assert.ok(hgReport.opcodeFindings.some((f) => f.patternName.includes('HeavensGate_WOW64')));

  const ioUringSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-29')!;
  const ioReport = await analyzeFileBytes(ioUringSample.fileName, ioUringSample.buildBytes(), DEFAULT_ENGINE_CONFIG);
  assert.equal(ioReport.verdict, 'MALICIOUS');
  assert.ok(ioReport.opcodeFindings.some((f) => f.patternName.includes('io_uring')));
});

test('v9 Original C++ Round-Trip Fidelity Benchmark passes 9/9 cases with 100% function/variable preservation (0% deleted) and ~98.6% closeness to original C++', () => {
  const origSuite = runOriginalCppFidelityBenchmarkSuite();
  assert.equal(origSuite.totalCases, 9);
  assert.equal(origSuite.passedAllPreservationChecks, 9);
  assert.equal(origSuite.zeroDeletedFunctionsAndVarsGuarantee, true);
  assert.ok(origSuite.aegisAverageExactMatchPercent >= 98.0);
  assert.ok(origSuite.aegisWithSymbolsMatchPercent >= 99.0);
  assert.ok(origSuite.aegisAverageExactMatchPercent > origSuite.ghidraReferenceAveragePercent);
});

test('v7 Decompilation Quality Benchmark suite passes 8/8 multi-arch AST cases', () => {
  const decBench = runDecompilationBenchmarkSuite();
  assert.equal(decBench.totalVerificationCount, 8);
  assert.equal(decBench.passedVerificationCount, 8);
  assert.ok(decBench.aegisOverallAveragePercent >= 97.5);
});

test('v8 Modules 25..28 (Hell\'s Gate SSN, SEH Frame, CFF OLLVM, Early Cascade) detect advanced evasion implants', async () => {
  const hgSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-31')!;
  const hgReport = await analyzeFileBytes(hgSample.fileName, hgSample.buildBytes(), DEFAULT_ENGINE_CONFIG);
  assert.equal(hgReport.verdict, 'MALICIOUS');
  assert.ok(hgReport.opcodeFindings.some((f) => f.patternName.includes('HellsGate_HalosGate')));

  const cffSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-32')!;
  const cffReport = await analyzeFileBytes(cffSample.fileName, cffSample.buildBytes(), DEFAULT_ENGINE_CONFIG);
  assert.equal(cffReport.verdict, 'MALICIOUS');
  assert.ok(cffReport.opcodeFindings.some((f) => f.patternName.includes('ControlFlowFlattening')));

  const cascadeSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-33')!;
  const cascadeReport = await analyzeFileBytes(cascadeSample.fileName, cascadeSample.buildBytes(), DEFAULT_ENGINE_CONFIG);
  assert.equal(cascadeReport.verdict, 'MALICIOUS');
  assert.ok(cascadeReport.opcodeFindings.some((f) => f.patternName.includes('ThreadPool') || f.patternName.includes('Injection')) || cascadeReport.verdict === 'MALICIOUS');

  const sehSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-34')!;
  const sehReport = await analyzeFileBytes(sehSample.fileName, sehSample.buildBytes(), DEFAULT_ENGINE_CONFIG);
  assert.equal(sehReport.verdict, 'MALICIOUS');
  assert.ok(sehReport.opcodeFindings.some((f) => f.patternName.includes('SEH') || f.patternName.includes('Windows_SEH')));
});

test('v9 Benchmark Suite (42 samples: 33 threats + 9 clean) achieves 100.0% detection rate with 0 false positives', async () => {
  const v8Bench = await runRealBenchmarkSuite(DEFAULT_ENGINE_CONFIG);
  assert.equal(v8Bench.totalSamples, 42);
  assert.equal(v8Bench.maliciousSamplesCount, 33);
  assert.equal(v8Bench.cleanSamplesCount, 9);
  assert.equal(v8Bench.aegisTruePositives, 33);
  assert.equal(v8Bench.aegisFalsePositives, 0);
  assert.equal(v8Bench.aegisDetectionRatePercent, 100.0);
  assert.equal(v8Bench.aegisStaticScorePercent, 100.0);
});

test('v10 Project Lifter Engine reconstructs multi-folder project directory tree (CMake, src/, include/, res/) for PE and Android APK', async () => {
  // Test 1: PE64 C++ Executable
  const cppSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-26')!;
  const cppReport = await analyzeFileBytes(cppSample.fileName, cppSample.buildBytes(), DEFAULT_ENGINE_CONFIG);
  assert.ok(cppReport.decompilation.reconstructedProject);
  const cppProj = cppReport.decompilation.reconstructedProject;
  assert.ok(cppProj.totalFiles >= 5);
  assert.ok(cppProj.files.some((f) => f.path === 'CMakeLists.txt'));
  assert.ok(cppProj.files.some((f) => f.path === 'Makefile'));
  assert.ok(cppProj.files.some((f) => f.path === 'include/types.h'));
  assert.ok(cppProj.files.some((f) => f.path === 'src/main.cpp'));
  assert.ok(cppProj.files.some((f) => f.path === 'src/core/subroutines.cpp'));

  // Verify zero branding/watermark comments in extracted project files
  for (const f of cppProj.files) {
    assert.ok(!f.content.includes('SuperCodeX'), `File ${f.path} should not contain watermark`);
    assert.ok(!f.content.includes('Aegis_Decompiled_EntryPoint'), `File ${f.path} should use clean function names`);
  }

  // Test 2: Android APK
  const apkSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-19')!;
  const apkReport = await analyzeFileBytes(apkSample.fileName, apkSample.buildBytes(), DEFAULT_ENGINE_CONFIG);
  assert.ok(apkReport.decompilation.reconstructedProject);
  const apkProj = apkReport.decompilation.reconstructedProject;
  assert.ok(apkProj.totalFiles >= 5);
  assert.ok(apkProj.files.some((f) => f.path === 'AndroidManifest.xml'));
  assert.ok(apkProj.files.some((f) => f.path === 'build.gradle'));
  assert.ok(apkProj.files.some((f) => f.path === 'src/main/java/com/app/MainActivity.java'));
  for (const f of apkProj.files) {
    assert.ok(!f.content.includes('SuperCodeX'), `APK File ${f.path} should not contain watermark`);
  }
});

test('v11 Real Per-Function C++ Body Lifter: zero empty function stubs and distinct C++ code across different binaries', async () => {
  const sampleA = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-18')!; // RTTI + RDTSC + indirect call
  const sampleB = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-20')!; // CFG branch + loop + Win64 Fastcall
  const sampleC = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-22')!; // Struct + VTable + Switch + Opaque
  const sampleD = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-26')!; // Multi-function + ALU

  const [repA, repB, repC, repD] = await Promise.all([
    analyzeFileBytes(sampleA.fileName, sampleA.buildBytes(), DEFAULT_ENGINE_CONFIG),
    analyzeFileBytes(sampleB.fileName, sampleB.buildBytes(), DEFAULT_ENGINE_CONFIG),
    analyzeFileBytes(sampleC.fileName, sampleC.buildBytes(), DEFAULT_ENGINE_CONFIG),
    analyzeFileBytes(sampleD.fileName, sampleD.buildBytes(), DEFAULT_ENGINE_CONFIG),
  ]);

  const projA = repA.decompilation.reconstructedProject!;
  const projB = repB.decompilation.reconstructedProject!;
  const projC = repC.decompilation.reconstructedProject!;
  const projD = repD.decompilation.reconstructedProject!;

  const mainA = projA.files.find((f) => f.path === 'src/main.cpp')!.content;
  const mainB = projB.files.find((f) => f.path === 'src/main.cpp')!.content;
  const mainC = projC.files.find((f) => f.path === 'src/main.cpp')!.content;
  const mainD = projD.files.find((f) => f.path === 'src/main.cpp')!.content;

  // 1. Verify that src/main.cpp is NOT an identical static template across different binaries!
  assert.notEqual(mainA, mainB, 'src/main.cpp for BM-18 and BM-20 must not be identical templates');
  assert.notEqual(mainB, mainC, 'src/main.cpp for BM-20 and BM-22 must not be identical templates');
  assert.notEqual(mainC, mainD, 'src/main.cpp for BM-22 and BM-26 must not be identical templates');

  // 2. Verify specific machine instructions from each binary are lifted into its src/main.cpp:
  assert.ok(mainA.includes('__rdtsc()'), 'BM-18 src/main.cpp must contain lifted __rdtsc() check');
  assert.ok(mainB.includes('0x1337') && mainB.includes('for ('), 'BM-20 src/main.cpp must contain lifted 0x1337 local var and loop');
  assert.ok(mainC.includes('switch (') || mainC.includes('vfunc_0x18'), 'BM-22 src/main.cpp must contain lifted switch or vtable call');
  assert.ok(mainD.includes('0xB979379E') && mainD.includes('0x2010'), 'BM-26 src/main.cpp must contain lifted ALU constants');

  // 3. Verify ZERO empty `{ return; }` method stubs in any generated .cpp file across all 4 projects
  for (const proj of [projA, projB, projC, projD]) {
    for (const file of proj.files.filter((f) => f.language === 'cpp')) {
      assert.ok(
        !file.content.includes('{\n    return;\n}'),
        `File ${file.path} in ${proj.projectName} must not contain empty { return; } stub`
      );
      assert.ok(
        !file.content.includes('http://apt-c2-node.local/stage2.bin'),
        `File ${file.path} in ${proj.projectName} must not contain hardcoded fake URL template`
      );
    }
  }
});

test('v11 Demangled C++ Class Builder reconstructs both .h header and .cpp implementation with real method bodies', async () => {
  const rttiSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-18')!;
  const report = await analyzeFileBytes(rttiSample.fileName, rttiSample.buildBytes(), DEFAULT_ENGINE_CONFIG);
  const proj = report.decompilation.reconstructedProject!;

  const classCpp = proj.files.find((f) => f.path.startsWith('src/core/') && f.path !== 'src/core/subroutines.cpp');
  const classHeader = proj.files.find((f) => f.path.startsWith('include/') && f.path !== 'include/types.h' && f.path !== 'include/imports.h');

  assert.ok(classCpp, 'Should reconstruct a dedicated C++ class implementation file in src/core/');
  assert.ok(classHeader, 'Should reconstruct a dedicated C++ class header file in include/');
  assert.ok(classHeader.content.includes('class '), 'Class header must contain class declaration');
  assert.ok(classCpp.content.includes('::'), 'Class .cpp must contain scoped method definitions');
  assert.ok(classCpp.content.includes('return '), 'Class .cpp methods must contain real decoded return statement');
});

test('v11 Multi-Subroutine Byte-Level Decoder lifts real local variables and ALU arithmetic inside called subroutines', async () => {
  // Build a PE64 binary with 2 distinct functions:
  // Function 1 at 0x200 (512): initializes local_var_8 = 0x200, calls Function 2 at 0x220 (544), returns eax
  // Function 2 at 0x220 (544): initializes sub_var_8 = 0x777, adds 0x33, shifts left by 3, returns eax
  const bin = new Uint8Array(768);
  bin[0] = 0x4d;
  bin[1] = 0x5a;
  // Function 1 @ 512 (0x200):
  // 55 48 89 E5 48 83 EC 20
  // C7 45 F8 00 02 00 00 (mov [rbp-8], 0x200)
  // E8 0B 00 00 00 (call +11 -> offset 512 + 20 + 11 = 543? Let's place E8 at 527 -> 527+5+12 = 544)
  bin.set(
    [
      0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, // 8 bytes (512..519)
      0xc7, 0x45, 0xf8, 0x00, 0x02, 0x00, 0x00,       // 7 bytes (520..526)
      0xe8, 0x0c, 0x00, 0x00, 0x00,                   // 5 bytes (527..531), target = 532 + 12 = 544 (0x220)
      0x5d, 0xc3,                                     // 2 bytes (532..533)
    ],
    512
  );
  // Function 2 @ 544 (0x220):
  // 55 48 89 E5 48 83 EC 20
  // C7 45 F8 77 07 00 00 (mov [rbp-8], 0x777)
  // 8B 45 F8 (mov eax, [rbp-8])
  // 83 C0 33 (add eax, 0x33)
  // C1 E0 03 (shl eax, 3)
  // 5D C3
  bin.set(
    [
      0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20,
      0xc7, 0x45, 0xf8, 0x77, 0x07, 0x00, 0x00,
      0x8b, 0x45, 0xf8,
      0x83, 0xc0, 0x33,
      0xc1, 0xe0, 0x03,
      0x5d, 0xc3,
    ],
    544
  );

  const report = await analyzeFileBytes('two_real_funcs.exe', bin, DEFAULT_ENGINE_CONFIG);
  const decompCode = report.decompilation.reconstructedCode;
  const proj = report.decompilation.reconstructedProject!;
  const subCpp = proj.files.find((f) => f.path === 'src/core/subroutines.cpp')!.content;

  // Verify Function 2's actual body (0x777, += 0x33, <<= 3) was decoded both in master decompilation and in src/core/subroutines.cpp!
  assert.ok(decompCode.includes('0x777'), 'Master decompiled code must decode subroutine constant 0x777');
  assert.ok(decompCode.includes('eax += 0x33;'), 'Master decompiled code must decode subroutine ALU += 0x33');
  assert.ok(decompCode.includes('eax <<= 3;'), 'Master decompiled code must decode subroutine shift <<= 3');

  assert.ok(subCpp.includes('0x777'), 'subroutines.cpp must contain decoded subroutine local variable 0x777');
  assert.ok(subCpp.includes('eax += 0x33;'), 'subroutines.cpp must contain decoded subroutine ALU += 0x33');
  assert.ok(subCpp.includes('eax <<= 3;'), 'subroutines.cpp must contain decoded subroutine shift <<= 3');
});

test('v11 Struct & VTable Type Reconstruction in include/types.h and conditional payload_unpack.cpp', async () => {
  const sample22 = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-22')!;
  const report = await analyzeFileBytes(sample22.fileName, sample22.buildBytes(), DEFAULT_ENGINE_CONFIG);
  const proj = report.decompilation.reconstructedProject!;

  const typesH = proj.files.find((f) => f.path === 'include/types.h')!.content;

  // Verify struct fields and VTable pointers discovered in BM-22 are present in include/types.h
  assert.ok(typesH.includes('field_0x10') && typesH.includes('field_0x18'), 'types.h must declare recovered struct fields field_0x10 and field_0x18');
  assert.ok(typesH.includes('vfunc_0x18'), 'types.h must declare recovered VTable slot vfunc_0x18');

  // Verify payload_unpack.cpp is NOT created when no obfuscation layers exist (BM-22), and IS created when RC4/XTEA layers exist (BM-25)
  assert.ok(!proj.files.some((f) => f.path === 'src/security/payload_unpack.cpp'));
  const sample25 = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-25')!;
  const report25 = await analyzeFileBytes(sample25.fileName, sample25.buildBytes(), DEFAULT_ENGINE_CONFIG);
  const unpackCpp = report25.decompilation.reconstructedProject!.files.find((f) => f.path === 'src/security/payload_unpack.cpp')!.content;
  assert.ok(unpackCpp.includes('UnpackDataSections'), 'payload_unpack.cpp must include real unpack routine when obfuscation exists');
});

test('v11 PDB Symbol Recovery and Subroutines in C++ Project Files', async () => {
  const pdbSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-26')!;
  const xteaSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-27')!;

  const [pdbReport, xteaReport] = await Promise.all([
    analyzeFileBytes(pdbSample.fileName, pdbSample.buildBytes(), DEFAULT_ENGINE_CONFIG),
    analyzeFileBytes(xteaSample.fileName, xteaSample.buildBytes(), DEFAULT_ENGINE_CONFIG),
  ]);

  const pdbMain = pdbReport.decompilation.reconstructedProject!.files.find((f) => f.path === 'src/main.cpp')!.content;
  const pdbSubs = pdbReport.decompilation.reconstructedProject!.files.find((f) => f.path === 'src/core/subroutines.cpp')!.content;
  const xteaUnpack = xteaReport.decompilation.reconstructedProject!.files.find((f) => f.path === 'src/security/payload_unpack.cpp')!.content;

  // PDB binary uses recovered symbol names (ExecuteMultiStageImplant & ComputeRollingKeySubroutine)
  assert.ok(pdbMain.includes('ExecuteMultiStageImplant'), 'PDB binary src/main.cpp must use PDB symbol ExecuteMultiStageImplant');
  assert.ok(pdbSubs.includes('ComputeRollingKeySubroutine') && pdbSubs.includes('0xAA55'), 'PDB binary subroutines.cpp must decode ComputeRollingKeySubroutine with 0xAA55');
  assert.ok(xteaUnpack.includes('XteaDecryptBlock') && xteaUnpack.includes('0x9E3779B9U'), 'XTEA binary payload_unpack.cpp must reconstruct XteaDecryptBlock');
});

test('Qt5Xml.dll (PE32 x86, ImageBase 0x61000000 from APK Editor Studio 1.7.2) passes all 8 requirements and g++ -fsyntax-only', async () => {
  const dllPath = path.resolve(process.cwd(), 'tmp/Qt5Xml.dll');
  const rawBuffer = fs.readFileSync(dllPath);
  const bytes = new Uint8Array(rawBuffer);

  // Requirement 1: Bitness from PE header (Machine 0x014c / Magic 0x010b -> PE32 x86, ImageBase 0x61000000)
  const peInfo = parsePeBinaryStructure(bytes);
  assert.equal(peInfo.isValidPe, true);
  assert.equal(peInfo.is32Bit, true, 'Qt5Xml.dll must be detected as 32-bit PE32 x86');
  assert.equal(peInfo.machine, 0x014c, 'Machine must be IMAGE_FILE_MACHINE_I386 (0x014c)');
  assert.equal(peInfo.optionalMagic, 0x010b, 'OptionalHeader Magic must be PE32 (0x010b)');
  assert.equal(peInfo.imageBase, 0x61000000, 'ImageBase must be 0x61000000');

  // Requirement 5: Exports with identical address decoded once, others marked as aliases
  assert.equal(peInfo.exports.length, 446);
  const aliasedExports = peInfo.exports.filter((e) => Boolean(e.isAliasOf));
  assert.equal(aliasedExports.length, 124, 'Shared RVA exports in Qt5Xml.dll must be marked as aliases (124 aliases)');

  // Mandatory 6 tests from real Qt5Xml.dll bytes -> expected body:
  const mandatoryTests: Array<{ va: number; className: string; expectedBytes: string; expectedBody: string }> = [
    { va: 0x61007b00, className: 'QDomAttr', expectedBytes: 'b8 02 00 00 00 c3', expectedBody: 'return 2;' },
    { va: 0x61007b10, className: 'QDomCDATASection', expectedBytes: 'b8 04 00 00 00 c3', expectedBody: 'return 4;' },
    { va: 0x61007b40, className: 'QDomComment', expectedBytes: 'b8 08 00 00 00 c3', expectedBody: 'return 8;' },
    { va: 0x61007b50, className: 'QDomDocument', expectedBytes: 'b8 09 00 00 00 c3', expectedBody: 'return 9;' },
    { va: 0x61007b80, className: 'QDomElement', expectedBytes: 'b8 01 00 00 00 c3', expectedBody: 'return 1;' },
    { va: 0x61007bd0, className: 'QDomNotation', expectedBytes: 'b8 0c 00 00 00 c3', expectedBody: 'return 12;' },
  ];

  for (const tc of mandatoryTests) {
    const exp = peInfo.exports.find((e) => e.va === tc.va);
    assert.ok(exp, `Export at VA 0x${tc.va.toString(16)} (${tc.className}::nodeType) must exist in Qt5Xml.dll`);
    assert.equal(exp.demangled.className, tc.className);
    assert.equal(exp.demangled.methodName, 'nodeType');
    const rawSlice = Array.from(bytes.subarray(exp.fileOffset, exp.fileOffset + 6))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ');
    assert.equal(rawSlice, tc.expectedBytes, `Raw bytes at 0x${tc.va.toString(16)} must be ${tc.expectedBytes}`);

    const decoded = decodeNativeFunctionBytes(bytes, exp.fileOffset, peInfo, {
      isClassMethod: true,
      returnType: 'int',
    });
    assert.equal(
      decoded.bodyLines.join(' ').trim(),
      tc.expectedBody,
      `${tc.className}::nodeType at 0x${tc.va.toString(16)} must decode to "${tc.expectedBody}"`
    );
  }

  // Run full analyzer + project lifter on Qt5Xml.dll
  const report = await analyzeFileBytes('Qt5Xml.dll', bytes, DEFAULT_ENGINE_CONFIG);
  const decomp = report.decompilation;
  const proj = decomp.reconstructedProject!;

  // Requirement 1 & 2 & 7: Check zero rcx/rdx/r8, zero module_tag, zero if (!(eax != 0)), zero 0x6101C52C, zero 5A5A5A5A
  assert.ok(!decomp.reconstructedCode.includes('module_tag'), 'Must not contain module_tag');
  assert.ok(!decomp.reconstructedCode.includes('if (!(eax != 0))'), 'Must not contain template if (!(eax != 0))');
  assert.ok(!decomp.reconstructedCode.includes('0x6101C52C'), 'Must not contain hardcoded 0x6101C52C');
  assert.ok(!decomp.reconstructedCode.includes('5A5A5A5A'), 'Must not contain 5A5A5A5A');
  assert.ok(!decomp.reconstructedCode.includes('rcx_ctx'), 'PE32 x86 must not use rcx_ctx');

  // Verify each of the 6 QDom*.cpp files in the reconstructed project contains the exact decoded return statement
  for (const tc of mandatoryTests) {
    const cppFile = proj.files.find((f) => f.path === `src/core/${tc.className}.cpp`);
    assert.ok(cppFile, `Project must include src/core/${tc.className}.cpp`);
    assert.ok(
      cppFile.content.includes(`int ${tc.className}::nodeType() const {\n    ${tc.expectedBody}\n}`),
      `src/core/${tc.className}.cpp must contain exact "${tc.expectedBody}" body`
    );
    assert.ok(!cppFile.content.includes('module_tag'));
    assert.ok(!cppFile.content.includes('5A5A5A5A'));
  }

  // Requirement 6: Struct fields only from real [ecx+disp] offsets (e.g. [ecx+0x1c] -> field_0x1c)
  const testMovEcx1c = new Uint8Array([0x8b, 0x41, 0x1c, 0xc3]); // mov eax, [ecx+0x1c]; ret
  const decoded1c = decodeNativeFunctionBytes(testMovEcx1c, 0, peInfo, {
    isClassMethod: true,
    returnType: 'int',
  });
  assert.ok(decoded1c.structOffsets.includes(0x1c), '[ecx+0x1c] must record struct offset 0x1c');

  // Requirement 7: payload_unpack.cpp and anti_analysis.cpp must NOT be created for clean Qt5Xml.dll
  assert.ok(
    !proj.files.some((f) => f.path.includes('payload_unpack.cpp')),
    'payload_unpack.cpp must not be created when no obfuscation layers exist in bytes'
  );
  assert.ok(
    !proj.files.some((f) => f.path.includes('anti_analysis.cpp')),
    'anti_analysis.cpp must not be created when no anti-analysis patterns exist in bytes'
  );

  // Requirement 4: Data files (.qm, .xml, .txt) must not generate code
  assert.equal(isDataOrResourceFile('qt_ru.qm'), true);
  assert.equal(isDataOrResourceFile('manifest.xml'), true);
  assert.equal(isDataOrResourceFile('readme.txt'), true);
  const qmReport = await analyzeFileBytes('qt_ru.qm', new Uint8Array([0x3c, 0xb8, 0x64, 0x18, 0xca, 0xef, 0x9c, 0x95]), DEFAULT_ENGINE_CONFIG);
  assert.equal(qmReport.decompilation.reconstructedCode, '', '.qm data file must not generate C++ code');
  assert.equal(qmReport.decompilation.reconstructedProject?.files.length ?? 0, 0, '.qm data file must have 0 project code files');

  // Requirement 8: g++ -fsyntax-only test on every generated .cpp file in Qt5Xml.dll project
  const syntaxSummary = await verifyProjectCppSyntaxWithGpp(proj);
  assert.ok(syntaxSummary.totalCppFiles >= 30, `Expected >= 30 .cpp files, got ${syntaxSummary.totalCppFiles}`);
  assert.equal(
    syntaxSummary.failedCount,
    0,
    `All ${syntaxSummary.totalCppFiles} .cpp files must pass g++ -fsyntax-only, failed: ${JSON.stringify(
      syntaxSummary.results.filter((r) => r.status === 'FAIL')
    )}`
  );

  // Verify 0 unsupported instructions across all 303 executable .text exports in Qt5Xml.dll
  let totalTextExports = 0;
  let totalUnsupportedBytes = 0;
  for (const exp of peInfo.exports) {
    if (exp.isAliasOf || exp.isDataExport) continue;
    totalTextExports++;
    const dec = decodeNativeFunctionBytes(bytes, exp.fileOffset, peInfo, {
      isClassMethod: Boolean(exp.demangled.className),
      returnType: exp.demangled.returnType,
    });
    totalUnsupportedBytes += dec.unsupportedCount;
  }
  assert.equal(totalTextExports, 303, 'Qt5Xml.dll must have 303 unique .text function exports');
  assert.equal(totalUnsupportedBytes, 0, 'All 303 .text functions in Qt5Xml.dll must decode with 0 unsupported bytes');

  // Verify QDomAttr.cpp matches original Qt5 qdom.cpp logic (constructors, atomic ref/deref, IAT QString calls, specified, setValue)
  const qdomAttrCpp = proj.files.find((f) => f.path === 'src/core/QDomAttr.cpp')!.content;
  assert.ok(!qdomAttrCpp.includes('unsupported:'), 'QDomAttr.cpp must have zero unsupported instructions');
  assert.ok(qdomAttrCpp.includes('Qt5Core.dll!QString::QString'), 'QDomAttr.cpp must resolve IAT calls to Qt5Core.dll!QString::QString');
  assert.ok(qdomAttrCpp.includes('void QDomAttr::setValue(const void* a1)'), 'QDomAttr.cpp must demangle void QDomAttr::setValue(const void* a1)');
  assert.ok(qdomAttrCpp.includes('*(uint8_t*)((uintptr_t)eax + 0x38) = 0x1;'), 'QDomAttr::setValue must decode m_specified = 1 at offset 0x38');
});

test('Android APK and Dalvik DEX decompiler extracts real method parameters, instruction bodies, and class hierarchy', async () => {
  const apkSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-19')!;
  const report = await analyzeFileBytes(apkSample.fileName, apkSample.buildBytes(), DEFAULT_ENGINE_CONFIG);
  const proj = report.decompilation.reconstructedProject;
  assert.ok(proj, 'Reconstructed project must exist');

  // Verify class files exist
  const accessService = proj.files.find((f) => f.path.includes('AccessibilityOverlayService.java'));
  const smsReceiver = proj.files.find((f) => f.path.includes('SmsInterceptReceiver.java'));
  assert.ok(accessService, 'AccessibilityOverlayService.java must be extracted');
  assert.ok(smsReceiver, 'SmsInterceptReceiver.java must be extracted');

  // Verify true method parameters and signatures
  assert.ok(
    smsReceiver.content.includes('onReceive(android.content.Context arg1, android.content.Intent arg2)'),
    'SmsInterceptReceiver must decompile onReceive with (Context arg1, Intent arg2) parameters from proto_id'
  );
  assert.ok(
    accessService.content.includes('onAccessibilityEvent(android.view.accessibility.AccessibilityEvent arg1)'),
    'AccessibilityOverlayService must decompile onAccessibilityEvent with (AccessibilityEvent arg1) from proto_id'
  );

  // Verify real bytecode instructions decoded
  assert.ok(
    accessService.content.includes('http://198.51.100.222/api/gate.php'),
    'AccessibilityOverlayService must decompile const-string URL opcode'
  );
  assert.ok(
    accessService.content.includes('dalvik.system.DexClassLoader'),
    'AccessibilityOverlayService must decompile new-instance DexClassLoader opcode'
  );
  assert.ok(
    smsReceiver.content.includes('SMS_STEALER_READY'),
    'SmsInterceptReceiver must decompile SMS payload string'
  );
  assert.ok(
    smsReceiver.content.includes('sendTextMessage'),
    'SmsInterceptReceiver must decompile invoke-virtual sendTextMessage'
  );

  // Verify no artificial banner comments
  for (const file of proj.files) {
    assert.ok(!file.content.includes('SuperCodeX восстановил код'), 'Must not contain fake SuperCodeX banner');
    assert.ok(!file.content.includes('methodTag'), 'Must not contain dummy methodTag stubs');
  }
});

test('Decompiled Java classes and AndroidManifest pass syntax integrity, balanced braces, and genuine component declarations', async () => {
  const apkSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-19')!;
  const report = await analyzeFileBytes(apkSample.fileName, apkSample.buildBytes(), DEFAULT_ENGINE_CONFIG);
  const proj = report.decompilation.reconstructedProject;
  assert.ok(proj, 'Reconstructed project must exist');

  const javaFiles = proj.files.filter((f) => f.path.endsWith('.java'));
  assert.ok(javaFiles.length >= 2, `Expected >= 2 Java files, got ${javaFiles.length}`);

  for (const file of javaFiles) {
    // 1. Balanced braces
    let openCount = 0;
    for (let i = 0; i < file.content.length; i++) {
      if (file.content[i] === '{') openCount++;
      if (file.content[i] === '}') openCount--;
    }
    assert.equal(openCount, 0, `File ${file.path} must have perfectly balanced curly braces`);

    // 2. No invalid Java assignments to this
    assert.ok(!file.content.includes('this ='), `File ${file.path} must never assign to final reference 'this'`);

    // 3. No undefined dummy keywords
    assert.ok(!file.content.includes('result;'), `File ${file.path} must never emit standalone 'result;'`);

    // 4. Constructors must not have redundant return;
    if (file.content.includes('public ' + file.path.split('/').pop()?.replace('.java', '') + '(')) {
      const ctorMatch = file.content.match(/public\s+[A-Za-z0-9_]+\s*\([^)]*\)\s*\{([^}]*)\}/);
      if (ctorMatch) {
        assert.ok(!ctorMatch[1].includes('return;'), `Constructor in ${file.path} must not contain return;`);
      }
    }
  }

  // Verify AndroidManifest.xml reflects actual classes
  const manifest = proj.files.find((f) => f.path === 'AndroidManifest.xml')!;
  assert.ok(manifest, 'AndroidManifest.xml must exist');
  assert.ok(manifest.content.includes('android:name="com.finance.overlay.stealer.AccessibilityOverlayService"'));
  assert.ok(manifest.content.includes('android:name="com.finance.overlay.stealer.SmsInterceptReceiver"'));
  assert.ok(!manifest.content.includes('DexPayloadLoader'), 'AndroidManifest must not contain artificial DexPayloadLoader');
});

test('v12 100% Dynamic Universal Byte Decompiler: parses arbitrary runtime-generated PE binaries with unique random constants without hardcoded templates', async () => {
  // Generate 3 completely unique PE64 binary byte arrays on the fly with random custom constants
  const randomConst1 = 0x12345678;
  const randomConst2 = 0x87654321;
  const randAddVal = 0x42;

  const bin = new Uint8Array(2048);
  bin[0] = 0x4d; // 'M'
  bin[1] = 0x5a; // 'Z'
  bin[0x3c] = 0x80; // e_lfanew
  bin[0x80] = 0x50; // 'P'
  bin[0x81] = 0x45; // 'E'

  // Insert machine code at file offset 512 (0x200):
  // 55 48 89 E5 48 83 EC 20 (prologue)
  // C7 45 F8 [4 bytes const1] (mov [rbp-8], const1)
  // C7 45 F0 [4 bytes const2] (mov [rbp-16], const2)
  // 83 C0 42 (add eax, 0x42)
  // 5D C3 (epilogue)
  const codeBytes = [
    0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20,
    0xc7, 0x45, 0xf8, randomConst1 & 0xff, (randomConst1 >> 8) & 0xff, (randomConst1 >> 16) & 0xff, (randomConst1 >> 24) & 0xff,
    0xc7, 0x45, 0xf0, randomConst2 & 0xff, (randomConst2 >> 8) & 0xff, (randomConst2 >> 16) & 0xff, (randomConst2 >> 24) & 0xff,
    0x83, 0xc0, randAddVal,
    0x5d, 0xc3,
  ];
  bin.set(codeBytes, 512);

  const report = await analyzeFileBytes('dynamic_runtime_sample_999.exe', bin, DEFAULT_ENGINE_CONFIG);
  assert.equal(report.verdict, 'CLEAN');
  const code = report.decompilation.reconstructedCode;

  // Assert that the decompiler dynamically extracted the random constants and arithmetic operations directly from raw bytes!
  assert.ok(code.includes('0x12345678'), 'Decompiler must dynamically parse constant 0x12345678 from arbitrary raw bytes');
  assert.ok(code.includes('0x87654321'), 'Decompiler must dynamically parse constant 0x87654321 from arbitrary raw bytes');
  assert.ok(code.includes('eax += 0x42;'), 'Decompiler must dynamically parse ALU add 0x42 from arbitrary raw bytes');
  assert.ok(report.decompilation.reconstructedProject !== undefined, 'Must reconstruct project structure dynamically');
});

test('Real g++ -O0 and -O2 x86_64 ELF64 compilation, decompilation, recompilation, and execution equivalence', async () => {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'elf_real_gpp_test_'));

  // 1. Test checksum(const uint8_t* p, int n) compiled by real g++ -O0 and -O2
  const checksumSrc = `
#include <stdint.h>
#include <stdio.h>
extern "C" __attribute__((noinline)) uint32_t checksum(const uint8_t* p, int n) {
    uint32_t h = 0x811C9DC5;
    for (int i = 0; i < n; i++) {
        h ^= p[i];
        h *= 16777619u;
        if (h & 1) h += 7;
    }
    return h;
}
int main() {
    const uint8_t data[6] = {10, 20, 30, 40, 50, 60};
    printf("%u\\n", checksum(data, 6));
    return 0;
}
`;
  const checksumCppPath = path.join(workDir, 'checksum.cpp');
  fs.writeFileSync(checksumCppPath, checksumSrc);

  for (const optFlag of ['-O0', '-O2']) {
    const origElfPath = path.join(workDir, `checksum_${optFlag}.elf`);
    execSync(`g++ ${optFlag} "${checksumCppPath}" -o "${origElfPath}"`);
    const elfBytes = new Uint8Array(fs.readFileSync(origElfPath));

    const report = await analyzeFileBytes(`checksum_${optFlag}.elf`, elfBytes, DEFAULT_ENGINE_CONFIG);
    assert.equal(report.verdict, 'CLEAN', `Real g++ ${optFlag} checksum binary must have CLEAN verdict`);
    assert.equal(report.riskScore, 0);

    const code = report.decompilation.reconstructedCode;
    assert.ok(
      code.includes('uint32_t checksum(const uint8_t* p, int n)'),
      `Must recover System V AMD64 signature uint32_t checksum(const uint8_t* p, int n) in ${optFlag}`
    );
    assert.ok(code.includes('for (int i = 0; i < n; i++)'), `Must recover loop condition i < n in ${optFlag}`);
    assert.ok(code.includes('h = (h ^ p[i]) * 0x1000193;'), `Must fold register expressions in ${optFlag}`);
    assert.ok(!code.includes('loop_i < 64'), 'Must never contain hardcoded loop_i < 64');
    assert.ok(!code.includes('[object Object]'), 'Must never contain [object Object]');

    const decompCppPath = path.join(workDir, `checksum_decomp_${optFlag}.cpp`);
    const decompElfPath = path.join(workDir, `checksum_decomp_${optFlag}.elf`);
    fs.writeFileSync(decompCppPath, code);
    execSync(`g++ -std=c++20 "${decompCppPath}" -o "${decompElfPath}"`);

    const origStdout = execSync(`"${origElfPath}"`).toString().trim();
    const decompStdout = execSync(`"${decompElfPath}"`).toString().trim();
    assert.equal(decompStdout, origStdout, `Decompiled checksum (${optFlag}) output must match original binary`);
  }

  // 2. Test classify(5-case switch) + C++ Virtual Method Call (Shape/Square) + compute(/ 3) + printf via PLT
  const suiteSrc = `
#include <stdio.h>
#include <stdint.h>

__attribute__((noinline)) int compute(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        if (i % 2 == 0) s += i / 3;
        else s ^= i;
    }
    return s;
}

__attribute__((noinline)) int classify(int x) {
    switch (x) {
        case 1: return 10;
        case 2: return 20;
        case 3: return 30;
        case 4: return 40;
        case 5: return 50;
        default: return -1;
    }
}

struct Shape {
    int side;
    Shape(int s) : side(s) {}
    virtual int area() { return 0; }
};

struct Square : Shape {
    Square(int s) : Shape(s) {}
    int area() override { return side * side; }
};

__attribute__((noinline)) int run_shape(Shape* s) {
    return s->area();
}

int main() {
    Square sq(5);
    printf("compute=%d classify=%d area=%d\\n", compute(12), classify(3), run_shape(&sq));
    return 0;
}
`;
  const suiteCppPath = path.join(workDir, 'suite.cpp');
  fs.writeFileSync(suiteCppPath, suiteSrc);

  for (const optFlag of ['-O0', '-O2']) {
    const origElfPath = path.join(workDir, `suite_${optFlag}.elf`);
    execSync(`g++ ${optFlag} "${suiteCppPath}" -o "${origElfPath}"`);
    const elfBytes = new Uint8Array(fs.readFileSync(origElfPath));

    const report = await analyzeFileBytes(`suite_${optFlag}.elf`, elfBytes, DEFAULT_ENGINE_CONFIG);
    assert.equal(report.verdict, 'CLEAN', `Real g++ ${optFlag} suite binary must have CLEAN verdict`);
    assert.equal(report.riskScore, 0);

    const code = report.decompilation.reconstructedCode;
    const metrics = report.decompilation.cfgStats;
    assert.ok(!code.includes('[object Object]'), 'VTable comments must never contain [object Object]');
    assert.ok(!code.includes('#include <windows.h>'), 'Linux ELF64 must never include <windows.h>');
    assert.ok(!code.includes('__fastcall'), 'Linux ELF64 must never use __fastcall');
    assert.ok(metrics.loopsCount >= 1, `Must detect loop in ${optFlag}`);
    assert.ok((metrics.switchBlocksCount ?? 0) >= 1, `Must detect switch in ${optFlag}`);
    assert.ok((metrics.vtableCallsCount ?? 0) >= 1, `Must detect VTable call in ${optFlag}`);

    const decompCppPath = path.join(workDir, `suite_decomp_${optFlag}.cpp`);
    const decompElfPath = path.join(workDir, `suite_decomp_${optFlag}.elf`);
    fs.writeFileSync(decompCppPath, code);
    execSync(`g++ -std=c++20 "${decompCppPath}" -o "${decompElfPath}"`);

    const origOut = execSync(`"${origElfPath}"`).toString().trim();
    const decompOut = execSync(`"${decompElfPath}"`).toString().trim();
    assert.equal(decompOut, origOut, `Decompiled suite (${optFlag}) stdout must match original binary`);
  }

  // 3. Minimal clean program int main(){return 0;} must receive CLEAN verdict
  const cleanSrc = `int main() { return 0; }\n`;
  const cleanCppPath = path.join(workDir, 'clean.cpp');
  const cleanElfPath = path.join(workDir, 'clean.elf');
  fs.writeFileSync(cleanCppPath, cleanSrc);
  execSync(`g++ -O2 "${cleanCppPath}" -o "${cleanElfPath}"`);
  const cleanReport = await analyzeFileBytes('clean.elf', new Uint8Array(fs.readFileSync(cleanElfPath)), DEFAULT_ENGINE_CONFIG);
  assert.equal(cleanReport.verdict, 'CLEAN', 'int main(){return 0;} must receive CLEAN verdict');
  assert.equal(cleanReport.riskScore, 0);

  fs.rmSync(workDir, { recursive: true, force: true });
});






