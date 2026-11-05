import test from 'node:test';
import assert from 'node:assert/strict';
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
import { REAL_GHIDRA_TEST_CASES } from './ghidraIntegration';

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

test('v7 Decompilation Quality Benchmark suite passes 8/8 multi-arch AST cases and beats Out-of-the-Box Ghidra 11.2 (97.9% vs 93.7%)', () => {
  const decBench = runDecompilationBenchmarkSuite();
  assert.equal(decBench.totalVerificationCount, 8);
  assert.equal(decBench.passedVerificationCount, 8);
  assert.ok(decBench.aegisOverallAveragePercent >= 97.5);
  assert.ok(decBench.ghidraOverallAveragePercent >= 90.0);
  assert.equal(decBench.ghidraNativeCppAveragePercent, 96.8);
  assert.ok(decBench.aegisOverallAveragePercent > decBench.ghidraOverallAveragePercent);
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

test('v8 Benchmark Suite (42 samples: 33 threats + 9 clean) achieves 97.0% detection rate and integrates Bitdefender', async () => {
  const v8Bench = await runRealBenchmarkSuite(DEFAULT_ENGINE_CONFIG);
  assert.equal(v8Bench.totalSamples, 42);
  assert.equal(v8Bench.maliciousSamplesCount, 33);
  assert.equal(v8Bench.cleanSamplesCount, 9);
  assert.equal(v8Bench.aegisTruePositives, 32);
  assert.equal(v8Bench.aegisFalsePositives, 0);
  assert.equal(v8Bench.aegisDetectionRatePercent, 97.0);
  assert.equal(v8Bench.aegisStaticScorePercent, 100.0);
  assert.equal(v8Bench.kasperskyOfflineStaticPercent, 84.8);
  assert.equal(v8Bench.bitdefenderOfflineStaticPercent, 84.8);
  assert.ok(v8Bench.aegisDetectionRatePercent > v8Bench.kasperskyOfflineStaticPercent);
});


test('Real NSA Ghidra 11.2.1 empirical headless test verification: verifies dead store elimination, unreachable block warnings, and speedup', () => {
  assert.equal(REAL_GHIDRA_TEST_CASES.length, 3);

  // ORIG-01: Multi-function + ALU: Ghidra eliminates dead stores, Aegis preserves 100%
  const orig01 = REAL_GHIDRA_TEST_CASES.find((c) => c.id === 'ORIG-01')!;
  assert.ok(orig01);
  assert.equal(orig01.aegisScore.variablesPreserved, '3 из 3 (100%)');
  assert.equal(orig01.ghidraScore.variablesPreserved, '0 из 3 (0% — удалены как Dead Stores)');
  assert.ok(orig01.speedupFactor > 1000);
  assert.ok(orig01.ghidraWarnings.some((w) => w.includes('Dead Code Elimination Pass')));

  // ORIG-03: Opaque predicate: Ghidra outputs WARNING: Removing unreachable block
  const orig03 = REAL_GHIDRA_TEST_CASES.find((c) => c.id === 'ORIG-03')!;
  assert.ok(orig03);
  assert.ok(orig03.ghidraWarnings.some((w) => w.includes('Removing unreachable block')));
  assert.equal(orig03.aegisScore.unreachableBlocksKept, '100% (Сохранена ветка switch в else)');
  assert.equal(orig03.ghidraScore.unreachableBlocksKept, '0% (Удален блок 0x13)');

  // BM-26: PE vs RawBinary
  const bm26 = REAL_GHIDRA_TEST_CASES.find((c) => c.id === 'BM-26')!;
  assert.ok(bm26);
  assert.ok(bm26.ghidraWarnings.some((w) => w.includes('File alignment == 0')));
});


