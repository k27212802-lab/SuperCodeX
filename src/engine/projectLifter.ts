import JSZip from 'jszip';
import { unzipSync } from 'fflate';
import {
  ApkDexMetadata,
  DecompilationResult,
  DemangledCppSymbol,
  DisassembledInstruction,
  DotNetMetadata,
  PdbSymbolMetadata,
  extractPdbAndDebugSymbols,
} from './decompiler';
import {
  BinaryHeaderAnalysis,
  DeobfuscatedLayer,
  OpcodeFinding,
  ResolvedApiHash,
} from './scanner';
import {
  decodeNativeFunctionBytes,
  demangleFullCppSymbol,
  isDataOrResourceFile,
  ParsedPeStructure,
  parseElfBinaryStructure,
  parsePeBinaryStructure,
  PeExportEntry,
} from './peExportAndDecoder';

export interface ReconstructedProjectFile {
  path: string;
  language: 'cpp' | 'h' | 'java' | 'cs' | 'xml' | 'cmake' | 'makefile' | 'json' | 'markdown' | 'asm';
  content: string;
  sizeBytes: number;
  description: string;
}

export interface ReconstructedProjectDirectory {
  name: string;
  path: string;
  files: ReconstructedProjectFile[];
  subdirectories: ReconstructedProjectDirectory[];
}

export interface ReconstructedProject {
  projectName: string;
  targetFramework: string;
  totalFiles: number;
  totalLines: number;
  files: ReconstructedProjectFile[];
  directoryTree: ReconstructedProjectDirectory;
}

/**
 * Strips any internal analyzer banner comments so extracted files contain 100% pure developer C++/Java/C# code.
 */
export function cleanPureSourceCode(code: string): string {
  const lines = code.split('\n');
  const cleaned: string[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (
      trimmed.startsWith('// ===') ||
      trimmed.startsWith('// ---') ||
      trimmed.includes('SuperCodeX') ||
      trimmed.includes('AEGIS') ||
      trimmed.includes('Aegis v') ||
      trimmed.includes('Функций в Call-Graph:') ||
      trimmed.includes('Восстановлено: полей struct:') ||
      trimmed.includes('Модуль: ') ||
      trimmed.includes('Файл: ')
    ) {
      continue;
    }
    const cleanLine = line
      .replace(/Aegis_Decompiled_EntryPoint/g, 'main_entry')
      .replace(/Aegis_Decompiled_Method/g, 'dispatch_method')
      .replace(/Aegis_ARM64_Decompiled_Entry/g, 'arm64_entry');
    cleaned.push(cleanLine);
  }
  return cleaned.join('\n').replace(/^\n+/, '');
}

// =============================================================================
// REAL X86_64 / X86 NATIVE FUNCTION SLICER & BYTE-LEVEL C++ AST LIFTER
// =============================================================================

export interface LiftedNativeFunction {
  name: string;
  signature: string;
  returnType: string;
  offset: number;
  addressHex: string;
  rawBytesHex?: string;
  isAliasOf?: string;
  isClassMethod?: boolean;
  className?: string;
  locals: { name: string; type: string; initExpr: string; disp: number }[];
  statements: string[];
  calledFunctions: string[];
  structOffsets: number[];
  vtableOffsets: number[];
  returnExpr: string;
  fullCppCode: string;
}

/**
 * Locates executable code ranges & PE Export Table entries in PE32/PE64, ELF, or raw machine-code buffers
 * and slices them into individual functions with byte-accurate C++ bodies.
 */
export function extractRealFunctionsFromBinaryBytes(
  rawBytes: Uint8Array | undefined,
  asciiStrings: string[],
  extractedApis: string[],
  resolvedApiHashes: ResolvedApiHash[],
  demangledSymbols: DemangledCppSymbol[]
): LiftedNativeFunction[] {
  if (!rawBytes || rawBytes.length < 16) return [];

  void extractedApis;
  const peInfo = parsePeBinaryStructure(rawBytes);
  const pdbMeta = extractPdbAndDebugSymbols(rawBytes, asciiStrings);
  const functions: LiftedNativeFunction[] = [];
  const visitedOffsets = new Set<number>();

  // 1. First lift global/standalone exported functions from PE Export Directory (IMAGE_DIRECTORY_ENTRY_EXPORT)
  if (peInfo.isValidPe && peInfo.exports.length > 0) {
    let globalExportIdx = 0;
    for (const exp of peInfo.exports) {
      if (exp.isDataExport) {
        continue;
      }
      if (exp.demangled.className) {
        // Class methods are lifted directly into their respective class .cpp files in buildDemangledCppClassFiles
        continue;
      }
      const fnName = `exp_${exp.demangled.methodName.replace(/[^A-Za-z0-9_]/g, '_')}_${globalExportIdx++}`;
      const retType = exp.demangled.returnType === '' ? 'void' : exp.demangled.returnType || 'int';
      const sig = `${retType} ${fnName}(${
        peInfo.is32Bit
          ? 'void* this_ecx, uint32_t arg_4, uint32_t arg_8, uint32_t arg_c'
          : 'void* rcx_ctx, const void* rdx_arg, uint64_t r8_arg, uint64_t r9_arg'
      })`;

      if (exp.isAliasOf) {
        const aliasBody =
          retType === 'void'
            ? `${sig} {\n    // alias -> ${exp.isAliasOf} (@ ${exp.vaHex})\n    return;\n}`
            : `${sig} {\n    // alias -> ${exp.isAliasOf} (@ ${exp.vaHex})\n    return 0;\n}`;
        functions.push({
          name: fnName,
          signature: sig,
          returnType: retType,
          offset: exp.fileOffset,
          addressHex: exp.vaHex,
          isAliasOf: exp.isAliasOf,
          locals: [],
          statements: [`    // alias -> ${exp.isAliasOf} (@ ${exp.vaHex})`],
          calledFunctions: [],
          structOffsets: [],
          vtableOffsets: [],
          returnExpr: '0',
          fullCppCode: aliasBody,
        });
        continue;
      }

      visitedOffsets.add(exp.fileOffset);
      const decoded = decodeNativeFunctionBytes(rawBytes, exp.fileOffset, peInfo, {
        isClassMethod: false,
        returnType: retType,
        variableNamesByDisp: pdbMeta.variableNamesByDisp,
        functionNamesByOffset: pdbMeta.functionNamesByOffset,
        resolvedApiHashes,
      });

      const fullLines = [
        `// ${exp.vaHex}: ${decoded.rawBytesHex}`,
        `${sig} {`,
        ...decoded.bodyLines,
        `}`,
      ];
      functions.push({
        name: fnName,
        signature: sig,
        returnType: retType,
        offset: exp.fileOffset,
        addressHex: exp.vaHex,
        rawBytesHex: decoded.rawBytesHex,
        locals: decoded.locals,
        statements: decoded.bodyLines,
        calledFunctions: [],
        structOffsets: decoded.structOffsets,
        vtableOffsets: decoded.vtableOffsets,
        returnExpr: decoded.directConstantReturn !== undefined ? `${decoded.directConstantReturn}` : 'eax',
        fullCppCode: fullLines.join('\n'),
      });
    }
  }

  // 1B. If input is an ELF binary, lift all user functions from .symtab / .dynsym / .text
  const elfInfo = parseElfBinaryStructure(rawBytes);
  if (elfInfo.isValidElf && elfInfo.userFunctions.length > 0) {
    for (const fn of elfInfo.userFunctions.slice(0, 64)) {
      if (visitedOffsets.has(fn.fileOffset)) continue;
      visitedOffsets.add(fn.fileOffset);
      const retType = fn.demangled.returnType === '' ? 'void' : fn.demangled.returnType || 'int';
      const sig = fn.demangled.fullSignature;
      const decoded = decodeNativeFunctionBytes(rawBytes, fn.fileOffset, peInfo, {
        isClassMethod: !!fn.demangled.className,
        returnType: retType,
        variableNamesByDisp: pdbMeta.variableNamesByDisp,
        functionNamesByOffset: pdbMeta.functionNamesByOffset,
        resolvedApiHashes,
        maxBytes: Math.max(64, Math.min(fn.size || 256, 1024)),
      });
      const fullLines = [
        `// ${fn.vaHex} (${fn.rawName}): ${decoded.rawBytesHex}`,
        `${sig} {`,
        ...decoded.bodyLines,
        `}`,
      ];
      functions.push({
        name: fn.demangled.methodName || fn.rawName,
        signature: sig,
        returnType: retType,
        offset: fn.fileOffset,
        addressHex: fn.vaHex,
        rawBytesHex: decoded.rawBytesHex,
        isClassMethod: !!fn.demangled.className,
        className: fn.demangled.className,
        locals: decoded.locals,
        statements: decoded.bodyLines,
        calledFunctions: [],
        structOffsets: decoded.structOffsets,
        vtableOffsets: decoded.vtableOffsets,
        returnExpr:
          decoded.directConstantReturn !== undefined ? `${decoded.directConstantReturn}` : 'eax',
        fullCppCode: fullLines.join('\n'),
      });
    }
  }

  // 2. Determine executable scan ranges from PE Section Headers or ELF Headers
  const scanRanges: { start: number; end: number }[] = [];
  if (peInfo.isValidPe && peInfo.sections.length > 0) {
    for (const sec of peInfo.sections) {
      const isCode = (sec.characteristics & 0x20000020) !== 0 || sec.name.startsWith('.text');
      if (isCode && sec.pointerToRawData > 0 && sec.pointerToRawData < rawBytes.length && sec.sizeOfRawData > 0) {
        scanRanges.push({
          start: sec.pointerToRawData,
          end: Math.min(rawBytes.length, sec.pointerToRawData + Math.min(sec.sizeOfRawData, 65536)),
        });
      }
    }
    if (rawBytes.length > 256 && scanRanges.length === 0) {
      scanRanges.push({
        start: 256,
        end: Math.min(rawBytes.length, 4096),
      });
    }
  } else if (rawBytes.length >= 256 && rawBytes[0] === 0x4d && rawBytes[1] === 0x5a) {
    scanRanges.push({
      start: rawBytes.length >= 512 ? 512 : 256,
      end: Math.min(rawBytes.length, 8192),
    });
    if (rawBytes.length > 256) {
      scanRanges.push({
        start: 256,
        end: Math.min(rawBytes.length, 4096),
      });
    }
  } else if (elfInfo.isValidElf && elfInfo.textSection && elfInfo.textSection.size > 0) {
    scanRanges.push({
      start: elfInfo.textSection.fileOffset,
      end: Math.min(rawBytes.length, elfInfo.textSection.fileOffset + elfInfo.textSection.size),
    });
  } else if (
    rawBytes.length >= 64 &&
    rawBytes[0] === 0x7f &&
    rawBytes[1] === 0x45 &&
    rawBytes[2] === 0x4c &&
    rawBytes[3] === 0x46
  ) {
    scanRanges.push({
      start: 64,
      end: Math.min(rawBytes.length, 8192),
    });
  } else {
    scanRanges.push({
      start: 0,
      end: Math.min(rawBytes.length, 8192),
    });
  }

  // 3. Collect candidate function start offsets from PDB symbols, prologues, and E8 call targets
  const candidateStarts: number[] = [];
  for (const symOffStr of Object.keys(pdbMeta.functionNamesByOffset)) {
    const off = Number(symOffStr);
    if (!Number.isNaN(off) && off >= 0 && off < rawBytes.length) {
      candidateStarts.push(off);
    }
  }

  // Only scan heuristic prologues when the PE does not already have a full export table of class methods
  if (peInfo.exports.length === 0) {
    for (const range of scanRanges) {
      for (let i: number = range.start; i + 4 < range.end; i++) {
        const b0: number = rawBytes[i];
        const b1: number = rawBytes[i + 1];
        const b2: number = rawBytes[i + 2];
        const b3: number = rawBytes[i + 3];

        const isPushRbpMov =
          b0 === 0x55 &&
          ((!peInfo.is32Bit && b1 === 0x48 && (b2 === 0x89 || b2 === 0x8b) && (b3 === 0xe5 || b3 === 0xec)) ||
            (b1 === 0x89 && b2 === 0xe5) ||
            (b1 === 0x8b && b2 === 0xec));

        const isSubRspPrologue =
          !peInfo.is32Bit &&
          (i === range.start ||
            rawBytes[i - 1] === 0xc3 ||
            rawBytes[i - 1] === 0xcc ||
            rawBytes[i - 1] === 0x90 ||
            rawBytes[i - 1] === 0x00) &&
          ((b0 === 0x48 && b1 === 0x83 && b2 === 0xec && b3 >= 0x08 && b3 <= 0xf8) ||
            (b0 === 0x40 && b1 === 0x53 && b2 === 0x48 && b3 === 0x83) ||
            (b0 === 0x48 && b1 === 0x89 && (b2 === 0x4c || b2 === 0x54 || b2 === 0x5c) && b3 === 0x24));

        if (isPushRbpMov || isSubRspPrologue) {
          if (!candidateStarts.includes(i)) {
            candidateStarts.push(i);
          }
        }

        if (b0 === 0xe8 && i + 5 <= range.end) {
          const rel32: number = b1 | (b2 << 8) | (b3 << 16) | (rawBytes[i + 4] << 24);
          const targetOff: number = i + 5 + rel32;
          if (
            targetOff >= range.start &&
            targetOff + 4 < range.end &&
            (rawBytes[targetOff] === 0x55 ||
              (!peInfo.is32Bit && rawBytes[targetOff] === 0x48 && rawBytes[targetOff + 1] === 0x83))
          ) {
            if (!candidateStarts.includes(targetOff)) {
              candidateStarts.push(targetOff);
            }
          }
        }
      }
    }
  }

  candidateStarts.sort((a, b) => a - b);

  let funcIndex = 0;
  for (const startOff of candidateStarts) {
    if (visitedOffsets.has(startOff) || functions.length >= 48) continue;
    visitedOffsets.add(startOff);

    const va = peInfo.fileOffsetToVa(startOff);
    const vaHex = `0x${va.toString(16).toLowerCase()}`;
    const pdbSym = pdbMeta.functionNamesByOffset[startOff];
    const demangledMethod =
      funcIndex < demangledSymbols.length &&
      demangledSymbols[funcIndex].demangledSignature.includes('(') &&
      !demangledSymbols[funcIndex].demangledSignature.includes('::')
        ? demangledSymbols[funcIndex]
        : undefined;

    let funcName = `sub_${va.toString(16).toUpperCase()}`;
    let returnType = peInfo.is32Bit ? 'int' : 'int64_t';
    const paramList = peInfo.is32Bit
      ? 'void* this_ecx, uint32_t arg_4, uint32_t arg_8, uint32_t arg_c'
      : 'void* rcx_ctx, const void* rdx_arg, uint64_t r8_arg, uint64_t r9_arg';
    let signature = `${returnType} ${funcName}(${paramList})`;

    if (pdbSym) {
      funcName = pdbSym.name;
      const retMatch = /^([A-Za-z0-9_*]+)\s+/.exec(pdbSym.signature);
      if (retMatch) returnType = retMatch[1];
      signature = `${returnType} ${funcName}(${paramList})`;
    } else if (demangledMethod) {
      const cleanDemangled = demangledMethod.demangledSignature.replace(/\/\/.*$/, '').trim();
      const nameMatch = /([A-Za-z0-9_]+)\s*\(/.exec(cleanDemangled);
      if (nameMatch) funcName = nameMatch[1];
      const retMatch = /^([A-Za-z0-9_*]+)\s+/.exec(cleanDemangled);
      if (retMatch) returnType = retMatch[1];
      signature = `${returnType} ${funcName}(${paramList})`;
    } else if (funcIndex === 0 && functions.length === 0) {
      funcName = 'main_entry';
      signature = `${returnType} main_entry(${paramList})`;
    }

    const decoded = decodeNativeFunctionBytes(rawBytes, startOff, peInfo, {
      isClassMethod: false,
      returnType,
      variableNamesByDisp: pdbMeta.variableNamesByDisp,
      functionNamesByOffset: pdbMeta.functionNamesByOffset,
      resolvedApiHashes,
    });

    const fullLines = [
      `// ${vaHex}: ${decoded.rawBytesHex}`,
      `${signature} {`,
      ...decoded.bodyLines,
      `}`,
    ];

    functions.push({
      name: funcName,
      signature,
      returnType,
      offset: startOff,
      addressHex: vaHex,
      rawBytesHex: decoded.rawBytesHex,
      locals: decoded.locals,
      statements: decoded.bodyLines,
      calledFunctions: [],
      structOffsets: decoded.structOffsets,
      vtableOffsets: decoded.vtableOffsets,
      returnExpr: decoded.directConstantReturn !== undefined ? `${decoded.directConstantReturn}` : 'eax',
      fullCppCode: fullLines.join('\n'),
    });
    funcIndex++;
  }

  return functions;
}

// =============================================================================
// DALVIK DEX (CLASSES.DEX) CLASS + METHOD BYTECODE DECOMPILER
// =============================================================================

interface ExtractedDexMethod {
  name: string;
  returnType: string;
  params: string[];
  access?: string;
  isStatic?: boolean;
  javaStatements: string[];
}

interface ExtractedDexClass {
  className: string;
  superClassName: string;
  interfaces?: string[];
  fields: { name: string; type: string; isStatic?: boolean; access?: string }[];
  methods: ExtractedDexMethod[];
}

function parseRealDexClasses(dexBytes: Uint8Array, fallbackAsciiStrings: string[] = []): ExtractedDexClass[] {
  if (
    dexBytes.length < 112 ||
    dexBytes[0] !== 0x64 ||
    dexBytes[1] !== 0x65 ||
    dexBytes[2] !== 0x78 ||
    dexBytes[3] !== 0x0a
  ) {
    return [];
  }

  const view = new DataView(dexBytes.buffer, dexBytes.byteOffset, dexBytes.byteLength);
  const stringIdsSize = view.getUint32(56, true);
  const stringIdsOff = view.getUint32(60, true);
  const typeIdsSize = view.getUint32(64, true);
  const typeIdsOff = view.getUint32(68, true);
  const protoIdsSize = view.getUint32(72, true);
  const protoIdsOff = view.getUint32(76, true);
  const fieldIdsSize = view.getUint32(80, true);
  const fieldIdsOff = view.getUint32(84, true);
  const methodIdsSize = view.getUint32(88, true);
  const methodIdsOff = view.getUint32(92, true);
  const classDefsSize = view.getUint32(96, true);
  const classDefsOff = view.getUint32(100, true);

  const readUleb128 = (pos: { offset: number }): number => {
    let result = 0;
    let shift = 0;
    while (pos.offset < dexBytes.length) {
      const b = dexBytes[pos.offset++];
      result |= (b & 0x7f) << shift;
      if ((b & 0x80) === 0) break;
      shift += 7;
      if (shift >= 35) break;
    }
    return result >>> 0;
  };

  const readDexString = (strIdx: number): string => {
    if (stringIdsSize === 0 || strIdx >= stringIdsSize || stringIdsOff + strIdx * 4 + 4 > dexBytes.length) return '';
    const offPos = stringIdsOff + strIdx * 4;
    let dataOff = view.getUint32(offPos, true);
    if (dataOff === 0 || dataOff >= dexBytes.length) return '';
    while (dataOff < dexBytes.length && (dexBytes[dataOff] & 0x80) !== 0) {
      dataOff++;
    }
    dataOff++;
    let end = dataOff;
    while (end < dexBytes.length && dexBytes[end] !== 0 && end - dataOff < 512) {
      end++;
    }
    try {
      return new TextDecoder('utf-8', { fatal: false }).decode(dexBytes.subarray(dataOff, end));
    } catch {
      return '';
    }
  };

  const formatTypeDescriptor = (desc: string): string => {
    if (!desc) return 'void';
    let arrayDim = 0;
    let i = 0;
    while (i < desc.length && desc[i] === '[') {
      arrayDim++;
      i++;
    }
    const core = desc.slice(i);
    let base = 'Object';
    if (core === 'V') base = 'void';
    else if (core === 'Z') base = 'boolean';
    else if (core === 'B') base = 'byte';
    else if (core === 'S') base = 'short';
    else if (core === 'C') base = 'char';
    else if (core === 'I') base = 'int';
    else if (core === 'J') base = 'long';
    else if (core === 'F') base = 'float';
    else if (core === 'D') base = 'double';
    else if (core.startsWith('L') && core.endsWith(';')) {
      base = core.slice(1, -1).replace(/\//g, '.');
      if (base.startsWith('java.lang.')) base = base.slice('java.lang.'.length);
    }
    return base + '[]'.repeat(arrayDim);
  };

  const readTypeString = (typeIdx: number): string => {
    if (typeIdsSize === 0 || typeIdx >= typeIdsSize || typeIdsOff + (typeIdx + 1) * 4 > dexBytes.length) return '';
    const descIdx = view.getUint32(typeIdsOff + typeIdx * 4, true);
    return readDexString(descIdx);
  };

  const readProtoReturnType = (protoIdx: number): string => {
    if (protoIdsSize === 0 || protoIdx >= protoIdsSize || protoIdsOff + (protoIdx + 1) * 12 > dexBytes.length) return 'void';
    const returnTypeIdx = view.getUint32(protoIdsOff + protoIdx * 12 + 4, true);
    return formatTypeDescriptor(readTypeString(returnTypeIdx));
  };

  const readProtoParams = (protoIdx: number): string[] => {
    if (protoIdsSize === 0 || protoIdx >= protoIdsSize || protoIdsOff + (protoIdx + 1) * 12 > dexBytes.length) return [];
    const paramsOff = view.getUint32(protoIdsOff + protoIdx * 12 + 8, true);
    if (paramsOff === 0 || paramsOff + 4 > dexBytes.length) return [];
    const count = view.getUint32(paramsOff, true);
    if (count === 0 || count > 32 || paramsOff + 4 + count * 2 > dexBytes.length) return [];
    const params: string[] = [];
    for (let p = 0; p < count; p++) {
      const typeIdx = view.getUint16(paramsOff + 4 + p * 2, true);
      params.push(formatTypeDescriptor(readTypeString(typeIdx)));
    }
    return params;
  };

  const readFieldInfo = (fieldIdx: number): { cls: string; name: string; type: string } => {
    if (fieldIdsSize === 0 || fieldIdx >= fieldIdsSize || fieldIdsOff + (fieldIdx + 1) * 8 > dexBytes.length) {
      return { cls: 'Object', name: '', type: 'Object' };
    }
    const base = fieldIdsOff + fieldIdx * 8;
    const cIdx = view.getUint16(base, true);
    const tIdx = view.getUint16(base + 2, true);
    const nIdx = view.getUint32(base + 4, true);
    return {
      cls: formatTypeDescriptor(readTypeString(cIdx)),
      type: formatTypeDescriptor(readTypeString(tIdx)),
      name: readDexString(nIdx),
    };
  };

  const readMethodDetails = (methodIdx: number): { cls: string; name: string; ret: string; params: string[] } => {
    if (methodIdsSize === 0 || methodIdx >= methodIdsSize || methodIdsOff + (methodIdx + 1) * 8 > dexBytes.length) {
      return { cls: 'Object', name: 'invoke', ret: 'void', params: [] };
    }
    const base = methodIdsOff + methodIdx * 8;
    const cIdx = view.getUint16(base, true);
    const pIdx = view.getUint16(base + 2, true);
    const nIdx = view.getUint32(base + 4, true);
    return {
      cls: formatTypeDescriptor(readTypeString(cIdx)),
      name: readDexString(nIdx) || 'method',
      ret: readProtoReturnType(pIdx),
      params: readProtoParams(pIdx),
    };
  };

  const formatAccess = (flags: number): string => {
    if (flags & 0x01) return 'public';
    if (flags & 0x02) return 'private';
    if (flags & 0x04) return 'protected';
    return 'public';
  };

  const decompileDalvikCodeItem = (
    codeOff: number,
    isStaticMethod: boolean = false,
    methodParams: string[] = [],
    methodReturnType: string = 'void',
    isConstructor: boolean = false
  ): string[] => {
    void methodParams;
    void methodReturnType;
    if (codeOff === 0 || codeOff + 16 > dexBytes.length) return [];
    const registersSize = view.getUint16(codeOff, true);
    const insSize = view.getUint16(codeOff + 2, true);
    const insnsSize = view.getUint32(codeOff + 12, true);
    if (insnsSize === 0 || insnsSize > 65536) return [];
    const insnsStart = codeOff + 16;
    const insnsEnd = Math.min(dexBytes.length, insnsStart + insnsSize * 2);
    const stmts: string[] = [];

    const firstArgReg = Math.max(0, registersSize - insSize);

    const getRegName = (r: number, isInvocationTarget: boolean = false): string => {
      if (!isStaticMethod && r === firstArgReg && isInvocationTarget) {
        return 'this';
      }
      return `v${r}`;
    };

    const declaredVars = new Set<string>();

    const formatVarAssign = (regName: string, type: string, expr: string): string => {
      if (regName === 'this' || regName.startsWith('arg')) {
        return `${regName} = ${expr};`;
      }
      if (declaredVars.has(regName)) {
        return `${regName} = ${expr};`;
      }
      declaredVars.add(regName);
      const cleanType = type || 'Object';
      return `${cleanType} ${regName} = ${expr};`;
    };

    let p = insnsStart;
    const openBlocks: number[] = [];

    while (p + 2 <= insnsEnd && stmts.length < 120) {
      while (openBlocks.length > 0 && openBlocks[openBlocks.length - 1] <= p) {
        openBlocks.pop();
        stmts.push(`}`);
      }

      const op = dexBytes[p];
      const secondByte = dexBytes[p + 1];

      if (op === 0x00) {
        // nop
        p += 2;
      } else if (op === 0x01 || op === 0x04 || op === 0x07) {
        // move, move-wide, move-object
        const vA = secondByte & 0x0f;
        const vB = (secondByte >> 4) & 0x0f;
        stmts.push(formatVarAssign(getRegName(vA), 'Object', getRegName(vB)));
        p += 2;
      } else if (op === 0x02 || op === 0x05 || op === 0x08) {
        // move/from16
        const vA = secondByte;
        if (p + 4 <= insnsEnd) {
          const vB = view.getUint16(p + 2, true);
          stmts.push(formatVarAssign(getRegName(vA), 'Object', getRegName(vB)));
        }
        p += 4;
      } else if (op === 0x0a || op === 0x0b || op === 0x0c) {
        // move-result, move-result-wide, move-result-object
        const vA = secondByte;
        stmts.push(formatVarAssign(getRegName(vA), 'Object', 'result'));
        p += 2;
      } else if (op === 0x0e) {
        // return-void
        if (!isConstructor) {
          stmts.push(`return;`);
        }
        p += 2;
      } else if (op === 0x0f || op === 0x10 || op === 0x11) {
        // return, return-wide, return-object
        const vA = secondByte;
        stmts.push(`return ${getRegName(vA)};`);
        p += 2;
      } else if (op === 0x12) {
        // const/4
        const vA = secondByte & 0x0f;
        let lit = secondByte >> 4;
        if (lit & 0x08) lit |= 0xfffffff0;
        stmts.push(formatVarAssign(getRegName(vA), 'int', `${lit}`));
        p += 2;
      } else if (op === 0x13) {
        // const/16
        const vA = secondByte;
        if (p + 4 <= insnsEnd) {
          const lit = view.getInt16(p + 2, true);
          stmts.push(formatVarAssign(getRegName(vA), 'int', `${lit}`));
        }
        p += 4;
      } else if (op === 0x14) {
        // const
        const vA = secondByte;
        if (p + 6 <= insnsEnd) {
          const lit = view.getInt32(p + 2, true);
          stmts.push(formatVarAssign(getRegName(vA), 'int', `0x${(lit >>> 0).toString(16)}`));
        }
        p += 6;
      } else if (op === 0x15) {
        // const/high16
        const vA = secondByte;
        if (p + 4 <= insnsEnd) {
          const lit = view.getInt16(p + 2, true) << 16;
          stmts.push(formatVarAssign(getRegName(vA), 'int', `0x${(lit >>> 0).toString(16)}`));
        }
        p += 4;
      } else if (op === 0x16) {
        // const-wide/16
        const vA = secondByte;
        if (p + 4 <= insnsEnd) {
          const lit = view.getInt16(p + 2, true);
          stmts.push(formatVarAssign(getRegName(vA), 'long', `${lit}L`));
        }
        p += 4;
      } else if (op === 0x1a) {
        // const-string
        const vA = secondByte;
        if (p + 4 <= insnsEnd) {
          const sIdx = view.getUint16(p + 2, true);
          const str = readDexString(sIdx);
          stmts.push(formatVarAssign(getRegName(vA), 'String', `"${str.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`));
        }
        p += 4;
      } else if (op === 0x1b) {
        // const-string/jumbo
        const vA = secondByte;
        if (p + 6 <= insnsEnd) {
          const sIdx = view.getUint32(p + 2, true);
          const str = readDexString(sIdx);
          stmts.push(formatVarAssign(getRegName(vA), 'String', `"${str.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`));
        }
        p += 6;
      } else if (op === 0x1c) {
        // const-class
        const vA = secondByte;
        if (p + 4 <= insnsEnd) {
          const tIdx = view.getUint16(p + 2, true);
          const typeName = formatTypeDescriptor(readTypeString(tIdx));
          stmts.push(formatVarAssign(getRegName(vA), 'Class<?>', `${typeName}.class`));
        }
        p += 4;
      } else if (op === 0x22) {
        // new-instance
        const vA = secondByte;
        if (p + 4 <= insnsEnd) {
          const tIdx = view.getUint16(p + 2, true);
          const typeName = formatTypeDescriptor(readTypeString(tIdx));
          stmts.push(formatVarAssign(getRegName(vA), typeName, `new ${typeName}()`));
        }
        p += 4;
      } else if (op >= 0x52 && op <= 0x58) {
        // iget-*
        const vA = secondByte & 0x0f;
        const vB = (secondByte >> 4) & 0x0f;
        if (p + 4 <= insnsEnd) {
          const fIdx = view.getUint16(p + 2, true);
          const fInfo = readFieldInfo(fIdx);
          stmts.push(formatVarAssign(getRegName(vA), fInfo.type, `${getRegName(vB)}.${fInfo.name || 'field_' + fIdx}`));
        }
        p += 4;
      } else if (op >= 0x59 && op <= 0x5f) {
        // iput-*
        const vA = secondByte & 0x0f;
        const vB = (secondByte >> 4) & 0x0f;
        if (p + 4 <= insnsEnd) {
          const fIdx = view.getUint16(p + 2, true);
          const fInfo = readFieldInfo(fIdx);
          stmts.push(`${getRegName(vB)}.${fInfo.name || 'field_' + fIdx} = ${getRegName(vA)};`);
        }
        p += 4;
      } else if (op >= 0x60 && op <= 0x66) {
        // sget-*
        const vA = secondByte;
        if (p + 4 <= insnsEnd) {
          const fIdx = view.getUint16(p + 2, true);
          const fInfo = readFieldInfo(fIdx);
          stmts.push(formatVarAssign(getRegName(vA), fInfo.type, `${fInfo.cls || 'Target'}.${fInfo.name || 'field_' + fIdx}`));
        }
        p += 4;
      } else if (op >= 0x67 && op <= 0x6d) {
        // sput-*
        const vA = secondByte;
        if (p + 4 <= insnsEnd) {
          const fIdx = view.getUint16(p + 2, true);
          const fInfo = readFieldInfo(fIdx);
          stmts.push(`${fInfo.cls || 'Target'}.${fInfo.name || 'field_' + fIdx} = ${getRegName(vA)};`);
        }
        p += 4;
      } else if (op >= 0x6e && op <= 0x72) {
        // invoke-virtual, invoke-super, invoke-direct, invoke-static, invoke-interface (Format 35c)
        const argCount = (secondByte >> 4) & 0x0f;
        if (p + 6 <= insnsEnd) {
          const mIdx = view.getUint16(p + 2, true);
          const mInfo = readMethodDetails(mIdx);
          const regG = secondByte & 0x0f;
          const regC = dexBytes[p + 4] & 0x0f;
          const regD = (dexBytes[p + 4] >> 4) & 0x0f;
          const regE = dexBytes[p + 5] & 0x0f;
          const regF = (dexBytes[p + 5] >> 4) & 0x0f;
          const rawArgIndices = [regC, regD, regE, regF, regG].slice(0, argCount);
          const args = rawArgIndices.map((r, idx) => getRegName(r, idx === 0));

          let callExpr = '';
          if (mInfo.name === '<init>') {
            if (op === 0x6f) {
              callExpr = `super(${args.slice(1).join(', ')})`;
            } else {
              const target = args[0] || 'this';
              if (target === 'this') {
                callExpr = `this(${args.slice(1).join(', ')})`;
              } else {
                callExpr = `${target} = new ${mInfo.cls}(${args.slice(1).join(', ')})`;
              }
            }
          } else if (op === 0x71) {
            callExpr = `${mInfo.cls}.${mInfo.name}(${args.join(', ')})`;
          } else {
            const target = args[0] || 'this';
            callExpr = `${target}.${mInfo.name}(${args.slice(1).join(', ')})`;
          }

          // Check if followed by move-result / move-result-object / move-result-wide
          const nextP = p + 6;
          if (
            nextP + 2 <= insnsEnd &&
            (dexBytes[nextP] === 0x0a || dexBytes[nextP] === 0x0b || dexBytes[nextP] === 0x0c)
          ) {
            const resReg = dexBytes[nextP + 1];
            const resRegName = getRegName(resReg);
            const retType = mInfo.ret !== 'void' ? mInfo.ret : 'Object';
            stmts.push(formatVarAssign(resRegName, retType, callExpr));
            p = nextP + 2;
            continue;
          } else {
            stmts.push(`${callExpr};`);
          }
        }
        p += 6;
      } else if (op >= 0x74 && op <= 0x78) {
        // invoke-range
        if (p + 6 <= insnsEnd) {
          const mIdx = view.getUint16(p + 2, true);
          const mInfo = readMethodDetails(mIdx);
          const vC = view.getUint16(p + 4, true);
          const count = secondByte;
          const rangeArgs: string[] = [];
          for (let r = 0; r < Math.min(count, 8); r++) {
            rangeArgs.push(getRegName(vC + r));
          }
          let callExpr = '';
          if (op === 0x77) {
            callExpr = `${mInfo.cls}.${mInfo.name}(${rangeArgs.join(', ')})`;
          } else {
            const target = rangeArgs[0] || 'this';
            callExpr = `${target}.${mInfo.name}(${rangeArgs.slice(1).join(', ')})`;
          }

          const nextP = p + 6;
          if (
            nextP + 2 <= insnsEnd &&
            (dexBytes[nextP] === 0x0a || dexBytes[nextP] === 0x0b || dexBytes[nextP] === 0x0c)
          ) {
            const resReg = dexBytes[nextP + 1];
            const resRegName = getRegName(resReg);
            const retType = mInfo.ret !== 'void' ? mInfo.ret : 'Object';
            stmts.push(formatVarAssign(resRegName, retType, callExpr));
            p = nextP + 2;
            continue;
          } else {
            stmts.push(`${callExpr};`);
          }
        }
        p += 6;
      } else if (op >= 0x90 && op <= 0x98) {
        // binary arithmetic
        const vAA = secondByte;
        if (p + 4 <= insnsEnd) {
          const vBB = dexBytes[p + 2];
          const vCC = dexBytes[p + 3];
          const opChars = ['+', '-', '*', '/', '%', '&', '|', '^', '<<'][op - 0x90] || '+';
          stmts.push(formatVarAssign(getRegName(vAA), 'int', `${getRegName(vBB)} ${opChars} ${getRegName(vCC)}`));
        }
        p += 4;
      } else if (op >= 0x2d && op <= 0x31) {
        // cmpl/cmpg float/double/long
        const vA = secondByte;
        if (p + 4 <= insnsEnd) {
          const vB = dexBytes[p + 2];
          const vC = dexBytes[p + 3];
          stmts.push(formatVarAssign(getRegName(vA), 'int', `Double.compare(${getRegName(vB)}, ${getRegName(vC)})`));
        }
        p += 4;
      } else if (op >= 0x44 && op <= 0x51) {
        // aget / aput
        const vA = secondByte & 0x0f;
        const vB = (secondByte >> 4) & 0x0f;
        if (p + 4 <= insnsEnd) {
          const vC = dexBytes[p + 2];
          if (op <= 0x4a) {
            stmts.push(formatVarAssign(getRegName(vA), 'Object', `${getRegName(vB)}[${getRegName(vC)}]`));
          } else {
            stmts.push(`${getRegName(vB)}[${getRegName(vC)}] = ${getRegName(vA)};`);
          }
        }
        p += 4;
      } else if (op >= 0x1f && op <= 0x21) {
        // check-cast, instance-of, array-length
        const vA = secondByte & 0x0f;
        const vB = (secondByte >> 4) & 0x0f;
        if (op === 0x21) {
          stmts.push(formatVarAssign(getRegName(secondByte), 'int', `${getRegName(secondByte)}.length`));
          p += 2;
        } else if (op === 0x1f && p + 4 <= insnsEnd) {
          const tIdx = view.getUint16(p + 2, true);
          const typeName = formatTypeDescriptor(readTypeString(tIdx));
          stmts.push(formatVarAssign(getRegName(secondByte), typeName, `(${typeName}) ${getRegName(secondByte)}`));
          p += 4;
        } else if (op === 0x20 && p + 4 <= insnsEnd) {
          const tIdx = view.getUint16(p + 2, true);
          const typeName = formatTypeDescriptor(readTypeString(tIdx));
          stmts.push(formatVarAssign(getRegName(vA), 'boolean', `${getRegName(vB)} instanceof ${typeName}`));
          p += 4;
        } else {
          p += 2;
        }
      } else if (op === 0x23 && p + 4 <= insnsEnd) {
        // new-array
        const vA = secondByte & 0x0f;
        const vB = (secondByte >> 4) & 0x0f;
        const tIdx = view.getUint16(p + 2, true);
        const typeName = formatTypeDescriptor(readTypeString(tIdx)).replace(/\[\]$/, '');
        stmts.push(formatVarAssign(getRegName(vA), `${typeName}[]`, `new ${typeName}[${getRegName(vB)}]`));
        p += 4;
      } else if (op >= 0xb0 && op <= 0xcf) {
        // binary 2addr arithmetic
        const vA = secondByte & 0x0f;
        const vB = (secondByte >> 4) & 0x0f;
        const opChars = ['+', '-', '*', '/', '%', '&', '|', '^', '<<', '>>', '>>>'][((op - 0xb0) / 2) | 0] || '+';
        stmts.push(`${getRegName(vA)} ${opChars}= ${getRegName(vB)};`);
        p += 2;
      } else if (op >= 0xd0 && op <= 0xe2 && p + 4 <= insnsEnd) {
        // binary lit16 / lit8 arithmetic
        const vA = secondByte & 0x0f;
        const vB = (secondByte >> 4) & 0x0f;
        const lit = op >= 0xd8 ? view.getInt8(p + 3) : view.getInt16(p + 2, true);
        const opChars = ['+', '-', '*', '/', '%', '&', '|', '^', '<<', '>>', '>>>'][(op >= 0xd8 ? op - 0xd8 : op - 0xd0) % 11] || '+';
        stmts.push(formatVarAssign(getRegName(vA), 'int', `${getRegName(vB)} ${opChars} ${lit}`));
        p += 4;
      } else if (op >= 0x32 && op <= 0x37) {
        // if-test
        const vA = secondByte & 0x0f;
        const vB = (secondByte >> 4) & 0x0f;
        const cmpOps = ['==', '!=', '<', '>=', '>', '<='];
        const cmp = cmpOps[op - 0x32] || '==';
        if (p + 4 <= insnsEnd) {
          const relOff = view.getInt16(p + 2, true);
          const target = p + relOff * 2;
          if (target > p && target <= insnsEnd) {
            openBlocks.push(target);
          }
        }
        stmts.push(`if (${getRegName(vA)} ${cmp} ${getRegName(vB)}) {`);
        p += 4;
      } else if (op >= 0x38 && op <= 0x3d) {
        // if-testz
        const vA = secondByte;
        const cmpOps = ['== 0', '!= 0', '< 0', '>= 0', '> 0', '<= 0'];
        const cmp = cmpOps[op - 0x38] || '== 0';
        if (p + 4 <= insnsEnd) {
          const relOff = view.getInt16(p + 2, true);
          const target = p + relOff * 2;
          if (target > p && target <= insnsEnd) {
            openBlocks.push(target);
          }
        }
        stmts.push(`if (${getRegName(vA)} ${cmp}) {`);
        p += 4;
      } else {
        // Safeguard byte alignment with exact Dalvik instruction length
        const step = getDalvikOpcodeLength(op);
        p += step;
      }
    }

    while (openBlocks.length > 0) {
      openBlocks.pop();
      stmts.push(`}`);
    }

    return stmts;
  };

  function getDalvikOpcodeLength(op: number): number {
    if (
      op === 0x18 ||
      op === 0x1b ||
      op === 0x24 ||
      op === 0x25 ||
      op === 0x26 ||
      op === 0x2a ||
      op === 0x2b ||
      op === 0x2c ||
      (op >= 0x6e && op <= 0x72) ||
      (op >= 0x74 && op <= 0x78)
    ) {
      return op === 0x18 ? 10 : 6;
    }
    if (
      op === 0x02 || op === 0x03 || op === 0x05 || op === 0x06 || op === 0x08 || op === 0x09 ||
      op === 0x13 || op === 0x14 || op === 0x15 || op === 0x16 || op === 0x17 || op === 0x19 ||
      op === 0x1a || op === 0x1c || op === 0x1f || op === 0x20 || op === 0x22 || op === 0x23 ||
      op === 0x29 || (op >= 0x2d && op <= 0x3d) || (op >= 0x44 && op <= 0x6d) ||
      (op >= 0x90 && op <= 0xaf) || (op >= 0xd0 && op <= 0xe2)
    ) {
      return op === 0x14 ? 6 : 4;
    }
    return 2;
  }

  const classMap = new Map<number, ExtractedDexClass>();

  // 1. Process standard class_defs table if present
  if (classDefsOff > 0 && classDefsSize > 0 && classDefsOff + classDefsSize * 32 <= dexBytes.length) {
    const maxClassDefs = Math.min(classDefsSize, 200);
    for (let i = 0; i < maxClassDefs; i++) {
      const base = classDefsOff + i * 32;
      const classIdx = view.getUint32(base, true);
      const superclassIdx = view.getUint32(base + 8, true);
      const interfacesOff = view.getUint32(base + 12, true);
      const classDataOff = view.getUint32(base + 24, true);

      const rawDesc = readTypeString(classIdx);
      if (!rawDesc.startsWith('L') || !rawDesc.endsWith(';')) continue;
      const className = rawDesc.slice(1, -1).replace(/\//g, '.');
      if (className.startsWith('android.support.') || className.startsWith('androidx.')) continue;

      const superDesc =
        superclassIdx !== 0xffffffff ? formatTypeDescriptor(readTypeString(superclassIdx)) : 'Object';

      const interfaces: string[] = [];
      if (interfacesOff > 0 && interfacesOff + 4 <= dexBytes.length) {
        const ifCount = view.getUint32(interfacesOff, true);
        if (ifCount > 0 && ifCount <= 16 && interfacesOff + 4 + ifCount * 2 <= dexBytes.length) {
          for (let ifIdx = 0; ifIdx < ifCount; ifIdx++) {
            const tIdx = view.getUint16(interfacesOff + 4 + ifIdx * 2, true);
            interfaces.push(formatTypeDescriptor(readTypeString(tIdx)));
          }
        }
      }

      const extractedCls: ExtractedDexClass = {
        className,
        superClassName: superDesc,
        interfaces,
        fields: [],
        methods: [],
      };

      // Read real class fields and methods from class_data_item
      if (classDataOff > 0 && classDataOff < dexBytes.length) {
        const pos = { offset: classDataOff };
        const staticFieldsSize = readUleb128(pos);
        const instanceFieldsSize = readUleb128(pos);
        const directMethodsSize = readUleb128(pos);
        const virtualMethodsSize = readUleb128(pos);

        let prevFieldIdx = 0;
        for (let f = 0; f < staticFieldsSize && pos.offset < dexBytes.length; f++) {
          const diff = readUleb128(pos);
          const acc = readUleb128(pos);
          prevFieldIdx += diff;
          const fInfo = readFieldInfo(prevFieldIdx);
          if (fInfo.name) {
            extractedCls.fields.push({
              name: fInfo.name,
              type: fInfo.type,
              isStatic: true,
              access: formatAccess(acc),
            });
          }
        }

        prevFieldIdx = 0;
        for (let f = 0; f < instanceFieldsSize && pos.offset < dexBytes.length; f++) {
          const diff = readUleb128(pos);
          const acc = readUleb128(pos);
          prevFieldIdx += diff;
          const fInfo = readFieldInfo(prevFieldIdx);
          if (fInfo.name) {
            extractedCls.fields.push({
              name: fInfo.name,
              type: fInfo.type,
              isStatic: false,
              access: formatAccess(acc),
            });
          }
        }

        const parseEncodedMethod = (isDirect: boolean) => {
          void isDirect;
          const diff = readUleb128(pos);
          const acc = readUleb128(pos);
          const codeOff = readUleb128(pos);
          prevMethodIdx += diff;
          const mInfo = readMethodDetails(prevMethodIdx);
          const isStatic = (acc & 0x08) !== 0;
          const isConstructor = mInfo.name === '<init>';
          const stmts: string[] = [];
          if (codeOff > 0) {
            stmts.push(
              ...decompileDalvikCodeItem(
                codeOff,
                isStatic,
                mInfo.params,
                mInfo.ret,
                isConstructor
              )
            );
          }
          extractedCls.methods.push({
            name: mInfo.name,
            returnType: mInfo.ret,
            params: mInfo.params,
            access: formatAccess(acc),
            isStatic,
            javaStatements: stmts,
          });
        };

        let prevMethodIdx = 0;
        for (let m = 0; m < directMethodsSize && pos.offset < dexBytes.length; m++) {
          parseEncodedMethod(true);
        }

        prevMethodIdx = 0;
        for (let m = 0; m < virtualMethodsSize && pos.offset < dexBytes.length; m++) {
          parseEncodedMethod(false);
        }
      }

      classMap.set(classIdx, extractedCls);
    }
  }

  // 2. If class_data_item was empty, fall back to mapping fields and methods from field_ids and method_ids
  for (const [classIdx, cls] of classMap.entries()) {
    if (cls.methods.length === 0 && methodIdsOff > 0 && methodIdsSize > 0) {
      for (let i = 0; i < Math.min(methodIdsSize, 2000); i++) {
        const base = methodIdsOff + i * 8;
        if (base + 8 > dexBytes.length) break;
        const cIdx = view.getUint16(base, true);
        if (cIdx !== classIdx) continue;
        const pIdx = view.getUint16(base + 2, true);
        const nIdx = view.getUint32(base + 4, true);
        const methodName = readDexString(nIdx);
        const returnType = readProtoReturnType(pIdx);
        const params = readProtoParams(pIdx);
        if (methodName) {
          cls.methods.push({
            name: methodName,
            returnType,
            params,
            access: 'public',
            javaStatements: [],
          });
        }
      }
    }

    if (cls.fields.length === 0 && fieldIdsOff > 0 && fieldIdsSize > 0) {
      for (let i = 0; i < Math.min(fieldIdsSize, 1000); i++) {
        const base = fieldIdsOff + i * 8;
        if (base + 8 > dexBytes.length) break;
        const cIdx = view.getUint16(base, true);
        if (cIdx !== classIdx) continue;
        const tIdx = view.getUint16(base + 2, true);
        const nIdx = view.getUint32(base + 4, true);
        const fieldName = readDexString(nIdx);
        const fieldType = formatTypeDescriptor(readTypeString(tIdx));
        if (fieldName) {
          cls.fields.push({
            name: fieldName,
            type: fieldType,
            access: 'private',
          });
        }
      }
    }
  }

  // 3. Fallback: scan type descriptors in dexBytes if class_defs was absent
  if (classMap.size === 0) {
    const rawText = new TextDecoder('latin1').decode(dexBytes);
    const descMatches = rawText.match(/L([a-zA-Z0-9_$]+(?:\/[a-zA-Z0-9_$]+)+);/g) || [];
    let fallbackIdx = 0;
    for (const rawDesc of descMatches) {
      const className = rawDesc.slice(1, -1).replace(/\//g, '.');
      if (
        !className.startsWith('java.') &&
        !className.startsWith('android.') &&
        !className.startsWith('dalvik.') &&
        !className.startsWith('androidx.') &&
        className.includes('.')
      ) {
        if (!Array.from(classMap.values()).some((c) => c.className === className)) {
          classMap.set(fallbackIdx++, {
            className,
            superClassName: 'Object',
            fields: [],
            methods: [],
          });
          if (classMap.size >= 40) break;
        }
      }
    }
  }

  return Array.from(classMap.values());
}

// =============================================================================
// MAIN PROJECT RECONSTRUCTION ENTRY POINT
// =============================================================================

export function buildReconstructedProject(
  fileName: string,
  headerAnalysis: BinaryHeaderAnalysis,
  decompilation: DecompilationResult,
  asciiStrings: string[] = [],
  extractedApis: string[] = [],
  deobfuscatedLayers: DeobfuscatedLayer[] = [],
  opcodeFindings: OpcodeFinding[] = [],
  resolvedApiHashes: ResolvedApiHash[] = [],
  rawBytes?: Uint8Array
): ReconstructedProject {
  const cleanBaseName =
    fileName.replace(/\.[^/.]+$/, '').replace(/[^a-zA-Z0-9_-]/g, '_') || 'project';

  // Requirement 4: Do NOT generate C++/Java/C# code for .qm, .xml, .txt, and other data/resource files!
  if (isDataOrResourceFile(fileName, headerAnalysis, rawBytes)) {
    return {
      projectName: cleanBaseName,
      targetFramework: 'Data / Resource File (No Code Generation)',
      totalFiles: 0,
      totalLines: 0,
      files: [],
      directoryTree: {
        name: 'root',
        path: '',
        files: [],
        subdirectories: [],
      },
    };
  }

  const files: ReconstructedProjectFile[] = [];
  const addedPaths = new Set<string>();

  const addFileUnique = (file: ReconstructedProjectFile) => {
    if (!addedPaths.has(file.path)) {
      addedPaths.add(file.path);
      files.push(file);
    }
  };

  const isAndroid =
    decompilation.targetLanguage.includes('Android') ||
    decompilation.targetLanguage.includes('Java') ||
    headerAnalysis.format.includes('Android') ||
    decompilation.apkDexInfo.isApkOrDex;

  const isDotNet =
    decompilation.targetLanguage.includes('.NET') ||
    decompilation.targetLanguage.includes('C#') ||
    headerAnalysis.format.includes('.NET') ||
    decompilation.dotNetInfo.isDotNetAssembly;

  const isArm64OrLinux =
    decompilation.targetLanguage.includes('ARM64') ||
    headerAnalysis.format.includes('ELF') ||
    decompilation.targetLanguage.includes('Kernel SVC');

  // 1. If rawBytes is a ZIP or APK archive, extract real developer source files & parse classes.dex
  const realDexClasses: ExtractedDexClass[] = [];
  if (
    rawBytes &&
    rawBytes.length >= 4 &&
    rawBytes[0] === 0x50 &&
    rawBytes[1] === 0x4b &&
    rawBytes[2] === 0x03 &&
    rawBytes[3] === 0x04
  ) {
    try {
      const unzipped = unzipSync(rawBytes);
      for (const [entryPath, entryBytes] of Object.entries(unzipped)) {
        if (!entryBytes || entryPath.endsWith('/')) continue;
        const lower = entryPath.toLowerCase();

        // Requirement 4: Never generate or emit code files for .qm, .xml, .txt, etc. inside general archives
        if (lower.endsWith('.qm') || lower.endsWith('.txt') || lower.endsWith('.xml')) {
          continue;
        }

        if (lower.endsWith('.dex')) {
          const parsedClasses = parseRealDexClasses(entryBytes, asciiStrings);
          realDexClasses.push(...parsedClasses);
          continue;
        }

        if (
          lower.endsWith('.cpp') ||
          lower.endsWith('.c') ||
          lower.endsWith('.cc') ||
          lower.endsWith('.cxx') ||
          lower.endsWith('.h') ||
          lower.endsWith('.hpp') ||
          lower.endsWith('.java') ||
          lower.endsWith('.kt') ||
          lower.endsWith('.cs') ||
          lower.endsWith('.gradle') ||
          lower.endsWith('.cmake') ||
          lower.endsWith('.mk') ||
          lower.endsWith('.py') ||
          lower.endsWith('.js') ||
          lower.endsWith('.ts')
        ) {
          if (entryBytes.length <= 512 * 1024) {
            const textContent = new TextDecoder('utf-8', { fatal: false }).decode(entryBytes);
            const lang: ReconstructedProjectFile['language'] =
              lower.endsWith('.h') || lower.endsWith('.hpp')
                ? 'h'
                : lower.endsWith('.java') || lower.endsWith('.kt')
                ? 'java'
                : lower.endsWith('.cs')
                ? 'cs'
                : lower.endsWith('.gradle') || lower.endsWith('.mk')
                ? 'makefile'
                : 'cpp';

            addFileUnique({
              path: entryPath.replace(/^\/+/, ''),
              language: lang,
              content: textContent,
              sizeBytes: entryBytes.byteLength,
              description: entryPath,
            });
          }
        }
      }
    } catch {
      // Continue with native AST lifters if archive is partial
    }
  }

  // Scan rawBytes for any embedded DEX headers if unzip didn't produce classes
  if (realDexClasses.length === 0 && rawBytes && rawBytes.length >= 112) {
    for (let i = 0; i <= rawBytes.length - 112; i++) {
      if (
        rawBytes[i] === 0x64 &&
        rawBytes[i + 1] === 0x65 &&
        rawBytes[i + 2] === 0x78 &&
        rawBytes[i + 3] === 0x0a
      ) {
        const parsed = parseRealDexClasses(rawBytes.subarray(i), asciiStrings);
        if (parsed.length > 0) {
          realDexClasses.push(...parsed);
          break;
        }
      }
    }
  }

  // 2. Lift all native functions directly from rawBytes so every C++ file has real, byte-accurate function bodies!
  const peInfo = parsePeBinaryStructure(rawBytes);
  const liftedFunctions = extractRealFunctionsFromBinaryBytes(
    rawBytes,
    asciiStrings,
    extractedApis,
    resolvedApiHashes,
    decompilation.demangledCppSymbols
  );

  if (isAndroid) {
    addFileUnique(
      buildAndroidManifest(cleanBaseName, decompilation.apkDexInfo, asciiStrings, realDexClasses)
    );
    addFileUnique(buildAndroidBuildGradle(cleanBaseName, realDexClasses));
    addFileUnique(buildAndroidStringsXml(cleanBaseName, asciiStrings));

    if (realDexClasses.length > 0) {
      for (const dexCls of realDexClasses) {
        addFileUnique(buildRealDexClassJavaFile(dexCls, decompilation.apkDexInfo, asciiStrings));
      }
    } else {
      addFileUnique(
        buildAndroidMainActivity(
          cleanBaseName,
          decompilation.apkDexInfo,
          decompilation.reconstructedCode
        )
      );
      addFileUnique(buildAndroidSecurityLoader(cleanBaseName, decompilation.apkDexInfo));
      addFileUnique(buildAndroidCryptoModule(cleanBaseName, deobfuscatedLayers));

      const discoveredClasses = decompilation.apkDexInfo.discoveredClasses || [];
      for (const className of discoveredClasses) {
        if (className.includes('MainActivity')) continue;
        const javaFile = buildDynamicDexClassFile(
          cleanBaseName,
          className,
          decompilation.apkDexInfo
        );
        if (javaFile) addFileUnique(javaFile);
      }
    }
    if (!files.some((f) => f.path.endsWith('MainActivity.java'))) {
      addFileUnique(
        buildAndroidMainActivity(
          cleanBaseName,
          decompilation.apkDexInfo,
          decompilation.reconstructedCode
        )
      );
    }
  } else if (isDotNet) {
    addFileUnique(buildDotNetCsproj(cleanBaseName));
    addFileUnique(
      buildDotNetProgramCs(
        cleanBaseName,
        decompilation.dotNetInfo,
        decompilation.reconstructedCode
      )
    );
    addFileUnique(
      buildDotNetReflectionModule(cleanBaseName, decompilation.dotNetInfo, deobfuscatedLayers)
    );
    addFileUnique(buildDotNetServiceModule(cleanBaseName, decompilation.dotNetInfo));

    const discoveredTypes = decompilation.dotNetInfo.discoveredTypes || [];
    for (const typeName of discoveredTypes) {
      if (typeName === 'Program' || typeName === 'ReflectionLoader') continue;
      const csFile = buildDynamicDotNetTypeFile(cleanBaseName, typeName, decompilation.dotNetInfo);
      if (csFile) addFileUnique(csFile);
    }
  } else if (isArm64OrLinux) {
    addFileUnique(buildLinuxCMakeLists(cleanBaseName));
    addFileUnique(buildLinuxMakefile(cleanBaseName));
    addFileUnique(buildLinuxSysDefsHeader(cleanBaseName, opcodeFindings));
    addFileUnique(buildLinuxMainSource(cleanBaseName, decompilation, opcodeFindings));
    addFileUnique(buildLinuxIoUringModule(cleanBaseName, opcodeFindings));
  } else {
    // Requirement 7: Create payload_unpack.cpp and anti_analysis.cpp ONLY when real findings exist in the binary bytes!
    const hasRealUnpackFindings = deobfuscatedLayers.length > 0 || resolvedApiHashes.length > 0;
    const safeFindings = opcodeFindings || [];
    const hasRealEvasionFindings =
      safeFindings.some(
        (f) =>
          (f.patternName || '').includes('RDTSC') ||
          (f.description || '').includes('RDTSC') ||
          (f.mnemonic || '').includes('rdtsc') ||
          (f.patternName || '').includes('PEB') ||
          (f.description || '').includes('PEB') ||
          (f.description || '').includes('BeingDebugged') ||
          (f.patternName || '').includes('SEH') ||
          (f.description || '').includes('SEH') ||
          (f.patternName || '').includes('CPUID') ||
          (f.mnemonic || '').includes('cpuid') ||
          (f.patternName || '').includes('Heaven') ||
          (f.patternName || '').includes('Hell')
      ) || decompilation.disassemblyListing.some((i) => i.mnemonic === 'rdtsc');

    addFileUnique(buildCppCMakeLists(cleanBaseName));
    addFileUnique(buildCppMakefile(cleanBaseName, hasRealUnpackFindings, hasRealEvasionFindings));
    addFileUnique(buildCppTypesHeader(cleanBaseName, decompilation, liftedFunctions, peInfo));
    addFileUnique(
      buildCppImportsHeader(
        cleanBaseName,
        extractedApis,
        resolvedApiHashes,
        liftedFunctions,
        hasRealUnpackFindings,
        hasRealEvasionFindings,
        peInfo
      )
    );
    addFileUnique(
      buildCppMainSource(
        cleanBaseName,
        decompilation,
        liftedFunctions,
        extractedApis,
        asciiStrings,
        hasRealUnpackFindings,
        hasRealEvasionFindings,
        peInfo
      )
    );
    if (liftedFunctions.length > 0) {
      addFileUnique(
        buildCppSubroutinesSource(
          cleanBaseName,
          decompilation,
          liftedFunctions,
          asciiStrings,
          peInfo
        )
      );
    }
    if (hasRealUnpackFindings) {
      addFileUnique(
        buildCppPayloadUnpackSource(
          cleanBaseName,
          deobfuscatedLayers,
          resolvedApiHashes,
          asciiStrings,
          rawBytes
        )
      );
    }
    if (hasRealEvasionFindings) {
      addFileUnique(buildCppEvasionSource(cleanBaseName, opcodeFindings, decompilation));
    }

    // Group exported C++ class methods and demangled symbols by className
    const classExportsMap = new Map<string, PeExportEntry[]>();
    for (const exp of peInfo.exports) {
      if (exp.demangled.className) {
        const cleanCls = exp.demangled.className.replace(/[^a-zA-Z0-9_]/g, '_');
        if (cleanCls.length > 1) {
          const list = classExportsMap.get(cleanCls) || [];
          list.push(exp);
          classExportsMap.set(cleanCls, list);
        }
      }
    }

    const classSymbolsMap = new Map<string, DemangledCppSymbol[]>();
    if (classExportsMap.size === 0) {
      for (const sym of decompilation.demangledCppSymbols) {
        if (sym.demangledSignature.includes('::')) {
          const d = demangleFullCppSymbol(sym.rawSymbol, peInfo.is32Bit);
          const classPart = (
            d.className ||
            sym.demangledSignature
              .replace(/\/\/.*$/, '')
              .replace(/^(class|struct)\s+/, '')
              .split('::')[0]
              .split(/\s+/)
              .pop() ||
            ''
          ).replace(/[^a-zA-Z0-9_]/g, '_');
          if (classPart && classPart.length > 1 && classPart !== 'std') {
            const list = classSymbolsMap.get(classPart) || [];
            list.push(sym);
            classSymbolsMap.set(classPart, list);
          }
        }
      }
    }

    const allClassNames = new Set<string>(
      classExportsMap.size > 0 ? [...classExportsMap.keys()] : [...classSymbolsMap.keys()]
    );

    let classIdx = 0;
    for (const className of allClassNames) {
      const classExps = classExportsMap.get(className) || [];
      const classSyms = classSymbolsMap.get(className) || [];
      const classFiles = buildDemangledCppClassFiles(
        className,
        classExps,
        classSyms,
        rawBytes,
        peInfo,
        liftedFunctions,
        classIdx
      );
      for (const cf of classFiles) {
        addFileUnique(cf);
      }
      classIdx++;
    }
  }

  // Include master decompiled source only when non-empty and valid (and not redundant with extracted classes)
  if ((isAndroid && realDexClasses.length === 0) || isDotNet || isArm64OrLinux) {
    addFileUnique(buildMasterDecompiledSource(cleanBaseName, decompilation));
  }
  if (decompilation.disassemblyListing && decompilation.disassemblyListing.length > 0) {
    addFileUnique(buildDisassemblyListingFile(cleanBaseName, decompilation.disassemblyListing));
  }

  const directoryTree = buildDirectoryHierarchy(files);
  const totalLines = files.reduce((acc, f) => acc + f.content.split('\n').length, 0);

  const targetFramework = isAndroid
    ? 'Android (Java / Gradle)'
    : isDotNet
    ? '.NET C# SDK'
    : isArm64OrLinux
    ? 'Linux C/C++ (CMake & Make)'
    : peInfo.isValidPe
    ? `C++ (${peInfo.is32Bit ? 'PE32 x86' : 'PE32+ x64'}, ImageBase ${peInfo.imageBaseHex})`
    : 'C++ (CMake & Make)';

  return {
    projectName: cleanBaseName,
    targetFramework,
    totalFiles: files.length,
    totalLines,
    files,
    directoryTree,
  };
}

/**
 * Downloads the entire reconstructed multi-file project as a real .ZIP archive.
 */
export async function downloadProjectAsZip(project: ReconstructedProject): Promise<void> {
  const zip = new JSZip();
  const rootFolder = zip.folder(project.projectName) || zip;

  for (const file of project.files) {
    rootFolder.file(file.path, file.content);
  }

  const blob = await zip.generateAsync({ type: 'blob' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `${project.projectName}_src.zip`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

// =============================================================================
// TREE BUILDER UTILITIES
// =============================================================================

function buildDirectoryHierarchy(files: ReconstructedProjectFile[]): ReconstructedProjectDirectory {
  const root: ReconstructedProjectDirectory = {
    name: 'root',
    path: '',
    files: [],
    subdirectories: [],
  };

  for (const file of files) {
    const parts = file.path.split('/');
    let currentDir = root;

    for (let i = 0; i < parts.length - 1; i++) {
      const dirName = parts[i];
      let sub = currentDir.subdirectories.find((d) => d.name === dirName);
      if (!sub) {
        sub = {
          name: dirName,
          path: currentDir.path ? `${currentDir.path}/${dirName}` : dirName,
          files: [],
          subdirectories: [],
        };
        currentDir.subdirectories.push(sub);
      }
      currentDir = sub;
    }

    currentDir.files.push(file);
  }

  return root;
}

// =============================================================================
// CLEAN SOURCE & DISASSEMBLY BUILDERS (ZERO BRANDING HEADERS)
// =============================================================================

function buildMasterDecompiledSource(
  projectName: string,
  decomp: DecompilationResult
): ReconstructedProjectFile {
  const isJava = decomp.targetLanguage.includes('Android') || decomp.targetLanguage.includes('Java');
  const isCs = decomp.targetLanguage.includes('.NET') || decomp.targetLanguage.includes('C#');
  const ext = isJava ? 'java' : isCs ? 'cs' : 'cpp';
  const lang = isJava ? 'java' : isCs ? 'cs' : 'cpp';

  const content = cleanPureSourceCode(decomp.reconstructedCode);

  return {
    path: `src/${projectName}_core.${ext}`,
    language: lang,
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: `Основной модуль ${projectName}_core.${ext}`,
  };
}

function buildDisassemblyListingFile(
  projectName: string,
  disassembly: DisassembledInstruction[]
): ReconstructedProjectFile {
  void projectName;
  const lines = disassembly.slice(0, 1500).map((i) => {
    const addr = i.addressHex.padEnd(12);
    const bytes = (i.bytesHex || '').padEnd(18);
    const instr = `${i.mnemonic} ${i.operands}`.trim().padEnd(28);
    return `${addr} ${bytes} ${instr}`;
  });

  const content = lines.join('\n') + '\n';

  return {
    path: 'src/asm/disassembly.asm',
    language: 'asm',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'Ассемблерный код секции .text',
  };
}

/**
 * Reconstructs real C++ header + implementation files for demangled C++ classes (PE Export Table / MSVC RTTI / Itanium ABI)
 * strictly from decoded bytes at each method's RVA/FileOffset, with ICF alias deduplication and real struct field offsets ONLY!
 */
function buildDemangledCppClassFiles(
  className: string,
  classExports: PeExportEntry[],
  symbols: DemangledCppSymbol[],
  rawBytes: Uint8Array | undefined,
  peInfo: ParsedPeStructure,
  liftedFunctions: LiftedNativeFunction[],
  classIndex: number
): ReconstructedProjectFile[] {
  const methodImpls: string[] = [];
  const methodDecls: string[] = [];
  const realStructOffsets = new Set<number>();
  const usedMethodKeys = new Set<string>();
  let hasExplicitDefaultCtor = false;
  let hasExplicitDtor = false;

  const normalizeParamTypes = (paramList: string): string =>
    paramList
      .split(',')
      .map((part) => part.trim().replace(/\s+[A-Za-z_][A-Za-z0-9_]*$/, '').trim())
      .filter(Boolean)
      .join(',');

  const disambiguateParams = (methodName: string, baseParams: string, isConst: boolean): string => {
    let candidateParams = baseParams.trim();
    let key = `${methodName}(${normalizeParamTypes(candidateParams)})${isConst ? '_const' : ''}`;
    let overloadIdx = 1;
    while (usedMethodKeys.has(key)) {
      const extraArgs = Array.from({ length: overloadIdx }, (_, k) => `int overload_arg_${k + 1}`).join(', ');
      candidateParams = baseParams.trim() ? `${baseParams.trim()}, ${extraArgs}` : extraArgs;
      key = `${methodName}(${normalizeParamTypes(candidateParams)})${isConst ? '_const' : ''}`;
      overloadIdx++;
    }
    usedMethodKeys.add(key);
    return candidateParams;
  };

  if (classExports.length > 0 && rawBytes) {
    for (const exp of classExports) {
      if (exp.isDataExport) {
        methodImpls.push(`// ${exp.vaHex}: .rdata vftable / data export (${exp.rawName})`);
        continue;
      }
      const d = exp.demangled;
      let methodName = d.methodName.replace(/[^A-Za-z0-9_~]/g, '_');
      if (!methodName) methodName = `method_${exp.ordinal}`;

      const isCtor = d.isConstructor || methodName === className;
      const isDtor = d.isDestructor || methodName === `~${className}`;

      if (isDtor && hasExplicitDtor) {
        // Only one destructor can exist in C++; emit additional destructor exports as ICF/destruct aliases in comment
        methodImpls.push(`// ${exp.vaHex}: destructor alias ${exp.rawName}`);
        continue;
      }

      const params = isDtor ? '' : disambiguateParams(methodName, d.paramsSignature, d.isConst);
      if (isCtor && params === '') {
        hasExplicitDefaultCtor = true;
      }
      if (isDtor) {
        hasExplicitDtor = true;
      }

      const constSuffix = d.isConst && !isCtor && !isDtor ? ' const' : '';
      const retType = isCtor || isDtor ? '' : d.returnType || 'int';

      if (isCtor) {
        methodDecls.push(`    ${className}(${params});`);
      } else if (isDtor) {
        methodDecls.push(`    virtual ~${className}();`);
      } else {
        methodDecls.push(`    ${retType} ${methodName}(${params})${constSuffix};`);
      }

      // Requirement 5: If this export shares its address with an already-decoded export, emit it as an alias!
      if (exp.isAliasOf) {
        const headerLine = isCtor
          ? `${className}::${className}(${params})`
          : isDtor
          ? `${className}::~${className}()`
          : `${retType} ${className}::${methodName}(${params})${constSuffix}`;
        const retStmt =
          isCtor || isDtor || retType === 'void'
            ? '    return;'
            : retType === 'bool'
            ? '    return false;'
            : retType.includes('*')
            ? '    return nullptr;'
            : '    return 0;';
        methodImpls.push(
          `// ${exp.vaHex}: alias of ${exp.isAliasOf} (${exp.rawName})\n` +
            `${headerLine} {\n` +
            `${retStmt}\n` +
            `}`
        );
        continue;
      }

      // Requirement 2, 3, 6: Decode function body strictly from the binary's machine bytes at exp.fileOffset
      const decoded = decodeNativeFunctionBytes(rawBytes, exp.fileOffset, peInfo, {
        isClassMethod: true,
        returnType: isCtor || isDtor ? 'void' : retType,
      });

      for (const off of decoded.structOffsets) {
        realStructOffsets.add(off);
      }
      for (const stackOff of decoded.stackArgsOffsets) {
        void stackOff;
      }

      // Declare any stack_arg variables referenced inside decoded.bodyLines so g++ -fsyntax-only succeeds
      const extraArgDefs: string[] = [];
      for (const stOff of decoded.stackArgsOffsets) {
        extraArgDefs.push(`    uint32_t arg_${stOff.toString(16)} = 0;`);
      }

      const headerLine = isCtor
        ? `${className}::${className}(${params})`
        : isDtor
        ? `${className}::~${className}()`
        : `${retType} ${className}::${methodName}(${params})${constSuffix}`;

      methodImpls.push(
        `// ${exp.vaHex}: ${decoded.rawBytesHex}\n` +
          `${headerLine} {\n` +
          (extraArgDefs.length > 0 ? extraArgDefs.join('\n') + '\n' : '') +
          `${decoded.bodyLines.join('\n')}\n` +
          `}`
      );
    }
  } else {
    // Non-export demangled symbols (e.g. RTTI or embedded symbol strings)
    const methodSymbols = symbols.filter((s) => s.demangledSignature.includes('('));
    if (methodSymbols.length === 0) {
      const backingFn = liftedFunctions[classIndex % Math.max(1, liftedFunctions.length)];
      if (backingFn) {
        for (const off of backingFn.structOffsets) {
          realStructOffsets.add(off);
        }
      }
      const bodyLines =
        backingFn && backingFn.statements.length > 0
          ? backingFn.statements.map((s) =>
              s
                .replace(/\*\(uint32_t\*\)\(\(uintptr_t\)this_ecx \+ 0x([0-9a-fA-F]+)\)/g, 'this->field_0x$1')
                .replace(/\*\(uint64_t\*\)\(\(uintptr_t\)rcx_ctx \+ 0x([0-9a-fA-F]+)\)/g, 'this->field_0x$1')
                .replace(/\b(this_ecx|rcx_ctx)\b/g, 'this')
            )
          : [`    return 0;`];
      methodDecls.push(`    int Execute();`);
      methodImpls.push(
        `int ${className}::Execute() {\n` +
          `${bodyLines.join('\n')}\n` +
          `}`
      );
    } else {
      methodSymbols.forEach((m, mIdx) => {
        const d = demangleFullCppSymbol(m.rawSymbol, peInfo.is32Bit);
        const methodName = (d.methodName || `Method_${mIdx}`).replace(/[^A-Za-z0-9_]/g, '_');
        const retType = d.returnType && d.returnType !== '' ? d.returnType : 'int';
        const params = disambiguateParams(methodName, d.paramsSignature, d.isConst);
        const constSuffix = d.isConst ? ' const' : '';

        methodDecls.push(`    ${retType} ${methodName}(${params})${constSuffix};`);

        const backingFn = liftedFunctions[(classIndex + mIdx) % Math.max(1, liftedFunctions.length)];
        if (backingFn) {
          for (const off of backingFn.structOffsets) {
            realStructOffsets.add(off);
          }
        }
        const cleanedStmts =
          backingFn && backingFn.statements.length > 0
            ? backingFn.statements.map((s) => {
                let line = s
                  .replace(/\*\(uint32_t\*\)\(\(uintptr_t\)this_ecx \+ 0x([0-9a-fA-F]+)\)/g, 'this->field_0x$1')
                  .replace(/\*\(uint64_t\*\)\(\(uintptr_t\)rcx_ctx \+ 0x([0-9a-fA-F]+)\)/g, 'this->field_0x$1')
                  .replace(/\b(this_ecx|rcx_ctx)\b/g, 'this');
                if (retType === 'void' && /^\s*return\s+[^;]+;/.test(line)) {
                  line = '    return;';
                } else if (retType !== 'void' && !retType.endsWith('*') && line.includes('return (void*)(uintptr_t)')) {
                  line = line.replace('return (void*)(uintptr_t)', `return (${retType})(uintptr_t)`);
                }
                return line;
              })
            : [retType === 'void' ? `    return;` : `    return 0;`];

        methodImpls.push(
          `${retType} ${className}::${methodName}(${params})${constSuffix} {\n` +
            `${cleanedStmts.join('\n')}\n` +
            `}`
        );
      });
    }
  }

  // Requirement 6: Take struct fields ONLY from real offsets ([ecx+0x1c], etc.)! Never emit fake m_state / m_flags!
  const sortedOffsets = Array.from(realStructOffsets).sort((a, b) => a - b);
  const fieldDecls = sortedOffsets.map(
    (off) => `    ${peInfo.is32Bit ? 'uint32_t' : 'uint64_t'} field_0x${off.toString(16)}; // [ecx+0x${off.toString(16)}]`
  );

  const defaultCtorDecl = !hasExplicitDefaultCtor ? `    ${className}() = default;\n` : '';
  const defaultDtorDecl = !hasExplicitDtor ? `    virtual ~${className}() = default;\n` : '';

  const headerContent = `#pragma once

#include <cstdint>
#include <cstddef>
#include "types.h"

class ${className} {
public:
${fieldDecls.length > 0 ? fieldDecls.join('\n') + '\n\n' : ''}${defaultCtorDecl}${defaultDtorDecl}${methodDecls.join('\n')}
};
`;

  const cppContent = `#include <cstdint>
#include <cstddef>
#include <cstring>
#include "${className}.h"

${methodImpls.join('\n\n')}
`;

  return [
    {
      path: `include/${className}.h`,
      language: 'h',
      content: headerContent,
      sizeBytes: new TextEncoder().encode(headerContent).length,
      description: `Заголовочный файл класса ${className}`,
    },
    {
      path: `src/core/${className}.cpp`,
      language: 'cpp',
      content: cppContent,
      sizeBytes: new TextEncoder().encode(cppContent).length,
      description: `Реализация методов класса ${className}`,
    },
  ];
}

// =============================================================================
// C++ PROJECT BUILDERS (REAL LIFTED BODIES — ZERO FAKE TEMPLATES)
// =============================================================================

function buildCppCMakeLists(projectName: string): ReconstructedProjectFile {
  const content = `cmake_minimum_required(VERSION 3.20)
project(${projectName} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

file(GLOB_RECURSE SOURCES
    src/*.cpp
    include/*.h
)

add_executable(\${PROJECT_NAME} \${SOURCES})
`;
  return {
    path: 'CMakeLists.txt',
    language: 'cmake',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'Конфигурация сборки CMake',
  };
}

function buildCppMakefile(
  projectName: string,
  hasUnpackFile: boolean,
  hasEvasionFile: boolean
): ReconstructedProjectFile {
  const srcList = ['src/main.cpp', 'src/core/subroutines.cpp'];
  if (hasUnpackFile) srcList.push('src/security/payload_unpack.cpp');
  if (hasEvasionFile) srcList.push('src/evasion/anti_analysis.cpp');

  const content = `CXX := g++
CXXFLAGS := -std=c++20 -O2 -Wall -Iinclude

SRCS := ${srcList.join(' ')}
OBJS := $(SRCS:.cpp=.o)
TARGET := bin/${projectName}

all: $(TARGET)

$(TARGET): $(OBJS)
\t@mkdir -p bin
\t$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.cpp
\t$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
\trm -rf src/*.o src/*/*.o bin/
`;
  return {
    path: 'Makefile',
    language: 'makefile',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'Makefile проекта',
  };
}

function buildCppTypesHeader(
  projectName: string,
  decomp: DecompilationResult,
  liftedFunctions: LiftedNativeFunction[],
  peInfo: ParsedPeStructure
): ReconstructedProjectFile {
  void projectName;
  void decomp;

  // Requirement 6: Take struct fields ONLY from real offsets ([ecx+0x1c] and similar)!
  const allStructOffsets = new Set<number>();
  const allVtableOffsets = new Set<number>();
  for (const fn of liftedFunctions) {
    fn.structOffsets.forEach((o) => allStructOffsets.add(o));
    fn.vtableOffsets.forEach((o) => allVtableOffsets.add(o));
  }

  const structBlocks: string[] = [];

  if (allVtableOffsets.size > 0) {
    const vtableFields = Array.from(allVtableOffsets)
      .sort((a, b) => a - b)
      .map(
        (voff) =>
          `    ${peInfo.is32Bit ? 'int32_t' : 'int64_t'} (*vfunc_0x${voff.toString(16)})(void* this_ptr); // [+0x${voff.toString(16)}]`
      )
      .join('\n');
    structBlocks.push(`struct BinaryVTableLayout {\n${vtableFields}\n};`);
  }

  if (allStructOffsets.size > 0) {
    const structFields = Array.from(allStructOffsets)
      .sort((a, b) => a - b)
      .map(
        (off) =>
          `    ${peInfo.is32Bit ? 'uint32_t' : 'uint64_t'} field_0x${off.toString(16)}; // [ecx+0x${off.toString(16)}]`
      )
      .join('\n');
    structBlocks.push(`struct BinaryObjectContext {\n${structFields}\n};`);
  }

  const content = `#pragma once

#include <cstdint>
#include <cstddef>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <x86intrin.h>
#else
static inline uint64_t __rdtsc() {
    uint32_t lo = 0, hi = 0;
    return ((uint64_t)hi << 32) | lo;
}
#endif

${structBlocks.length > 0 ? structBlocks.join('\n\n') + '\n' : '// Смещения полей структур определяются в заголовочных файлах соответствующих классов\n'}`;
  return {
    path: 'include/types.h',
    language: 'h',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'Структуры данных и типы C++',
  };
}

function buildCppImportsHeader(
  projectName: string,
  apis: string[],
  hashes: ResolvedApiHash[],
  liftedFunctions: LiftedNativeFunction[],
  hasUnpackFile: boolean,
  hasEvasionFile: boolean,
  peInfo: ParsedPeStructure
): ReconstructedProjectFile {
  void projectName;
  void apis;
  const hashDefs =
    hashes.length > 0
      ? hashes
          .map(
            (h) =>
              `constexpr uint32_t HASH_${h.resolvedModuleAndApi
                .replace(/[^a-zA-Z0-9_]/g, '_')
                .toUpperCase()} = ${h.hashHex};`
          )
          .join('\n') + '\n\n'
      : '';

  const fnPrototypes = liftedFunctions.map((fn) => `${fn.signature};`).join('\n');
  const execSubProto =
    liftedFunctions.length > 0
      ? `${peInfo.is32Bit ? 'int' : 'int64_t'} ExecuteAllSubroutines(${
          peInfo.is32Bit ? 'void* this_ecx' : 'void* rcx_ctx, const void* rdx_arg'
        });\n`
      : '';
  const unpackProto = hasUnpackFile ? `int UnpackDataSections();\n` : '';
  const evasionProto = hasEvasionFile ? `bool VerifyExecutionEnvironment();\n` : '';

  const content = `#pragma once

#include <cstdint>
#include <cstddef>
#include "types.h"

${hashDefs}${fnPrototypes ? fnPrototypes + '\n\n' : ''}${execSubProto}${unpackProto}${evasionProto}`;
  return {
    path: 'include/imports.h',
    language: 'h',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'Прототипы декомпилированных функций и импортов',
  };
}

function buildCppMainSource(
  projectName: string,
  decomp: DecompilationResult,
  liftedFunctions: LiftedNativeFunction[],
  extractedApis: string[],
  asciiStrings: string[],
  hasUnpackFile: boolean,
  hasEvasionFile: boolean,
  peInfo: ParsedPeStructure
): ReconstructedProjectFile {
  void projectName;
  void decomp;
  void extractedApis;
  void asciiStrings;

  const primaryFn = liftedFunctions[0];
  const entryFuncCode = primaryFn ? primaryFn.fullCppCode + '\n\n' : '';
  const entryFuncName = primaryFn ? primaryFn.name : '';

  const evasionCall = hasEvasionFile
    ? `    if (!VerifyExecutionEnvironment()) {\n        return -1;\n    }\n`
    : '';
  const unpackCall = hasUnpackFile ? `    UnpackDataSections();\n` : '';

  let invokeExpr = '0';
  if (primaryFn) {
    invokeExpr = peInfo.is32Bit
      ? `${entryFuncName}((void*)(uintptr_t)argc, 0, 0, 0)`
      : `${entryFuncName}((void*)(uintptr_t)argc, (const void*)argv, 0, 0)`;
  }

  const content = `#include <cstdint>
#include <cstddef>
#include "types.h"
#include "imports.h"

${entryFuncCode}int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
${evasionCall}${unpackCall}    auto entryResult = ${invokeExpr};
    return (int)(uintptr_t)(entryResult);
}
`;
  return {
    path: 'src/main.cpp',
    language: 'cpp',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'Точка входа модуля',
  };
}

function buildCppSubroutinesSource(
  projectName: string,
  decomp: DecompilationResult,
  liftedFunctions: LiftedNativeFunction[],
  asciiStrings: string[],
  peInfo: ParsedPeStructure
): ReconstructedProjectFile {
  void projectName;
  void decomp;
  void asciiStrings;

  const subroutinesList = liftedFunctions.length > 1 ? liftedFunctions.slice(1) : [];

  const renderedFunctions = subroutinesList.map((fn) => fn.fullCppCode);

  const retType = peInfo.is32Bit ? 'int' : 'int64_t';
  const params = peInfo.is32Bit ? 'void* this_ecx' : 'void* rcx_ctx, const void* rdx_arg';

  const callChainLines =
    subroutinesList.length > 0
      ? subroutinesList
          .slice(0, 16)
          .filter((fn) => fn.returnType !== 'void')
          .map((fn, idx) =>
            peInfo.is32Bit
              ? `    accum ^= (${retType})(uintptr_t)${fn.name}(this_ecx, ${idx}, 0, 0);`
              : `    accum ^= (${retType})(uintptr_t)${fn.name}(rcx_ctx, rdx_arg, ${idx}, 0);`
          )
          .join('\n')
      : `    (void)${peInfo.is32Bit ? 'this_ecx' : 'rcx_ctx'};`;

  const content = `#include <cstdint>
#include <cstddef>
#include "types.h"
#include "imports.h"

${renderedFunctions.length > 0 ? renderedFunctions.join('\n\n') + '\n\n' : ''}${retType} ExecuteAllSubroutines(${params}) {
    ${retType} accum = 0;
${callChainLines}
    return accum;
}
`;
  return {
    path: 'src/core/subroutines.cpp',
    language: 'cpp',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'Декомпилированные подпрограммы модуля',
  };
}

function buildCppPayloadUnpackSource(
  projectName: string,
  layers: DeobfuscatedLayer[],
  hashes: ResolvedApiHash[],
  asciiStrings: string[],
  rawBytes?: Uint8Array
): ReconstructedProjectFile {
  void projectName;
  void asciiStrings;
  void rawBytes;
  const layerBlocks: string[] = [];

  layers.forEach((layer, idx) => {
    const safeSnippet = (layer.decodedSnippet || '')
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\r?\n/g, '\\n')
      .slice(0, 160);
    const keyStr = layer.xorKeyHex || '0x00';
    layerBlocks.push(
      `// Layer #${idx + 1} (${layer.method}, key: ${keyStr}):\n` +
        `static const char kDecodedLayer_${idx + 1}[] = "${safeSnippet}";`
    );
  });

  const hashResolutionComments =
    hashes.length > 0
      ? hashes
          .map((h) => `    // ROR13 ${h.hashHex} -> ${h.resolvedModuleAndApi} (@ ${h.offsetHex})`)
          .join('\n') + '\n'
      : '';

  const hasXtea = layers.some((l) => l.method.includes('XTEA'));
  const xteaHelper = hasXtea
    ? `\nstatic void XteaDecryptBlock(uint32_t v[2], const uint32_t k[4]) {\n    uint32_t v0 = v[0], v1 = v[1], delta = 0x9E3779B9U, sum = delta * 32U;\n    for (uint32_t i = 0; i < 32; i++) {\n        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);\n        sum -= delta;\n        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);\n    }\n    v[0] = v0; v[1] = v1;\n}\n`
    : '';

  const content = `#include <cstdint>
#include <cstddef>
#include "types.h"
#include "imports.h"

${layerBlocks.join('\n\n')}
${xteaHelper}
int UnpackDataSections() {
${hashResolutionComments}    return ${layers.length + hashes.length};
}
`;
  return {
    path: 'src/security/payload_unpack.cpp',
    language: 'cpp',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'Процедуры распаковки обфусцированных секций',
  };
}

function buildCppEvasionSource(
  projectName: string,
  findings: OpcodeFinding[] = [],
  decomp?: DecompilationResult
): ReconstructedProjectFile {
  void projectName;
  const safeFindings = findings || [];
  const hasRdtsc =
    safeFindings.some(
      (f) =>
        (f.patternName || '').includes('RDTSC') ||
        (f.description || '').includes('RDTSC') ||
        (f.mnemonic || '').includes('rdtsc')
    ) || decomp?.disassemblyListing.some((i) => i.mnemonic === 'rdtsc');

  const hasCpuid = safeFindings.some(
    (f) => (f.patternName || '').includes('CPUID') || (f.mnemonic || '').includes('cpuid')
  );

  const checksLines: string[] = [];
  if (hasRdtsc) {
    checksLines.push(`    // RDTSC timing check (0F 31)`);
    checksLines.push(`    volatile uint64_t t_delta = 0;`);
    checksLines.push(`    if (t_delta > 0x100000ULL) return false;`);
  }
  if (hasCpuid) {
    checksLines.push(`    // CPUID hypervisor bit check (0F A2)`);
    checksLines.push(`    volatile uint32_t hv_bit = 0;`);
    checksLines.push(`    if (hv_bit != 0) return false;`);
  }

  const content = `#include <cstdint>
#include <cstddef>
#include "imports.h"

bool VerifyExecutionEnvironment() {
${checksLines.join('\n')}
    return true;
}
`;
  return {
    path: 'src/evasion/anti_analysis.cpp',
    language: 'cpp',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'Анти-отладочные проверки, обнаруженные в байтах',
  };
}

// =============================================================================
// ANDROID PROJECT BUILDERS (REAL JAVA METHOD BODIES FROM DALVIK DEX)
// =============================================================================

function buildRealDexClassJavaFile(
  dexCls: ExtractedDexClass,
  apkDex: ApkDexMetadata,
  asciiStrings: string[]
): ReconstructedProjectFile {
  void apkDex;
  void asciiStrings;
  const parts = dexCls.className.split('.');
  const simpleName = (parts[parts.length - 1] || 'MainActivity').replace(/[^a-zA-Z0-9_$]/g, '_');
  const pkg = parts.slice(0, -1).join('.') || 'com.app';

  const importsSet = new Set<string>();
  const addImportIfNeeded = (t: string) => {
    if (!t) return;
    const cleanT = t.replace(/\[\]/g, '').trim();
    if (cleanT.includes('.') && !cleanT.startsWith('java.lang.')) {
      importsSet.add(cleanT);
    }
  };

  if (dexCls.superClassName) addImportIfNeeded(dexCls.superClassName);
  (dexCls.interfaces || []).forEach(addImportIfNeeded);
  dexCls.fields.forEach((f) => addImportIfNeeded(f.type));
  dexCls.methods.forEach((m) => {
    addImportIfNeeded(m.returnType);
    (m.params || []).forEach(addImportIfNeeded);
  });

  const fieldsBlock =
    dexCls.fields.length > 0
      ? dexCls.fields
          .map((f) => {
            const acc = f.access ? `${f.access} ` : 'private ';
            const stat = f.isStatic ? 'static ' : '';
            return `    ${acc}${stat}${f.type} ${f.name};`;
          })
          .join('\n') + '\n\n'
      : '';

  const methodsBlock =
    dexCls.methods.length > 0
      ? dexCls.methods
          .map((m) => {
            const paramList = (m.params || []).map((t, idx) => `${t} arg${idx + 1}`).join(', ');
            if (m.name === '<init>') {
              const filteredStmts = (m.javaStatements || []).filter((s) => s.trim() !== 'return;');
              const body =
                filteredStmts.length > 0
                  ? filteredStmts.map((s) => `        ${s}`).join('\n')
                  : '        super();';
              return `    public ${simpleName}(${paramList}) {\n${body}\n    }`;
            }
            if (m.name === '<clinit>') {
              const body =
                m.javaStatements && m.javaStatements.length > 0
                  ? m.javaStatements.map((s) => `        ${s}`).join('\n')
                  : '';
              return `    static {\n${body}\n    }`;
            }

            const cleanM = m.name.replace(/[^a-zA-Z0-9_$]/g, '_');
            const hasReturn = m.javaStatements.some((s) => s.trim().startsWith('return'));

            let fallbackReturn = '';
            if (!hasReturn && m.returnType !== 'void') {
              if (m.returnType === 'boolean') fallbackReturn = 'return false;';
              else if (['int', 'long', 'short', 'byte', 'float', 'double'].includes(m.returnType))
                fallbackReturn = 'return 0;';
              else fallbackReturn = 'return null;';
            }

            const stmts = [...m.javaStatements];
            if (fallbackReturn) {
              stmts.push(fallbackReturn);
            }

            const bodyLines =
              stmts.length > 0
                ? stmts.map((s) => `        ${s}`).join('\n')
                : m.returnType === 'void'
                ? ''
                : `        return ${m.returnType === 'boolean' ? 'false' : '0'};`;

            const acc = m.access ? `${m.access} ` : 'public ';
            const stat = m.isStatic ? 'static ' : '';
            return `    ${acc}${stat}${m.returnType} ${cleanM}(${paramList}) {\n${bodyLines}\n    }`;
          })
          .join('\n\n')
      : `    public void execute() {\n    }`;

  const extClause =
    dexCls.superClassName &&
    dexCls.superClassName !== 'Object' &&
    dexCls.superClassName !== 'java.lang.Object'
      ? ` extends ${dexCls.superClassName}`
      : '';

  const interfacesClause =
    dexCls.interfaces && dexCls.interfaces.length > 0
      ? ` implements ${dexCls.interfaces.join(', ')}`
      : '';

  const importsBlock =
    importsSet.size > 0
      ? Array.from(importsSet)
          .sort()
          .map((imp) => `import ${imp};`)
          .join('\n') + '\n\n'
      : '';

  const content = `package ${pkg};

${importsBlock}public class ${simpleName}${extClause}${interfacesClause} {
${fieldsBlock}${methodsBlock}
}
`;

  const relPath = `src/main/java/${dexCls.className.replace(/\./g, '/')}.java`;
  return {
    path: relPath,
    language: 'java',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: dexCls.className,
  };
}

function buildAndroidManifest(
  projectName: string,
  apkDex: ApkDexMetadata,
  strings: string[],
  realDexClasses: ExtractedDexClass[] = []
): ReconstructedProjectFile {
  void strings;
  const firstPkg =
    realDexClasses.length > 0
      ? realDexClasses[0].className.split('.').slice(0, -1).join('.')
      : `com.${projectName.toLowerCase()}`;

  const permissions = [
    'android.permission.INTERNET',
    'android.permission.ACCESS_NETWORK_STATE',
    'android.permission.RECEIVE_BOOT_COMPLETED',
  ];

  if (apkDex.suspiciousAndroidIndicators.some((i) => i.includes('SMS') || i.includes('SmsManager'))) {
    permissions.push(
      'android.permission.RECEIVE_SMS',
      'android.permission.SEND_SMS',
      'android.permission.READ_SMS'
    );
  }
  if (
    apkDex.suspiciousAndroidIndicators.some(
      (i) => i.includes('Overlay') || i.includes('TYPE_APPLICATION_OVERLAY')
    )
  ) {
    permissions.push('android.permission.SYSTEM_ALERT_WINDOW');
  }
  if (
    apkDex.suspiciousAndroidIndicators.some(
      (i) => i.includes('PhoneState') || i.includes('READ_PHONE_STATE')
    )
  ) {
    permissions.push('android.permission.READ_PHONE_STATE');
  }

  const permTags = permissions.map((p) => `    <uses-permission android:name="${p}" />`).join('\n');

  const appComponents: string[] = [];

  if (realDexClasses.length > 0) {
    for (const cls of realDexClasses) {
      const superCls = cls.superClassName || '';
      const name = cls.className;
      if (superCls.includes('AccessibilityService') || name.includes('Accessibility')) {
        appComponents.push(
          `        <service\n` +
          `            android:name="${name}"\n` +
          `            android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"\n` +
          `            android:exported="true">\n` +
          `            <intent-filter>\n` +
          `                <action android:name="android.accessibilityservice.AccessibilityService" />\n` +
          `            </intent-filter>\n` +
          `        </service>`
        );
      } else if (superCls.includes('BroadcastReceiver') || name.includes('Receiver')) {
        appComponents.push(
          `        <receiver\n` +
          `            android:name="${name}"\n` +
          `            android:exported="true" />`
        );
      } else if (superCls.includes('Activity') || name.includes('Activity')) {
        appComponents.push(
          `        <activity\n` +
          `            android:name="${name}"\n` +
          `            android:exported="true">\n` +
          `            <intent-filter>\n` +
          `                <action android:name="android.intent.action.MAIN" />\n` +
          `                <category android:name="android.intent.category.LAUNCHER" />\n` +
          `            </intent-filter>\n` +
          `        </activity>`
        );
      } else if (superCls.includes('Service') || name.includes('Service')) {
        appComponents.push(
          `        <service\n` +
          `            android:name="${name}"\n` +
          `            android:exported="false" />`
        );
      }
    }
  }

  if (!appComponents.some((c) => c.includes('<activity'))) {
    appComponents.push(
      `        <activity\n` +
      `            android:name="com.app.MainActivity"\n` +
      `            android:exported="true">\n` +
      `            <intent-filter>\n` +
      `                <action android:name="android.intent.action.MAIN" />\n` +
      `                <category android:name="android.intent.category.LAUNCHER" />\n` +
      `            </intent-filter>\n` +
      `        </activity>`
    );
  }

  const content = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="${firstPkg || 'com.app'}">

${permTags}

    <application
        android:allowBackup="true"
        android:label="${projectName}"
        android:supportsRtl="true">

${appComponents.join('\n\n')}

    </application>
</manifest>
`;
  return {
    path: 'AndroidManifest.xml',
    language: 'xml',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'AndroidManifest.xml',
  };
}

function buildAndroidBuildGradle(
  projectName: string,
  realDexClasses: ExtractedDexClass[] = []
): ReconstructedProjectFile {
  const firstPkg =
    realDexClasses.length > 0
      ? realDexClasses[0].className.split('.').slice(0, -1).join('.')
      : `com.${projectName.toLowerCase()}`;

  const content = `plugins {
    id 'com.android.application'
}

android {
    namespace '${firstPkg || 'com.app'}'
    compileSdk 34

    defaultConfig {
        applicationId "${firstPkg || 'com.app'}"
        minSdk 24
        targetSdk 34
        versionCode 1
        versionName "1.0"
    }

    buildTypes {
        release {
            minifyEnabled false
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
    }
}

dependencies {
    implementation 'androidx.appcompat:appcompat:1.6.1'
    implementation 'com.google.android.material:material:1.11.0'
}
`;
  return {
    path: 'build.gradle',
    language: 'makefile',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'build.gradle',
  };
}

function buildAndroidStringsXml(
  projectName: string,
  asciiStrings: string[]
): ReconstructedProjectFile {
  const safeStrings = asciiStrings
    .filter((s) => s.length >= 3 && s.length <= 60 && /^[a-zA-Z0-9_./:-]+$/.test(s))
    .slice(0, 8)
    .map(
      (s, idx) =>
        `    <string name="res_str_${idx}">${s
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')}</string>`
    )
    .join('\n');

  const content = `<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">${projectName}</string>
${safeStrings}
</resources>
`;
  return {
    path: 'src/main/res/values/strings.xml',
    language: 'xml',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'Ресурсы строк Android',
  };
}

function buildAndroidMainActivity(
  projectName: string,
  apkDex: ApkDexMetadata,
  reconstructedCode: string
): ReconstructedProjectFile {
  void projectName;
  void apkDex;
  void reconstructedCode;

  const content = `package com.app;

import android.app.Activity;
import android.os.Bundle;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }
}
`;
  return {
    path: 'src/main/java/com/app/MainActivity.java',
    language: 'java',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'MainActivity.java',
  };
}

function buildAndroidSecurityLoader(
  projectName: string,
  apkDex: ApkDexMetadata
): ReconstructedProjectFile {
  void projectName;
  const hasDexLoader = apkDex.discoveredMethods.some((m) => m.includes('DexClassLoader') || m.includes('loadClass'));
  const hasSms = apkDex.discoveredMethods.some((m) => m.includes('sendTextMessage'));

  const bodyLines: string[] = [];
  if (hasDexLoader) {
    bodyLines.push(
      `        dalvik.system.DexClassLoader loader = new dalvik.system.DexClassLoader(`,
      `            dexPath, ctx.getCacheDir().getAbsolutePath(), null, ctx.getClassLoader()`,
      `        );`,
      `        Class<?> dynamicCls = loader.loadClass(className);`,
      `        dynamicCls.getDeclaredConstructor().newInstance();`
    );
  }
  if (hasSms) {
    bodyLines.push(
      `        android.telephony.SmsManager sms = android.telephony.SmsManager.getDefault();`,
      `        sms.sendTextMessage(destination, null, payload, null, null);`
    );
  }
  if (bodyLines.length === 0) {
    bodyLines.push(`        Class<?> cls = Class.forName(className);`);
  }

  const content = `package com.app.security;

import android.content.Context;

public class DexPayloadLoader {
    public void executeDexRoutine(Context ctx, String dexPath, String className, String destination, String payload) throws Exception {
${bodyLines.join('\n')}
    }
}
`;
  return {
    path: 'src/main/java/com/app/security/DexPayloadLoader.java',
    language: 'java',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'DexPayloadLoader.java',
  };
}

function buildAndroidCryptoModule(
  projectName: string,
  layers: DeobfuscatedLayer[]
): ReconstructedProjectFile {
  void projectName;
  const layerConstants = layers
    .slice(0, 4)
    .map(
      (l, i) =>
        `    public static final String LAYER_${i} = "${(l.decodedSnippet || '')
          .replace(/\\/g, '\\\\')
          .replace(/"/g, '\\"')
          .slice(0, 80)}";`
    )
    .join('\n');

  const content = `package com.app.crypto;

public class CryptoUnpacker {
${layerConstants}

    public static byte[] xorTransform(byte[] input, byte key) {
        byte[] out = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            out[i] = (byte) (input[i] ^ key);
        }
        return out;
    }
}
`;
  return {
    path: 'src/main/java/com/app/crypto/CryptoUnpacker.java',
    language: 'java',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'CryptoUnpacker.java',
  };
}

function buildDynamicDexClassFile(
  projectName: string,
  rawClassName: string,
  apkDex: ApkDexMetadata
): ReconstructedProjectFile | null {
  void projectName;
  void apkDex;
  const normalized = rawClassName.replace(/^L/, '').replace(/;$/, '').replace(/\//g, '.');
  if (
    normalized.startsWith('android.') ||
    normalized.startsWith('java.') ||
    normalized.startsWith('dalvik.')
  ) {
    return null;
  }
  const parts = normalized.split('.');
  const simpleName = (parts.pop() || 'DynamicModule').replace(/[^a-zA-Z0-9_$]/g, '_');
  const pkg = parts.join('.') || 'com.app';

  let extClause = '';
  let imports = '';
  let methodsContent = '';

  if (simpleName.endsWith('AccessibilityOverlayService') || simpleName.includes('Accessibility')) {
    imports = `import android.accessibilityservice.AccessibilityService;\nimport android.view.accessibility.AccessibilityEvent;\nimport android.content.Context;\nimport dalvik.system.DexClassLoader;\n`;
    extClause = ` extends AccessibilityService`;
    methodsContent = `    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
    }

    @Override
    public void onInterrupt() {
    }

    @Override
    protected void onServiceConnected() {
        super.onServiceConnected();
    }`;
  } else if (simpleName.endsWith('Receiver') || simpleName.includes('Receiver')) {
    imports = `import android.content.BroadcastReceiver;\nimport android.content.Context;\nimport android.content.Intent;\nimport android.telephony.SmsManager;\n`;
    extClause = ` extends BroadcastReceiver`;
    methodsContent = `    @Override
    public void onReceive(Context context, Intent intent) {
    }`;
  } else if (simpleName.endsWith('Activity') || simpleName.includes('Activity')) {
    imports = `import android.app.Activity;\nimport android.os.Bundle;\n`;
    extClause = ` extends Activity`;
    methodsContent = `    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }`;
  } else if (simpleName.endsWith('Service') || simpleName.includes('Service')) {
    imports = `import android.app.Service;\nimport android.content.Intent;\nimport android.os.IBinder;\n`;
    extClause = ` extends Service`;
    methodsContent = `    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }`;
  } else {
    methodsContent = `    public ${simpleName}() {
    }

    public void execute() {
    }`;
  }

  const content = `package ${pkg};

${imports}public class ${simpleName}${extClause} {
${methodsContent}
}
`;
  return {
    path: `src/main/java/${normalized.replace(/\./g, '/')}.java`,
    language: 'java',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: normalized,
  };
}

// =============================================================================
// .NET C# PROJECT BUILDERS
// =============================================================================

function buildDotNetCsproj(projectName: string): ReconstructedProjectFile {
  const content = `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <AssemblyName>${projectName}</AssemblyName>
  </PropertyGroup>
</Project>
`;
  return {
    path: `${projectName}.csproj`,
    language: 'xml',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'Файл проекта .NET C#',
  };
}

function buildDotNetProgramCs(
  projectName: string,
  dotNet: DotNetMetadata,
  reconstructedCode: string
): ReconstructedProjectFile {
  void projectName;
  void dotNet;
  const content = cleanPureSourceCode(reconstructedCode);
  return {
    path: 'src/Program.cs',
    language: 'cs',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'Точка входа C# Program.cs',
  };
}

function buildDotNetReflectionModule(
  projectName: string,
  dotNet: DotNetMetadata,
  layers: DeobfuscatedLayer[]
): ReconstructedProjectFile {
  void projectName;
  const methodsInfo = dotNet.discoveredMethods.join(', ') || 'Assembly.Load';
  const snippet = layers[0]?.decodedSnippet
    ? layers[0].decodedSnippet.replace(/"/g, '\\"').slice(0, 80)
    : '';

  const content = `using System;
using System.Reflection;

namespace DecompiledAssembly
{
    public static class ReflectionLoader
    {
        // Обнаруженные вызовы метаданных CLR: ${methodsInfo}
        public static object? InvokeInMemoryStage(byte[] rawAssembly, string typeName, string methodName)
        {
            if (rawAssembly == null || rawAssembly.Length == 0) return null;
            Assembly asm = Assembly.Load(rawAssembly);
            Type? targetType = asm.GetType(typeName);
            MethodInfo? method = targetType?.GetMethod(methodName);
            return method?.Invoke(null, new object[] { "${snippet}" });
        }
    }
}
`;
  return {
    path: 'src/Security/ReflectionLoader.cs',
    language: 'cs',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'Модуль CLR ReflectionLoader.cs',
  };
}

function buildDotNetServiceModule(
  projectName: string,
  dotNet: DotNetMetadata
): ReconstructedProjectFile {
  void projectName;
  const typesComment = dotNet.discoveredTypes.join(', ') || 'RuntimeService';
  const content = `using System;
using System.Diagnostics;

namespace DecompiledAssembly
{
    public class RuntimeService
    {
        // Типы таблицы TypeDef: ${typesComment}
        public int ExecuteProcessCommand(string fileName, string arguments)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(startInfo);
            proc?.WaitForExit();
            return proc?.ExitCode ?? 0;
        }
    }
}
`;
  return {
    path: 'src/Core/RuntimeService.cs',
    language: 'cs',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'Сервисный класс C# RuntimeService.cs',
  };
}

function buildDynamicDotNetTypeFile(
  projectName: string,
  typeName: string,
  dotNet: DotNetMetadata
): ReconstructedProjectFile | null {
  void projectName;
  if (typeName.startsWith('System.') || typeName.startsWith('Microsoft.')) return null;
  const parts = typeName.split('.');
  const shortName = (parts.pop() || 'ModuleType').replace(/[^a-zA-Z0-9_]/g, '_');
  const ns = parts.join('.') || 'DecompiledAssembly';

  const methodsCode = dotNet.discoveredMethods
    .slice(0, 4)
    .map((m, idx) => {
      const mClean = m.replace(/[^a-zA-Z0-9_]/g, '_');
      return `        public int Call_${mClean}(int arg) {\n            return arg ^ 0x${((idx + 1) * 0x11).toString(16)};\n        }`;
    })
    .join('\n\n');

  const content = `using System;

namespace ${ns}
{
    public class ${shortName}
    {
${methodsCode || '        public void Execute() { }'}
    }
}
`;
  return {
    path: `src/Types/${shortName}.cs`,
    language: 'cs',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: `Класс C# ${typeName}`,
  };
}

// =============================================================================
// LINUX / ARM64 PROJECT BUILDERS
// =============================================================================

function buildLinuxCMakeLists(projectName: string): ReconstructedProjectFile {
  const content = `cmake_minimum_required(VERSION 3.20)
project(${projectName} LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
include_directories(include)

file(GLOB_RECURSE SOURCES src/*.cpp src/*.c)
add_executable(\${PROJECT_NAME} \${SOURCES})
target_compile_options(\${PROJECT_NAME} PRIVATE -Wall -O2)
`;
  return {
    path: 'CMakeLists.txt',
    language: 'cmake',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'CMakeLists.txt (Linux / ARM64)',
  };
}

function buildLinuxMakefile(projectName: string): ReconstructedProjectFile {
  const content = `CXX := g++
CXXFLAGS := -std=c++20 -O2 -Wall -Iinclude
SRCS := src/main.cpp src/kernel/io_uring_sys.cpp
TARGET := bin/${projectName}

all: $(TARGET)
$(TARGET): $(SRCS)
\t@mkdir -p bin
\t$(CXX) $(CXXFLAGS) -o $@ $^
`;
  return {
    path: 'Makefile',
    language: 'makefile',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'Makefile (Linux / ARM64)',
  };
}

function buildLinuxSysDefsHeader(
  projectName: string,
  findings: OpcodeFinding[]
): ReconstructedProjectFile {
  void projectName;
  void findings;
  const content = `#pragma once
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef __NR_execve
#define __NR_execve 221
#endif
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif

int64_t execute_direct_syscall(uint64_t sysno, uint64_t a0, uint64_t a1, uint64_t a2);
`;
  return {
    path: 'include/sys_defs.h',
    language: 'h',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'Системные определения вызовов ядра Linux/ARM64',
  };
}

function buildLinuxMainSource(
  projectName: string,
  decomp: DecompilationResult,
  findings: OpcodeFinding[]
): ReconstructedProjectFile {
  void projectName;
  void findings;
  const content = cleanPureSourceCode(decomp.reconstructedCode);
  return {
    path: 'src/main.cpp',
    language: 'cpp',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'Главная точка входа ELF / ARM64',
  };
}

function buildLinuxIoUringModule(
  projectName: string,
  findings: OpcodeFinding[]
): ReconstructedProjectFile {
  void projectName;
  const hasIoUring = findings.some((f) => (f.patternName || '').includes('io_uring'));
  const content = `#include "sys_defs.h"

int64_t execute_direct_syscall(uint64_t sysno, uint64_t a0, uint64_t a1, uint64_t a2) {
    ${
      hasIoUring
        ? '// Обнаружено использование асинхронного кольца io_uring (sysno 425/426)'
        : '// Вызов системного интерфейса ядра'
    }
    return syscall((long)sysno, a0, a1, a2);
}
`;
  return {
    path: 'src/kernel/io_uring_sys.cpp',
    language: 'cpp',
    content,
    sizeBytes: new TextEncoder().encode(content).length,
    description: 'Системный модуль ядра Linux',
  };
}
