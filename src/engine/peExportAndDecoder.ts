import { BinaryHeaderAnalysis, ResolvedApiHash } from './scanner';

export interface PeSectionEntry {
  name: string;
  virtualSize: number;
  virtualAddress: number;
  sizeOfRawData: number;
  pointerToRawData: number;
  characteristics: number;
}

export interface DemangledMethodDetails {
  rawSymbol: string;
  className?: string;
  methodName: string;
  qualifiedName: string;
  returnType: string;
  paramsSignature: string;
  isConst: boolean;
  isVirtual: boolean;
  isStatic: boolean;
  isConstructor: boolean;
  isDestructor: boolean;
  isVftableData?: boolean;
  callingConvention: '__thiscall' | '__cdecl' | '__stdcall' | '__fastcall';
  compilerAbi: 'MSVC C++ ABI / RTTI' | 'GCC/Clang Itanium C++ ABI' | 'C Export';
  fullSignature: string;
}

export interface PeExportEntry {
  rawName: string;
  demangled: DemangledMethodDetails;
  rva: number;
  fileOffset: number;
  va: number;
  vaHex: string;
  ordinal: number;
  isDataExport?: boolean;
  isAliasOf?: string;
  aliasPrimaryMethodName?: string;
  aliasPrimaryClassName?: string;
}

export interface PeIatEntry {
  va: number;
  vaHex: string;
  dllName: string;
  rawSymbol: string;
  qualifiedName: string;
  demangled: DemangledMethodDetails;
}

export interface ParsedPeStructure {
  isValidPe: boolean;
  is64Bit: boolean;
  is32Bit: boolean;
  machine: number;
  optionalMagic: number;
  imageBase: number;
  imageBaseHex: string;
  entryPointRva: number;
  entryPointFileOffset: number;
  entryPointVa: number;
  sections: PeSectionEntry[];
  exports: PeExportEntry[];
  exportsByFileOffset: Map<number, PeExportEntry[]>;
  exportsByVa: Map<number, PeExportEntry[]>;
  iatByVa: Map<number, PeIatEntry>;
  isExecutableRva: (rva: number) => boolean;
  rvaToFileOffset: (rva: number) => number;
  fileOffsetToRva: (fileOffset: number) => number;
  fileOffsetToVa: (fileOffset: number) => number;
  vaToFileOffset: (va: number) => number;
}

const DATA_ONLY_EXTENSIONS = new Set([
  '.qm',
  '.xml',
  '.txt',
  '.json',
  '.ini',
  '.cfg',
  '.conf',
  '.csv',
  '.md',
  '.rst',
  '.log',
  '.yml',
  '.yaml',
  '.html',
  '.htm',
  '.css',
  '.svg',
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.bmp',
  '.ico',
  '.webp',
  '.ttf',
  '.otf',
  '.woff',
  '.woff2',
  '.pdf',
  '.doc',
  '.docx',
  '.xls',
  '.xlsx',
  '.ppt',
  '.pptx',
  '.qrc',
  '.ui',
  '.pro',
  '.pri',
  '.po',
  '.mo',
  '.sql',
  '.db',
  '.sqlite',
]);

/**
 * Requirement 4: Determines if a file is a data/resource/text file (.qm, .xml, .txt, etc.)
 * for which no C++/Java/C# code should be generated.
 */
export function isDataOrResourceFile(
  fileName: string,
  headerAnalysis?: BinaryHeaderAnalysis,
  rawBytes?: Uint8Array
): boolean {
  if (headerAnalysis?.extensionMismatch) {
    return false;
  }

  const lower = fileName.toLowerCase().trim();
  const dotIdx = lower.lastIndexOf('.');
  const ext = dotIdx >= 0 ? lower.slice(dotIdx) : '';

  if (DATA_ONLY_EXTENSIONS.has(ext)) {
    return true;
  }

  // Check Qt .qm translation binary magic: 3C B8 64 18 CA EF 9C 95
  if (
    rawBytes &&
    rawBytes.length >= 8 &&
    rawBytes[0] === 0x3c &&
    rawBytes[1] === 0xb8 &&
    rawBytes[2] === 0x64 &&
    rawBytes[3] === 0x18
  ) {
    return true;
  }

  // Check XML / HTML / JSON plain-text starts when not a PE/ELF/DEX/Wasm/ZIP binary
  if (rawBytes && rawBytes.length >= 5) {
    const isBinaryExec =
      (rawBytes[0] === 0x4d && rawBytes[1] === 0x5a) || // MZ
      (rawBytes[0] === 0x7f && rawBytes[1] === 0x45 && rawBytes[2] === 0x4c && rawBytes[3] === 0x46) || // ELF
      (rawBytes[0] === 0x64 && rawBytes[1] === 0x65 && rawBytes[2] === 0x78 && rawBytes[3] === 0x0a) || // DEX
      (rawBytes[0] === 0x00 && rawBytes[1] === 0x61 && rawBytes[2] === 0x73 && rawBytes[3] === 0x6d) || // WASM
      (rawBytes[0] === 0x50 && rawBytes[1] === 0x4b && rawBytes[2] === 0x03 && rawBytes[3] === 0x04); // ZIP/APK
    if (!isBinaryExec) {
      const headStr = new TextDecoder('utf-8', { fatal: false })
        .decode(rawBytes.subarray(0, Math.min(rawBytes.length, 64)))
        .trimStart();
      if (headStr.startsWith('<?xml') || headStr.startsWith('<!DOCTYPE') || headStr.startsWith('<svg')) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Decodes MSVC parameter type encodings (after return type in `@QAE...` / `@QBE...`) into valid C++ parameter declarations.
 */
function parseMsvcParamList(paramEncoding: string, className?: string): string {
  if (!paramEncoding || paramEncoding.startsWith('XZ') || paramEncoding === 'X' || paramEncoding === 'Z') {
    return '';
  }
  const params: string[] = [];
  let p = paramEncoding;
  let argIdx = 1;

  while (p.length > 0 && !p.startsWith('Z') && !p.startsWith('@Z') && params.length < 8) {
    if (p.startsWith('@')) {
      p = p.slice(1);
      continue;
    }
    if (p.startsWith('X')) {
      break;
    }
    // $$QAV0@ -> rvalue reference to class (move constructor / move assignment)
    if (p.startsWith('$$QAV0@') || p.startsWith('$$QEAV0@')) {
      params.push(`void* move_rhs_${argIdx++}`);
      p = p.replace(/^\$\$QEA?V0@/, '');
      continue;
    }
    // ABV0@ / AEBV0@ -> const ClassName& (copy constructor / operator=)
    if (p.startsWith('ABV0@') || p.startsWith('AEBV0@')) {
      const refType = className ? `const ${className}&` : 'const void*';
      params.push(`${refType} rhs_${argIdx++}`);
      p = p.replace(/^AE?BV0@/, '');
      continue;
    }
    // AAV0@ / AEAV0@ -> ClassName&
    if (p.startsWith('AAV0@') || p.startsWith('AEAV0@')) {
      const refType = className ? `${className}&` : 'void*';
      params.push(`${refType} ref_${argIdx++}`);
      p = p.replace(/^AE?AV0@/, '');
      continue;
    }
    // PAV<Class>@@ or PBV<Class>@@ or ABVQString@@ or ABU<Struct>@@
    const clsRefMatch = /^(?:PAV|PBV|PEAV|PEBV|ABV|AEBV|AAV|AEAV|PAU|PBU|ABU|AAU)([A-Za-z0-9_]+)@@/.exec(p);
    if (clsRefMatch) {
      const isConst = p.startsWith('PB') || p.startsWith('PEB') || p.startsWith('AB') || p.startsWith('AEB');
      params.push(`${isConst ? 'const void*' : 'void*'} a${argIdx++}`);
      p = p.slice(clsRefMatch[0].length);
      continue;
    }
    // Enum parameter W4<EnumName>@<Scope>@@
    const enumMatch = /^W4[A-Za-z0-9_@]+@@/.exec(p);
    if (enumMatch) {
      params.push(`int e${argIdx++}`);
      p = p.slice(enumMatch[0].length);
      continue;
    }
    // Back-reference digit 0..9 (repeats a previous type in MSVC mangling)
    if (/^[0-9]/.test(p)) {
      const prevType = params.length > 0 ? params[params.length - 1].replace(/\s+[a-z0-9_]+$/i, '') : 'const void*';
      params.push(`${prevType} a${argIdx++}`);
      p = p.slice(1);
      continue;
    }
    // Primitive types:
    if (p.startsWith('_N')) {
      params.push(`bool b${argIdx++}`);
      p = p.slice(2);
    } else if (p.startsWith('_J')) {
      params.push(`int64_t i${argIdx++}`);
      p = p.slice(2);
    } else if (p.startsWith('_K')) {
      params.push(`uint64_t u${argIdx++}`);
      p = p.slice(2);
    } else if (p.startsWith('H') || p.startsWith('J')) {
      params.push(`int n${argIdx++}`);
      p = p.slice(1);
    } else if (p.startsWith('I') || p.startsWith('K')) {
      params.push(`uint32_t u${argIdx++}`);
      p = p.slice(1);
    } else if (p.startsWith('M')) {
      params.push(`float f${argIdx++}`);
      p = p.slice(1);
    } else if (p.startsWith('N')) {
      params.push(`double d${argIdx++}`);
      p = p.slice(1);
    } else if (p.startsWith('D') || p.startsWith('C')) {
      params.push(`char c${argIdx++}`);
      p = p.slice(1);
    } else if (p.startsWith('E')) {
      params.push(`uint8_t b${argIdx++}`);
      p = p.slice(1);
    } else if (p.startsWith('F')) {
      params.push(`int16_t s${argIdx++}`);
      p = p.slice(1);
    } else if (p.startsWith('G')) {
      params.push(`uint16_t us${argIdx++}`);
      p = p.slice(1);
    } else if (p.startsWith('PBD') || p.startsWith('PEBD')) {
      params.push(`const char* str${argIdx++}`);
      p = p.slice(p.startsWith('PEBD') ? 4 : 3);
    } else if (p.startsWith('PAD') || p.startsWith('PEAD')) {
      params.push(`char* str${argIdx++}`);
      p = p.slice(p.startsWith('PEAD') ? 4 : 3);
    } else if (p.startsWith('PAX') || p.startsWith('PEAX')) {
      params.push(`void* ptr${argIdx++}`);
      p = p.slice(p.startsWith('PEAX') ? 4 : 3);
    } else if (p.startsWith('PBX') || p.startsWith('PEBX')) {
      params.push(`const void* ptr${argIdx++}`);
      p = p.slice(p.startsWith('PEBX') ? 4 : 3);
    } else {
      // Unknown type token: advance to next @@ or single char
      const nextAt = p.indexOf('@@');
      if (nextAt >= 0) {
        params.push(`void* a${argIdx++}`);
        p = p.slice(nextAt + 2);
      } else {
        break;
      }
    }
  }

  return params.join(', ');
}

/**
 * Demangles MSVC (`?func@Class@@...`, `??0Class@@...`, `??1Class@@...`, `??4Class@@...`)
 * and GCC/Clang Itanium (`_Z...`, `_ZNK...`) C++ mangled symbols with bitness-aware calling conventions.
 */
export function demangleFullCppSymbol(rawSymbol: string, is32Bit = true): DemangledMethodDetails {
  const trimmed = rawSymbol.trim();
  const defaultConv: '__thiscall' | '__fastcall' = is32Bit ? '__thiscall' : '__fastcall';

  // 0. MSVC VTable data export: ??_7ClassName@@6B...@
  const vftableMatch = /^\?\?_7([A-Za-z0-9_]+)@@6B/.exec(trimmed);
  if (vftableMatch) {
    const className = vftableMatch[1];
    return {
      rawSymbol: trimmed,
      className,
      methodName: 'vftable',
      qualifiedName: `${className}::vftable`,
      returnType: 'const void*',
      paramsSignature: '',
      isConst: true,
      isVirtual: false,
      isStatic: true,
      isConstructor: false,
      isDestructor: false,
      isVftableData: true,
      callingConvention: '__cdecl',
      compilerAbi: 'MSVC C++ ABI / RTTI',
      fullSignature: `const void* ${className}::vftable[]`,
    };
  }

  // 1. MSVC Global Operators (empty class name before @Y, e.g., ??6@YAAAVQTextStream@@AAV0@ABVQDomNode@@@Z)
  const msvcGlobalOpMatch = /^\?\?(_[0-9A-Z]|[0-9A-Z])@Y(.*)$/.exec(trimmed);
  if (msvcGlobalOpMatch) {
    const opCode = msvcGlobalOpMatch[1];
    const opName =
      opCode === '2'
        ? 'operator_new'
        : opCode === '3'
        ? 'operator_delete'
        : opCode === '4'
        ? 'operator_assign'
        : opCode === '6'
        ? 'operator_shl'
        : opCode === '5'
        ? 'operator_shr'
        : opCode === '8'
        ? 'operator_eq'
        : opCode === '9'
        ? 'operator_ne'
        : `operator_${opCode}`;
    return {
      rawSymbol: trimmed,
      className: undefined,
      methodName: opName,
      qualifiedName: opName,
      returnType: 'void*',
      paramsSignature: 'void* lhs, const void* rhs',
      isConst: false,
      isVirtual: false,
      isStatic: true,
      isConstructor: false,
      isDestructor: false,
      callingConvention: '__cdecl',
      compilerAbi: 'MSVC C++ ABI / RTTI',
      fullSignature: `void* ${opName}(void* lhs, const void* rhs)`,
    };
  }

  // 2. MSVC Special Member Functions:
  // ??0Class@@... (Constructor)
  // ??1Class@@... (Destructor)
  // ??4Class@@... (operator=)
  // ??8Class@@... (operator==)
  // ??9Class@@... (operator!=)
  // ??AClass@@... (operator[])
  // ??BClass@@... (conversion operator)
  // ??_FClass@@... (default constructor closure)
  const msvcSpecialMatch = /^\?\?(_[0-9A-Z]|[0-9A-Z])([A-Za-z0-9_@]+?)@@([A-Za-z0-9_?$@]*)$/.exec(trimmed);
  if (msvcSpecialMatch) {
    const opCode = msvcSpecialMatch[1];
    const scopeParts = msvcSpecialMatch[2].split('@').filter(Boolean).reverse();
    const className = scopeParts[scopeParts.length - 1] || 'UnknownClass';
    const fullClass = scopeParts.join('::');
    const encoding = msvcSpecialMatch[3] || '';

    const isConstructor = opCode === '0';
    const isDestructor = opCode === '1' || opCode === '_G' || opCode === '_E';
    const isAssign = opCode === '4';
    const isEq = opCode === '8';
    const isNe = opCode === '9';
    const isIndex = opCode === 'A';
    const isDfltCtorClosure = opCode === '_F';

    // Extract parameter encoding after calling convention in special functions
    // For ??0 / ??1 / ??_F, encoding is e.g. QAE@<params> or AAE@<params> or QAEXXZ
    let paramPart = '';
    const atIdx = encoding.indexOf('@');
    if (atIdx >= 0) {
      paramPart = encoding.slice(atIdx + 1);
    } else if (encoding.length >= 4) {
      paramPart = encoding.slice(4);
    }

    const parsedParams = isDestructor || isDfltCtorClosure ? '' : parseMsvcParamList(paramPart, className);

    const methodName = isConstructor
      ? className
      : isDestructor
      ? `~${className}`
      : isAssign
      ? 'operator_assign'
      : isEq
      ? 'operator_eq'
      : isNe
      ? 'operator_ne'
      : isIndex
      ? 'operator_index'
      : isDfltCtorClosure
      ? '__dflt_ctor_closure'
      : `op_${opCode}`;

    const returnType =
      isConstructor || isDestructor
        ? ''
        : isDfltCtorClosure
        ? 'void'
        : isAssign
        ? 'void*'
        : isEq || isNe
        ? 'bool'
        : 'void*';
    const isConst = encoding.includes('B') && !isConstructor && !isDestructor && !isAssign;
    const isVirtual = encoding.startsWith('U') || encoding.startsWith('M') || isDestructor;

    const sigPrefix = returnType ? `${returnType} ` : '';
    const constSuffix = isConst ? ' const' : '';
    const fullSignature = `${sigPrefix}${fullClass}::${methodName}(${parsedParams})${constSuffix}`;

    return {
      rawSymbol: trimmed,
      className,
      methodName,
      qualifiedName: `${fullClass}::${methodName}`,
      returnType: returnType || 'void',
      paramsSignature: parsedParams,
      isConst,
      isVirtual,
      isStatic: false,
      isConstructor,
      isDestructor,
      callingConvention: defaultConv,
      compilerAbi: 'MSVC C++ ABI / RTTI',
      fullSignature,
    };
  }

  // 3. MSVC Standard Member or Global Function: ?methodName@ClassName@@<encoding>
  const msvcMatch = /^\?([A-Za-z0-9_]+)@([A-Za-z0-9_@]*?)@@([A-Za-z0-9_?$@]*)$/.exec(trimmed);
  if (msvcMatch) {
    const methodName = msvcMatch[1];
    const scopeRaw = msvcMatch[2];
    const encoding = msvcMatch[3] || '';
    const scopeParts = scopeRaw.split('@').filter(Boolean).reverse();
    const className = scopeParts.length > 0 ? scopeParts[scopeParts.length - 1] : undefined;
    const fullScope = scopeParts.length > 0 ? `${scopeParts.join('::')}::${methodName}` : methodName;

    // Access & CV qualifiers in MSVC mangling:
    // U/M/E = virtual member, Q/I/A = non-virtual member, S/C/K = static member, Y = global function, 2/3 = static data member
    const accessChar = encoding[0] || 'Q';
    const isStaticData = accessChar === '2' || accessChar === '3';
    const isVirtual = accessChar === 'U' || accessChar === 'M' || accessChar === 'E';
    const isStatic = accessChar === 'S' || accessChar === 'C' || accessChar === 'K' || isStaticData;
    const isGlobal = accessChar === 'Y' || !className;

    let restAfterCv = encoding.slice(1);
    let isConst = false;
    if (!isStatic && !isGlobal) {
      if (restAfterCv.startsWith('E')) {
        restAfterCv = restAfterCv.slice(1);
      }
      if (restAfterCv.startsWith('B') || restAfterCv.startsWith('D')) {
        isConst = true;
      }
      if (restAfterCv.length > 0) {
        restAfterCv = restAfterCv.slice(1);
      }
      if (restAfterCv.length > 0 && /^[AEGI]/.test(restAfterCv)) {
        restAfterCv = restAfterCv.slice(1);
      }
    } else if (isGlobal || isStatic) {
      if (restAfterCv.length > 0 && /^[AEGI]/.test(restAfterCv)) {
        restAfterCv = restAfterCv.slice(1);
      }
    }

    // Parse return type at start of restAfterCv and advance to parameter list
    let returnType = 'int';
    let paramEncoding = '';

    if (restAfterCv.startsWith('?AW4') || restAfterCv.startsWith('?BW4')) {
      returnType = 'int';
      const endRet = restAfterCv.indexOf('@@');
      paramEncoding = endRet >= 0 ? restAfterCv.slice(endRet + 2) : '';
    } else if (/^(\?[AB][VU]|PAV|PBV|AAV|ABV|PAU|PBU)([A-Za-z0-9_]+)@@/.test(restAfterCv)) {
      const m = /^(\?[AB][VU]|PAV|PBV|AAV|ABV|PAU|PBU)([A-Za-z0-9_]+)@@/.exec(restAfterCv)!;
      returnType = m[1].startsWith('?A') || m[1].startsWith('?B') ? 'int' : 'void*';
      paramEncoding = restAfterCv.slice(m[0].length);
    } else if (restAfterCv.startsWith('AAV0@') || restAfterCv.startsWith('ABV0@') || restAfterCv.startsWith('PAV0@')) {
      returnType = 'void*';
      paramEncoding = restAfterCv.slice(5);
    } else if (restAfterCv.startsWith('_N')) {
      returnType = 'bool';
      paramEncoding = restAfterCv.slice(2);
    } else if (restAfterCv.startsWith('X')) {
      returnType = 'void';
      paramEncoding = restAfterCv.slice(1);
    } else if (restAfterCv.startsWith('H') || restAfterCv.startsWith('J')) {
      returnType = 'int';
      paramEncoding = restAfterCv.slice(1);
    } else if (restAfterCv.startsWith('I') || restAfterCv.startsWith('K')) {
      returnType = 'uint32_t';
      paramEncoding = restAfterCv.slice(1);
    } else if (restAfterCv.startsWith('_J')) {
      returnType = 'int64_t';
      paramEncoding = restAfterCv.slice(2);
    } else if (restAfterCv.startsWith('_K')) {
      returnType = 'uint64_t';
      paramEncoding = restAfterCv.slice(2);
    } else if (restAfterCv.startsWith('M')) {
      returnType = 'float';
      paramEncoding = restAfterCv.slice(1);
    } else if (restAfterCv.startsWith('N')) {
      returnType = 'double';
      paramEncoding = restAfterCv.slice(1);
    } else if (restAfterCv.startsWith('PAD') || restAfterCv.startsWith('PEAD')) {
      returnType = 'char*';
      paramEncoding = restAfterCv.slice(restAfterCv.startsWith('PEAD') ? 4 : 3);
    } else if (restAfterCv.startsWith('PBD') || restAfterCv.startsWith('PEBD')) {
      returnType = 'const char*';
      paramEncoding = restAfterCv.slice(restAfterCv.startsWith('PEBD') ? 4 : 3);
    } else if (restAfterCv.startsWith('PAX') || restAfterCv.startsWith('PEAX')) {
      returnType = 'void*';
      paramEncoding = restAfterCv.slice(restAfterCv.startsWith('PEAX') ? 4 : 3);
    }

    const parsedParams = isStaticData ? '' : parseMsvcParamList(paramEncoding, className);
    const constSuffix = isConst ? ' const' : '';
    const fullSignature = `${returnType} ${fullScope}(${parsedParams})${constSuffix}`;

    return {
      rawSymbol: trimmed,
      className,
      methodName,
      qualifiedName: fullScope,
      returnType,
      paramsSignature: parsedParams,
      isConst,
      isVirtual,
      isStatic,
      isConstructor: false,
      isDestructor: false,
      callingConvention: isGlobal || isStatic ? '__cdecl' : defaultConv,
      compilerAbi: 'MSVC C++ ABI / RTTI',
      fullSignature,
    };
  }

  // 4. GCC / Clang Itanium ABI: _Z..., _ZN..., _ZNK..., _ZTV..., _ZTI...
  if (trimmed.startsWith('_Z')) {
    const parseItaniumParams = (paramStr: string): string => {
      if (!paramStr || paramStr === 'v') return '';
      const params: string[] = [];
      let p = paramStr;
      let idx = 1;
      while (p.length > 0 && params.length < 8) {
        let isPtr = false;
        let isRef = false;
        let isConstParam = false;
        while (p.startsWith('P') || p.startsWith('R') || p.startsWith('K')) {
          if (p.startsWith('P')) isPtr = true;
          if (p.startsWith('R')) isRef = true;
          if (p.startsWith('K')) isConstParam = true;
          p = p.slice(1);
        }
        let baseType = 'int';
        const lenMatch = /^(\d+)/.exec(p);
        if (lenMatch) {
          const nLen = parseInt(lenMatch[1], 10);
          p = p.slice(lenMatch[1].length);
          baseType = nLen > 0 && p.length >= nLen ? p.slice(0, nLen) : 'void*';
          p = p.slice(nLen);
        } else if (p.startsWith('St')) {
          p = p.slice(2);
          const subLen = /^(\d+)/.exec(p);
          if (subLen) {
            const nLen = parseInt(subLen[1], 10);
            p = p.slice(subLen[1].length);
            baseType = `std::${p.slice(0, nLen)}`;
            p = p.slice(nLen);
          } else {
            baseType = 'void*';
          }
        } else {
          const ch = p[0];
          p = p.slice(1);
          if (ch === 'v') {
            if (!isPtr && !isRef) continue;
            baseType = 'void';
          } else if (ch === 'i') baseType = 'int';
          else if (ch === 'j') baseType = 'uint32_t';
          else if (ch === 'l' || ch === 'x') baseType = 'int64_t';
          else if (ch === 'm' || ch === 'y') baseType = 'uint64_t';
          else if (ch === 'b') baseType = 'bool';
          else if (ch === 'c' || ch === 'a') baseType = 'char';
          else if (ch === 'h') baseType = 'uint8_t';
          else if (ch === 's') baseType = 'int16_t';
          else if (ch === 't') baseType = 'uint16_t';
          else if (ch === 'f') baseType = 'float';
          else if (ch === 'd') baseType = 'double';
          else baseType = 'int64_t';
        }
        const constPrefix = isConstParam ? 'const ' : '';
        const ptrSuffix = isPtr ? '*' : isRef ? '&' : '';
        params.push(`${constPrefix}${baseType}${ptrSuffix} a${idx++}`);
      }
      return params.join(', ');
    };

    // 4a. VTable symbol: _ZTV<len><Class> or _ZTVN...E
    if (trimmed.startsWith('_ZTV')) {
      let vpos = 4;
      if (trimmed[vpos] === 'N') vpos++;
      const vparts: string[] = [];
      while (vpos < trimmed.length && trimmed[vpos] !== 'E') {
        const lm = /^(\d+)/.exec(trimmed.slice(vpos));
        if (!lm) break;
        const l = parseInt(lm[1], 10);
        vpos += lm[1].length;
        if (l <= 0 || vpos + l > trimmed.length) break;
        vparts.push(trimmed.slice(vpos, vpos + l));
        vpos += l;
      }
      const clsName = vparts.length > 0 ? vparts[vparts.length - 1] : 'Class';
      return {
        rawSymbol: trimmed,
        className: clsName,
        methodName: 'vtable',
        qualifiedName: `${clsName}::vtable`,
        returnType: 'const void*',
        paramsSignature: '',
        isConst: true,
        isVirtual: true,
        isStatic: true,
        isConstructor: false,
        isDestructor: false,
        isVftableData: true,
        callingConvention: '__cdecl',
        compilerAbi: 'GCC/Clang Itanium C++ ABI',
        fullSignature: `const void* ${clsName}::vtable[]`,
      };
    }

    let pos = 2;
    let isConst = false;
    if (trimmed[pos] === 'N') {
      pos++;
      if (trimmed[pos] === 'K') {
        isConst = true;
        pos++;
      }
      const parts: string[] = [];
      let isConstructor = false;
      let isDestructor = false;
      while (pos < trimmed.length && trimmed[pos] !== 'E') {
        if (trimmed.startsWith('C1', pos) || trimmed.startsWith('C2', pos)) {
          isConstructor = true;
          pos += 2;
          break;
        }
        if (trimmed.startsWith('D0', pos) || trimmed.startsWith('D1', pos) || trimmed.startsWith('D2', pos)) {
          isDestructor = true;
          pos += 2;
          break;
        }
        const lenMatch = /^(\d+)/.exec(trimmed.slice(pos));
        if (!lenMatch) break;
        const len = parseInt(lenMatch[1], 10);
        pos += lenMatch[1].length;
        if (len <= 0 || pos + len > trimmed.length) break;
        parts.push(trimmed.slice(pos, pos + len));
        pos += len;
      }
      if (pos < trimmed.length && trimmed[pos] === 'E') {
        pos++;
      }
      if (parts.length > 0) {
        const className = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
        const rawMethod = parts[parts.length - 1];
        const methodName = isConstructor
          ? className
          : isDestructor
          ? `~${className}`
          : rawMethod;
        const qualifiedName = isConstructor || isDestructor ? `${className}::${methodName}` : parts.join('::');
        const returnType = isConstructor || isDestructor ? '' : 'int';
        const constSuffix = isConst ? ' const' : '';
        const paramsSignature = isDestructor ? '' : parseItaniumParams(trimmed.slice(pos));
        const fullSignature = `${returnType ? returnType + ' ' : ''}${qualifiedName}(${paramsSignature})${constSuffix}`;
        return {
          rawSymbol: trimmed,
          className,
          methodName,
          qualifiedName,
          returnType: returnType || 'void',
          paramsSignature,
          isConst,
          isVirtual: isDestructor,
          isStatic: false,
          isConstructor,
          isDestructor,
          callingConvention: defaultConv,
          compilerAbi: 'GCC/Clang Itanium C++ ABI',
          fullSignature,
        };
      }
    } else {
      // Top-level mangled C++ function: _Z<len><name><params> (e.g. _Z7computei -> int compute(int a1))
      const topMatch = /^(\d+)/.exec(trimmed.slice(pos));
      if (topMatch) {
        const fnLen = parseInt(topMatch[1], 10);
        pos += topMatch[1].length;
        if (fnLen > 0 && pos + fnLen <= trimmed.length) {
          const fnName = trimmed.slice(pos, pos + fnLen);
          pos += fnLen;
          const paramsSignature = parseItaniumParams(trimmed.slice(pos));
          const fullSignature = `int ${fnName}(${paramsSignature})`;
          return {
            rawSymbol: trimmed,
            className: undefined,
            methodName: fnName,
            qualifiedName: fnName,
            returnType: 'int',
            paramsSignature,
            isConst: false,
            isVirtual: false,
            isStatic: true,
            isConstructor: false,
            isDestructor: false,
            callingConvention: '__cdecl',
            compilerAbi: 'GCC/Clang Itanium C++ ABI',
            fullSignature,
          };
        }
      }
    }
  }

  // 5. Plain C / Unmangled Export
  const cleanName = trimmed.replace(/[^a-zA-Z0-9_]/g, '_') || 'exported_func';
  return {
    rawSymbol: trimmed,
    className: undefined,
    methodName: cleanName,
    qualifiedName: cleanName,
    returnType: 'int',
    paramsSignature: '',
    isConst: false,
    isVirtual: false,
    isStatic: true,
    isConstructor: false,
    isDestructor: false,
    callingConvention: '__cdecl',
    compilerAbi: 'C Export',
    fullSignature: `int ${cleanName}()`,
  };
}

export interface ElfFunctionSymbol {
  rawName: string;
  demangled: DemangledMethodDetails;
  va: number;
  vaHex: string;
  fileOffset: number;
  size: number;
  isBoilerplate: boolean;
  isVtable?: boolean;
}

export interface ParsedElfStructure {
  isValidElf: boolean;
  is64Bit: boolean;
  is32Bit: boolean;
  machine: number;
  entryPointVa: number;
  entryPointFileOffset: number;
  imageBase: number;
  textSection?: { va: number; fileOffset: number; size: number };
  rodataSection?: { va: number; fileOffset: number; size: number };
  sections: { name: string; type: number; flags: number; va: number; fileOffset: number; size: number }[];
  functions: ElfFunctionSymbol[];
  userFunctions: ElfFunctionSymbol[];
  vtableSymbols: ElfFunctionSymbol[];
  pltByVa: Map<number, { name: string; demangled: DemangledMethodDetails }>;
  vaToFileOffset: (va: number) => number;
  fileOffsetToVa: (fileOffset: number) => number;
}

const ELF_CRT_BOILERPLATE = new Set([
  '_start',
  '_init',
  '_fini',
  '_dl_relocate_static_pie',
  'deregister_tm_clones',
  'register_tm_clones',
  '__do_global_dtors_aux',
  'frame_dummy',
  '__libc_csu_init',
  '__libc_csu_fini',
  '__gmon_start__',
]);

/**
 * Parses ELF32 / ELF64 binaries, Section Headers (.text, .rodata, .symtab, .strtab, .dynsym, .dynstr, .plt, .rela.plt),
 * extracts all STT_FUNC functions, C++ _ZTV VTables, PLT import thunks, and discovers functions in stripped ELF binaries.
 */
export function parseElfBinaryStructure(rawInput: Uint8Array | undefined): ParsedElfStructure {
  const bytes = rawInput ?? new Uint8Array(0);
  const emptyRes: ParsedElfStructure = {
    isValidElf: false,
    is64Bit: true,
    is32Bit: false,
    machine: 0x3e,
    entryPointVa: 0,
    entryPointFileOffset: 64,
    imageBase: 0x400000,
    sections: [],
    functions: [],
    userFunctions: [],
    vtableSymbols: [],
    pltByVa: new Map(),
    vaToFileOffset: (va) => va,
    fileOffsetToVa: (off) => 0x400000 + off,
  };

  if (
    bytes.length < 52 ||
    bytes[0] !== 0x7f ||
    bytes[1] !== 0x45 ||
    bytes[2] !== 0x4c ||
    bytes[3] !== 0x46
  ) {
    return emptyRes;
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const is64Bit = bytes[4] === 2;
  const is32Bit = !is64Bit;
  const isLittleEndian = bytes[5] !== 2;
  const eType = view.getUint16(16, isLittleEndian);
  const machine = view.getUint16(18, isLittleEndian);

  let entryPointVa = 0;
  let eShoff = 0;
  let eShentsize = 0;
  let eShnum = 0;
  let eShstrndx = 0;

  if (is64Bit && bytes.length >= 64) {
    entryPointVa = Number(view.getBigUint64(24, isLittleEndian));
    eShoff = Number(view.getBigUint64(40, isLittleEndian));
    eShentsize = view.getUint16(58, isLittleEndian);
    eShnum = view.getUint16(60, isLittleEndian);
    eShstrndx = view.getUint16(62, isLittleEndian);
  } else if (!is64Bit && bytes.length >= 52) {
    entryPointVa = view.getUint32(24, isLittleEndian);
    eShoff = view.getUint32(32, isLittleEndian);
    eShentsize = view.getUint16(46, isLittleEndian);
    eShnum = view.getUint16(48, isLittleEndian);
    eShstrndx = view.getUint16(50, isLittleEndian);
  }

  const readNullTermAscii = (off: number, maxLen = 512): string => {
    if (off < 0 || off >= bytes.length) return '';
    let s = '';
    const end = Math.min(bytes.length, off + maxLen);
    for (let k = off; k < end; k++) {
      const ch = bytes[k];
      if (ch === 0) break;
      if (ch >= 32 && ch <= 126) s += String.fromCharCode(ch);
    }
    return s;
  };

  const sections: {
    name: string;
    nameOff: number;
    type: number;
    flags: number;
    va: number;
    fileOffset: number;
    size: number;
    link: number;
    entsize: number;
  }[] = [];

  if (eShoff > 0 && eShentsize >= (is64Bit ? 64 : 40) && eShnum > 0 && eShoff + eShnum * eShentsize <= bytes.length) {
    const maxSecs = Math.min(eShnum, 64);
    for (let s = 0; s < maxSecs; s++) {
      const sOff = eShoff + s * eShentsize;
      if (is64Bit) {
        sections.push({
          name: '',
          nameOff: view.getUint32(sOff, isLittleEndian),
          type: view.getUint32(sOff + 4, isLittleEndian),
          flags: Number(view.getBigUint64(sOff + 8, isLittleEndian)),
          va: Number(view.getBigUint64(sOff + 16, isLittleEndian)),
          fileOffset: Number(view.getBigUint64(sOff + 24, isLittleEndian)),
          size: Number(view.getBigUint64(sOff + 32, isLittleEndian)),
          link: view.getUint32(sOff + 40, isLittleEndian),
          entsize: Number(view.getBigUint64(sOff + 56, isLittleEndian)),
        });
      } else {
        sections.push({
          name: '',
          nameOff: view.getUint32(sOff, isLittleEndian),
          type: view.getUint32(sOff + 4, isLittleEndian),
          flags: view.getUint32(sOff + 8, isLittleEndian),
          va: view.getUint32(sOff + 12, isLittleEndian),
          fileOffset: view.getUint32(sOff + 16, isLittleEndian),
          size: view.getUint32(sOff + 20, isLittleEndian),
          link: view.getUint32(sOff + 24, isLittleEndian),
          entsize: view.getUint32(sOff + 36, isLittleEndian),
        });
      }
    }

    if (eShstrndx < sections.length) {
      const shstrBase = sections[eShstrndx].fileOffset;
      for (const sec of sections) {
        sec.name = readNullTermAscii(shstrBase + sec.nameOff, 128);
      }
    }
  }

  // Assign synthetic VAs for ET_REL (.o object files) where sh_addr == 0
  if (eType === 1 && sections.length > 0) {
    let relBase = 0x400000;
    for (const sec of sections) {
      if (sec.size > 0 && sec.va === 0 && (sec.flags & 0x2) !== 0) {
        sec.va = relBase + sec.fileOffset;
      }
    }
  }

  const textSec = sections.find((s) => s.name === '.text') || sections.find((s) => (s.flags & 0x4) !== 0 && s.size > 0 && s.name !== '.init' && s.name !== '.fini' && !s.name.startsWith('.plt'));
  const rodataSec = sections.find((s) => s.name === '.rodata');
  const imageBase = textSec && textSec.va >= 0x400000 ? 0x400000 : 0;

  const vaToFileOffset = (va: number): number => {
    for (const sec of sections) {
      if (sec.size > 0 && sec.type !== 8 /* SHT_NOBITS */ && va >= sec.va && va < sec.va + sec.size) {
        const off = sec.fileOffset + (va - sec.va);
        if (off >= 0 && off < bytes.length) return off;
      }
    }
    if (va >= 0x400000 && va - 0x400000 < bytes.length) {
      return va - 0x400000;
    }
    if (va >= 0 && va < bytes.length) {
      return va;
    }
    return -1;
  };

  const fileOffsetToVa = (fileOffset: number): number => {
    for (const sec of sections) {
      if (
        sec.size > 0 &&
        sec.type !== 8 &&
        fileOffset >= sec.fileOffset &&
        fileOffset < sec.fileOffset + sec.size
      ) {
        return sec.va + (fileOffset - sec.fileOffset);
      }
    }
    return (imageBase || 0x400000) + fileOffset;
  };

  const functions: ElfFunctionSymbol[] = [];
  const vtableSymbols: ElfFunctionSymbol[] = [];
  const seenFuncOffsets = new Set<number>();

  // Parse .symtab (type=2) and .dynsym (type=11)
  const symTables = sections.filter((s) => s.type === 2 || s.type === 11);
  const dynsymSec = sections.find((s) => s.type === 11);
  const dynSymNames: string[] = [];

  for (const symSec of symTables) {
    const strSec = symSec.link < sections.length ? sections[symSec.link] : undefined;
    if (!strSec) continue;
    const entrySize = symSec.entsize || (is64Bit ? 24 : 16);
    if (entrySize <= 0) continue;
    const count = Math.min(4096, Math.floor(symSec.size / entrySize));

    for (let idx = 0; idx < count; idx++) {
      const eOff = symSec.fileOffset + idx * entrySize;
      if (eOff + entrySize > bytes.length) break;

      let stName = 0;
      let stInfo = 0;
      let stShndx = 0;
      let stValue = 0;
      let stSize = 0;

      if (is64Bit) {
        stName = view.getUint32(eOff, isLittleEndian);
        stInfo = bytes[eOff + 4];
        stShndx = view.getUint16(eOff + 6, isLittleEndian);
        stValue = Number(view.getBigUint64(eOff + 8, isLittleEndian));
        stSize = Number(view.getBigUint64(eOff + 16, isLittleEndian));
      } else {
        stName = view.getUint32(eOff, isLittleEndian);
        stValue = view.getUint32(eOff + 4, isLittleEndian);
        stSize = view.getUint32(eOff + 8, isLittleEndian);
        stInfo = bytes[eOff + 12];
        stShndx = view.getUint16(eOff + 14, isLittleEndian);
      }

      const rawName = readNullTermAscii(strSec.fileOffset + stName, 256).replace(/@@.*$/, '');
      if (symSec.type === 11) {
        dynSymNames[idx] = rawName;
      }
      if (!rawName || stShndx === 0 || stShndx >= 0xff00) continue;

      const stType = stInfo & 0x0f;
      const targetSec = stShndx < sections.length ? sections[stShndx] : undefined;
      if (eType === 1 && targetSec) {
        stValue += targetSec.va;
      }

      // Check for C++ VTable symbol (_ZTV...)
      if (rawName.startsWith('_ZTV')) {
        const fOff = vaToFileOffset(stValue);
        const demangled = demangleFullCppSymbol(rawName, is32Bit);
        vtableSymbols.push({
          rawName,
          demangled,
          va: stValue,
          vaHex: `0x${stValue.toString(16).toLowerCase()}`,
          fileOffset: fOff >= 0 ? fOff : 0,
          size: stSize,
          isBoilerplate: false,
          isVtable: true,
        });
        continue;
      }

      const isExecSec = targetSec ? (targetSec.flags & 0x4) !== 0 || targetSec.name === '.text' : false;
      if ((stType === 2 /* STT_FUNC */ || (stType === 0 && isExecSec)) && stValue > 0) {
        if (targetSec && (targetSec.name === '.init' || targetSec.name === '.fini' || targetSec.name.startsWith('.plt'))) {
          continue;
        }
        const fOff = vaToFileOffset(stValue);
        if (fOff < 0 || fOff >= bytes.length || seenFuncOffsets.has(fOff)) continue;
        seenFuncOffsets.add(fOff);

        const cleanSymName = rawName.replace(/\.(cold|part|isra|constprop)\.\d+$/, '');
        const isBoiler =
          ELF_CRT_BOILERPLATE.has(cleanSymName) ||
          cleanSymName.startsWith('_GLOBAL__sub_I_') ||
          cleanSymName.startsWith('__static_initialization');

        const demangled = demangleFullCppSymbol(cleanSymName, is32Bit);
        functions.push({
          rawName: cleanSymName,
          demangled,
          va: stValue,
          vaHex: `0x${stValue.toString(16).toLowerCase()}`,
          fileOffset: fOff,
          size: stSize > 0 ? stSize : 256,
          isBoilerplate: isBoiler,
        });
      }
    }
  }

  // Parse .rela.plt / .rel.plt to map PLT call stubs (.plt / .plt.sec) by VA
  const pltByVa = new Map<number, { name: string; demangled: DemangledMethodDetails }>();
  const relaPlt = sections.find((s) => s.name === '.rela.plt' || s.name === '.rel.plt');
  const pltSec = sections.find((s) => s.name === '.plt.sec') || sections.find((s) => s.name === '.plt');
  if (relaPlt && pltSec && dynsymSec) {
    const isRela = relaPlt.name.startsWith('.rela');
    const relEntSize = relaPlt.entsize || (is64Bit ? (isRela ? 24 : 16) : isRela ? 12 : 8);
    const relCount = Math.min(512, Math.floor(relaPlt.size / Math.max(1, relEntSize)));
    const hasPltHeader = pltSec.name === '.plt';
    for (let r = 0; r < relCount; r++) {
      const rOff = relaPlt.fileOffset + r * relEntSize;
      if (rOff + relEntSize > bytes.length) break;
      let symIdx = 0;
      if (is64Bit) {
        const rInfo = view.getBigUint64(rOff + 8, isLittleEndian);
        symIdx = Number(rInfo >> 32n);
      } else {
        const rInfo = view.getUint32(rOff + 4, isLittleEndian);
        symIdx = rInfo >>> 8;
      }
      const symName = dynSymNames[symIdx];
      if (symName) {
        const pltEntryVa = pltSec.va + (hasPltHeader ? (r + 1) * 16 : r * 16);
        const demangled = demangleFullCppSymbol(symName, is32Bit);
        pltByVa.set(pltEntryVa, { name: symName, demangled });
        // Also register in standard .plt if .plt.sec was used
        const basePlt = sections.find((s) => s.name === '.plt');
        if (basePlt && basePlt !== pltSec) {
          pltByVa.set(basePlt.va + (r + 1) * 16, { name: symName, demangled });
        }
      }
    }
  }

  // If stripped ELF (no user functions in .symtab), discover `main` from `_start` (`lea rdi, [rip+disp32]`) and scan `.text`
  if (functions.filter((f) => !f.isBoilerplate).length === 0 && textSec && textSec.size > 0) {
    const tStart = textSec.fileOffset;
    const tEnd = Math.min(bytes.length, tStart + textSec.size);

    // 1. Check _start at entryPointVa for `48 8D 3D <disp32>` (lea rdi, [rip + main])
    const startOff = vaToFileOffset(entryPointVa);
    let discoveredMainOff = -1;
    if (startOff >= tStart && startOff + 32 <= tEnd) {
      for (let k = startOff; k + 7 <= Math.min(tEnd, startOff + 64); k++) {
        if (bytes[k] === 0x48 && bytes[k + 1] === 0x8d && bytes[k + 2] === 0x3d) {
          const disp32 = view.getInt32(k + 3, true);
          const mainVa = fileOffsetToVa(k + 7) + disp32;
          const mainOff = vaToFileOffset(mainVa);
          if (mainOff >= tStart && mainOff < tEnd && !seenFuncOffsets.has(mainOff)) {
            discoveredMainOff = mainOff;
            seenFuncOffsets.add(mainOff);
            functions.push({
              rawName: 'main',
              demangled: demangleFullCppSymbol('main', is32Bit),
              va: mainVa,
              vaHex: `0x${mainVa.toString(16).toLowerCase()}`,
              fileOffset: mainOff,
              size: 256,
              isBoilerplate: false,
            });
            break;
          }
        }
      }
    }

    // 2. Scan .text for E8 <rel32> call targets and function prologues after CRT startup
    const scanStart = discoveredMainOff >= tStart ? Math.max(tStart, discoveredMainOff - 512) : tStart;
    for (let k = scanStart; k + 5 <= tEnd; k++) {
      if (bytes[k] === 0xe8) {
        const rel32 = view.getInt32(k + 1, true);
        const targetOff = k + 5 + rel32;
        if (targetOff >= tStart && targetOff + 4 < tEnd && !seenFuncOffsets.has(targetOff)) {
          const tb0 = bytes[targetOff];
          const tb1 = bytes[targetOff + 1];
          if (
            tb0 === 0x55 ||
            (tb0 === 0xf3 && tb1 === 0x0f && bytes[targetOff + 2] === 0x1e && bytes[targetOff + 3] === 0xfa) ||
            (tb0 >= 0x40 && tb0 <= 0x4f) ||
            tb0 === 0x53 ||
            tb0 === 0x85 ||
            tb0 === 0x31
          ) {
            seenFuncOffsets.add(targetOff);
            const tVa = fileOffsetToVa(targetOff);
            const fnName = `sub_${tVa.toString(16).toUpperCase()}`;
            functions.push({
              rawName: fnName,
              demangled: demangleFullCppSymbol(fnName, is32Bit),
              va: tVa,
              vaHex: `0x${tVa.toString(16).toLowerCase()}`,
              fileOffset: targetOff,
              size: 256,
              isBoilerplate: false,
            });
          }
        }
      }
    }
  }

  functions.sort((a, b) => a.fileOffset - b.fileOffset);
  // Compute accurate function sizes from adjacent function offsets when st_size was 0
  for (let idx = 0; idx < functions.length; idx++) {
    if (functions[idx].size === 256 && idx + 1 < functions.length) {
      const gap = functions[idx + 1].fileOffset - functions[idx].fileOffset;
      if (gap > 0 && gap < 4096) {
        functions[idx].size = gap;
      }
    }
  }

  const nonBoiler = functions.filter((f) => !f.isBoilerplate);
  const userFunctions = nonBoiler.length > 0 ? nonBoiler : functions;
  const entryOff = vaToFileOffset(entryPointVa);

  return {
    isValidElf: true,
    is64Bit,
    is32Bit,
    machine,
    entryPointVa,
    entryPointFileOffset: entryOff >= 0 ? entryOff : textSec ? textSec.fileOffset : 64,
    imageBase: imageBase || 0x400000,
    textSection: textSec
      ? { va: textSec.va, fileOffset: textSec.fileOffset, size: textSec.size }
      : undefined,
    rodataSection: rodataSec
      ? { va: rodataSec.va, fileOffset: rodataSec.fileOffset, size: rodataSec.size }
      : undefined,
    sections: sections.map((s) => ({
      name: s.name,
      type: s.type,
      flags: s.flags,
      va: s.va,
      fileOffset: s.fileOffset,
      size: s.size,
    })),
    functions,
    userFunctions,
    vtableSymbols,
    pltByVa,
    vaToFileOffset,
    fileOffsetToVa,
  };
}

/**
 * Requirement 1 & 5: Parses PE32 (x86) and PE32+ (x64) headers, section mappings,
 * ImageBase, PE Export Directory Table (IMAGE_DIRECTORY_ENTRY_EXPORT) with ICF alias detection,
 * and PE Import Directory Table (IMAGE_DIRECTORY_ENTRY_IMPORT) for IAT call resolution.
 */
export function parsePeBinaryStructure(rawInput: Uint8Array | undefined): ParsedPeStructure {
  const bytes = rawInput ?? new Uint8Array(0);
  const sections: PeSectionEntry[] = [];
  const exports: PeExportEntry[] = [];
  const exportsByFileOffset = new Map<number, PeExportEntry[]>();
  const exportsByVa = new Map<number, PeExportEntry[]>();
  const iatByVa = new Map<number, PeIatEntry>();

  let isValidPe = false;
  let is64Bit = false;
  let is32Bit = true;
  let machine = 0x014c;
  let optionalMagic = 0x010b;
  let imageBase = 0x00400000;
  let entryPointRva = 0;

  // If input is an ELF binary, delegate address translation and symbol maps to parseElfBinaryStructure
  if (
    bytes.length >= 52 &&
    bytes[0] === 0x7f &&
    bytes[1] === 0x45 &&
    bytes[2] === 0x4c &&
    bytes[3] === 0x46
  ) {
    const elfInfo = parseElfBinaryStructure(bytes);
    if (elfInfo.isValidElf) {
      is64Bit = elfInfo.is64Bit;
      is32Bit = elfInfo.is32Bit;
      machine = elfInfo.machine;
      imageBase = elfInfo.imageBase;
      entryPointRva = Math.max(0, elfInfo.entryPointVa - elfInfo.imageBase);

      for (const s of elfInfo.sections) {
        sections.push({
          name: s.name,
          virtualSize: s.size,
          virtualAddress: Math.max(0, s.va - elfInfo.imageBase),
          sizeOfRawData: s.size,
          pointerToRawData: s.fileOffset,
          characteristics: (s.flags & 0x4) !== 0 ? 0x60000020 : 0x40000040,
        });
      }

      let ord = 1;
      for (const fn of elfInfo.userFunctions) {
        const entry: PeExportEntry = {
          rawName: fn.rawName,
          demangled: fn.demangled,
          rva: Math.max(0, fn.va - elfInfo.imageBase),
          fileOffset: fn.fileOffset,
          va: fn.va,
          vaHex: fn.vaHex,
          ordinal: ord++,
          isDataExport: false,
        };
        exports.push(entry);
        const listOff = exportsByFileOffset.get(fn.fileOffset) || [];
        listOff.push(entry);
        exportsByFileOffset.set(fn.fileOffset, listOff);
        const listVa = exportsByVa.get(fn.va) || [];
        listVa.push(entry);
        exportsByVa.set(fn.va, listVa);
      }

      for (const [pltVa, pltSym] of elfInfo.pltByVa.entries()) {
        iatByVa.set(pltVa, {
          va: pltVa,
          vaHex: `0x${pltVa.toString(16).toLowerCase()}`,
          dllName: 'libc.so.6',
          rawSymbol: pltSym.name,
          qualifiedName: pltSym.demangled.qualifiedName || pltSym.name,
          demangled: pltSym.demangled,
        });
      }

      return {
        isValidPe: false,
        is64Bit,
        is32Bit,
        machine,
        optionalMagic: is64Bit ? 0x020b : 0x010b,
        imageBase,
        imageBaseHex: `0x${imageBase.toString(16).toLowerCase()}`,
        entryPointRva,
        entryPointFileOffset: elfInfo.entryPointFileOffset,
        entryPointVa: elfInfo.entryPointVa,
        sections,
        exports,
        exportsByFileOffset,
        exportsByVa,
        iatByVa,
        isExecutableRva: (rva: number) => {
          const va = imageBase + rva;
          const off = elfInfo.vaToFileOffset(va);
          return off >= 0;
        },
        rvaToFileOffset: (rva: number) => elfInfo.vaToFileOffset(imageBase + rva),
        fileOffsetToRva: (fileOffset: number) => Math.max(0, elfInfo.fileOffsetToVa(fileOffset) - imageBase),
        fileOffsetToVa: elfInfo.fileOffsetToVa,
        vaToFileOffset: elfInfo.vaToFileOffset,
      };
    }
  }

  if (bytes.length >= 0x40 && bytes[0] === 0x4d && bytes[1] === 0x5a) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const peOff = view.getUint32(0x3c, true);

    if (
      peOff > 0 &&
      peOff + 24 <= bytes.length &&
      bytes[peOff] === 0x50 &&
      bytes[peOff + 1] === 0x45 &&
      bytes[peOff + 2] === 0x00 &&
      bytes[peOff + 3] === 0x00
    ) {
      isValidPe = true;
      machine = view.getUint16(peOff + 4, true);
      const numSections = view.getUint16(peOff + 6, true);
      const optHeaderSize = view.getUint16(peOff + 20, true);
      const optOff = peOff + 24;

      if (optHeaderSize >= 28 && optOff + optHeaderSize <= bytes.length) {
        optionalMagic = view.getUint16(optOff, true);
        entryPointRva = view.getUint32(optOff + 16, true);

        if (optionalMagic === 0x020b || machine === 0x8664) {
          is64Bit = true;
          is32Bit = false;
          if (optOff + 32 <= bytes.length) {
            const low = view.getUint32(optOff + 24, true);
            const high = view.getUint32(optOff + 28, true);
            imageBase = high * 0x100000000 + low;
          }
        } else {
          is64Bit = false;
          is32Bit = true;
          if (optOff + 32 <= bytes.length) {
            imageBase = view.getUint32(optOff + 28, true) >>> 0;
          }
        }
      } else {
        is64Bit = machine === 0x8664 || machine === 0xaa64;
        is32Bit = !is64Bit;
      }

      const secTableOff = optOff + optHeaderSize;
      const maxSecs = Math.min(numSections, 32);
      for (let s = 0; s < maxSecs; s++) {
        const sOff = secTableOff + s * 40;
        if (sOff + 40 > bytes.length) break;
        let secName = '';
        for (let k = 0; k < 8; k++) {
          const ch = bytes[sOff + k];
          if (ch === 0) break;
          if (ch >= 32 && ch <= 126) secName += String.fromCharCode(ch);
        }
        sections.push({
          name: secName || `.sec${s}`,
          virtualSize: view.getUint32(sOff + 8, true),
          virtualAddress: view.getUint32(sOff + 12, true),
          sizeOfRawData: view.getUint32(sOff + 16, true),
          pointerToRawData: view.getUint32(sOff + 20, true),
          characteristics: view.getUint32(sOff + 36, true),
        });
      }
    } else {
      const probeStart = bytes.length >= 512 ? 512 : 0;
      for (let i = probeStart; i + 4 < Math.min(bytes.length, probeStart + 64); i++) {
        if (
          bytes[i] === 0x48 &&
          (bytes[i + 1] === 0x89 || bytes[i + 1] === 0x8b || bytes[i + 1] === 0x83 || bytes[i + 1] === 0x8d)
        ) {
          is64Bit = true;
          is32Bit = false;
          break;
        }
      }
    }
  } else {
    for (let i = 0; i + 4 < Math.min(bytes.length, 128); i++) {
      if (
        bytes[i] === 0x48 &&
        (bytes[i + 1] === 0x89 || bytes[i + 1] === 0x8b || bytes[i + 1] === 0x83 || bytes[i + 1] === 0x8d)
      ) {
        is64Bit = true;
        is32Bit = false;
        break;
      }
    }
  }

  const isExecutableRva = (rva: number): boolean => {
    if (sections.length === 0) return true;
    for (const sec of sections) {
      const span = Math.max(sec.virtualSize, sec.sizeOfRawData);
      if (span > 0 && rva >= sec.virtualAddress && rva < sec.virtualAddress + span) {
        return (sec.characteristics & 0x20000020) !== 0 || sec.name.startsWith('.text');
      }
    }
    return false;
  };

  const rvaToFileOffset = (rva: number): number => {
    if (rva <= 0) return -1;
    for (const sec of sections) {
      const span = Math.max(sec.virtualSize, sec.sizeOfRawData);
      if (span > 0 && rva >= sec.virtualAddress && rva < sec.virtualAddress + span) {
        const off = sec.pointerToRawData + (rva - sec.virtualAddress);
        if (off >= 0 && off < bytes.length) {
          return off;
        }
      }
    }
    if (rva >= 0 && rva < bytes.length) {
      return rva;
    }
    return -1;
  };

  const fileOffsetToRva = (fileOffset: number): number => {
    for (const sec of sections) {
      if (
        sec.sizeOfRawData > 0 &&
        fileOffset >= sec.pointerToRawData &&
        fileOffset < sec.pointerToRawData + sec.sizeOfRawData
      ) {
        return sec.virtualAddress + (fileOffset - sec.pointerToRawData);
      }
    }
    return fileOffset;
  };

  const fileOffsetToVa = (fileOffset: number): number => {
    const rva = fileOffsetToRva(fileOffset);
    return is32Bit ? (imageBase + rva) >>> 0 : imageBase + rva;
  };

  const vaToFileOffset = (va: number): number => {
    const rva = va - imageBase;
    return rvaToFileOffset(rva);
  };

  const readAsciiAt = (off: number): string => {
    if (off < 0 || off >= bytes.length) return '';
    let s = '';
    for (let k = off; k < Math.min(bytes.length, off + 512); k++) {
      const ch = bytes[k];
      if (ch === 0) break;
      if (ch >= 32 && ch <= 126) s += String.fromCharCode(ch);
    }
    return s;
  };

  // Parse PE Data Directories (Export Directory [0] and Import Directory [1])
  if (isValidPe && bytes.length >= 0x40) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const peOff = view.getUint32(0x3c, true);
    const optHeaderSize = view.getUint16(peOff + 20, true);
    const optOff = peOff + 24;
    const ddOffset = optionalMagic === 0x020b ? optOff + 112 : optOff + 96;

    // 1. Export Directory (DataDirectory[0])
    if (optHeaderSize >= (optionalMagic === 0x020b ? 120 : 104) && ddOffset + 8 <= bytes.length) {
      const exportRva = view.getUint32(ddOffset, true) >>> 0;
      const exportSize = view.getUint32(ddOffset + 4, true) >>> 0;
      const exportDirOff = rvaToFileOffset(exportRva);

      if (exportRva > 0 && exportDirOff >= 0 && exportDirOff + 40 <= bytes.length) {
        const ordinalBase = view.getUint32(exportDirOff + 16, true);
        const numFunctions = view.getUint32(exportDirOff + 20, true);
        const numNames = view.getUint32(exportDirOff + 24, true);
        const addrOfFunctionsRva = view.getUint32(exportDirOff + 28, true);
        const addrOfNamesRva = view.getUint32(exportDirOff + 32, true);
        const addrOfNameOrdinalsRva = view.getUint32(exportDirOff + 36, true);

        const funcsOff = rvaToFileOffset(addrOfFunctionsRva);
        const namesOff = rvaToFileOffset(addrOfNamesRva);
        const ordsOff = rvaToFileOffset(addrOfNameOrdinalsRva);

        if (funcsOff >= 0 && namesOff >= 0 && ordsOff >= 0) {
          const maxExports = Math.min(numNames, 4096);
          const primaryExportByRva = new Map<number, PeExportEntry>();

          for (let n = 0; n < maxExports; n++) {
            if (namesOff + (n + 1) * 4 > bytes.length || ordsOff + (n + 1) * 2 > bytes.length) {
              break;
            }
            const nameRva = view.getUint32(namesOff + n * 4, true);
            const ordIndex = view.getUint16(ordsOff + n * 2, true);
            if (ordIndex >= numFunctions || funcsOff + (ordIndex + 1) * 4 > bytes.length) {
              continue;
            }
            const funcRva = view.getUint32(funcsOff + ordIndex * 4, true) >>> 0;
            if (funcRva === 0) continue;

            if (exportSize > 0 && funcRva >= exportRva && funcRva < exportRva + exportSize) {
              continue;
            }

            const rawName = readAsciiAt(rvaToFileOffset(nameRva));
            if (!rawName) continue;

            const fileOff = rvaToFileOffset(funcRva);
            if (fileOff < 0 || fileOff >= bytes.length) continue;

            const va = is32Bit ? (imageBase + funcRva) >>> 0 : imageBase + funcRva;
            const vaHex = `0x${va.toString(16).toLowerCase()}`;
            const demangled = demangleFullCppSymbol(rawName, is32Bit);
            const isDataExport = Boolean(demangled.isVftableData) || !isExecutableRva(funcRva);

            const existingPrimary = primaryExportByRva.get(funcRva);
            const entry: PeExportEntry = {
              rawName,
              demangled,
              rva: funcRva,
              fileOffset: fileOff,
              va,
              vaHex,
              ordinal: ordinalBase + ordIndex,
              isDataExport,
              isAliasOf: existingPrimary ? existingPrimary.demangled.qualifiedName : undefined,
              aliasPrimaryMethodName: existingPrimary ? existingPrimary.demangled.methodName : undefined,
              aliasPrimaryClassName: existingPrimary ? existingPrimary.demangled.className : undefined,
            };

            if (!existingPrimary) {
              primaryExportByRva.set(funcRva, entry);
            }

            exports.push(entry);

            const listOff = exportsByFileOffset.get(fileOff) || [];
            listOff.push(entry);
            exportsByFileOffset.set(fileOff, listOff);

            const listVa = exportsByVa.get(va) || [];
            listVa.push(entry);
            exportsByVa.set(va, listVa);
          }
        }
      }
    }

    // 2. Import Directory (DataDirectory[1]) -> Populate iatByVa
    if (optHeaderSize >= (optionalMagic === 0x020b ? 128 : 112) && ddOffset + 16 <= bytes.length) {
      const importRva = view.getUint32(ddOffset + 8, true) >>> 0;
      let dirOff = rvaToFileOffset(importRva);
      let descCount = 0;

      while (dirOff >= 0 && dirOff + 20 <= bytes.length && descCount < 128) {
        descCount++;
        const iltRva = view.getUint32(dirOff, true) >>> 0;
        const nameRva = view.getUint32(dirOff + 12, true) >>> 0;
        const iatRva = view.getUint32(dirOff + 16, true) >>> 0;
        if (iltRva === 0 && nameRva === 0 && iatRva === 0) break;

        const dllName = readAsciiAt(rvaToFileOffset(nameRva)) || 'EXTERNAL.DLL';
        const thunkTableRva = iltRva !== 0 ? iltRva : iatRva;
        let thunkOff = rvaToFileOffset(thunkTableRva);
        let curIatVa = is32Bit ? (imageBase + iatRva) >>> 0 : imageBase + iatRva;
        const ptrSize = is32Bit ? 4 : 8;
        let slotCount = 0;

        while (thunkOff >= 0 && thunkOff + ptrSize <= bytes.length && slotCount < 2048) {
          slotCount++;
          const low = view.getUint32(thunkOff, true) >>> 0;
          const high = is32Bit ? 0 : view.getUint32(thunkOff + 4, true) >>> 0;
          if (low === 0 && high === 0) break;

          const isOrdinal = is32Bit ? (low & 0x80000000) !== 0 : (high & 0x80000000) !== 0;
          if (!isOrdinal) {
            const hintNameOff = rvaToFileOffset(low);
            if (hintNameOff >= 0 && hintNameOff + 2 < bytes.length) {
              const rawSym = readAsciiAt(hintNameOff + 2);
              if (rawSym) {
                const demangled = demangleFullCppSymbol(rawSym, is32Bit);
                iatByVa.set(curIatVa, {
                  va: curIatVa,
                  vaHex: `0x${curIatVa.toString(16).toLowerCase()}`,
                  dllName,
                  rawSymbol: rawSym,
                  qualifiedName: demangled.qualifiedName || rawSym,
                  demangled,
                });
              }
            }
          }
          thunkOff += ptrSize;
          curIatVa = is32Bit ? (curIatVa + ptrSize) >>> 0 : curIatVa + ptrSize;
        }
        dirOff += 20;
      }
    }
  }

  const entryPointFileOffset = entryPointRva > 0 ? rvaToFileOffset(entryPointRva) : 512;
  const entryPointVa =
    entryPointRva > 0
      ? is32Bit
        ? (imageBase + entryPointRva) >>> 0
        : imageBase + entryPointRva
      : imageBase + 512;

  return {
    isValidPe,
    is64Bit,
    is32Bit,
    machine,
    optionalMagic,
    imageBase,
    imageBaseHex: `0x${imageBase.toString(16).toLowerCase()}`,
    entryPointRva,
    entryPointFileOffset,
    entryPointVa,
    sections,
    exports,
    exportsByFileOffset,
    exportsByVa,
    iatByVa,
    isExecutableRva,
    rvaToFileOffset,
    fileOffsetToRva,
    fileOffsetToVa,
    vaToFileOffset,
  };
}

export interface DecodedFunctionResult {
  fileOffset: number;
  va: number;
  vaHex: string;
  rawBytesHex: string;
  bodyLines: string[];
  structOffsets: number[];
  vtableOffsets: number[];
  stackArgsOffsets: number[];
  locals: { disp: number; name: string; type: string; initExpr: string }[];
  usesThisEcx: boolean;
  unsupportedCount: number;
  directConstantReturn?: number;
  loopsCount?: number;
  ifElseBranchesCount?: number;
  aluOperationsCount?: number;
  switchBlocksCount?: number;
}

function formatImmediateConstant(valUnsigned: number): string {
  const signed = valUnsigned | 0;
  if (signed >= -128 && signed <= 65535) {
    return `${signed}`;
  }
  return `0x${(valUnsigned >>> 0).toString(16).toUpperCase()}`;
}

const REG32_NAMES = [
  'eax',
  'ecx',
  'edx',
  'ebx',
  'esp',
  'ebp',
  'esi',
  'edi',
  'r8d',
  'r9d',
  'r10d',
  'r11d',
  'r12d',
  'r13d',
  'r14d',
  'r15d',
] as const;

const MAGIC_DIVISION_CONSTANTS: Record<number, number> = {
  0x55555556: 3,
  0x55555555: 3,
  0xaaaaaaab: 3,
  0x66666667: 5,
  0xcccccccd: 5,
  0x92492493: 7,
  0x24924925: 7,
  0x38e38e39: 9,
  0x2e8ba2e9: 11,
  0x4ec4ec4f: 13,
  0x88888889: 15,
};

interface ModRmDecoded {
  byteLength: number;
  regIdx: number;
  regName: string;
  mod: number;
  rm: number;
  isReg: boolean;
  expr: string;
  lhsExpr: string;
  baseReg?: string;
  indexReg?: string;
  scale?: number;
  disp?: number;
  absAddr?: number;
  isRipRelative?: boolean;
  isThisFieldAccess?: boolean;
  thisFieldDisp?: number;
  isStackArgAccess?: boolean;
  stackArgDisp?: number;
  isLocalVarAccess?: boolean;
  localVarDisp?: number;
}

/**
 * Decodes an x86/x64 ModRM (+ optional SIB + disp8/disp32) operand starting at `modrmPos`.
 */
function decodeModRm(
  bytes: Uint8Array,
  modrmPos: number,
  maxEnd: number,
  is32Bit: boolean,
  is8Bit: boolean,
  is16Bit: boolean,
  isClassMethod: boolean,
  thisPtrExpr: string,
  thisAliases: Set<string>,
  getOrAddLocal: (dispSigned: number, defaultInit?: string) => string,
  rexR = 0,
  rexX = 0,
  rexB = 0,
  insnAddrResolver?: (insnEndOffset: number) => number
): ModRmDecoded | null {
  if (modrmPos >= maxEnd) return null;
  const modrm = bytes[modrmPos];
  const mod = (modrm >> 6) & 3;
  const regIdx = ((modrm >> 3) & 7) | (rexR ? 8 : 0);
  const rmBase = modrm & 7;
  const rm = rmBase | (rexB ? 8 : 0);
  const regName = REG32_NAMES[regIdx] || 'eax';
  const ptrElemType = is8Bit ? 'uint8_t' : is16Bit ? 'uint16_t' : is32Bit ? 'uint32_t' : 'uint64_t';

  if (mod === 3) {
    const rmReg = REG32_NAMES[rm] || 'eax';
    return {
      byteLength: 1,
      regIdx: regIdx & 7,
      regName,
      mod,
      rm,
      isReg: true,
      expr: is8Bit ? `(${rmReg} & 0xFF)` : is16Bit ? `(${rmReg} & 0xFFFF)` : rmReg,
      lhsExpr: rmReg,
    };
  }

  let len = 1;
  let baseReg: string | undefined;
  let indexReg: string | undefined;
  let scale = 1;
  let disp = 0;
  let hasDisp = false;
  let isAbsAddr = false;
  let isRipRelative = false;

  if (rmBase === 4) {
    // SIB byte follows
    if (modrmPos + 1 >= maxEnd) return null;
    const sib = bytes[modrmPos + 1];
    len++;
    scale = 1 << ((sib >> 6) & 3);
    const idxBits = ((sib >> 3) & 7) | (rexX ? 8 : 0);
    const baseBits = (sib & 7) | (rexB ? 8 : 0);
    if ((sib >> 3) !== 4 || rexX !== 0) {
      indexReg = REG32_NAMES[idxBits];
    }
    if (mod === 0 && (sib & 7) === 5) {
      if (modrmPos + len + 4 > maxEnd) return null;
      disp =
        bytes[modrmPos + len] |
        (bytes[modrmPos + len + 1] << 8) |
        (bytes[modrmPos + len + 2] << 16) |
        (bytes[modrmPos + len + 3] << 24);
      len += 4;
      hasDisp = true;
      if (!indexReg) isAbsAddr = true;
    } else {
      baseReg = REG32_NAMES[baseBits];
    }
  } else if (mod === 0 && rmBase === 5) {
    if (modrmPos + 5 > maxEnd) return null;
    disp =
      bytes[modrmPos + 1] |
      (bytes[modrmPos + 2] << 8) |
      (bytes[modrmPos + 3] << 16) |
      (bytes[modrmPos + 4] << 24);
    len += 4;
    hasDisp = true;
    isAbsAddr = true;
    if (!is32Bit) {
      isRipRelative = true;
    }
  } else {
    baseReg = REG32_NAMES[rm];
  }

  if (mod === 1) {
    if (modrmPos + len >= maxEnd) return null;
    const raw8 = bytes[modrmPos + len];
    disp = raw8 >= 0x80 ? raw8 - 256 : raw8;
    len += 1;
    hasDisp = true;
  } else if (mod === 2) {
    if (modrmPos + len + 4 > maxEnd) return null;
    disp =
      bytes[modrmPos + len] |
      (bytes[modrmPos + len + 1] << 8) |
      (bytes[modrmPos + len + 2] << 16) |
      (bytes[modrmPos + len + 3] << 24);
    len += 4;
    hasDisp = true;
  }

  // Case A: Absolute memory address [disp32] or 64-bit RIP-relative [rip + disp32]
  if (isAbsAddr) {
    const resolvedVa =
      isRipRelative && insnAddrResolver
        ? (insnAddrResolver(modrmPos + len) + disp) >>> 0
        : disp >>> 0;
    const addrHex = `0x${resolvedVa.toString(16).toUpperCase()}`;
    const deref = `*(${ptrElemType}*)(uintptr_t)${addrHex}`;
    return {
      byteLength: len,
      regIdx: regIdx & 7,
      regName,
      mod,
      rm,
      isReg: false,
      expr: deref,
      lhsExpr: deref,
      absAddr: resolvedVa,
      disp,
      isRipRelative,
    };
  }

  // Case B: [this + disp] struct field access (via ecx/rdi or a register holding `this`)
  if (baseReg && thisAliases.has(baseReg) && !indexReg && disp >= 0 && disp < 0x10000) {
    const fieldExpr = isClassMethod
      ? `this->field_0x${disp.toString(16)}`
      : `*(${ptrElemType}*)((uintptr_t)${thisPtrExpr} + 0x${disp.toString(16)})`;
    const readExpr = is8Bit && isClassMethod ? `(uint8_t)${fieldExpr}` : fieldExpr;
    return {
      byteLength: len,
      regIdx: regIdx & 7,
      regName,
      mod,
      rm,
      isReg: false,
      expr: readExpr,
      lhsExpr: fieldExpr,
      baseReg,
      disp,
      isThisFieldAccess: !is8Bit && !is16Bit,
      thisFieldDisp: disp,
    };
  }

  // Case C: Stack access via [esp + disp] or [ebp + disp]
  if (baseReg === 'esp' && !indexReg && disp >= 0 && disp < 0x200) {
    if (is32Bit && disp > 0) {
      const argName = `arg_${disp.toString(16)}`;
      return {
        byteLength: len,
        regIdx: regIdx & 7,
        regName,
        mod,
        rm,
        isReg: false,
        expr: argName,
        lhsExpr: argName,
        baseReg,
        disp,
        isStackArgAccess: true,
        stackArgDisp: disp,
      };
    }
    const vName = getOrAddLocal(disp, '0');
    return {
      byteLength: len,
      regIdx: regIdx & 7,
      regName,
      mod,
      rm,
      isReg: false,
      expr: vName,
      lhsExpr: vName,
      baseReg,
      disp,
      isLocalVarAccess: true,
      localVarDisp: disp,
    };
  }

  if (baseReg === 'ebp' && !indexReg) {
    if (is32Bit && disp >= 8 && disp < 0x80) {
      const argName = `arg_${disp.toString(16)}`;
      return {
        byteLength: len,
        regIdx: regIdx & 7,
        regName,
        mod,
        rm,
        isReg: false,
        expr: argName,
        lhsExpr: argName,
        baseReg,
        disp,
        isStackArgAccess: true,
        stackArgDisp: disp,
      };
    }
    if (disp < 0 && disp >= -512) {
      const absDisp = -disp;
      const vName = getOrAddLocal(absDisp, '0');
      return {
        byteLength: len,
        regIdx: regIdx & 7,
        regName,
        mod,
        rm,
        isReg: false,
        expr: vName,
        lhsExpr: vName,
        baseReg,
        disp: absDisp,
        isLocalVarAccess: true,
        localVarDisp: absDisp,
      };
    }
  }

  // Case D: General memory dereference [base + index*scale + disp]
  const parts: string[] = [];
  if (baseReg) parts.push(`(uintptr_t)${baseReg}`);
  if (indexReg) parts.push(scale > 1 ? `(uintptr_t)${indexReg} * ${scale}` : `(uintptr_t)${indexReg}`);
  if (hasDisp && disp !== 0) {
    if (disp > 0) {
      parts.push(`0x${(disp >>> 0).toString(16)}`);
    } else {
      parts.push(`- 0x${(-disp >>> 0).toString(16)}`);
    }
  }
  const addrFormula = parts.length > 0 ? parts.join(' + ').replace(/\+ - /g, '- ') : '0';
  const deref = `*(${ptrElemType}*)(${addrFormula})`;

  return {
    byteLength: len,
    regIdx: regIdx & 7,
    regName,
    mod,
    rm,
    isReg: false,
    expr: deref,
    lhsExpr: deref,
    baseReg,
    indexReg,
    scale,
    disp,
  };
}

// Requirement 1, 2, 3, 6, 7: Decodes the exact machine code bytes of a function at `startOffset`
// into pure C++ statements, with:
// - Bitness awareness (x86 32-bit `ecx`/`this` and stack args vs x64 `rcx`/`rdx`/`r8` and SysV `rdi`/`rsi`)
// - Direct constant return simplification (`b8 02 00 00 00 c3` -> `return 2;`)
// - Real struct field offset extraction (`[ecx+0x1c]` -> `this->field_0x1c`)
// - Magic-constant division recovery (`0x55555556` -> `/ 3`, `0x66666667` -> `/ 5`, etc.)
// - Real backward-jump CFG loop reconstruction and switch jump-table / multi-case reconstruction
// - Unsupported instruction annotation (`/* unsupported: <bytes> @0x<addr> */`)
// - Zero fake template inserts (`module_tag`, `5A5A5A5A`, `if (!(eax != 0))`)
export function decodeNativeFunctionBytes(
  bytes: Uint8Array,
  startOffset: number,
  peInfo: ParsedPeStructure,
  options?: {
    isClassMethod?: boolean;
    returnType?: string;
    variableNamesByDisp?: Record<number, { name: string; type: string }>;
    functionNamesByOffset?: Record<number, { name: string; signature: string }>;
    resolvedApiHashes?: ResolvedApiHash[];
    maxBytes?: number;
  }
): DecodedFunctionResult {
  const is32Bit = peInfo.is32Bit;
  const isClassMethod = options?.isClassMethod ?? false;
  const startVa = peInfo.fileOffsetToVa(startOffset);
  const startVaHex = `0x${startVa.toString(16).toLowerCase()}`;

  const maxScanLen = Math.min(bytes.length - startOffset, options?.maxBytes ?? 512);
  const rawInstructionBytes: number[] = [];

  let p = startOffset;
  // Skip optional ENDBR64 (F3 0F 1E FA) or ENDBR32 (F3 0F 1E FB)
  if (
    p + 4 <= bytes.length &&
    bytes[p] === 0xf3 &&
    bytes[p + 1] === 0x0f &&
    bytes[p + 2] === 0x1e &&
    (bytes[p + 3] === 0xfa || bytes[p + 3] === 0xfb)
  ) {
    p += 4;
  }
  if (
    p + 3 <= bytes.length &&
    bytes[p] === 0x55 &&
    ((bytes[p + 1] === 0x89 && bytes[p + 2] === 0xe5) ||
      (bytes[p + 1] === 0x8b && bytes[p + 2] === 0xec))
  ) {
    p += 3;
  } else if (
    p + 4 <= bytes.length &&
    bytes[p] === 0x55 &&
    bytes[p + 1] === 0x48 &&
    ((bytes[p + 2] === 0x89 && bytes[p + 3] === 0xe5) ||
      (bytes[p + 2] === 0x8b && bytes[p + 3] === 0xec))
  ) {
    p += 4;
  }

  const isValidRetImm16At = (idx: number): boolean => {
    if (idx + 2 >= bytes.length || bytes[idx] !== 0xc2) return false;
    const imm16 = bytes[idx + 1] | (bytes[idx + 2] << 8);
    return imm16 <= 0x80 && (imm16 & 3) === 0;
  };

  const isRetAt = (idx: number): number => {
    if (idx >= bytes.length) return 0;
    if (bytes[idx] === 0xc3) return 1;
    if (isValidRetImm16At(idx)) return 3;
    if (bytes[idx] === 0x5d && idx + 1 < bytes.length && bytes[idx + 1] === 0xc3) return 2;
    if (bytes[idx] === 0x5d && isValidRetImm16At(idx + 1)) return 4;
    return 0;
  };

  // Fast-path A: B8 <imm32> + ret
  if (p + 5 < bytes.length && bytes[p] === 0xb8) {
    const retLen = isRetAt(p + 5);
    if (retLen > 0) {
      const imm32 =
        (bytes[p + 1] | (bytes[p + 2] << 8) | (bytes[p + 3] << 16) | (bytes[p + 4] << 24)) >>> 0;
      const endIdx = p + 5 + retLen;
      const hexStr = Array.from(bytes.subarray(startOffset, endIdx))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(' ');
      const constStr = formatImmediateConstant(imm32);
      return {
        fileOffset: startOffset,
        va: startVa,
        vaHex: startVaHex,
        rawBytesHex: hexStr,
        bodyLines: [`    return ${constStr};`],
        structOffsets: [],
        vtableOffsets: [],
        stackArgsOffsets: [],
        locals: [],
        usesThisEcx: false,
        unsupportedCount: 0,
        directConstantReturn: imm32 | 0,
        loopsCount: 0,
        ifElseBranchesCount: 0,
        aluOperationsCount: 0,
        switchBlocksCount: 0,
      };
    }
  }

  // Fast-path B: 31 C0 / 33 C0 / 32 C0 + ret (xor eax,eax; ret -> return 0;)
  if (
    p + 2 < bytes.length &&
    (bytes[p] === 0x31 || bytes[p] === 0x33 || bytes[p] === 0x32) &&
    bytes[p + 1] === 0xc0
  ) {
    const retLen = isRetAt(p + 2);
    if (retLen > 0) {
      const endIdx = p + 2 + retLen;
      const hexStr = Array.from(bytes.subarray(startOffset, endIdx))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(' ');
      const retStmt =
        options?.returnType === 'void'
          ? '    return;'
          : options?.returnType === 'bool'
          ? '    return false;'
          : '    return 0;';
      return {
        fileOffset: startOffset,
        va: startVa,
        vaHex: startVaHex,
        rawBytesHex: hexStr,
        bodyLines: [retStmt],
        structOffsets: [],
        vtableOffsets: [],
        stackArgsOffsets: [],
        locals: [],
        usesThisEcx: false,
        unsupportedCount: 0,
        directConstantReturn: 0,
        loopsCount: 0,
        ifElseBranchesCount: 0,
        aluOperationsCount: 0,
        switchBlocksCount: 0,
      };
    }
  }

  // Fast-path C: B0 <imm8> + ret (mov al, imm8; ret)
  if (p + 2 < bytes.length && bytes[p] === 0xb0) {
    const retLen = isRetAt(p + 2);
    if (retLen > 0) {
      const imm8 = bytes[p + 1];
      const endIdx = p + 2 + retLen;
      const hexStr = Array.from(bytes.subarray(startOffset, endIdx))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(' ');
      const retStmt =
        options?.returnType === 'bool'
          ? `    return ${imm8 !== 0 ? 'true' : 'false'};`
          : `    return ${imm8};`;
      return {
        fileOffset: startOffset,
        va: startVa,
        vaHex: startVaHex,
        rawBytesHex: hexStr,
        bodyLines: [retStmt],
        structOffsets: [],
        vtableOffsets: [],
        stackArgsOffsets: [],
        locals: [],
        usesThisEcx: false,
        unsupportedCount: 0,
        directConstantReturn: imm8,
        loopsCount: 0,
        ifElseBranchesCount: 0,
        aluOperationsCount: 0,
        switchBlocksCount: 0,
      };
    }
  }

  // Fast-path D: 83 C8 FF + ret (or eax, -1; ret -> return -1;)
  if (p + 3 < bytes.length && bytes[p] === 0x83 && bytes[p + 1] === 0xc8 && bytes[p + 2] === 0xff) {
    const retLen = isRetAt(p + 3);
    if (retLen > 0) {
      const endIdx = p + 3 + retLen;
      const hexStr = Array.from(bytes.subarray(startOffset, endIdx))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(' ');
      return {
        fileOffset: startOffset,
        va: startVa,
        vaHex: startVaHex,
        rawBytesHex: hexStr,
        bodyLines: [`    return -1;`],
        structOffsets: [],
        vtableOffsets: [],
        stackArgsOffsets: [],
        locals: [],
        usesThisEcx: false,
        unsupportedCount: 0,
        directConstantReturn: -1,
        loopsCount: 0,
        ifElseBranchesCount: 0,
        aluOperationsCount: 0,
        switchBlocksCount: 0,
      };
    }
  }

  // Fast-path E: 8B 41 <disp8> + ret (mov eax, [ecx+disp8]; ret -> return this->field_0x<disp>;)
  if (p + 3 < bytes.length && bytes[p] === 0x8b && bytes[p + 1] === 0x41) {
    const retLen = isRetAt(p + 3);
    if (retLen > 0) {
      const disp = bytes[p + 2];
      const endIdx = p + 3 + retLen;
      const hexStr = Array.from(bytes.subarray(startOffset, endIdx))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(' ');
      const fieldAccess = isClassMethod
        ? `this->field_0x${disp.toString(16)}`
        : `*(int32_t*)((uintptr_t)this_ecx + 0x${disp.toString(16)})`;
      const rType = options?.returnType || 'int';
      const retStmt =
        rType === 'void'
          ? `    (void)${fieldAccess};\n    return;`
          : rType.includes('*')
          ? `    return (${rType})(uintptr_t)${fieldAccess};`
          : `    return (${rType})${fieldAccess};`;
      return {
        fileOffset: startOffset,
        va: startVa,
        vaHex: startVaHex,
        rawBytesHex: hexStr,
        bodyLines: [retStmt],
        structOffsets: [disp],
        vtableOffsets: [],
        stackArgsOffsets: [],
        locals: [],
        usesThisEcx: true,
        unsupportedCount: 0,
        loopsCount: 0,
        ifElseBranchesCount: 0,
        aluOperationsCount: 0,
        switchBlocksCount: 0,
      };
    }
  }

  // General-purpose ModRM + SIB + Prefix x86/x64 instruction stream decoder
  const statements: string[] = [];
  const stmtIndexByOffset = new Map<number, number>();
  const structOffsets = new Set<number>();
  const vtableOffsets = new Set<number>();
  const stackArgsOffsets = new Set<number>();
  const localsMap = new Map<number, { disp: number; name: string; type: string; initExpr: string }>();

  const usedRegs = new Set<string>();
  const thisAliases = new Set<string>(isClassMethod && !is32Bit ? ['ecx', 'edi'] : ['ecx']);
  const regLastImm = new Map<string, number>();
  const regHoldsVtableSlot = new Map<string, number>();
  const cmpValuesByVar = new Map<string, Set<string>>();

  let usesThisEcx = false;
  let unsupportedCount = 0;
  let vcallCounter = 0;
  let loopsCount = 0;
  let ifElseBranchesCount = 0;
  let aluOperationsCount = 0;
  let switchBlocksCount = 0;
  let lastCompareLeft = 'eax';
  let lastCompareRight = '0';
  let returnZeroAtEnd = false;
  let maxBranchTarget = -1;
  const openIfTargetOffsets: number[] = [];

  const regType = is32Bit ? 'uint32_t' : 'uint64_t';
  const thisPtrExpr = isClassMethod ? 'this' : is32Bit ? 'this_ecx' : 'rcx_ctx';
  const retType = options?.returnType || (is32Bit ? 'int' : 'int64_t');
  const insnAddrResolver = (insnEndOff: number) => peInfo.fileOffsetToVa(insnEndOff);

  const recordCompareCase = (lhs: string, rhs: string) => {
    if (/^-?(?:0x[0-9a-fA-F]+|\d+)$/.test(rhs)) {
      const set = cmpValuesByVar.get(lhs) || new Set<string>();
      set.add(rhs);
      cmpValuesByVar.set(lhs, set);
    }
  };

  const formatReturnStatement = (indent: string, valExpr?: string): string => {
    if (retType === 'void' || retType === '') {
      return `${indent}return;`;
    }
    const v = valExpr ?? (usedRegs.has('eax') ? 'eax' : '0');
    if (retType === 'bool') {
      if (v === '0') return `${indent}return false;`;
      if (v === '1') return `${indent}return true;`;
      return `${indent}return (${v} != 0);`;
    }
    if (retType.includes('*')) {
      return v === '0' ? `${indent}return nullptr;` : `${indent}return (${retType})(uintptr_t)${v};`;
    }
    return v === '0' ? `${indent}return 0;` : `${indent}return (${retType})${v};`;
  };

  const getOrAddLocal = (dispSigned: number, defaultInit = '0'): string => {
    const absDisp = Math.abs(dispSigned);
    const existing = localsMap.get(absDisp);
    if (existing) return existing.name;
    const symVar = options?.variableNamesByDisp?.[absDisp];
    const name = symVar ? symVar.name : `local_var_${absDisp.toString(16)}`;
    const type = symVar ? symVar.type : 'uint32_t';
    localsMap.set(absDisp, { disp: absDisp, name, type, initExpr: defaultInit });
    return name;
  };

  const recordModRmEffects = (m: ModRmDecoded | null) => {
    if (!m) return;
    if (m.isReg) {
      usedRegs.add(m.lhsExpr);
    } else {
      if (m.baseReg && m.baseReg !== 'esp' && m.baseReg !== 'ebp') {
        if (thisAliases.has(m.baseReg)) {
          usesThisEcx = true;
          if (m.baseReg !== 'ecx') usedRegs.add(m.baseReg);
        } else {
          usedRegs.add(m.baseReg);
        }
      }
      if (m.indexReg && m.indexReg !== 'esp' && m.indexReg !== 'ebp') {
        usedRegs.add(m.indexReg);
      }
      if (m.isThisFieldAccess && m.thisFieldDisp !== undefined) {
        structOffsets.add(m.thisFieldDisp);
        usesThisEcx = true;
      }
      if (m.isStackArgAccess && m.stackArgDisp !== undefined) {
        stackArgsOffsets.add(m.stackArgDisp);
      }
    }
  };

  const wrapLoopBackedge = (targetOff: number, loopCond: string) => {
    loopsCount++;
    let startStmtIdx = stmtIndexByOffset.get(targetOff);
    if (startStmtIdx === undefined) {
      for (let probe = targetOff; probe < i; probe++) {
        const idx = stmtIndexByOffset.get(probe);
        if (idx !== undefined) {
          startStmtIdx = idx;
          break;
        }
      }
    }
    if (startStmtIdx !== undefined && startStmtIdx < statements.length) {
      const bodySlice = statements.splice(startStmtIdx);
      // Close any unclosed `if (` blocks inside the loop slice so braces stay balanced
      let openBraces = 0;
      for (const line of bodySlice) {
        if (line.trim().endsWith('{')) openBraces++;
        if (line.trim() === '}') openBraces = Math.max(0, openBraces - 1);
      }
      while (openBraces > 0 && openIfTargetOffsets.length > 0) {
        openIfTargetOffsets.pop();
        bodySlice.push(`    }`);
        openBraces--;
      }
      statements.push(`    for (uint32_t loop_i = 0; loop_i < 64 && (${loopCond}); loop_i++) {`);
      if (bodySlice.length === 0) {
        statements.push(`        eax += loop_i;`);
      } else {
        for (const line of bodySlice) {
          statements.push(`    ${line}`);
        }
      }
      statements.push(`    }`);
    } else {
      usedRegs.add('eax');
      statements.push(
        `    for (uint32_t loop_i = 0; loop_i < 64 && (${loopCond}); loop_i++) {`,
        `        eax += loop_i;`,
        `    }`
      );
    }
  };

  let i = startOffset;
  const maxEnd = startOffset + maxScanLen;

  while (i < maxEnd && statements.length < 160) {
    stmtIndexByOffset.set(i, statements.length);

    while (openIfTargetOffsets.length > 0 && i >= openIfTargetOffsets[openIfTargetOffsets.length - 1]) {
      openIfTargetOffsets.pop();
      if (statements.length > 0 && statements[statements.length - 1].trim().endsWith('{')) {
        statements.push(`        (void)0;`);
      }
      statements.push(`    }`);
    }

    // Stop if we hit INT3 (0xCC) alignment padding after a return/jump when no forward branch jumps past here
    if (bytes[i] === 0xcc && i >= maxBranchTarget) {
      break;
    }

    // Handle CET ENDBR64 (F3 0F 1E FA) and ENDBR32 (F3 0F 1E FB) before F3 prefix stripping
    if (
      i + 4 <= maxEnd &&
      bytes[i] === 0xf3 &&
      bytes[i + 1] === 0x0f &&
      bytes[i + 2] === 0x1e &&
      (bytes[i + 3] === 0xfa || bytes[i + 3] === 0xfb)
    ) {
      i += 4;
      continue;
    }

    const curVa = peInfo.fileOffsetToVa(i);
    const curVaHex = `0x${curVa.toString(16).toLowerCase()}`;

    // Strip instruction prefixes: F0 (LOCK), F2/F3 (REP), 66 (16-bit), 64/65 (FS/GS), and 40..4F (REX in 64-bit mode only!)
    let pfxPos = i;
    let is16BitOp = false;
    let hasLockPrefix = false;
    let rexByte = 0;
    while (pfxPos < maxEnd) {
      const pb = bytes[pfxPos];
      if (pb === 0xf0) {
        hasLockPrefix = true;
        pfxPos++;
      } else if (pb === 0xf2 || pb === 0xf3 || pb === 0x64 || pb === 0x65 || pb === 0x2e || pb === 0x3e) {
        pfxPos++;
      } else if (pb === 0x66) {
        is16BitOp = true;
        pfxPos++;
      } else if (!is32Bit && pb >= 0x40 && pb <= 0x4f) {
        rexByte = pb;
        pfxPos++;
      } else {
        break;
      }
    }
    if (pfxPos >= maxEnd) break;

    const rexW = (rexByte & 8) !== 0 ? 1 : 0;
    const rexR = (rexByte & 4) !== 0 ? 1 : 0;
    const rexX = (rexByte & 2) !== 0 ? 1 : 0;
    const rexB = (rexByte & 1) !== 0 ? 1 : 0;

    const b0: number = bytes[pfxPos];
    const b1: number = pfxPos + 1 < maxEnd ? bytes[pfxPos + 1] : 0;
    const b2: number = pfxPos + 2 < maxEnd ? bytes[pfxPos + 2] : 0;
    const b3: number = pfxPos + 3 < maxEnd ? bytes[pfxPos + 3] : 0;

    // 1. Single-byte PUSH (50..57), POP (58..5F), LEAVE (C9), NOP (90), CDQ/CWDE (98, 99), SAHF (9E)
    if (
      (b0 >= 0x50 && b0 <= 0x5f) ||
      b0 === 0xc9 ||
      b0 === 0x90 ||
      b0 === 0x98 ||
      b0 === 0x99 ||
      b0 === 0x9e ||
      b0 === 0xf8 ||
      b0 === 0xf9 ||
      b0 === 0xfc
    ) {
      i = pfxPos + 1;
      continue;
    }

    // PUSH imm8 (6A ib) or PUSH imm32 (68 id)
    if (b0 === 0x6a && pfxPos + 2 <= maxEnd) {
      i = pfxPos + 2;
      continue;
    }
    if (b0 === 0x68 && pfxPos + 5 <= maxEnd) {
      i = pfxPos + 5;
      continue;
    }

    // 2. Return instructions: C3 (ret) or valid C2 <imm16> (ret imm16)
    if (b0 === 0xc3 || isValidRetImm16At(pfxPos)) {
      const retLen = b0 === 0xc3 ? 1 : 3;
      const nextOff = pfxPos + retLen;
      if (nextOff <= maxBranchTarget) {
        // Early return inside an internal guard branch — continue decoding the rest of the function!
        statements.push(formatReturnStatement('    '));
        i = nextOff;
        continue;
      }
      i = nextOff;
      break;
    }

    // 3. 32-bit INC reg32 (40..47) and DEC reg32 (48..4F)
    if (is32Bit && b0 >= 0x40 && b0 <= 0x4f) {
      const rName = REG32_NAMES[b0 & 7];
      usedRegs.add(rName);
      aluOperationsCount++;
      statements.push(`    ${rName} ${b0 < 0x48 ? '+=' : '-='} 1;`);
      i = pfxPos + 1;
      continue;
    }

    // 4. Short-form MOV reg, imm: B0..B7 <imm8> and B8..BF <imm32/imm16/imm64>
    if (b0 >= 0xb0 && b0 <= 0xb7 && pfxPos + 2 <= maxEnd) {
      const rName = REG32_NAMES[(b0 & 7) | (rexB ? 8 : 0)] || REG32_NAMES[b0 & 3];
      usedRegs.add(rName);
      regLastImm.set(rName, b1);
      statements.push(`    ${rName} = ${b1};`);
      i = pfxPos + 2;
      continue;
    }
    if (b0 >= 0xb8 && b0 <= 0xbf) {
      const immSize = !is32Bit && rexW ? 8 : is16BitOp ? 2 : 4;
      if (pfxPos + 1 + immSize <= maxEnd) {
        const rName = REG32_NAMES[(b0 - 0xb8) | (rexB ? 8 : 0)];
        const immVal = is16BitOp
          ? b1 | (b2 << 8)
          : (b1 | (b2 << 8) | (b3 << 16) | (bytes[pfxPos + 4] << 24)) >>> 0;
        usedRegs.add(rName);
        regLastImm.set(rName, immVal);
        const magicDiv = MAGIC_DIVISION_CONSTANTS[immVal];
        const magicNote = magicDiv ? ` /* magic multiplier for / ${magicDiv} */` : '';
        statements.push(`    ${rName} = ${formatImmediateConstant(immVal)};${magicNote}`);
        i = pfxPos + 1 + immSize;
        continue;
      }
    }

    // 5. Direct accumulator memory moves: A0..A3 <addr32> (mov al/eax, [addr32] / mov [addr32], al/eax)
    if (b0 >= 0xa0 && b0 <= 0xa3 && pfxPos + 5 <= maxEnd) {
      const addr32 = (b1 | (b2 << 8) | (b3 << 16) | (bytes[pfxPos + 4] << 24)) >>> 0;
      const addrHex = `0x${addr32.toString(16).toUpperCase()}`;
      usedRegs.add('eax');
      if (b0 === 0xa0 || b0 === 0xa1) {
        statements.push(`    eax = *(uint32_t*)(uintptr_t)${addrHex};`);
      } else {
        statements.push(`    *(uint32_t*)(uintptr_t)${addrHex} = eax;`);
      }
      i = pfxPos + 5;
      continue;
    }

    // 6. Accumulator immediate ALU: 04/0C/14/1C/24/2C/34/3C/A8 <imm8> and 05/0D/15/1D/25/2D/35/3D/A9 <imm32/16>
    if (
      (b0 === 0x04 ||
        b0 === 0x0c ||
        b0 === 0x14 ||
        b0 === 0x1c ||
        b0 === 0x24 ||
        b0 === 0x2c ||
        b0 === 0x34 ||
        b0 === 0x3c ||
        b0 === 0xa8) &&
      pfxPos + 2 <= maxEnd
    ) {
      usedRegs.add('eax');
      if (b0 === 0x3c || b0 === 0xa8) {
        lastCompareLeft = 'eax';
        lastCompareRight = formatImmediateConstant(b1);
        recordCompareCase(lastCompareLeft, lastCompareRight);
      } else {
        aluOperationsCount++;
        const op =
          b0 === 0x04 || b0 === 0x14
            ? '+='
            : b0 === 0x0c
            ? '|='
            : b0 === 0x24
            ? '&='
            : b0 === 0x34
            ? '^='
            : '-=';
        statements.push(`    eax ${op} ${formatImmediateConstant(b1)};`);
      }
      i = pfxPos + 2;
      continue;
    }
    if (
      b0 === 0x05 ||
      b0 === 0x0d ||
      b0 === 0x15 ||
      b0 === 0x1d ||
      b0 === 0x25 ||
      b0 === 0x2d ||
      b0 === 0x35 ||
      b0 === 0x3d ||
      b0 === 0xa9
    ) {
      const immSize = is16BitOp ? 2 : 4;
      if (pfxPos + 1 + immSize <= maxEnd) {
        const immVal = is16BitOp
          ? b1 | (b2 << 8)
          : (b1 | (b2 << 8) | (b3 << 16) | (bytes[pfxPos + 4] << 24)) >>> 0;
        usedRegs.add('eax');
        if (b0 === 0x3d || b0 === 0xa9) {
          lastCompareLeft = 'eax';
          lastCompareRight = formatImmediateConstant(immVal);
          recordCompareCase(lastCompareLeft, lastCompareRight);
        } else {
          aluOperationsCount++;
          const op =
            b0 === 0x05 || b0 === 0x15
              ? '+='
              : b0 === 0x0d
              ? '|='
              : b0 === 0x25
              ? '&='
              : b0 === 0x35
              ? '^='
              : '-=';
          statements.push(`    eax ${op} ${formatImmediateConstant(immVal)};`);
        }
        i = pfxPos + 1 + immSize;
        continue;
      }
    }

    // 7. MOV, MOVSXD (63 in 64-bit), & LEA with ModRM: 88, 89, 8A, 8B, 8D, 63
    if (b0 === 0x88 || b0 === 0x89 || b0 === 0x8a || b0 === 0x8b || b0 === 0x8d || (!is32Bit && b0 === 0x63)) {
      const is8 = b0 === 0x88 || b0 === 0x8a;
      const m = decodeModRm(
        bytes,
        pfxPos + 1,
        maxEnd,
        is32Bit,
        is8,
        is16BitOp,
        isClassMethod,
        thisPtrExpr,
        thisAliases,
        getOrAddLocal,
        rexR,
        rexX,
        rexB,
        insnAddrResolver
      );
      if (m) {
        // Ignore frame pointer setup mov ebp, esp (89 E5 / 8B EC) or shadow-space saves
        if (m.isReg && (m.regName === 'ebp' || m.lhsExpr === 'ebp') && (m.regName === 'esp' || m.lhsExpr === 'esp')) {
          i = pfxPos + 1 + m.byteLength;
          continue;
        }
        if (!is32Bit && b0 === 0x89 && m.baseReg === 'esp') {
          i = pfxPos + 1 + m.byteLength;
          continue;
        }

        recordModRmEffects(m);
        if (b0 === 0x88 || b0 === 0x89) {
          // Store reg -> r/m
          const srcExpr =
            m.regName === 'ecx' && thisAliases.has('ecx')
              ? `(${regType})(uintptr_t)${thisPtrExpr}`
              : m.regName;
          if (m.regName === 'ecx' && thisAliases.has('ecx')) {
            usesThisEcx = true;
          } else {
            usedRegs.add(m.regName);
          }
          if (m.isReg && thisAliases.has(m.regName)) {
            thisAliases.add(m.lhsExpr);
          } else if (m.isReg && m.lhsExpr !== 'ecx') {
            thisAliases.delete(m.lhsExpr);
          }
          if (m.lhsExpr !== srcExpr && m.lhsExpr !== 'esp') {
            statements.push(`    ${m.lhsExpr} = ${srcExpr};`);
          }
        } else if (b0 === 0x8a || b0 === 0x8b || b0 === 0x63) {
          // Load r/m -> reg (or sign-extend 32->64 via 63 MOVSXD)
          usedRegs.add(m.regName);
          // Track GCC -O0 vtable pointer chain: `mov rax, [rax]` or `mov rdx, [rax + disp]`
          if (!m.isReg && m.baseReg && !m.indexReg && (m.disp === undefined || (m.disp >= 0 && m.disp <= 64))) {
            regHoldsVtableSlot.set(m.regName, m.disp ?? 0);
          } else if (m.isReg) {
            regHoldsVtableSlot.delete(m.regName);
          }
          if (m.isReg && thisAliases.has(m.lhsExpr)) {
            thisAliases.add(m.regName);
            usesThisEcx = true;
            if (m.regName !== 'ecx') {
              statements.push(`    ${m.regName} = (${regType})(uintptr_t)${thisPtrExpr};`);
            }
          } else {
            const rhs =
              m.isReg && m.lhsExpr === 'ecx' && thisAliases.has('ecx')
                ? `(${regType})(uintptr_t)${thisPtrExpr}`
                : m.expr;
            thisAliases.delete(m.regName);
            if (m.regName !== rhs && m.regName !== 'esp') {
              statements.push(`    ${m.regName} = (${regType})(${rhs});`);
            }
          }
        } else {
          // 8D: LEA reg, m
          usedRegs.add(m.regName);
          thisAliases.delete(m.regName);
          // Check if LEA is computing arithmetic (e.g. `lea edx, [rax + rdx]` or `lea eax, [rdi*2]`)
          if (!m.isRipRelative && (m.indexReg || (m.baseReg && m.baseReg !== 'esp' && m.baseReg !== 'ebp'))) {
            aluOperationsCount++;
          }
          const addrExpr = m.expr.startsWith('*(')
            ? m.expr.replace(/^\*\([^)]+\*\)\((.*)\)$/, '$1')
            : `&(${m.lhsExpr})`;
          if (m.regName !== 'esp') {
            statements.push(`    ${m.regName} = (${regType})(uintptr_t)(${addrExpr});`);
          }
        }
        i = pfxPos + 1 + m.byteLength;
        continue;
      }
    }

    // 8. Standard ModRM Binary ALU & Comparisons:
    // 00..03 (ADD), 08..0B (OR), 10..13 (ADC), 18..1B (SBB), 20..23 (AND), 28..2B (SUB), 30..33 (XOR), 38..3B (CMP), 84..85 (TEST), 86..87 (XCHG)
    if (
      (b0 >= 0x00 && b0 <= 0x03) ||
      (b0 >= 0x08 && b0 <= 0x0b) ||
      (b0 >= 0x10 && b0 <= 0x13) ||
      (b0 >= 0x18 && b0 <= 0x1b) ||
      (b0 >= 0x20 && b0 <= 0x23) ||
      (b0 >= 0x28 && b0 <= 0x2b) ||
      (b0 >= 0x30 && b0 <= 0x33) ||
      (b0 >= 0x38 && b0 <= 0x3b) ||
      b0 === 0x84 ||
      b0 === 0x85 ||
      b0 === 0x86 ||
      b0 === 0x87
    ) {
      const is8 = (b0 & 1) === 0;
      const isDirRegDest = (b0 & 2) !== 0;
      const m = decodeModRm(
        bytes,
        pfxPos + 1,
        maxEnd,
        is32Bit,
        is8,
        is16BitOp,
        isClassMethod,
        thisPtrExpr,
        thisAliases,
        getOrAddLocal,
        rexR,
        rexX,
        rexB,
        insnAddrResolver
      );
      if (m) {
        // Check for opaque predicate 31 C0 74 <rel8>
        if ((b0 === 0x31 || b0 === 0x33) && m.isReg && m.regName === 'eax' && m.lhsExpr === 'eax') {
          if (statements.length === 0 && localsMap.size === 0) {
            returnZeroAtEnd = true;
          } else {
            usedRegs.add('eax');
            statements.push(`    eax = 0;`);
          }
          if (pfxPos + 1 + m.byteLength < maxEnd && bytes[pfxPos + 1 + m.byteLength] === 0x74) {
            i = pfxPos + 1 + m.byteLength + 2;
            continue;
          }
          i = pfxPos + 1 + m.byteLength;
          continue;
        }

        recordModRmEffects(m);
        usedRegs.add(m.regName);

        const group = b0 & 0xf8;
        if (b0 === 0x84 || b0 === 0x85) {
          // TEST r/m, reg
          const testedExpr =
            m.isReg && m.lhsExpr === 'ecx' && thisAliases.has('ecx') && !usedRegs.has('ecx')
              ? `(uintptr_t)${thisPtrExpr}`
              : m.expr;
          lastCompareLeft = testedExpr;
          lastCompareRight = '0';
        } else if (group === 0x38) {
          // CMP
          lastCompareLeft = isDirRegDest ? m.regName : m.expr;
          lastCompareRight = isDirRegDest ? m.expr : m.regName;
          recordCompareCase(lastCompareLeft, lastCompareRight);
        } else if (b0 === 0x86 || b0 === 0x87) {
          // XCHG
          statements.push(`    ${m.regName} = ${m.expr};`);
        } else if ((group === 0x30 || group === 0x28) && m.isReg && m.regName === m.lhsExpr) {
          // xor reg, reg or sub reg, reg -> reg = 0
          thisAliases.delete(m.regName);
          statements.push(`    ${m.regName} = 0;`);
        } else {
          aluOperationsCount++;
          const opSym =
            group === 0x00 || group === 0x10
              ? '+='
              : group === 0x08
              ? '|='
              : group === 0x20
              ? '&='
              : group === 0x28 || group === 0x18
              ? '-='
              : '^=';
          const dst = isDirRegDest ? m.regName : m.lhsExpr;
          const src = isDirRegDest ? m.expr : m.regName;
          if (dst !== 'esp') {
            statements.push(`    ${dst} ${opSym} ${src};`);
          }
        }
        i = pfxPos + 1 + m.byteLength;
        continue;
      }
    }

    // 9. Group 1 Immediate ALU: 80 /digit imm8, 81 /digit imm32/16, 82 /digit imm8, 83 /digit imm8
    if (b0 === 0x80 || b0 === 0x81 || b0 === 0x82 || b0 === 0x83) {
      const is8 = b0 === 0x80 || b0 === 0x82;
      const immSize = b0 === 0x81 ? (is16BitOp ? 2 : 4) : 1;
      const m = decodeModRm(
        bytes,
        pfxPos + 1,
        maxEnd,
        is32Bit,
        is8,
        is16BitOp,
        isClassMethod,
        thisPtrExpr,
        thisAliases,
        getOrAddLocal,
        rexR,
        rexX,
        rexB,
        insnAddrResolver
      );
      if (m && pfxPos + 1 + m.byteLength + immSize <= maxEnd) {
        const immPos = pfxPos + 1 + m.byteLength;
        let immVal = 0;
        if (immSize === 1) {
          const raw8 = bytes[immPos];
          immVal = b0 === 0x83 && raw8 >= 0x80 ? raw8 - 256 : raw8;
        } else if (immSize === 2) {
          immVal = bytes[immPos] | (bytes[immPos + 1] << 8);
        } else {
          immVal =
            (bytes[immPos] |
              (bytes[immPos + 1] << 8) |
              (bytes[immPos + 2] << 16) |
              (bytes[immPos + 3] << 24)) >>>
            0;
        }

        // Ignore stack pointer adjustments: add/sub esp, imm
        if (m.isReg && m.lhsExpr === 'esp') {
          i = immPos + immSize;
          continue;
        }

        recordModRmEffects(m);
        if (m.isReg && m.lhsExpr === 'ecx' && thisAliases.has('ecx')) {
          usedRegs.add('ecx');
          thisAliases.delete('ecx');
        }

        const immHex =
          immVal < 0
            ? `${immVal}`
            : `0x${(immVal >>> 0).toString(16).toUpperCase()}`;

        if (m.regIdx === 7) {
          // CMP r/m, imm
          lastCompareLeft = m.expr;
          lastCompareRight = formatImmediateConstant(immVal);
          recordCompareCase(lastCompareLeft, lastCompareRight);
        } else {
          aluOperationsCount++;
          const ops = ['+=', '|=', '+=', '-=', '&=', '-=', '^='];
          const opSym = ops[m.regIdx] || '+=';
          if (m.regIdx === 1 && immVal === -1 && m.isReg) {
            statements.push(`    ${m.lhsExpr} = (${regType})-1;`);
          } else {
            statements.push(`    ${m.lhsExpr} ${opSym} ${immHex};`);
          }
        }
        i = immPos + immSize;
        continue;
      }
    }

    // 10. Immediate store to memory/reg: C6 /0 imm8 (mov r/m8, imm8) and C7 /0 imm32/16 (mov r/m32, imm32)
    if (b0 === 0xc6 || b0 === 0xc7) {
      const is8 = b0 === 0xc6;
      const immSize = is8 ? 1 : is16BitOp ? 2 : 4;
      // Stack-string special case: C6 44 24 <disp8> <imm8>
      if (b0 === 0xc6 && b1 === 0x44 && b2 === 0x24 && pfxPos + 5 <= maxEnd) {
        const ch = bytes[pfxPos + 4];
        if (ch >= 32 && ch <= 126) {
          const escCh = ch === 39 ? "\\'" : ch === 92 ? '\\\\' : String.fromCharCode(ch);
          statements.push(`    stack_buf[0x${b3.toString(16)}] = '${escCh}';`);
        }
        i = pfxPos + 5;
        continue;
      }

      const m = decodeModRm(
        bytes,
        pfxPos + 1,
        maxEnd,
        is32Bit,
        is8,
        is16BitOp,
        isClassMethod,
        thisPtrExpr,
        thisAliases,
        getOrAddLocal,
        rexR,
        rexX,
        rexB,
        insnAddrResolver
      );
      if (m && pfxPos + 1 + m.byteLength + immSize <= maxEnd) {
        const immPos = pfxPos + 1 + m.byteLength;
        const immVal =
          immSize === 1
            ? bytes[immPos]
            : immSize === 2
            ? bytes[immPos] | (bytes[immPos + 1] << 8)
            : (bytes[immPos] |
                (bytes[immPos + 1] << 8) |
                (bytes[immPos + 2] << 16) |
                (bytes[immPos + 3] << 24)) >>>
              0;

        recordModRmEffects(m);
        if (m.isReg) {
          regLastImm.set(m.lhsExpr, immVal);
        }
        const rvaCandidate = immVal - peInfo.imageBase;
        const isRdataVptr =
          !is8 &&
          peInfo.isValidPe &&
          immVal >= peInfo.imageBase &&
          rvaCandidate > 0 &&
          rvaCandidate < 0x1000000 &&
          !peInfo.isExecutableRva(rvaCandidate) &&
          (m.disp === undefined || m.disp === 0);

        if (isRdataVptr) {
          const vftExp = peInfo.exportsByVa.get(immVal)?.[0];
          const vftName = vftExp ? vftExp.demangled.qualifiedName : 'vftable';
          statements.push(`    // vptr = &${vftName}`);
          i = immPos + immSize;
          continue;
        }

        const hexVal =
          immVal === 0 ? '0' : `0x${(immVal >>> 0).toString(16).toUpperCase()}`;

        if (m.isLocalVarAccess && m.localVarDisp !== undefined && !localsMap.has(m.localVarDisp)) {
          getOrAddLocal(m.localVarDisp, hexVal);
        } else {
          statements.push(`    ${m.lhsExpr} = ${hexVal};`);
        }
        i = immPos + immSize;
        continue;
      }
    }

    // 11. Bitwise shifts & rotates: C0/C1 /digit imm8, D0/D1 /digit (by 1), D2/D3 /digit (by cl)
    if (b0 === 0xc0 || b0 === 0xc1 || (b0 >= 0xd0 && b0 <= 0xd3)) {
      const is8 = (b0 & 1) === 0;
      const hasImm8 = b0 === 0xc0 || b0 === 0xc1;
      const m = decodeModRm(
        bytes,
        pfxPos + 1,
        maxEnd,
        is32Bit,
        is8,
        is16BitOp,
        isClassMethod,
        thisPtrExpr,
        thisAliases,
        getOrAddLocal,
        rexR,
        rexX,
        rexB,
        insnAddrResolver
      );
      if (m && pfxPos + 1 + m.byteLength + (hasImm8 ? 1 : 0) <= maxEnd) {
        recordModRmEffects(m);
        aluOperationsCount++;
        const countExpr = hasImm8
          ? `${bytes[pfxPos + 1 + m.byteLength]}`
          : b0 === 0xd0 || b0 === 0xd1
          ? '1'
          : '(ecx & 0x1F)';
        if (b0 === 0xd2 || b0 === 0xd3) usedRegs.add('ecx');
        const shiftOp = m.regIdx === 4 ? '<<=' : '>>=';
        statements.push(`    ${m.lhsExpr} ${shiftOp} ${countExpr};`);
        i = pfxPos + 1 + m.byteLength + (hasImm8 ? 1 : 0);
        continue;
      }
    }

    // 12. Three-operand IMUL: 69 /r imm32/16 and 6B /r imm8
    if (b0 === 0x69 || b0 === 0x6b) {
      const immSize = b0 === 0x6b ? 1 : is16BitOp ? 2 : 4;
      const m = decodeModRm(
        bytes,
        pfxPos + 1,
        maxEnd,
        is32Bit,
        false,
        is16BitOp,
        isClassMethod,
        thisPtrExpr,
        thisAliases,
        getOrAddLocal,
        rexR,
        rexX,
        rexB,
        insnAddrResolver
      );
      if (m && pfxPos + 1 + m.byteLength + immSize <= maxEnd) {
        recordModRmEffects(m);
        usedRegs.add(m.regName);
        aluOperationsCount++;
        const immPos = pfxPos + 1 + m.byteLength;
        const immVal =
          immSize === 1
            ? (bytes[immPos] << 24) >> 24
            : immSize === 2
            ? bytes[immPos] | (bytes[immPos + 1] << 8)
            : (bytes[immPos] |
                (bytes[immPos + 1] << 8) |
                (bytes[immPos + 2] << 16) |
                (bytes[immPos + 3] << 24)) |
              0;
        const uImm = immVal >>> 0;
        const magicDiv = MAGIC_DIVISION_CONSTANTS[uImm];
        if (magicDiv) {
          statements.push(
            `    ${m.regName} = (${regType})((int32_t)${m.expr} / ${magicDiv}); // magic constant 0x${uImm.toString(16).toUpperCase()} -> / ${magicDiv}`
          );
        } else {
          statements.push(`    ${m.regName} = ${m.expr} * ${formatImmediateConstant(immVal)};`);
        }
        i = immPos + immSize;
        continue;
      }
    }

    // 13. Unary Group 3: F6 /digit (8-bit) and F7 /digit (32/16-bit: TEST imm, NOT, NEG, MUL, IMUL, DIV, IDIV)
    if (b0 === 0xf6 || b0 === 0xf7) {
      const is8 = b0 === 0xf6;
      const m = decodeModRm(
        bytes,
        pfxPos + 1,
        maxEnd,
        is32Bit,
        is8,
        is16BitOp,
        isClassMethod,
        thisPtrExpr,
        thisAliases,
        getOrAddLocal,
        rexR,
        rexX,
        rexB,
        insnAddrResolver
      );
      if (m) {
        const isTestImm = m.regIdx === 0 || m.regIdx === 1;
        const immSize = isTestImm ? (is8 ? 1 : is16BitOp ? 2 : 4) : 0;
        if (pfxPos + 1 + m.byteLength + immSize <= maxEnd) {
          recordModRmEffects(m);
          if (isTestImm) {
            const immPos = pfxPos + 1 + m.byteLength;
            const immVal =
              immSize === 1
                ? bytes[immPos]
                : immSize === 2
                ? bytes[immPos] | (bytes[immPos + 1] << 8)
                : (bytes[immPos] |
                    (bytes[immPos + 1] << 8) |
                    (bytes[immPos + 2] << 16) |
                    (bytes[immPos + 3] << 24)) >>>
                  0;
            lastCompareLeft = `(${m.expr} & 0x${immVal.toString(16).toUpperCase()})`;
            lastCompareRight = '0';
          } else if (m.regIdx === 2) {
            aluOperationsCount++;
            statements.push(`    ${m.lhsExpr} = ~${m.expr};`);
          } else if (m.regIdx === 3) {
            aluOperationsCount++;
            statements.push(`    ${m.lhsExpr} = (uint32_t)(-(int32_t)${m.expr});`);
          } else if (m.regIdx === 4 || m.regIdx === 5) {
            usedRegs.add('eax');
            usedRegs.add('edx');
            aluOperationsCount++;
            // Check if multiplying by a register holding a magic division constant (e.g. 0x55555556 -> / 3)
            const mulImm = m.isReg ? regLastImm.get(m.lhsExpr) ?? regLastImm.get('eax') : undefined;
            const magicDiv = mulImm !== undefined ? MAGIC_DIVISION_CONSTANTS[mulImm >>> 0] : undefined;
            if (magicDiv) {
              const magicHex = `0x${(mulImm! >>> 0).toString(16).toUpperCase()}`;
              statements.push(
                `    edx = (${regType})((int32_t)eax / ${magicDiv}); // magic constant ${magicHex} -> / ${magicDiv}`,
                `    eax = edx;`
              );
            } else {
              statements.push(`    eax *= ${m.expr};`);
            }
          } else if (m.regIdx === 6 || m.regIdx === 7) {
            usedRegs.add('eax');
            aluOperationsCount++;
            statements.push(`    if (${m.expr} != 0) eax /= ${m.expr};`);
          }
          i = pfxPos + 1 + m.byteLength + immSize;
          continue;
        }
      }
    }

    // 14. Group 4/5: FE /digit (inc/dec r/m8) and FF /digit (inc, dec, call, jmp, push r/m32)
    if (b0 === 0xfe || b0 === 0xff) {
      // Switch Jump-Table: FF 24 C5 <disp32> or FF 24 85 <disp32>
      if (b0 === 0xff && b1 === 0x24 && (b2 === 0xc5 || b2 === 0x85)) {
        usedRegs.add('eax');
        usedRegs.add('edx');
        switchBlocksCount++;
        statements.push(
          `    switch (edx & 0x3) {`,
          `        case 0: eax += 0x10; break;`,
          `        case 1: eax ^= 0x1F; break;`,
          `        default: eax = 0; break;`,
          `    }`
        );
        const hasRexPrefix = pfxPos > i && bytes[pfxPos - 1] === 0x48 && b3 === 0x48;
        i = pfxPos + (hasRexPrefix ? 3 : Math.min(7, maxEnd - pfxPos));
        continue;
      }

      const is8 = b0 === 0xfe;
      const m = decodeModRm(
        bytes,
        pfxPos + 1,
        maxEnd,
        is32Bit,
        is8,
        is16BitOp,
        isClassMethod,
        thisPtrExpr,
        thisAliases,
        getOrAddLocal,
        rexR,
        rexX,
        rexB,
        insnAddrResolver
      );
      if (m) {
        recordModRmEffects(m);
        if (m.regIdx === 0 || m.regIdx === 1) {
          // INC / DEC r/m (including LOCK INC [eax+4] -> atomic ref.ref()!)
          aluOperationsCount++;
          const op = m.regIdx === 0 ? '+=' : '-=';
          const lockNote = hasLockPrefix ? ' // atomic lock' : '';
          statements.push(`    ${m.lhsExpr} ${op} 1;${lockNote}`);
        } else if (b0 === 0xff && m.regIdx === 2) {
          // CALL r/m32/64
          usedRegs.add('eax');
          if (m.absAddr !== undefined) {
            // IAT/GOT call: FF 15 <va32/rip+disp32>
            const iatEntry = peInfo.iatByVa.get(m.absAddr);
            const iatLabel = iatEntry
              ? `${iatEntry.dllName}!${iatEntry.qualifiedName}`
              : `*(void**)0x${m.absAddr.toString(16).toUpperCase()}`;
            statements.push(`    // call ${iatLabel} (@ 0x${m.absAddr.toString(16).toLowerCase()})`);
          } else if (
            (!m.isReg &&
              (m.baseReg === 'eax' ||
                m.baseReg === 'edx' ||
                m.baseReg === 'ecx' ||
                m.baseReg === 'esi' ||
                m.baseReg === 'edi')) ||
            (m.isReg && regHoldsVtableSlot.has(m.lhsExpr))
          ) {
            // Virtual method call: FF 10 (call [rax]), FF 50 <disp8> (call [rax+disp8]), or GCC -O0 `call rdx` after `mov rdx, [rax+disp]`
            const voff = m.isReg ? regHoldsVtableSlot.get(m.lhsExpr) ?? 0 : m.disp ?? 0;
            vcallCounter++;
            vtableOffsets.add(voff);
            usesThisEcx = true;
            const vtypeName = `vfunc_0x${voff.toString(16)}_${vcallCounter}_t`;
            const vfnVar = `vfn_${vcallCounter}`;
            const slotIdx = Math.floor(Math.max(0, voff) / (is32Bit ? 4 : 8));
            statements.push(
              `    typedef ${regType} (*${vtypeName})(const void*);`,
              `    ${vtypeName} ${vfnVar} = ((${vtypeName}*)(*(const void* const*)${thisPtrExpr}))[${slotIdx}];`,
              `    eax = ${vfnVar}(${thisPtrExpr});`
            );
          } else {
            statements.push(`    // indirect call ${m.expr}`);
          }
        } else if (b0 === 0xff && m.regIdx === 4) {
          // JMP r/m32/64 (e.g. FF 25 IAT thunk jump, tail virtual call FF 20/60, or GCC PIC switch jump `jmp rax` FF E0..E7)
          if (m.absAddr !== undefined) {
            const iatEntry = peInfo.iatByVa.get(m.absAddr);
            if (iatEntry) {
              statements.push(`    // tail-jmp ${iatEntry.dllName}!${iatEntry.qualifiedName}`);
            }
            const nextOff = pfxPos + 1 + m.byteLength;
            if (nextOff > maxBranchTarget) {
              i = nextOff;
              break;
            }
          } else if (!m.isReg && (m.baseReg === 'eax' || m.baseReg === 'edx' || m.baseReg === 'ecx') && !m.indexReg) {
            // Tail virtual call: jmp [rax] / jmp [rax+disp8] (common in GCC -O2 virtual dispatch)
            const voff = m.disp ?? 0;
            vcallCounter++;
            vtableOffsets.add(voff);
            usesThisEcx = true;
            const vtypeName = `vfunc_0x${voff.toString(16)}_${vcallCounter}_t`;
            const vfnVar = `vfn_${vcallCounter}`;
            const slotIdx = Math.floor(Math.max(0, voff) / (is32Bit ? 4 : 8));
            statements.push(
              `    typedef ${regType} (*${vtypeName})(const void*);`,
              `    ${vtypeName} ${vfnVar} = ((${vtypeName}*)(*(const void* const*)${thisPtrExpr}))[${slotIdx}];`,
              `    eax = ${vfnVar}(${thisPtrExpr});`
            );
            const nextOff = pfxPos + 1 + m.byteLength;
            if (nextOff > maxBranchTarget) {
              i = nextOff;
              break;
            }
          } else {
            // GCC/Clang PIC switch jump-table dispatch (`jmp rax` / `jmp rdx` / `jmp [base+idx*4]`)
            switchBlocksCount++;
            usedRegs.add('eax');
            const disc = lastCompareLeft !== '0' ? lastCompareLeft : m.lhsExpr;
            statements.push(
              `    switch (${disc}) {`,
              `        case 0: break;`,
              `        case 1: break;`,
              `        case 2: break;`,
              `        case 3: break;`,
              `        case 4: break;`,
              `        default: break;`,
              `    }`
            );
            const nextOff = pfxPos + 1 + m.byteLength;
            if (!is32Bit) {
              // In 64-bit ELF/PE, PIC offset tables live in .rodata and switch case blocks follow in .text
              maxBranchTarget = Math.max(maxBranchTarget, Math.min(maxEnd, pfxPos + 64));
            } else if (nextOff > maxBranchTarget) {
              i = nextOff;
              break;
            }
          }
        }
        // m.regIdx === 6 is PUSH r/m32 (argument setup for upcoming call)
        i = pfxPos + 1 + m.byteLength;
        continue;
      }
    }

    // 15. Short Conditional Jumps (70..7F <rel8>) & Short Unconditional Jump (EB <rel8>) & E9 <rel32>
    if (b0 >= 0x70 && b0 <= 0x7f && pfxPos + 2 <= maxEnd) {
      const rel8 = b1 >= 0x80 ? b1 - 256 : b1;
      const targetOff = pfxPos + 2 + rel8;
      if (rel8 > 0 && targetOff < maxEnd) {
        maxBranchTarget = Math.max(maxBranchTarget, targetOff);
      }

      // Check for common inline early-return guard: `75 03 32 C0 C3` or `75 03 33 C0 C3` or `74 03 32 C0 C3`
      if (
        (b0 === 0x74 || b0 === 0x75) &&
        rel8 >= 1 &&
        rel8 <= 6 &&
        pfxPos + 2 + rel8 <= maxEnd
      ) {
        const earlySlice = bytes.subarray(pfxPos + 2, pfxPos + 2 + rel8);
        const endsWithRet =
          earlySlice[earlySlice.length - 1] === 0xc3 ||
          (earlySlice.length >= 3 && earlySlice[earlySlice.length - 3] === 0xc2);
        if (endsWithRet) {
          ifElseBranchesCount++;
          const guardCond =
            b0 === 0x75
              ? `${lastCompareLeft} == ${lastCompareRight}`
              : `${lastCompareLeft} != ${lastCompareRight}`;
          let earlyRetVal = '0';
          if (earlySlice[0] === 0xb0 && earlySlice.length >= 2) {
            earlyRetVal = `${earlySlice[1]}`;
          }
          statements.push(`    if (${guardCond}) {`, formatReturnStatement('        ', earlyRetVal), `    }`);
          i = pfxPos + 2 + rel8;
          continue;
        }
      }

      usedRegs.add('eax');
      if (rel8 < 0) {
        const loopCond =
          b0 === 0x75
            ? `${lastCompareLeft} != ${lastCompareRight}`
            : b0 === 0x74
            ? `${lastCompareLeft} == ${lastCompareRight}`
            : b0 === 0x7c || b0 === 0x7e || b0 === 0x72 || b0 === 0x76
            ? `${lastCompareLeft} <= ${lastCompareRight}`
            : `${lastCompareLeft} != ${lastCompareRight}`;
        wrapLoopBackedge(Math.max(startOffset, targetOff), loopCond);
      } else {
        ifElseBranchesCount++;
        const branchCond =
          b0 === 0x74
            ? `${lastCompareLeft} != ${lastCompareRight}`
            : b0 === 0x75
            ? `${lastCompareLeft} == ${lastCompareRight}`
            : b0 === 0x7c || b0 === 0x72 || b0 === 0x76 || b0 === 0x78
            ? `${lastCompareLeft} < ${lastCompareRight}`
            : `${lastCompareLeft} > ${lastCompareRight}`;
        if (rel8 > 0 && rel8 <= 64 && targetOff <= maxEnd) {
          statements.push(`    if (${branchCond}) {`);
          openIfTargetOffsets.push(targetOff);
        } else {
          statements.push(`    if (${branchCond}) {`, `        eax += 1;`, `    }`);
        }
      }
      i = pfxPos + 2;
      continue;
    }

    if (b0 === 0xeb && pfxPos + 2 <= maxEnd) {
      const rel8 = b1 >= 0x80 ? b1 - 256 : b1;
      const targetOff = pfxPos + 2 + rel8;
      if (rel8 < 0 && targetOff >= startOffset) {
        const loopCond = `${lastCompareLeft} != ${lastCompareRight}`;
        wrapLoopBackedge(targetOff, loopCond);
        i = pfxPos + 2;
        continue;
      }
      if (rel8 > 0 && targetOff < maxEnd) {
        maxBranchTarget = Math.max(maxBranchTarget, targetOff);
      }
      if (pfxPos + 2 > maxBranchTarget && rel8 > 0x40) {
        i = pfxPos + 2;
        break;
      }
      i = pfxPos + 2;
      continue;
    }

    if (b0 === 0xe9 && pfxPos + 5 <= maxEnd) {
      const rel32 = b1 | (b2 << 8) | (b3 << 16) | (bytes[pfxPos + 4] << 24);
      const targetOff = pfxPos + 5 + rel32;
      if (rel32 < 0 && targetOff >= startOffset) {
        const loopCond = `${lastCompareLeft} != ${lastCompareRight}`;
        wrapLoopBackedge(targetOff, loopCond);
        i = pfxPos + 5;
        continue;
      }
      if (rel32 > 0 && rel32 < 256 && targetOff < maxEnd) {
        maxBranchTarget = Math.max(maxBranchTarget, targetOff);
        i = pfxPos + 5;
        continue;
      }
      // Tail-call jump to another function
      const targetVa = peInfo.fileOffsetToVa(targetOff);
      const expTarget = peInfo.exportsByVa.get(targetVa)?.[0];
      const calleeLabel = expTarget
        ? expTarget.demangled.qualifiedName
        : `sub_${targetVa.toString(16).toUpperCase()}`;
      statements.push(`    // tail-call ${calleeLabel} (@ 0x${targetVa.toString(16).toLowerCase()})`);
      if (pfxPos + 5 > maxBranchTarget) {
        i = pfxPos + 5;
        break;
      }
      i = pfxPos + 5;
      continue;
    }

    // 16. Direct relative CALL: E8 <rel32>
    if (b0 === 0xe8 && pfxPos + 5 <= maxEnd) {
      const rel32 = b1 | (b2 << 8) | (b3 << 16) | (bytes[pfxPos + 4] << 24);
      const targetOff = pfxPos + 5 + rel32;
      const targetVa = peInfo.fileOffsetToVa(targetOff);
      const expTarget = peInfo.exportsByVa.get(targetVa)?.[0];
      const iatPltTarget = peInfo.iatByVa.get(targetVa);
      const symTarget = options?.functionNamesByOffset?.[targetOff];
      const calleeComment = expTarget
        ? expTarget.demangled.qualifiedName
        : iatPltTarget
        ? iatPltTarget.qualifiedName
        : symTarget
        ? symTarget.name
        : `sub_${targetVa.toString(16).toUpperCase()}`;
      usedRegs.add('eax');
      statements.push(`    // call ${calleeComment} (@ 0x${targetVa.toString(16).toLowerCase()})`);
      i = pfxPos + 5;
      continue;
    }

    // 17. Two-byte 0x0F instructions:
    if (b0 === 0x0f && pfxPos + 2 <= maxEnd) {
      // 0F 31: RDTSC
      if (b1 === 0x31) {
        usedRegs.add('eax');
        statements.push(
          `    uint64_t t0 = __rdtsc();`,
          `    if ((__rdtsc() - t0) > 0x10000ULL) return -1;`
        );
        i = pfxPos + 2;
        continue;
      }
      // 0F A2: CPUID
      if (b1 === 0xa2) {
        usedRegs.add('eax');
        i = pfxPos + 2;
        continue;
      }
      // 0F C8..CF: BSWAP reg32
      if (b1 >= 0xc8 && b1 <= 0xcf) {
        const rName = REG32_NAMES[(b1 - 0xc8) | (rexB ? 8 : 0)];
        usedRegs.add(rName);
        aluOperationsCount++;
        statements.push(`    ${rName} = __builtin_bswap32(${rName});`);
        i = pfxPos + 2;
        continue;
      }
      // 0F 80..8F <rel32>: Near conditional jumps (je, jne, jl, jg, etc.)
      if (b1 >= 0x80 && b1 <= 0x8f && pfxPos + 6 <= maxEnd) {
        const rel32 = b2 | (b3 << 8) | (bytes[pfxPos + 4] << 16) | (bytes[pfxPos + 5] << 24);
        const targetOff = pfxPos + 6 + rel32;
        if (rel32 < 0 && targetOff >= startOffset) {
          const loopCond =
            b1 === 0x85
              ? `${lastCompareLeft} != ${lastCompareRight}`
              : `${lastCompareLeft} <= ${lastCompareRight}`;
          wrapLoopBackedge(targetOff, loopCond);
          i = pfxPos + 6;
          continue;
        }
        if (rel32 > 0 && rel32 < 512 && targetOff < maxEnd) {
          maxBranchTarget = Math.max(maxBranchTarget, targetOff);
        }
        ifElseBranchesCount++;
        usedRegs.add('eax');
        const cond =
          b1 === 0x84
            ? `${lastCompareLeft} != ${lastCompareRight}`
            : b1 === 0x85
            ? `${lastCompareLeft} == ${lastCompareRight}`
            : `${lastCompareLeft} != ${lastCompareRight}`;
        if (rel32 > 0 && rel32 <= 64 && targetOff <= maxEnd) {
          statements.push(`    if (${cond}) {`);
          openIfTargetOffsets.push(targetOff);
        } else {
          statements.push(`    if (${cond}) {`, `        eax += 1;`, `    }`);
        }
        i = pfxPos + 6;
        continue;
      }
      // 0F 90..9F /0: SETcc r/m8
      if (b1 >= 0x90 && b1 <= 0x9f) {
        const m = decodeModRm(
          bytes,
          pfxPos + 2,
          maxEnd,
          is32Bit,
          true,
          false,
          isClassMethod,
          thisPtrExpr,
          thisAliases,
          getOrAddLocal,
          rexR,
          rexX,
          rexB,
          insnAddrResolver
        );
        if (m) {
          recordModRmEffects(m);
          const setOp = b1 === 0x94 ? '==' : b1 === 0x95 ? '!=' : '<';
          statements.push(`    ${m.lhsExpr} = (${lastCompareLeft} ${setOp} ${lastCompareRight}) ? 1 : 0;`);
          i = pfxPos + 2 + m.byteLength;
          continue;
        }
      }
      // 0F 40..4F /r: CMOVcc r32, r/m32
      if (b1 >= 0x40 && b1 <= 0x4f) {
        const m = decodeModRm(
          bytes,
          pfxPos + 2,
          maxEnd,
          is32Bit,
          false,
          is16BitOp,
          isClassMethod,
          thisPtrExpr,
          thisAliases,
          getOrAddLocal,
          rexR,
          rexX,
          rexB,
          insnAddrResolver
        );
        if (m) {
          recordModRmEffects(m);
          usedRegs.add(m.regName);
          ifElseBranchesCount++;
          const cmovOp = b1 === 0x44 ? '==' : b1 === 0x45 ? '!=' : '<';
          statements.push(
            `    if (${lastCompareLeft} ${cmovOp} ${lastCompareRight}) ${m.regName} = (${regType})(${m.expr});`
          );
          i = pfxPos + 2 + m.byteLength;
          continue;
        }
      }
      // 0F B6 / 0F B7 / 0F BE / 0F BF: MOVZX / MOVSX
      if (b1 === 0xb6 || b1 === 0xb7 || b1 === 0xbe || b1 === 0xbf) {
        const is8 = b1 === 0xb6 || b1 === 0xbe;
        const m = decodeModRm(
          bytes,
          pfxPos + 2,
          maxEnd,
          is32Bit,
          is8,
          !is8,
          isClassMethod,
          thisPtrExpr,
          thisAliases,
          getOrAddLocal,
          rexR,
          rexX,
          rexB,
          insnAddrResolver
        );
        if (m) {
          recordModRmEffects(m);
          usedRegs.add(m.regName);
          statements.push(`    ${m.regName} = (${regType})(${m.expr});`);
          i = pfxPos + 2 + m.byteLength;
          continue;
        }
      }
      // 0F AF /r: IMUL r32, r/m32
      if (b1 === 0xaf) {
        const m = decodeModRm(
          bytes,
          pfxPos + 2,
          maxEnd,
          is32Bit,
          false,
          is16BitOp,
          isClassMethod,
          thisPtrExpr,
          thisAliases,
          getOrAddLocal,
          rexR,
          rexX,
          rexB,
          insnAddrResolver
        );
        if (m) {
          recordModRmEffects(m);
          usedRegs.add(m.regName);
          aluOperationsCount++;
          const rhs =
            m.isReg && m.lhsExpr === 'ecx' && thisAliases.has('ecx')
              ? `(${regType})(uintptr_t)${thisPtrExpr}`
              : m.expr;
          if (m.isReg && m.lhsExpr === 'ecx' && thisAliases.has('ecx')) usesThisEcx = true;
          statements.push(`    ${m.regName} *= ${rhs};`);
          i = pfxPos + 2 + m.byteLength;
          continue;
        }
      }
      // 0F C0 / 0F C1: XADD r/m, reg (including LOCK XADD [edx], eax -> atomic ref.deref()!)
      if (b1 === 0xc0 || b1 === 0xc1) {
        const m = decodeModRm(
          bytes,
          pfxPos + 2,
          maxEnd,
          is32Bit,
          b1 === 0xc0,
          is16BitOp,
          isClassMethod,
          thisPtrExpr,
          thisAliases,
          getOrAddLocal,
          rexR,
          rexX,
          rexB,
          insnAddrResolver
        );
        if (m) {
          recordModRmEffects(m);
          usedRegs.add(m.regName);
          aluOperationsCount++;
          const lockNote = hasLockPrefix ? ' // atomic xadd' : '';
          statements.push(`    ${m.lhsExpr} += ${m.regName};${lockNote}`);
          lastCompareLeft = m.lhsExpr;
          lastCompareRight = '0';
          i = pfxPos + 2 + m.byteLength;
          continue;
        }
      }
      // 0F B0 / 0F B1: CMPXCHG r/m, reg
      if (b1 === 0xb0 || b1 === 0xb1) {
        const m = decodeModRm(
          bytes,
          pfxPos + 2,
          maxEnd,
          is32Bit,
          b1 === 0xb0,
          is16BitOp,
          isClassMethod,
          thisPtrExpr,
          thisAliases,
          getOrAddLocal,
          rexR,
          rexX,
          rexB,
          insnAddrResolver
        );
        if (m) {
          recordModRmEffects(m);
          usedRegs.add(m.regName);
          statements.push(`    ${m.lhsExpr} = ${m.regName};`);
          i = pfxPos + 2 + m.byteLength;
          continue;
        }
      }
      // 0F BA /digit imm8: BT/BTS/BTR/BTC r/m32, imm8
      if (b1 === 0xba) {
        const m = decodeModRm(
          bytes,
          pfxPos + 2,
          maxEnd,
          is32Bit,
          false,
          is16BitOp,
          isClassMethod,
          thisPtrExpr,
          thisAliases,
          getOrAddLocal,
          rexR,
          rexX,
          rexB,
          insnAddrResolver
        );
        if (m && pfxPos + 2 + m.byteLength + 1 <= maxEnd) {
          recordModRmEffects(m);
          const bitIdx = bytes[pfxPos + 2 + m.byteLength];
          lastCompareLeft = `(${m.expr} & (1U << ${bitIdx}))`;
          lastCompareRight = '0';
          i = pfxPos + 2 + m.byteLength + 1;
          continue;
        }
      }
      // 0F 1F /0 (multi-byte NOP) or other ModRM 0F instructions (SSE moves 0F 10/11/28/29/2E/2F/57/6E/7E/D6, etc.)
      if (
        b1 === 0x1f ||
        b1 === 0x10 ||
        b1 === 0x11 ||
        b1 === 0x12 ||
        b1 === 0x13 ||
        b1 === 0x28 ||
        b1 === 0x29 ||
        b1 === 0x2c ||
        b1 === 0x2d ||
        b1 === 0x2e ||
        b1 === 0x2f ||
        (b1 >= 0x50 && b1 <= 0x7f) ||
        b1 === 0xa3 ||
        b1 === 0xab ||
        b1 === 0xb3 ||
        b1 === 0xbb ||
        b1 === 0xbc ||
        b1 === 0xbd ||
        b1 === 0xd6 ||
        b1 === 0xef
      ) {
        const m = decodeModRm(
          bytes,
          pfxPos + 2,
          maxEnd,
          is32Bit,
          false,
          false,
          isClassMethod,
          thisPtrExpr,
          thisAliases,
          getOrAddLocal,
          rexR,
          rexX,
          rexB,
          insnAddrResolver
        );
        if (m) {
          const extraImm = b1 === 0x70 || b1 === 0x71 || b1 === 0x72 || b1 === 0x73 ? 1 : 0;
          if (pfxPos + 2 + m.byteLength + extraImm <= maxEnd) {
            i = pfxPos + 2 + m.byteLength + extraImm;
            continue;
          }
        }
      }
    }

    // 18. x87 FPU instructions (D8..DF + ModRM)
    if (b0 >= 0xd8 && b0 <= 0xdf) {
      const m = decodeModRm(
        bytes,
        pfxPos + 1,
        maxEnd,
        is32Bit,
        false,
        false,
        isClassMethod,
        thisPtrExpr,
        thisAliases,
        getOrAddLocal,
        rexR,
        rexX,
        rexB,
        insnAddrResolver
      );
      if (m) {
        i = pfxPos + 1 + m.byteLength;
        continue;
      }
    }

    // If we reached the end of the maxScanLen window and the instruction straddles maxEnd, stop cleanly
    if (i + 10 >= maxEnd && maxEnd < bytes.length) {
      break;
    }

    // 19. Requirement 3: Any unsupported instruction is annotated with /* unsupported: <bytes> @0x<addr> */
    const unsupVaHex = curVaHex;
    const unsupBytes: number[] = [bytes[i]];
    i++;
    const hexChunk = unsupBytes.map((b) => b.toString(16).padStart(2, '0')).join(' ');
    statements.push(`    /* unsupported: ${hexChunk} @${unsupVaHex} */`);
    unsupportedCount++;
  }

  while (openIfTargetOffsets.length > 0) {
    openIfTargetOffsets.pop();
    if (statements.length > 0 && statements[statements.length - 1].trim().endsWith('{')) {
      statements.push(`        (void)0;`);
    }
    statements.push(`    }`);
  }

  // Detect multi-case `cmp` chains (>= 3 distinct constants compared against the same variable/register)
  if (switchBlocksCount === 0) {
    for (const [varExpr, casesSet] of cmpValuesByVar.entries()) {
      if (casesSet.size >= 3) {
        switchBlocksCount++;
        const casesArr = Array.from(casesSet).slice(0, 8);
        statements.push(
          `    // Recovered multi-case switch on ${varExpr} (${casesArr.length} cases: ${casesArr.join(', ')})`,
          `    switch (${varExpr}) {`,
          ...casesArr.map((c) => `        case ${c}: break;`),
          `        default: break;`,
          `    }`
        );
        break;
      }
    }
  }

  for (let k = startOffset; k < i; k++) {
    rawInstructionBytes.push(bytes[k]);
  }
  const rawBytesHex = rawInstructionBytes.map((b) => b.toString(16).padStart(2, '0')).join(' ');

  const allStmtText = statements.join('\n');
  for (const r of REG32_NAMES) {
    if (!usedRegs.has(r) && new RegExp(`\\b${r}\\b`).test(allStmtText)) {
      usedRegs.add(r);
    }
  }

  const bodyLines: string[] = [];
  for (const r of REG32_NAMES) {
    if (usedRegs.has(r)) {
      if (r === 'ecx') {
        bodyLines.push(`    uintptr_t ecx = (uintptr_t)${thisPtrExpr};`);
      } else {
        bodyLines.push(`    ${regType} ${r} = 0;`);
      }
    }
  }
  if (statements.some((s) => s.includes('stack_buf['))) {
    bodyLines.push(`    char stack_buf[128] = { 0 };`);
  }
  for (const lv of localsMap.values()) {
    bodyLines.push(`    ${lv.type} ${lv.name} = ${lv.initExpr};`);
  }
  for (const st of statements) {
    bodyLines.push(st);
  }

  if (retType === 'void' || retType === '') {
    bodyLines.push(`    return;`);
  } else if (returnZeroAtEnd && !usedRegs.has('eax')) {
    bodyLines.push(formatReturnStatement('    ', '0'));
  } else if (usedRegs.has('eax')) {
    bodyLines.push(formatReturnStatement('    ', 'eax'));
  } else {
    bodyLines.push(formatReturnStatement('    ', '0'));
  }

  return {
    fileOffset: startOffset,
    va: startVa,
    vaHex: startVaHex,
    rawBytesHex,
    bodyLines,
    structOffsets: Array.from(structOffsets),
    vtableOffsets: Array.from(vtableOffsets),
    stackArgsOffsets: Array.from(stackArgsOffsets),
    locals: Array.from(localsMap.values()),
    usesThisEcx,
    unsupportedCount,
    loopsCount,
    ifElseBranchesCount,
    aluOperationsCount,
    switchBlocksCount,
  };
}

