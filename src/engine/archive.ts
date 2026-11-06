import JSZip from 'jszip';
import { gunzipSync } from 'fflate';

export interface ExtractedArchiveFile {
  name: string;
  bytes: Uint8Array;
}

/**
 * Unpacks archives (.zip, .tar.gz, .tgz, .gz, .tar) into extracted files
 */
export async function unpackArchiveFiles(
  fileName: string,
  bytes: Uint8Array
): Promise<ExtractedArchiveFile[]> {
  const lowerName = fileName.toLowerCase();
  const extractedFiles: ExtractedArchiveFile[] = [];

  try {
    // 1. ZIP Archives (.zip, .apk, .msi, .jar)
    if (
      lowerName.endsWith('.zip') ||
      lowerName.endsWith('.jar') ||
      (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04)
    ) {
      const zip = await JSZip.loadAsync(bytes);
      const fileNames = Object.keys(zip.files);
      for (const fn of fileNames) {
        const entry = zip.files[fn];
        if (!entry.dir) {
          const fileBytes = await entry.async('uint8array');
          extractedFiles.push({
            name: fn,
            bytes: fileBytes,
          });
        }
      }
      return extractedFiles;
    }

    // 2. GZIP / TAR.GZ / TGZ Archives (.tar.gz, .tgz, .gz)
    if (
      lowerName.endsWith('.tar.gz') ||
      lowerName.endsWith('.tgz') ||
      lowerName.endsWith('.gz') ||
      (bytes[0] === 0x1f && bytes[1] === 0x8b)
    ) {
      const decompressedGzip = gunzipSync(bytes);
      // Check if decompressed bytes are TAR archive
      if (isTarArchive(decompressedGzip)) {
        const tarFiles = parseTarBytes(decompressedGzip);
        extractedFiles.push(...tarFiles);
      } else {
        const innerName = fileName.replace(/\.(gz|tgz)$/i, '');
        extractedFiles.push({
          name: innerName || 'decompressed_payload.bin',
          bytes: decompressedGzip,
        });
      }
      return extractedFiles;
    }

    // 3. TAR Archives (.tar)
    if (lowerName.endsWith('.tar') || isTarArchive(bytes)) {
      const tarFiles = parseTarBytes(bytes);
      extractedFiles.push(...tarFiles);
      return extractedFiles;
    }
  } catch (err) {
    console.warn(`Archive extraction failed for ${fileName}:`, err);
  }

  return extractedFiles;
}

function isTarArchive(bytes: Uint8Array): boolean {
  if (bytes.length < 512) return false;
  // TAR magic "ustar" at offset 257
  const magic = String.fromCharCode(...bytes.slice(257, 262));
  return magic === 'ustar';
}

function parseTarBytes(bytes: Uint8Array): ExtractedArchiveFile[] {
  const result: ExtractedArchiveFile[] = [];
  let offset = 0;

  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    // Null block check
    if (header.every((b) => b === 0)) break;

    const nameBytes = header.subarray(0, 100);
    const nullIdx = nameBytes.indexOf(0);
    const fileName = new TextDecoder().decode(
      nullIdx >= 0 ? nameBytes.subarray(0, nullIdx) : nameBytes
    ).trim();

    const sizeBytes = header.subarray(124, 136);
    const sizeStr = new TextDecoder().decode(sizeBytes).trim();
    const fileSize = parseInt(sizeStr, 8) || 0;

    const typeFlag = header[156]; // '0' or '\0' for normal file

    offset += 512; // move past header

    if (fileName && fileSize > 0 && (typeFlag === 0 || typeFlag === 48)) {
      const fileContent = bytes.slice(offset, offset + fileSize);
      result.push({
        name: fileName,
        bytes: fileContent,
      });
    }

    // Move to next 512-byte block boundary
    const blocks = Math.ceil(fileSize / 512);
    offset += blocks * 512;
  }

  return result;
}
