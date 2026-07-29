/**
 * MP4 SAMPLE-AES Decrypter
 *
 * Implements per-sample decryption for HLS fragmented MP4 (fMP4) segments
 * protected with METHOD=SAMPLE-AES, following:
 *   - Apple HLS Sample Encryption specification
 *   - ISO/IEC 23001-7 Common Encryption (cbcs scheme: AES-CBC with a pattern)
 *   - ISO/IEC 14496-12 (ISOBMFF box structures: senc, sinf, tenc, saiz, saio)
 *
 * Encryption scheme details (cbcs):
 *   Video tracks: 1-out-of-10 block pattern (1 encrypted × 16 B + 9 clears × 16 B)
 *                 per-subunit clear/protected map carried in senc subsamples.
 *   Audio tracks: full AES-CBC encryption of the protected region.
 *
 * The per-sample Initialization Vector is stored in the senc box inside each
 * traf.  The IV is reset at the beginning of every encrypted stripe in the
 * pattern (i.e. IV does NOT chain between pattern cycles).
 */

import AESDecryptor from '../crypt/aes-decryptor';
import {
  findBox,
  readSint32,
  readUint16,
  readUint32,
} from '../utils/mp4-tools';
import { bin2str } from '../utils/numeric-encoding-utils';
import type { KeyData } from '../types/demuxer';

const BLOCK_SIZE = 16 as const; // AES block = 128 bits = 16 bytes

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

/** Default encryption parameters extracted from the tenc box (per track). */
export interface TrackEncryptionDefaults {
  /** Encryption scheme code: 'cbcs' (CBC+pattern) or 'cenc' (CTR). */
  scheme: 'cbcs' | 'cenc';
  /**
   * Number of consecutive 16-byte blocks to encrypt per pattern cycle.
   * 0 means full encryption (no pattern / skip).
   */
  cryptByteBlock: number;
  /** Number of consecutive 16-byte clear blocks per pattern cycle. */
  skipByteBlock: number;
  /**
   * Per-sample IV size in bytes (typically 8 or 16).
   * 0 indicates a constant IV stored below.
   */
  ivSize: number;
  /** Present when ivSize == 0 – a single IV used for every sample. */
  constantIv?: Uint8Array;
}

/** Per-sample encryption entry parsed from the senc box. */
interface SencSampleEntry {
  /** InitializationVector (ivSize bytes from senc). */
  iv: Uint8Array;
  /**
   * Optional subsample map (clear-bytes / protected-bytes pairs).
   * Present when senc flags bit 0x02 is set.
   */
  subsamples?: Array<{ clearBytes: number; protectedBytes: number }>;
}

// ---------------------------------------------------------------------------
// Public helper – parse tenc boxes from an init segment
// ---------------------------------------------------------------------------

/**
 * Walk an fMP4 init segment and return a Map<trackId, TrackEncryptionDefaults>
 * for every encrypted track found (enca / encv boxes with cbcs or cenc sinf).
 */
export function parseEncryptionData(
  initSegment: Uint8Array,
): Map<number, TrackEncryptionDefaults> {
  const map = new Map<number, TrackEncryptionDefaults>();
  const traks = findBox(initSegment, ['moov', 'trak']);
  const encTypes: [string, number][] = [
    ['encv', 78], // VisualSampleEntry fields before codec-specific boxes
    ['enca', 28], // AudioSampleEntry fields before codec-specific boxes
  ];

  for (let ti = 0; ti < traks.length; ti++) {
    const trak = traks[ti];
    const tkhd = findBox(trak, ['tkhd'])[0];
    if (!tkhd) continue;
    const version = tkhd[0];
    const trackId = readUint32(tkhd, version === 0 ? 12 : 20);

    const stsd = findBox(trak, ['mdia', 'minf', 'stbl', 'stsd'])[0];
    if (!stsd) continue;

    // stsd FullBox header is 8 bytes (version+flags+entry_count); skip it
    const sampleEntries = stsd.subarray(8);

    for (let ei = 0; ei < encTypes.length; ei++) {
      const [encType, headerOff] = encTypes[ei];
      const encBoxes = findBox(sampleEntries, [encType]);
      for (let bi = 0; bi < encBoxes.length; bi++) {
        const encContent = encBoxes[bi];
        const encChildren = encContent.subarray(headerOff);
        const sinfs = findBox(encChildren, ['sinf']);
        for (let si = 0; si < sinfs.length; si++) {
          const sinf = sinfs[si];
          const schm = findBox(sinf, ['schm'])[0];
          if (!schm) continue;
          const scheme = bin2str(schm.subarray(4, 8));
          if (scheme !== 'cbcs' && scheme !== 'cenc') continue;

          const tenc = findBox(sinf, ['schi', 'tenc'])[0];
          if (!tenc) continue;

          // tenc FullBox layout:
          //  [0]   version
          //  [1-3] flags
          //  [4]   reserved (v0) / crypt_byte_block<<4 | skip_byte_block (v>=1)
          //  [5]   reserved
          //  [6]   default_isProtected
          //  [7]   default_Per_Sample_IV_Size
          //  [8-23] default_KID (16 bytes)
          //  if isProtected==1 && ivSize==0:
          //    [24] default_constant_IV_size
          //    [25..] default_constant_IV
          const tencVersion = tenc[0];
          let cryptByteBlock = 0;
          let skipByteBlock = 0;
          if (tencVersion >= 1) {
            cryptByteBlock = (tenc[4] >> 4) & 0x0f;
            skipByteBlock = tenc[4] & 0x0f;
          }
          const isProtected = tenc[6];
          const ivSize = tenc[7];
          let constantIv: Uint8Array | undefined;
          if (isProtected === 1 && ivSize === 0) {
            const constIvSize = tenc[24];
            constantIv = tenc.slice(25, 25 + constIvSize);
          }

          map.set(trackId, {
            scheme: scheme as 'cbcs' | 'cenc',
            cryptByteBlock,
            skipByteBlock,
            ivSize,
            constantIv,
          });
        }
      }
    }
  }
  return map;
}

// ---------------------------------------------------------------------------
// Main decrypter class
// ---------------------------------------------------------------------------

/**
 * Decrypts fMP4 media segments that use METHOD=SAMPLE-AES (cbcs/cenc).
 *
 * Usage:
 *   1. Construct once per key rotation with the active `KeyData`.
 *   2. Construct with `trackDefaults` from `parseEncryptionData()`.
 *   3. Call `decryptSegment()` for every media segment.
 */
export class Mp4SampleAesDecrypter {
  private readonly keyData: KeyData;
  private readonly trackDefaults: Map<number, TrackEncryptionDefaults>;
  /** Lazily created and cached software AES-128 decryptor. */
  private aesDecryptor: AESDecryptor | null = null;

  constructor(
    keyData: KeyData,
    trackDefaults: Map<number, TrackEncryptionDefaults>,
  ) {
    this.keyData = keyData;
    this.trackDefaults = trackDefaults;
  }

  // -------------------------------------------------------------------------
  // Segment decryption
  // -------------------------------------------------------------------------

  /**
   * Decrypt all SAMPLE-AES protected samples in `segmentData`.
   *
   * Returns a *new* Uint8Array (copy of `segmentData`) with:
   *   – Sample data decrypted in-place according to the cbcs pattern.
   *   – `senc`, `saiz`, and `saio` boxes renamed to `free` so MSE ignores them.
   */
  decryptSegment(
    segmentData: Uint8Array<ArrayBuffer>,
  ): Uint8Array<ArrayBuffer> {
    // Work on a zero-byteOffset copy, so absolute byte indexing is straightforward.
    const data = new Uint8Array(
      segmentData.buffer.slice(
        segmentData.byteOffset,
        segmentData.byteOffset + segmentData.byteLength,
      ),
    ) as Uint8Array<ArrayBuffer>;

    const moofs = findBox(data, ['moof']);
    for (let mi = 0; mi < moofs.length; mi++) {
      const moofContent = moofs[mi];
      // Absolute offset of the moof box start (size field) within `data`.
      const moofStart = moofContent.byteOffset - 8;
      const trafs = findBox(moofContent, ['traf']);
      for (let ti = 0; ti < trafs.length; ti++) {
        this.decryptTraf(data, trafs[ti], moofStart);
      }
    }

    return data;
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /** Decrypt one track fragment (traf) inside `data`. */
  private decryptTraf(
    data: Uint8Array<ArrayBuffer>,
    traf: Uint8Array,
    moofStart: number,
  ): void {
    const tfhd = findBox(traf, ['tfhd'])[0];
    if (!tfhd) return;

    const trackId = readUint32(tfhd, 4);
    const defaults = this.trackDefaults.get(trackId);
    if (!defaults) return; // track is not encrypted

    // ---- Parse senc box ------------------------------------------------
    const sencBoxes = findBox(traf, ['senc']);
    if (!sencBoxes.length) return;
    const effectiveIvSize =
      defaults.ivSize > 0 ? defaults.ivSize : (defaults.constantIv?.length ?? 16);
    const sencEntries = this.parseSenc(sencBoxes[0], effectiveIvSize);
    if (!sencEntries.length) return;

    // ---- Rename senc / saiz / saio to 'free' ---------------------------
    const protBoxTypes = ['senc', 'saiz', 'saio'];
    for (let pbi = 0; pbi < protBoxTypes.length; pbi++) {
      const boxes = findBox(traf, [protBoxTypes[pbi]]);
      for (let bi = 0; bi < boxes.length; bi++) {
        const pos = boxes[bi].byteOffset - 4;
        data[pos] = 0x66; // 'f'
        data[pos + 1] = 0x72; // 'r'
        data[pos + 2] = 0x65; // 'e'
        data[pos + 3] = 0x65; // 'e'
      }
    }

    // ---- Parse tfhd to determine base_data_offset ----------------------
    const tfhdFlags = readUint32(tfhd, 0) & 0xffffff;
    const baseDataOffsetPresent = (tfhdFlags & 0x000001) !== 0;
    const sampleDescriptionIndexPresent = (tfhdFlags & 0x000002) !== 0;
    const defaultSampleDurationPresent = (tfhdFlags & 0x000008) !== 0;
    const defaultSampleSizePresent = (tfhdFlags & 0x000010) !== 0;
    const defaultBaseIsMoof =
      !baseDataOffsetPresent && (tfhdFlags & 0x020000) !== 0;

    // tfhd content: version+flags(4) + track_ID(4) = 8 bytes already consumed
    let tfhdOff = 8;
    let baseDataOffset: number;

    if (baseDataOffsetPresent) {
      // 64-bit offset – upper 32 bits should be 0 for any realistic HLS segment
      const hi = readUint32(tfhd, tfhdOff);
      const lo = readUint32(tfhd, tfhdOff + 4);
      baseDataOffset = hi * 0x100000000 + lo;
      tfhdOff += 8;
    } else if (defaultBaseIsMoof) {
      baseDataOffset = moofStart;
    } else {
      // Fallback: treat as if default-base-is-moof (common in HLS CMAF)
      baseDataOffset = moofStart;
    }

    if (sampleDescriptionIndexPresent) tfhdOff += 4;
    if (defaultSampleDurationPresent) tfhdOff += 4;
    let defaultSampleSize = 0;
    if (defaultSampleSizePresent) {
      defaultSampleSize = readUint32(tfhd, tfhdOff);
    }

    // ---- Walk trun(s) and decrypt each sample --------------------------
    let sampleIndex = 0;
    const truns = findBox(traf, ['trun']);
    for (let ri = 0; ri < truns.length; ri++) {
      const trun = truns[ri];
      const sampleCount = readUint32(trun, 4);
      const trunFlags = readUint32(trun, 0) & 0xffffff;
      const dataOffsetPresent = (trunFlags & 0x0001) !== 0;
      const firstSampleFlagsPresent = (trunFlags & 0x0004) !== 0;
      const sampleDurationPresent = (trunFlags & 0x0100) !== 0;
      const sampleSizePresent = (trunFlags & 0x0200) !== 0;
      const sampleFlagsPresent = (trunFlags & 0x0400) !== 0;
      const sampleCtsPresent = (trunFlags & 0x0800) !== 0;

      // skip version+flags(4) + sample_count(4)
      let trunOff = 8;
      let dataOffset = 0;

      if (dataOffsetPresent) {
        // data_offset is a signed 32-bit value per spec
        dataOffset = readSint32(trun, trunOff);
        trunOff += 4;
      }
      if (firstSampleFlagsPresent) {
        trunOff += 4;
      }

      // Absolute byte position of the first sample within `data`
      let sampleByteOffset = baseDataOffset + dataOffset;

      for (let i = 0; i < sampleCount; i++, sampleIndex++) {
        if (sampleDurationPresent) trunOff += 4;

        let sampleSize = defaultSampleSize;
        if (sampleSizePresent) {
          sampleSize = readUint32(trun, trunOff);
          trunOff += 4;
        }
        if (sampleFlagsPresent) trunOff += 4;
        if (sampleCtsPresent) trunOff += 4;

        if (!sampleSize) {
          sampleByteOffset += sampleSize;
          continue;
        }

        const entry = sencEntries[sampleIndex];
        if (!entry) {
          sampleByteOffset += sampleSize;
          continue;
        }

        // Resolve effective IV (per-sample from senc, or constant from tenc)
        const iv =
          defaults.ivSize > 0 ? entry.iv : (defaults.constantIv ?? entry.iv);

        this.decryptCbcs(
          data,
          sampleByteOffset,
          sampleSize,
          iv,
          defaults.cryptByteBlock,
          defaults.skipByteBlock,
          entry.subsamples,
        );

        sampleByteOffset += sampleSize;
      }
    }
  }

  /**
   * Apply cbcs (or full-CBC) in-place decryption to a sample's protected
   * byte ranges as described by the subsample map (if present).
   *
   * - When a subsample map is present, only the `protectedBytes` runs are touched.
   * - Within each protected region, pattern-based AES-CBC is applied:
   *     cryptByteBlock == 0 → full CBC (no skip);
   *     cryptByteBlock > 0 → encrypt `crypt` blocks, skip `skip` blocks, repeat.
   * - The IV is RESET to the per-sample IV at the start of each stripe
   *   (no CBC chaining between stripe boundaries, per ISO 23001-7 cbcs).
   */
  private decryptCbcs(
    data: Uint8Array<ArrayBuffer>,
    sampleStart: number,
    sampleLength: number,
    iv: Uint8Array,
    cryptByteBlock: number,
    skipByteBlock: number,
    subsamples?: SencSampleEntry['subsamples'],
  ): void {
    // Pad 8-byte IVs to 16 bytes (left-aligned, zero-padded on the right)
    let ivPadded: Uint8Array<ArrayBuffer>;
    if (iv.length >= 16) {
      ivPadded = (
        iv.length === 16 ? iv : iv.subarray(0, 16)
      ) as Uint8Array<ArrayBuffer>;
    } else {
      ivPadded = new Uint8Array(16) as Uint8Array<ArrayBuffer>;
      ivPadded.set(iv);
    }
    const ivBuffer: ArrayBuffer = ivPadded.buffer as ArrayBuffer;

    const decryptProtected = (pos: number, length: number) => {
      if (cryptByteBlock === 0) {
        // Full AES-CBC: decrypt all aligned 16-byte blocks
        this.decryptAlignedBlocks(data, pos, length, ivBuffer);
        return;
      }
      // Pattern: encrypt `cryptByteBlock` × 16 B, skip `skipByteBlock` × 16 B
      let rel = 0;
      while (rel < length) {
        const remaining = length - rel;
        if (remaining < BLOCK_SIZE) break; // partial trailing block → clear
        const encLen = Math.min(cryptByteBlock * BLOCK_SIZE, remaining);
        // IV resets to the per-sample IV for every encrypted stripe
        this.decryptAlignedBlocks(data, pos + rel, encLen, ivBuffer);
        rel += cryptByteBlock * BLOCK_SIZE;
        rel += skipByteBlock * BLOCK_SIZE; // advance past clear skip blocks
      }
    };

    if (subsamples && subsamples.length > 0) {
      let pos = sampleStart;
      for (let si = 0; si < subsamples.length; si++) {
        const { clearBytes, protectedBytes } = subsamples[si];
        pos += clearBytes; // skip clear run
        if (protectedBytes > 0) {
          decryptProtected(pos, protectedBytes);
          pos += protectedBytes;
        }
      }
    } else {
      decryptProtected(sampleStart, sampleLength);
    }
  }

  /**
   * Decrypt the largest multiple-of-16 prefix of `data[offset..offset+len)`
   * using AES-128-CBC with the given `iv`, writing the result back.
   * Any trailing bytes (< 16) are left untouched (they are clear per spec).
   */
  private decryptAlignedBlocks(
    data: Uint8Array<ArrayBuffer>,
    offset: number,
    len: number,
    iv: ArrayBuffer,
  ): void {
    const alignedLen = len - (len % BLOCK_SIZE);
    if (alignedLen < BLOCK_SIZE) return;

    // Lazily create + cache the software AES decryptor (key expansion is expensive)
    let dec = this.aesDecryptor;
    if (!dec) {
      dec = this.aesDecryptor = new AESDecryptor();
      dec.expandKey(this.keyData.key.buffer);
    }

    // Extract exactly the aligned block range into a fresh ArrayBuffer slice
    const cipherBuf: ArrayBuffer = data.buffer.slice(
      data.byteOffset + offset,
      data.byteOffset + offset + alignedLen,
    ) as ArrayBuffer;
    const plainBuf = dec.decrypt(cipherBuf, 0, iv);
    data.set(new Uint8Array(plainBuf), offset);
  }

  // -------------------------------------------------------------------------
  // senc box parser
  // -------------------------------------------------------------------------

  /**
   * Parse a senc (Sample Encryption) box and return an entry for each sample.
   *
   * senc (FullBox) layout:
   *   [0-3]  version(1) + flags(3)
   *   [4-7]  sample_count
   *   for each sample:
   *     [ivSize bytes]  InitializationVector
   *     if (flags & 0x02):
   *       [2 bytes]  subsample_count
   *       for each subsample:
   *         [2 bytes]  BytesOfClearData
   *         [4 bytes]  BytesOfProtectedData
   */
  private parseSenc(senc: Uint8Array, ivSize: number): SencSampleEntry[] {
    const flags = readUint32(senc, 0) & 0xffffff;
    const hasSubsamples = (flags & 0x02) !== 0;
    const sampleCount = readUint32(senc, 4);
    const entries: SencSampleEntry[] = [];
    let offset = 8;

    for (let i = 0; i < sampleCount; i++) {
      // slice() copies so each entry's iv is independent of the senc buffer
      const iv = senc.slice(offset, offset + ivSize);
      offset += ivSize;

      const entry: SencSampleEntry = { iv };
      if (hasSubsamples) {
        const subsampleCount = readUint16(senc, offset);
        offset += 2;
        entry.subsamples = [];
        for (let j = 0; j < subsampleCount; j++) {
          const clearBytes = readUint16(senc, offset);
          const protectedBytes = readUint32(senc, offset + 2);
          offset += 6;
          entry.subsamples.push({ clearBytes, protectedBytes });
        }
      }
      entries.push(entry);
    }
    return entries;
  }
}

