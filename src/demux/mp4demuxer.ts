/**
 * MP4 demuxer
 */
import { dummyTrack } from './dummy-demuxed-track';
import {
  Mp4SampleAesDecrypter,
  parseEncryptionData,
  type TrackEncryptionDefaults,
} from './mp4-sample-aes';
import {
  type DemuxedAudioTrack,
  type DemuxedMetadataTrack,
  type DemuxedUserdataTrack,
  type Demuxer,
  type DemuxerResult,
  type KeyData,
  MetadataSchema,
  type PassthroughTrack,
} from '../types/demuxer';
import {
  appendUint8Array,
  findBox,
  hasBoxData,
  parseEmsg,
  parseInitSegment,
  parseSamples,
  RemuxerTrackIdConfig,
  segmentValidRange,
} from '../utils/mp4-tools';
import type { HlsConfig } from '../config';
import type { HlsEventEmitter } from '../events';
import type { IEmsgParsingData } from '../utils/mp4-tools';
import type { DecryptData } from '../loader/level-key';
import type { ChunkMetadata } from '../hls';

const emsgSchemePattern = /\/emsg[-/]ID3/i;

class MP4Demuxer implements Demuxer {
  private remainderData: Uint8Array<ArrayBuffer> | null = null;
  private timeOffset: number = 0;
  private config: HlsConfig;
  private videoTrack?: PassthroughTrack;
  private audioTrack?: DemuxedAudioTrack;
  private id3Track?: DemuxedMetadataTrack;
  private txtTrack?: DemuxedUserdataTrack;
  /** Encryption defaults parsed from the last SAMPLE-AES init segment. */
  private encryptionData: Map<number, TrackEncryptionDefaults> | null = null;
  /** Cached decrypter instance (reused across segments for a given key). */
  private sampleAesDecrypter: Mp4SampleAesDecrypter | null = null;

  constructor(observer: HlsEventEmitter, config: HlsConfig) {
    this.config = config;
  }

  public resetTimeStamp() {}

  public resetInitSegment(
    initSegment: Uint8Array | undefined,
    audioCodec: string | undefined,
    videoCodec: string | undefined,
    trackDuration: number,
    decryptdata?: DecryptData | null,
    _chunkMeta?: ChunkMetadata,
  ) {
    const videoTrack = (this.videoTrack = dummyTrack(
      'video',
      1,
    ) as PassthroughTrack);
    const audioTrack = (this.audioTrack = dummyTrack(
      'audio',
      1,
    ) as DemuxedAudioTrack);
    const captionTrack = (this.txtTrack = dummyTrack(
      'text',
      1,
    ) as DemuxedUserdataTrack);

    this.id3Track = dummyTrack('id3', 1) as DemuxedMetadataTrack;
    this.timeOffset = 0;

    // Reset SAMPLE-AES state; will be re-populated below if applicable.
    this.encryptionData = null;
    this.sampleAesDecrypter = null;

    if (!initSegment?.byteLength) {
      return;
    }

    // Parse SAMPLE-AES encryption metadata from the init segment so that
    // demuxSampleAes() can use it for per-segment decryption.
    if (decryptdata?.method === 'SAMPLE-AES') {
      this.encryptionData = parseEncryptionData(initSegment);
    }

    const initData = parseInitSegment(initSegment);

    if (initData.video) {
      const { id, timescale, codec, supplemental } = initData.video;
      videoTrack.id = id;
      videoTrack.timescale = captionTrack.timescale = timescale;
      videoTrack.codec = codec;
      videoTrack.supplemental = supplemental;
    }

    if (initData.audio) {
      const { id, timescale, codec } = initData.audio;
      audioTrack.id = id;
      audioTrack.timescale = timescale;
      audioTrack.codec = codec;
    }

    captionTrack.id = RemuxerTrackIdConfig.text;
    videoTrack.sampleDuration = 0;
    videoTrack.duration = audioTrack.duration = trackDuration;
  }

  public resetContiguity(): void {
    this.remainderData = null;
  }

  static probe(data: Uint8Array) {
    return hasBoxData(data, 'moof');
  }

  public demux(
    data: Uint8Array<ArrayBuffer>,
    timeOffset: number,
  ): DemuxerResult {
    this.timeOffset = timeOffset;
    // Load all data into the avc track. The CMAF remuxer will look for the data in the samples object; the rest of the fields do not matter
    let videoSamples = data;
    const videoTrack = this.videoTrack as PassthroughTrack;
    const textTrack = this.txtTrack as DemuxedUserdataTrack;
    if (this.config.progressive) {
      // Split the bytestream into two ranges: one encompassing all data up until the start of the last moof, and everything else.
      // This is done to guarantee that we're sending valid data to MSE - when demuxing progressively, we have no guarantee
      // that the fetch loader gives us flush moof+mdat pairs. If we push jagged data to MSE, it will throw an exception.
      if (this.remainderData) {
        videoSamples = appendUint8Array(this.remainderData, data);
      }
      const segmentedData = segmentValidRange(videoSamples);
      this.remainderData = segmentedData.remainder;
      videoTrack.samples = segmentedData.valid || new Uint8Array();
    } else {
      videoTrack.samples = videoSamples;
    }
    const id3Track = this.extractID3Track(videoTrack, timeOffset);
    textTrack.samples = parseSamples(timeOffset, videoTrack);

    return {
      videoTrack,
      audioTrack: this.audioTrack as DemuxedAudioTrack,
      id3Track,
      textTrack: this.txtTrack as DemuxedUserdataTrack,
    };
  }

  public flush() {
    const timeOffset = this.timeOffset;
    const videoTrack = this.videoTrack as PassthroughTrack;
    const textTrack = this.txtTrack as DemuxedUserdataTrack;
    videoTrack.samples = this.remainderData || new Uint8Array();
    this.remainderData = null;

    const id3Track = this.extractID3Track(videoTrack, this.timeOffset);
    textTrack.samples = parseSamples(timeOffset, videoTrack);

    return {
      videoTrack,
      audioTrack: dummyTrack() as DemuxedAudioTrack,
      id3Track,
      textTrack: dummyTrack() as DemuxedUserdataTrack,
    };
  }

  private extractID3Track(
    videoTrack: PassthroughTrack,
    timeOffset: number,
  ): DemuxedMetadataTrack {
    const id3Track = this.id3Track as DemuxedMetadataTrack;
    if (videoTrack.samples.length) {
      const emsgs = findBox(videoTrack.samples, ['emsg']);
      if (emsgs) {
        emsgs.forEach((data: Uint8Array) => {
          const emsgInfo = parseEmsg(data);
          if (emsgSchemePattern.test(emsgInfo.schemeIdUri)) {
            const pts = getEmsgStartTime(emsgInfo, timeOffset);
            let duration =
              emsgInfo.eventDuration === 0xffffffff
                ? Number.POSITIVE_INFINITY
                : emsgInfo.eventDuration / emsgInfo.timeScale;
            // Safari takes anything <= 0.001 seconds and maps it to Infinity
            if (duration <= 0.001) {
              duration = Number.POSITIVE_INFINITY;
            }
            const payload = emsgInfo.payload;
            id3Track.samples.push({
              data: payload,
              len: payload.byteLength,
              dts: pts,
              pts: pts,
              type: MetadataSchema.emsg,
              duration: duration,
            });
          } else if (this.config.enableEmsgKLVMetadata) {
            const klvSchemaUri =
              this.config.emsgKLVSchemaUri || MetadataSchema.misbklv;
            if (emsgInfo.schemeIdUri.startsWith(klvSchemaUri)) {
              const pts = getEmsgStartTime(emsgInfo, timeOffset);
              id3Track.samples.push({
                data: emsgInfo.payload,
                len: emsgInfo.payload.byteLength,
                dts: pts,
                pts: pts,
                type: MetadataSchema.misbklv,
                duration: Number.POSITIVE_INFINITY,
              });
            }
          }
        });
      }
    }
    return id3Track;
  }

  /**
   * Decrypt a SAMPLE-AES protected fMP4 media segment and return the result
   * through the normal demux pipeline.
   *
   * Algorithm:
   *  1. Resolve (or lazily create) an `Mp4SampleAesDecrypter` for the current
   *     key.  The decrypter carries the software AES context and per-track
   *     encryption defaults parsed from the init segment.
   *  2. Call `decryptSegment()` which:
   *     a. Copies the segment bytes.
   *     b. Decrypts every sample according to the cbcs pattern + senc IVs.
   *     c. Renames `senc` / `saiz` / `saio` boxes to `free`.
   *  3. Push the plain-text bytes through the regular `demux()` path.
   */
  demuxSampleAes(
    data: Uint8Array,
    keyData: KeyData,
    timeOffset: number,
    _chunkMeta?: ChunkMetadata,
  ): Promise<DemuxerResult> {
    const { encryptionData } = this;
    if (!encryptionData || encryptionData.size === 0) {
      return Promise.reject(
        new Error(
          'MP4 SAMPLE-AES: no track encryption data found in init segment. ' +
            'Ensure resetInitSegment() is called with a SAMPLE-AES init segment ' +
            'before demuxSampleAes().',
        ),
      );
    }

    // Lazily create (or reuse) the decrypter for this key.
    // The decrypter caches the expanded AES key schedule across segments.
    let { sampleAesDecrypter } = this;
    if (!sampleAesDecrypter) {
      sampleAesDecrypter = this.sampleAesDecrypter = new Mp4SampleAesDecrypter(
        keyData,
        encryptionData,
      );
    }

    let decryptedData: Uint8Array;
    try {
      decryptedData = sampleAesDecrypter.decryptSegment(
        data as Uint8Array<ArrayBuffer>,
      );
    } catch (err) {
      return Promise.reject(err);
    }

    return Promise.resolve(
      this.demux(decryptedData as Uint8Array<ArrayBuffer>, timeOffset),
    );
  }

  destroy() {
    // @ts-ignore
    this.config = null;
    this.remainderData = null;
    this.encryptionData = null;
    this.sampleAesDecrypter = null;
    this.videoTrack =
      this.audioTrack =
      this.id3Track =
      this.txtTrack =
        undefined;
  }
}

function getEmsgStartTime(
  emsgInfo: IEmsgParsingData,
  timeOffset: number,
): number {
  return Number.isFinite(emsgInfo.presentationTime)
    ? (emsgInfo.presentationTime as number) / emsgInfo.timeScale
    : timeOffset +
        (emsgInfo.presentationTimeDelta as number) / emsgInfo.timeScale;
}

export default MP4Demuxer;
