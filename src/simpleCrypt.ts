import * as pako from "pako";

export enum CompressionMode {
  CompressionAuto = "auto",
  CompressionAlways = "always",
  CompressionNever = "never",
}

export enum IntegrityProtectionMode {
  ProtectionNone = "none",
  ProtectionChecksum = "checksum",
  ProtectionHash = "hash",
}

export enum SimpleCryptError {
  ErrorNoError = "No error",
  ErrorNoKeySet = "No key set",
  ErrorUnknownVersion = "Unknown version or invalid encrypted data",
  ErrorIntegrityFailed = "Integrity check failed. Wrong key or damaged data.",
}

const CryptoFlagNone = 0x00;
const CryptoFlagCompression = 0x01;
const CryptoFlagChecksum = 0x02;
const CryptoFlagHash = 0x04;
const Version = 0x03;

export const DEFAULT_ENCODE_KEY = "0x181098181098";

export class SimpleCrypt {
  public compressionMode = CompressionMode.CompressionAuto;
  public protectionMode = IntegrityProtectionMode.ProtectionChecksum;
  public lastError = SimpleCryptError.ErrorNoError;

  private key = 0n;
  private keyParts: number[] = [];

  constructor(key?: bigint | number | string) {
    if (key !== undefined) this.setKey(key);
  }

  setKey(key: bigint | number | string): void {
    this.key = typeof key === "string" ? parseKey(key) : BigInt(key);
    this.splitKey();
  }

  hasKey(): boolean {
    return this.keyParts.length === 8;
  }

  async encryptToString(plaintext: string | Uint8Array): Promise<string> {
    const bytes = typeof plaintext === "string" ? new TextEncoder().encode(plaintext) : plaintext;
    return bytesToBase64(await this.encryptToByteArray(bytes));
  }

  async decryptToString(ciphertext: string | Uint8Array): Promise<string> {
    const bytes = typeof ciphertext === "string" ? base64ToBytes(ciphertext.trim()) : ciphertext;
    return new TextDecoder().decode(await this.decryptToByteArray(bytes));
  }

  async encryptToByteArray(plaintext: Uint8Array): Promise<Uint8Array> {
    if (!this.hasKey()) {
      this.lastError = SimpleCryptError.ErrorNoKeySet;
      return new Uint8Array();
    }

    let ba = new Uint8Array(plaintext);
    let flags = CryptoFlagNone;

    if (this.compressionMode === CompressionMode.CompressionAlways) {
      ba = qCompress(ba);
      flags |= CryptoFlagCompression;
    } else if (this.compressionMode === CompressionMode.CompressionAuto) {
      const compressed = qCompress(ba);
      if (compressed.length < ba.length) {
        ba = compressed;
        flags |= CryptoFlagCompression;
      }
    }

    let integrityProtection = new Uint8Array();
    if (this.protectionMode === IntegrityProtectionMode.ProtectionChecksum) {
      flags |= CryptoFlagChecksum;
      const checksum = qChecksum(ba);
      // QDataStream writes quint16 in big-endian order by default.
      integrityProtection = new Uint8Array([(checksum >> 8) & 0xff, checksum & 0xff]);
    } else if (this.protectionMode === IntegrityProtectionMode.ProtectionHash) {
      flags |= CryptoFlagHash;
      integrityProtection = await sha1(ba);
    }

    const randomByte = crypto.getRandomValues(new Uint8Array(1));
    ba = concatBytes(randomByte, integrityProtection, ba);

    let lastChar = 0;
    for (let pos = 0; pos < ba.length; pos++) {
      ba[pos] = ba[pos] ^ this.keyParts[pos % 8] ^ lastChar;
      lastChar = ba[pos];
    }

    this.lastError = SimpleCryptError.ErrorNoError;
    return concatBytes(new Uint8Array([Version, flags]), ba);
  }

  async decryptToByteArray(cipher: Uint8Array): Promise<Uint8Array> {
    if (!this.hasKey()) {
      this.lastError = SimpleCryptError.ErrorNoKeySet;
      return new Uint8Array();
    }

    if (cipher.length < 3) {
      this.lastError = SimpleCryptError.ErrorUnknownVersion;
      return new Uint8Array();
    }

    const version = cipher[0];
    if (version !== Version) {
      this.lastError = SimpleCryptError.ErrorUnknownVersion;
      return new Uint8Array();
    }

    const flags = cipher[1];
    let ba = cipher.slice(2);

    let lastChar = 0;
    for (let pos = 0; pos < ba.length; pos++) {
      const currentChar = ba[pos];
      ba[pos] = ba[pos] ^ lastChar ^ this.keyParts[pos % 8];
      lastChar = currentChar;
    }

    ba = ba.slice(1); // remove random byte

    if ((flags & CryptoFlagChecksum) !== 0) {
      if (ba.length < 2) {
        this.lastError = SimpleCryptError.ErrorIntegrityFailed;
        return new Uint8Array();
      }

      const storedChecksum = (ba[0] << 8) | ba[1];
      ba = ba.slice(2);

      if (qChecksum(ba) !== storedChecksum) {
        this.lastError = SimpleCryptError.ErrorIntegrityFailed;
        return new Uint8Array();
      }
    } else if ((flags & CryptoFlagHash) !== 0) {
      if (ba.length < 20) {
        this.lastError = SimpleCryptError.ErrorIntegrityFailed;
        return new Uint8Array();
      }

      const storedHash = ba.slice(0, 20);
      ba = ba.slice(20);
      const actualHash = await sha1(ba);
      if (!bytesEqual(actualHash, storedHash)) {
        this.lastError = SimpleCryptError.ErrorIntegrityFailed;
        return new Uint8Array();
      }
    }

    if ((flags & CryptoFlagCompression) !== 0) {
      ba = qUncompress(ba);
    }

    this.lastError = SimpleCryptError.ErrorNoError;
    return ba;
  }

  private splitKey(): void {
    this.keyParts = [];
    for (let i = 0; i < 8; i++) {
      this.keyParts.push(Number((this.key >> BigInt(i * 8)) & 0xffn));
    }
  }
}

export function parseKey(input: string): bigint {
  const value = input.trim();
  if (!value) throw new Error("Key is empty");
  if (/^0x[0-9a-f]+$/i.test(value)) return BigInt(value);
  if (/^[0-9]+$/.test(value)) return BigInt(value);
  throw new Error("Key must be decimal or hex, for example 0x181098181098");
}

function concatBytes(...arrays: Uint8Array<ArrayBufferLike>[]): Uint8Array<ArrayBuffer> {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  const cleaned = base64.trim().replace(/\s+/g, "");
  const binary = atob(cleaned);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// Qt qCompress format: 4 byte big-endian original size + zlib data.
function qCompress(data: Uint8Array): Uint8Array<ArrayBuffer> {
  const compressed = Uint8Array.from(pako.deflate(data, { level: 9 }));
  const size = data.length;
  const header = new Uint8Array([
    (size >>> 24) & 0xff,
    (size >>> 16) & 0xff,
    (size >>> 8) & 0xff,
    size & 0xff,
  ]);
  return concatBytes(header, compressed);
}

function qUncompress(data: Uint8Array): Uint8Array<ArrayBuffer> {
  if (data.length < 4) return new Uint8Array();
  return Uint8Array.from(pako.inflate(data.slice(4)));
}

// CRC-16/CCITT-FALSE; matches the Qt qChecksum mode used by this SimpleCrypt code.
function qChecksum(data: Uint8Array): number {
  let crc = 0xffff;
  for (const byte of data) {
    crc ^= byte << 8;
    for (let i = 0; i < 8; i++) {
      crc = (crc & 0x8000) !== 0 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc & 0xffff;
}


async function sha1(data: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const copy = Uint8Array.from(data);
  const digest = await crypto.subtle.digest("SHA-1", copy.buffer);
  return new Uint8Array(digest);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
