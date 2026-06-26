import { CompressionMode, IntegrityProtectionMode } from "./simpleCrypt";

// Edit values here when you need to match another desktop SimpleCrypt config.
export const SIMPLECRYPT_KEY = "0x181098181098";

// Used only when encrypting new data.
// Decryption reads compression/integrity from the encrypted bytes themselves.
export const ENCRYPT_COMPRESSION_MODE = CompressionMode.CompressionAuto;
export const ENCRYPT_INTEGRITY_MODE = IntegrityProtectionMode.ProtectionHash;

export const DEFAULT_OUTPUT_FILENAME = "simplecrypt-output.txt";
