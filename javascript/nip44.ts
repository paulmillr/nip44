import { chacha20 } from '@noble/ciphers/chacha';
import { ensureBytes, equalBytes } from '@noble/ciphers/utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { extract as hkdf_extract, expand as hkdf_expand } from '@noble/hashes/hkdf';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils';
import { base64 } from '@scure/base';

const decoder = new TextDecoder();

export const utils = {
  v2: {
    minPlaintextSize: 1, // 1b msg => padded to 32b
    maxPlaintextSize: 0xffff, // 65535 (64kb-1) => padded to 64kb

    utf8Encode: utf8ToBytes,
    utf8Decode(bytes: Uint8Array) {
      return decoder.decode(bytes);
    },

    getConversationKey(privkeyA: string, pubkeyB: string): Uint8Array {
      const sharedX = secp256k1.getSharedSecret(privkeyA, '02' + pubkeyB).subarray(1, 33);
      const conversationKey = hkdf_extract(sha256, sharedX, 'nip44-v2');
      return conversationKey;
    },

    getMessageKeys(conversationKey: Uint8Array, nonce: Uint8Array) {
      ensureBytes(conversationKey, 32);
      ensureBytes(nonce, 32);
      const keys = hkdf_expand(sha256, conversationKey, nonce, 76);
      return {
        chacha_key: keys.subarray(0, 32),
        chacha_nonce: keys.subarray(32, 44),
        hmac_key: keys.subarray(44, 76),
      };
    },

    calcPaddedLen(len: number): number {
      if (!Number.isSafeInteger(len) || len < 0) throw new Error('expected positive integer');
      if (len <= 32) return 32;
      const nextPower = 1 << (Math.floor(Math.log2(len - 1)) + 1);
      const chunk = nextPower <= 256 ? 32 : nextPower / 8;
      return chunk * (Math.floor((len - 1) / chunk) + 1);
    },

    writeU16BE(num: number) {
      if (!Number.isSafeInteger(num) || num < 1 || num > 0xffff)
        throw new Error('invalid plaintext length: must be between 1 and 65535 bytes');
      const arr = new Uint8Array(2);
      new DataView(arr.buffer).setUint16(0, num, false);
      return arr;
    },

    pad(plaintext: string): Uint8Array {
      const u = utils.v2;
      const unpadded = u.utf8Encode(plaintext);
      const unpaddedLen = unpadded.length;
      const prefix = u.writeU16BE(unpaddedLen);
      // zeros(len) == new Uint8Array(len)
      const suffix = new Uint8Array(u.calcPaddedLen(unpaddedLen) - unpaddedLen);
      const paddedBytes = concatBytes(prefix, unpadded, suffix);
      return paddedBytes;
    },

    unpad(padded: Uint8Array): string {
      const u = utils.v2;
      const unpaddedLen = new DataView(padded.buffer).getUint16(0);
      const unpadded = padded.subarray(2, 2 + unpaddedLen);
      if (
        unpaddedLen < u.minPlaintextSize ||
        unpaddedLen > u.maxPlaintextSize ||
        unpadded.length !== unpaddedLen ||
        padded.length !== 2 + u.calcPaddedLen(unpaddedLen)
      )
        throw new Error('invalid padding');
      const plaintext = u.utf8Decode(unpadded);
      return plaintext;
    },

    hmacAad(key: Uint8Array, message: Uint8Array, aad: Uint8Array) {
      if (aad.length !== 32) throw new Error('AAD associated data must be 32 bytes');
      const combined = concatBytes(Uint8Array.from([aad.length]), aad, message);
      return hmac(sha256, key, combined);
    },

    decodePayload(payload: string) {
      const plen = payload.length;
      if (payload[0] === '#') throw new Error('unknown encryption version');
      if (plen < 132 || plen > 87471) throw new Error('invalid payload length: ' + plen);
      let data: Uint8Array;
      try {
        data = base64.decode(payload);
      } catch (error) {
        throw new Error('invalid base64: ' + (error as any).message);
      }
      const dlen = data.length;
      if (dlen < 99 || dlen > 65603) throw new Error('invalid data length: ' + dlen);
      const vers = data[0];
      if (vers !== 2) throw new Error('unknown encryption version ' + vers);
      return {
        nonce: data.subarray(1, 33),
        ciphertext: data.subarray(33, -32),
        mac: data.subarray(-32),
      };
    },
  },
};

export function encrypt(
  conversationKey: Uint8Array,
  plaintext: string,
  options: { nonce?: Uint8Array; version?: number } = {},
): string {
  const u = utils.v2;
  const version = options.version ?? 2;
  if (version !== 2) throw new Error('unknown encryption version ' + version);
  const nonce = options.nonce ?? randomBytes(32);
  const { chacha_key, chacha_nonce, hmac_key } = u.getMessageKeys(conversationKey, nonce);
  const padded = u.pad(plaintext);
  const ciphertext = chacha20(chacha_key, chacha_nonce, padded);
  const mac = u.hmacAad(hmac_key, ciphertext, nonce);
  const payload = base64.encode(concatBytes(new Uint8Array([version]), nonce, ciphertext, mac));
  return payload;
}

export function decrypt(conversationKey: Uint8Array, payload: string): string {
  const u = utils.v2;
  const { nonce, ciphertext, mac } = u.decodePayload(payload);
  const { chacha_key, chacha_nonce, hmac_key } = u.getMessageKeys(conversationKey, nonce);
  const calculatedMac = u.hmacAad(hmac_key, ciphertext, nonce);
  if (!equalBytes(calculatedMac, mac)) throw new Error('invalid MAC');
  const padded = chacha20(chacha_key, chacha_nonce, ciphertext);
  const plaintext = u.unpad(padded);
  return plaintext;
}
