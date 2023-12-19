import { v2 } from './lib/index.js';
import { bytesToHex, randomBytes } from '@noble/hashes/utils'
import { sha256 } from '@noble/hashes/sha256';

function genVector(plaintext = 'abc') {
  let conversation_key = randomBytes(32);
  let nonce = randomBytes(32);
  let ciphertext = v2.encrypt(plaintext, conversation_key, nonce);
  return { conversation_key: bytesToHex(conversation_key), nonce: bytesToHex(nonce), p_sha: bytesToHex(sha256(plaintext)), c_sha: bytesToHex(sha256(ciphertext)) }
}

console.log(JSON.stringify(genVector('🦄'.repeat(16383)), null, 2));