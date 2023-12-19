import {schnorr} from '@noble/curves/secp256k1';
import {bytesToHex, hexToBytes, randomBytes} from '@noble/hashes/utils'
import { v2 } from '../index.js';
import vectors_ from './nip44.vectors.json' assert { type: "json" };
const vectors = vectors_.v2

function genVectors(v) {
  const pub2 = bytesToHex(schnorr.getPublicKey(v.sec2));
  let conversation_key = v2.utils.getConversationKey(v.sec1, pub2)
  let ciphertext = v2.encrypt(v.plaintext, conversation_key, hexToBytes(v.nonce))
  const res = {
    sec1: v.sec1,
    sec2: v.sec2,
    conversation_key: bytesToHex(conversation_key),
    nonce: v.nonce,
    plaintext: v.plaintext,
    ciphertext: ciphertext
  };
  if (v.note) res.note = v.note;
  return res;
}

function genOneVector() {
  let conversation_key = randomBytes(32);
  let nonce = randomBytes(32);
  let plaintext = '3';
  let ciphertext = v2.encrypt(plaintext, conversation_key, nonce);
  return { conversation_key: bytesToHex(conversation_key), nonce: bytesToHex(nonce), plaintext, ciphertext }
}

function genConvKey(v) {
  const conversation_key = v2.utils.getConversationKey(v.sec1, v.pub2);
  const res = { sec1: v.sec1, pub2: v.pub2, conversation_key: bytesToHex(conversation_key) };
  if (v.note) res.note = v.note;
  return res;
}

// console.log("valid.encrypt_decrypt")
// console.log(JSON.stringify(Object.values(vectors.valid.encrypt_decrypt).map(genVectors), null, 2))
// console.log("valid.get_conversation_key")
// console.log(JSON.stringify(Object.values(vectors.valid.get_conversation_key).map(genConvKey), null, 2))

// const padded = concatBytes(utils.v2.pad(plaintext), new Uint8Array(250))
// const mac = randomBytes(32)
// console.log("invalid")
// console.log(JSON.stringify(Object.values(vectors.invalid).map(genVectors), null, 2))

function genInvalid(v) {
  let ciphertext = v2.encrypt(v.plaintext, hexToBytes(v.conversation_key), hexToBytes(v.nonce))
  console.log(ciphertext);
}
// genInvalid(vectors.invalid.decrypt[5])

function genConversationKeys() {
  const sec1 = bytesToHex(randomBytes(32));
  const pub2 = bytesToHex(schnorr.getPublicKey(randomBytes(32)));
  const conversation_key = bytesToHex(v2.utils.getConversationKey(sec1, pub2));
  return { sec1, pub2, conversation_key }
}
function getMessageKeys() {
  const conversation_key = 'a1a3d60f3470a8612633924e91febf96dc5366ce130f658b1f0fc652c20b3b54';
  const nonce = randomBytes(32);
  const keys = v2.utils.getMessageKeys(hexToBytes(conversation_key), nonce);
  return {
    nonce: bytesToHex(nonce),
    chacha_key: bytesToHex(keys.chacha_key),
    chacha_nonce: bytesToHex(keys.chacha_nonce),
    hmac_key: bytesToHex(keys.hmac_key)
  };
}
// console.log(JSON.stringify(new Array(32).fill(0).map(i => genConversationKeys()), null, 2));

// console.log(JSON.stringify(new Array(32).fill(0).map(i => getMessageKeys()), null, 2));

console.log(JSON.stringify(genOneVector()));