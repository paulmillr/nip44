import { should } from 'micro-should';
import { encrypt, decrypt, utils } from './nip44.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import allVectors from './nip44.vectors.json' assert { type: "json" };
import { schnorr } from '@noble/curves/secp256k1';
import { strictEqual, throws } from 'node:assert';
const { v2: vectors } = allVectors;

should('NIP44: valid_sec', async () => {
    for (const v of vectors.valid_sec) {
        const pub2 = bytesToHex(schnorr.getPublicKey(v.sec2));
        const key = utils.v2.getConversationKey(v.sec1, pub2);
        strictEqual(bytesToHex(key), v.conversation_key);
        const ciphertext = encrypt(key, v.plaintext, { nonce: hexToBytes(v.nonce) });
        strictEqual(ciphertext, v.ciphertext);
        const decrypted = decrypt(key, ciphertext);
        strictEqual(decrypted, v.plaintext);
    }
});
should('NIP44: valid_pub', async () => {
    for (const v of vectors.valid_pub) {
        const key = utils.v2.getConversationKey(v.sec1, v.pub2);
        strictEqual(bytesToHex(key), v.conversation_key);
        const ciphertext = encrypt(key, v.plaintext, { nonce: hexToBytes(v.nonce) });
        strictEqual(ciphertext, v.ciphertext);
        const decrypted = decrypt(key, ciphertext);
        strictEqual(decrypted, v.plaintext);
    }
});
should('NIP44: invalid', async () => {
    for (const v of vectors.invalid) {
        throws(() => {
            const key = utils.v2.getConversationKey(v.sec1, v.pub2);
            const ciphertext = decrypt(key, v.ciphertext);
        }, { message: new RegExp(v.note) });
    }
});
should('NIP44: invalid_conversation_key', async () => {
    for (const v of vectors.invalid_conversation_key) {
        throws(() => {
            utils.v2.getConversationKey(v.sec1, v.pub2);
            const key = utils.v2.getConversationKey(v.sec1, v.pub2);
            const ciphertext = encrypt(key, 'a');
        }, { message: /(Point is not on curve|Cannot find square root)/ });
    }
});
should('NIP44: v1 calcPadding', () => {
    for (const [len, shouldBePaddedTo] of vectors.padding) {
        const actual = utils.v2.calcPadding(len);
        strictEqual(actual, shouldBePaddedTo);
    }
});
should.run();
// To re-generate vectors and produce new ones:
// Create regen.mjs with this content:
// import {getPublicKey, nip44} from './lib/esm/nostr.mjs'
// import {bytesToHex, hexToBytes} from '@noble/hashes/utils'
// import vectors from './nip44.vectors.json' assert { type: "json" };
// function genVectors(v) {
//   const pub2 = v.pub2 ?? getPublicKey(v.sec2);
//   let sharedKey = nip44.utils.v2.getConversationKey(v.sec1, pub2)
//   let ciphertext = nip44.encrypt(sharedKey, v.plaintext, { nonce: hexToBytes(v.nonce) })
//   console.log({
//     sec1: v.sec1,
//     pub2: pub2,
//     sharedx: bytesToHex(sharedx),
//     nonce: v.nonce,
//     plaintext: v.plaintext,
//     ciphertext
//   })
// }
// for (let v of vectors.valid_sec) genVectors(v);
// for (let v of vectors.valid_pub) genVectors(v);
// const padded = concatBytes(utils.v2.pad(plaintext), new Uint8Array(250))
// const mac = randomBytes(32)
