import { should } from 'micro-should';
import { v2 } from './index.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
// @ts-ignore
import { default as vec } from './nip44.vectors.json' assert { type: 'json' };
import { schnorr } from '@noble/curves/secp256k1';
// @ts-ignore
import { strictEqual, throws } from 'node:assert';
const v2vec = vec.v2;

should('NIP44: valid.encrypt_decrypt', async () => {
  for (const v of v2vec.valid.encrypt_decrypt) {
    const pub2 = bytesToHex(schnorr.getPublicKey(v.sec2));
    const key = v2.utils.getConversationKey(v.sec1, pub2);
    strictEqual(bytesToHex(key), v.conversation_key);
    const ciphertext = v2.encrypt(v.plaintext, key, hexToBytes(v.nonce));
    strictEqual(ciphertext, v.ciphertext);
    const decrypted = v2.decrypt(ciphertext, key);
    strictEqual(decrypted, v.plaintext);
  }
});
should('NIP44: valid.get_conversation_key', async () => {
  for (const v of v2vec.valid.get_conversation_key) {
    const key = v2.utils.getConversationKey(v.sec1, v.pub2);
    strictEqual(bytesToHex(key), v.conversation_key);
  }
});
should('NIP44: invalid', async () => {
  for (const v of v2vec.invalid.general) {
    throws(
      () => {
        const key = v2.utils.getConversationKey(v.sec1, v.pub2);
        v2.decrypt(v.ciphertext, key);
      },
      { message: new RegExp(v.note) },
    );
  }
});
should('NIP44: invalid_conversation_key', async () => {
  for (const v of v2vec.invalid.get_conversation_key) {
    throws(
      () => {
        v2.utils.getConversationKey(v.sec1, v.pub2);
        const key = v2.utils.getConversationKey(v.sec1, v.pub2);
        v2.encrypt('a', key);
      },
      { message: /(Point is not on curve|Cannot find square root)/ },
    );
  }
});
should('NIP44: v1 calcPadding', () => {
  for (const [len, shouldBePaddedTo] of v2vec.calc_padded_len) {
    const actual = v2.utils.calcPaddedLen(len);
    strictEqual(actual, shouldBePaddedTo);
  }
});
should.run();
