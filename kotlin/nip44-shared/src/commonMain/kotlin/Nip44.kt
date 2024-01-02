interface Nip44 {
    fun getConversationKey(privateKey: ByteArray, pubKey: ByteArray): ByteArray

    fun encrypt(msg: String, privateKey: ByteArray, pubKey: ByteArray): EncryptedPayload
    fun encrypt(plaintext: String, conversationKey: ByteArray): EncryptedPayload
    fun encryptWithNonce(plaintext: String, conversationKey: ByteArray, nonce: ByteArray): EncryptedPayload

    fun decrypt(payload: String, privateKey: ByteArray, pubKey: ByteArray): String?
    fun decrypt(decoded: EncryptedPayload, privateKey: ByteArray, pubKey: ByteArray): String?
    fun decrypt(payload: String, conversationKey: ByteArray): String?
    fun decrypt(decoded: EncryptedPayload, conversationKey: ByteArray): String

    fun calcPaddedLen(len: Int): Int
}

expect fun getNip44(): Nip44