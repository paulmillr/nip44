interface LibSodium {
    fun chacha(
        cipher: ByteArray?,
        message: ByteArray,
        messageLen: Long,
        nonce: ByteArray?,
        key: ByteArray?
    ): Boolean
}