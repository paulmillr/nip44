import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import kotlin.math.floor
import kotlin.math.log2

open class Nip44v2(
    private val secp256k1: Secp256k1,
    private val random: SecureRandom,
    private val crypto: LibSodium
) : Nip44 {
    private val hkdf = Hkdf("HmacSHA256", hashLen = hashLength)

    companion object {
        private val h02 = Hex.decode("02")
        private val saltPrefix = "nip44-v2".toByteArray(Charsets.UTF_8)
        private const val hashLength = 32

        private const val minPlaintextSize: Int = 0x0001 // 1b msg => padded to 32b
        private const val maxPlaintextSize: Int = 0xffff // 65535 (64kb-1) => padded to 64kb
    }

    override fun encrypt(msg: String, privateKey: ByteArray, pubKey: ByteArray): EncryptedPayload {
        return encrypt(msg, getConversationKey(privateKey, pubKey))
    }

    override fun encrypt(plaintext: String, conversationKey: ByteArray): EncryptedPayload {
        val nonce = ByteArray(hashLength)
        random.nextBytes(nonce)
        return encryptWithNonce(plaintext, conversationKey, nonce)
    }

    override fun encryptWithNonce(plaintext: String, conversationKey: ByteArray, nonce: ByteArray): EncryptedPayload {
        val messageKeys = getMessageKeys(conversationKey, nonce)
        val padded = pad(plaintext)

        val ciphertext = ByteArray(padded.size)

        crypto.chacha(
            ciphertext, padded, padded.size.toLong(), messageKeys.chachaNonce, messageKeys.chachaKey
        )

        val mac = hmacAad(messageKeys.hmacKey, ciphertext, nonce)

        return EncryptedPayload(
            nonce = nonce,
            ciphertext = ciphertext,
            mac = mac
        )
    }


    override fun decrypt(payload: String, privateKey: ByteArray, pubKey: ByteArray): String? {
        return decrypt(payload, getConversationKey(privateKey, pubKey))
    }

    override fun decrypt(decoded: EncryptedPayload, privateKey: ByteArray, pubKey: ByteArray): String? {
        return decrypt(decoded, getConversationKey(privateKey, pubKey))
    }

    override fun decrypt(payload: String, conversationKey: ByteArray): String? {
        val decoded = EncryptedPayload.decode(payload) ?: return null
        return decrypt(decoded, conversationKey)
    }

    override fun decrypt(decoded: EncryptedPayload, conversationKey: ByteArray): String {
        val messageKey = getMessageKeys(conversationKey, decoded.nonce)
        val calculatedMac = hmacAad(messageKey.hmacKey, decoded.ciphertext, decoded.nonce)

        check(calculatedMac.contentEquals(decoded.mac)) {
            "Invalid Mac: Calculated ${Hex.encode(calculatedMac)}, decoded: ${Hex.encode(decoded.mac)}"
        }

        val mLen = decoded.ciphertext.size.toLong()
        val padded = ByteArray(decoded.ciphertext.size)

        crypto.chacha(
            padded, decoded.ciphertext, mLen, messageKey.chachaNonce, messageKey.chachaKey
        )

        return unpad(padded)
    }

    override fun calcPaddedLen(len: Int): Int {
        check(len > 0) {
            "expected positive integer"
        }
        if (len <= 32) return 32
        val nextPower = 1 shl (floor(log2(len - 1f)) + 1).toInt()
        val chunk = if (nextPower <= 256) 32 else nextPower / 8
        return chunk * (floor((len - 1f) / chunk).toInt() + 1)
    }

    fun pad(plaintext: String): ByteArray {
        val unpadded = plaintext.toByteArray(Charsets.UTF_8)
        val unpaddedLen = unpadded.size

        check(unpaddedLen > 0) {
            "Message is empty ($unpaddedLen): $plaintext"
        }

        check(unpaddedLen <= maxPlaintextSize) {
            "Message is too long ($unpaddedLen): $plaintext"
        }

        val prefix = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).putShort(unpaddedLen.toShort()).array()
        val suffix = ByteArray(calcPaddedLen(unpaddedLen) - unpaddedLen)
        return ByteBuffer.wrap(prefix + unpadded + suffix).array()
    }

    fun bytesToInt(byte1: Byte, byte2: Byte, bigEndian: Boolean): Int {
        return if (bigEndian)
            (byte1.toInt() and 0xFF shl 8 or (byte2.toInt() and 0xFF))
        else
            (byte2.toInt() and 0xFF shl 8 or (byte1.toInt() and 0xFF))
    }

    fun unpad(padded: ByteArray): String {
        val unpaddedLen: Int = bytesToInt(padded[0], padded[1], true)
        val unpadded = padded.sliceArray(2 until 2 + unpaddedLen)

        check(
            unpaddedLen in minPlaintextSize..maxPlaintextSize
                && unpadded.size == unpaddedLen
                && padded.size == 2 + calcPaddedLen(unpaddedLen)) {
            "invalid padding ${unpadded.size} != $unpaddedLen"
        }

        return unpadded.decodeToString()
    }

    fun hmacAad(key: ByteArray, message: ByteArray, aad: ByteArray): ByteArray {
        check (aad.size == hashLength) {
            "AAD associated data must be 32 bytes, but it was ${aad.size} bytes"
        }

        return hkdf.extract(aad + message, key)
    }

    fun getMessageKeys(conversationKey: ByteArray, nonce: ByteArray): MessageKey {
        val keys = hkdf.expand(conversationKey, nonce, 76)
        return MessageKey(
            chachaKey = keys.copyOfRange(0, 32),
            chachaNonce = keys.copyOfRange(32, 44),
            hmacKey = keys.copyOfRange(44, 76),
        )
    }

    class MessageKey(
        val chachaKey: ByteArray,
        val chachaNonce: ByteArray,
        val hmacKey: ByteArray
    )

    /**
     * @return 32B shared secret
     */
    override fun getConversationKey(privateKey: ByteArray, pubKey: ByteArray): ByteArray {
        val sharedX = secp256k1.pubKeyTweakMul(h02 + pubKey, privateKey).copyOfRange(1, 33)
        return hkdf.extract(sharedX, saltPrefix)
    }
}



