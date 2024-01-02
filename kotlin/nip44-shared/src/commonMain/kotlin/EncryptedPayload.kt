import java.util.Base64

class EncryptedPayload(
    val nonce: ByteArray,
    val ciphertext: ByteArray,
    val mac: ByteArray
) {
    companion object {
        const val v: Int = 2

        fun decode(payload: String): EncryptedPayload? {
            check(payload.length >= 132 || payload.length <= 87472) {
                "Invalid payload length ${payload.length} for ${payload}"
            }
            check(payload[0] != '#') {
                "Unknown encryption version ${payload.get(0)}"
            }

            return try {
                val byteArray = Base64.getDecoder().decode(payload)
                check(byteArray[0].toInt() == v)
                return EncryptedPayload(
                    nonce = byteArray.copyOfRange(1, 33),
                    ciphertext = byteArray.copyOfRange(33, byteArray.size - 32),
                    mac = byteArray.copyOfRange(byteArray.size - 32, byteArray.size)
                )
            } catch (e: Exception) {
                e.printStackTrace()
                null
            }
        }
    }


    fun encode(): String {
        return Base64.getEncoder().encodeToString(
            byteArrayOf(v.toByte()) + nonce + ciphertext + mac
        )
    }
}


