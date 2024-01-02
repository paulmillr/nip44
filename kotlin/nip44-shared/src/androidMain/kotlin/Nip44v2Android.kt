import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import fr.acinq.secp256k1.Secp256k1
import java.security.SecureRandom

class LibSodiumAndroid: LibSodium {
    private val lazySodium = LazySodiumAndroid(SodiumAndroid())

    override fun chacha(
        cipher: ByteArray?,
        message: ByteArray,
        messageLen: Long,
        nonce: ByteArray?,
        key: ByteArray?
    ): Boolean {
        return lazySodium.cryptoStreamChaCha20IetfXor(
            cipher, message, messageLen, nonce, key
        )
    }
}

actual fun getNip44(): Nip44 = Nip44v2(
    secp256k1 = Secp256k1.get(),
    random = SecureRandom(),
    crypto = LibSodiumAndroid()
)