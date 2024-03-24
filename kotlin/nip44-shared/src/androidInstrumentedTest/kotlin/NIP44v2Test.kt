import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry.getInstrumentation
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import junit.framework.TestCase.assertEquals
import junit.framework.TestCase.assertNotNull
import junit.framework.TestCase.assertNull
import junit.framework.TestCase.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest
import java.security.SecureRandom

@RunWith(AndroidJUnit4::class)
class NIP44v2Test {
    private val vectors: VectorFile = jacksonObjectMapper().readValue(
        getInstrumentation().context.assets.open("nip44.vectors.json"),
        VectorFile::class.java
    )

    private val nip44v2 = getNip44()

    private fun sha256Hex(data: ByteArray): String {
        // Creates a new buffer every time
        return Hex.encode(MessageDigest.getInstance("SHA-256").digest(data))
    }

    @Test
    fun conversationKeyTest() {
        for (v in vectors.v2?.valid?.getConversationKey!!) {
            val conversationKey = nip44v2.getConversationKey(
                Hex.decode(v.sec1!!),
                Hex.decode(v.pub2!!)
            )

            assertEquals(v.conversationKey, Hex.encode(conversationKey))
        }
    }

    @Test
    fun paddingTest() {
        for (v in vectors.v2?.valid?.calcPaddedLen!!) {
            val actual = nip44v2.calcPaddedLen(v[0])
            assertEquals(v[1], actual)
        }
    }

    @Test
    fun encryptDecryptTest() {
        val secp256k1 = Secp256k1.get()
        for (v in vectors.v2?.valid?.encryptDecrypt!!) {
            val pub2 = secp256k1.pubKeyCompress(secp256k1.pubkeyCreate(Hex.decode(v.sec2!!))).copyOfRange(1, 33)
            val conversationKey1 = nip44v2.getConversationKey(Hex.decode(v.sec1!!), pub2)
            assertEquals(v.conversationKey, Hex.encode(conversationKey1))

            val ciphertext = nip44v2.encryptWithNonce(
                v.plaintext!!,
                conversationKey1,
                Hex.decode(v.nonce!!)
            ).encode()

            assertEquals(v.payload, ciphertext)

            val pub1 = secp256k1.pubKeyCompress(secp256k1.pubkeyCreate(Hex.decode(v.sec1))).copyOfRange(1, 33)
            val conversationKey2 = nip44v2.getConversationKey(Hex.decode(v.sec2), pub1)
            assertEquals(v.conversationKey, Hex.encode(conversationKey2))

            val decrypted2 = nip44v2.decrypt(v.payload!!, conversationKey2)
            assertEquals(v.plaintext, decrypted2)
        }
    }

    @Test
    fun encryptDecryptLongTest() {
        for (v in vectors.v2?.valid?.encryptDecryptLongMsg!!) {
            val conversationKey = Hex.decode(v.conversationKey!!)
            val plaintext = v.pattern!!.repeat(v.repeat!!)

            assertEquals(v.plaintextSha256, sha256Hex(plaintext.toByteArray(Charsets.UTF_8)))

            val ciphertext = nip44v2.encryptWithNonce(
                plaintext,
                conversationKey,
                Hex.decode(v.nonce!!)
            ).encode()

            assertEquals(v.payloadSha256, sha256Hex(ciphertext.toByteArray(Charsets.UTF_8)))

            val decrypted = nip44v2.decrypt(ciphertext, conversationKey)

            assertEquals(plaintext, decrypted)
        }
    }

    @Test
    fun invalidMessageLengths() {
        val random = SecureRandom()
        for (v in vectors.v2?.invalid?.encryptMsgLengths!!) {
            val key = ByteArray(32)
            random.nextBytes(key)
            try {
                nip44v2.encrypt("a".repeat(v), key)
                fail("Should Throw for $v")
            } catch (e: Exception) {
                assertNotNull(e)
            }
        }
    }

    @Test
    fun invalidDecrypt() {
        for (v in vectors.v2?.invalid?.decrypt!!) {
            try {
                val result = nip44v2.decrypt(v.payload!!, Hex.decode(v.conversationKey!!))
                assertNull(result)
            } catch (e: Exception) {
                assertNotNull(e)
            }
        }
    }

    @Test
    fun invalidConversationKey() {
        for (v in vectors.v2?.invalid?.getConversationKey!!) {
            try {
                nip44v2.getConversationKey(Hex.decode(v.sec1!!), Hex.decode(v.pub2!!))
                fail("Should Throw for ${v.note}")
            } catch (e: Exception) {
                assertNotNull(e)
            }
        }
    }
}