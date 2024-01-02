import com.fasterxml.jackson.annotation.JsonProperty

data class VectorFile (
    val v2 : V2? = V2()
)

data class V2 (
    val valid   : Valid?   = Valid(),
    val invalid : Invalid? = Invalid()
)

data class Valid (
    @JsonProperty("get_conversation_key"     ) val getConversationKey    : ArrayList<GetConversationKey>    = arrayListOf(),
    @JsonProperty("get_message_keys"         ) val getMessageKeys        : GetMessageKeys?                  = GetMessageKeys(),
    @JsonProperty("calc_padded_len"          ) val calcPaddedLen         : ArrayList<ArrayList<Int>>        = arrayListOf(),
    @JsonProperty("encrypt_decrypt"          ) val encryptDecrypt        : ArrayList<EncryptDecrypt>        = arrayListOf(),
    @JsonProperty("encrypt_decrypt_long_msg" ) val encryptDecryptLongMsg : ArrayList<EncryptDecryptLongMsg> = arrayListOf()
)

data class Invalid (
    @JsonProperty("encrypt_msg_lengths"  ) val encryptMsgLengths  : ArrayList<Int>                = arrayListOf(),
    @JsonProperty("get_conversation_key" ) val getConversationKey : ArrayList<GetConversationKey> = arrayListOf(),
    @JsonProperty("decrypt"              ) val decrypt            : ArrayList<Decrypt>            = arrayListOf()
)

data class GetConversationKey (
    val sec1 : String? = null,
    val pub2 : String? = null,
    val note : String? = null,
    @JsonProperty("conversation_key" ) val conversationKey : String? = null
)

data class GetMessageKeys (
    @JsonProperty("conversation_key" ) val conversationKey : String?         = null,
    val keys : ArrayList<Keys> = arrayListOf()
)

data class Keys (
    @JsonProperty("nonce"        ) val nonce       : String? = null,
    @JsonProperty("chacha_key"   ) val chachaKey   : String? = null,
    @JsonProperty("chacha_nonce" ) val chachaNonce : String? = null,
    @JsonProperty("hmac_key"     ) val hmacKey     : String? = null
)

data class EncryptDecrypt (
    val sec1            : String? = null,
    val sec2            : String? = null,
    @JsonProperty("conversation_key" ) val conversationKey : String? = null,
    val nonce           : String? = null,
    val plaintext       : String? = null,
    val payload         : String? = null
)

data class EncryptDecryptLongMsg (
    @JsonProperty("conversation_key" ) val conversationKey : String? = null,
    val nonce           : String? = null,
    val pattern         : String? = null,
    val repeat          : Int?    = null,
    @JsonProperty("plaintext_sha256" ) val plaintextSha256 : String? = null,
    @JsonProperty("payload_sha256"   ) val payloadSha256   : String? = null
)

data class Decrypt (
    @JsonProperty("conversation_key" ) val conversationKey : String? = null,
    val nonce           : String? = null,
    val plaintext       : String? = null,
    val payload         : String? = null,
    val note            : String? = null
)