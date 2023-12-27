namespace Nip44

open System
open System.Security.Cryptography
open System.Text
open CSChaCha20
open NBitcoin.Secp256k1

module Key =
    let createNewRandom () =
        fun _ -> ECPrivKey.TryCreate(ReadOnlySpan(RandomNumberGenerator.GetBytes(32)))
        |> Seq.initInfinite
        |> Seq.skipWhile (fun (succeed, _) -> not succeed)
        |> Seq.map snd
        |> Seq.head

    let getPubKey (secret: ECPrivKey) = secret.CreateXOnlyPubKey()

module EncryptedPayload =

    let expect expectation errorMsg =
        if not expectation then failwith errorMsg
        
    let sharedKey (he : ECXOnlyPubKey) (mySecret: ECPrivKey) =
        let ecPubKey = ReadOnlySpan(Array.insertAt 0 2uy (he.ToBytes()))
        let hisPubKey = ECPubKey.Create ecPubKey
        let sharedPubKey = hisPubKey.GetSharedPubkey(mySecret).ToBytes()
        sharedPubKey[1..]

    let calculatePaddedLen (len : int) =
        let nextPower = 1 <<< int (Math.Floor(Math.Log2(float (len - 1)))) + 1
        let chunk = if nextPower <= 256 then 32 else nextPower / 8
        if len <= 32 then 32 else chunk * (int (Math.Floor(decimal (len - 1) / decimal chunk)) + 1)

    let pad (plainText : string) =
        let unpadded = Encoding.UTF8.GetBytes plainText
        let unpaddedLen = uint16 unpadded.Length
        expect (unpaddedLen > UInt16.MinValue && unpaddedLen < UInt16.MaxValue) "Invalid plaintext length"
        Array.concat [|
            BitConverter.GetBytes (uint16 unpadded.Length) |> Array.rev
            unpadded
            Array.zeroCreate ((calculatePaddedLen unpadded.Length) - unpadded.Length)
            |]

    let unpad (padded : byte[]) =
        let unpaddedLen = padded[0] * 0xffuy + padded[1] |> int
        let unpadded = padded[2..(2 + unpaddedLen - 1)]
        expect (not (unpaddedLen = 0 || unpaddedLen <> unpadded.Length || (2 + calculatePaddedLen unpaddedLen) <> padded.Length)) "Invalid padding"
        Encoding.UTF8.GetString unpadded

    let conversationKey (sharedKey : byte[]) =
        HKDF.Extract (HashAlgorithmName.SHA256, sharedKey, Encoding.UTF8.GetBytes "nip44-v2")

    let messageKeys (conversationKey : byte[]) (nonce : byte[]) =
        let keys = HKDF.Expand (HashAlgorithmName.SHA256, conversationKey, 76, nonce)
        keys[0..31], keys[32..43], keys[44..75]

    let encrypt (conversationKey : byte[]) (plainText : string) (salt : byte[]) =
        let chachaKey, chachaNonce, authKey = messageKeys conversationKey salt
        let padded = pad plainText
        let chacha20 = new ChaCha20 (chachaKey, chachaNonce, 0u)
        let cipherText = chacha20.EncryptBytes(padded)
        let mac = HMACSHA256.HashData(authKey, Array.concat [| salt;  cipherText |] )
        Array.concat [|
            [| 2uy |] // Version 2
            salt
            cipherText
            mac
        |] |> Convert.ToBase64String

    let decrypt (conversationKey : byte[]) (cipherText : string) =
        expect (cipherText.Length > 0 && cipherText[0] <> '#') "Encryption version is not yet supported"
        expect (cipherText.Length >= 132 && cipherText.Length <= 87472) "Invalid payload size"
        let decoded = Convert.FromBase64String cipherText
        let decodedLen = decoded.Length
        let version, salt, cipherText_, hmac_ = decoded[0], decoded[1..32], decoded[33..decodedLen-33], decoded[decodedLen-32..]
        expect (version = 2uy) "Encryption version is not supported"
        let chachaKey, chachaNonce, authKey = messageKeys conversationKey salt
        let hmac = HMACSHA256.HashData(authKey, Array.concat [| salt; cipherText_ |])
        expect (hmac = hmac_) "Authentication failed"
        let chacha20 = new ChaCha20 (chachaKey, chachaNonce, 0u)
        let padded = chacha20.DecryptBytes(cipherText_)
        unpad padded

