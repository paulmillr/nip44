namespace Nip44

open System
open System.IO
open NBitcoin.Secp256k1
open Newtonsoft.Json.Linq
open Xunit
open Xunit.Abstractions
open FsUnit.Xunit

type ``Nip44 Payload encryption``(output:ITestOutputHelper) =

    static let readHex (property : string) (obj : JToken) = obj.Value<string>(property) |> Convert.FromHexString

    static let testVectorsJson path =
        "nip44.vectors.json"
        |> File.ReadAllText
        |> JObject.Parse
        |> fun o -> o["v2"][path]

    static let ConversationKeys () =
        "valid"
        |> testVectorsJson
        |> fun x -> x["get_conversation_key"]
        |> Seq.map (fun x ->
            [|
               x |> readHex "sec1" |> ECPrivKey.Create |> box
               x |> readHex "pub2" |> ECXOnlyPubKey.Create |> box
               x |> readHex "conversation_key" |> box
            |])

    static let MessageKeys () =
        "valid"
        |> testVectorsJson
        |> fun x -> x["get_message_keys"]
        |> fun x -> (x["keys"] |> Seq.map (fun k -> k, x |> readHex "conversation_key"))
        |> Seq.map (fun (k, ck) ->
            [|
              ck |> box
              k |> readHex "nonce" |> box
              k |> readHex "chacha_key" |> box
              k |> readHex "chacha_nonce" |> box
              k |> readHex "hmac_key" |> box
            |])

    static let PadLengths () =
        "valid"
        |> testVectorsJson
        |> fun x -> x["calc_padded_len"]
        |> Seq.map (fun arr -> [| box (int arr[0]); box (int arr[1]) |])

    static let EncryptDecrypts () =
        "valid"
        |> testVectorsJson
        |> fun x -> x["encrypt_decrypt"]
        |> Seq.map (fun x ->
            [|
              x |> readHex "sec1" |> ECPrivKey.Create |> box
              x |> readHex "sec2" |> ECPrivKey.Create |> box
              x |> readHex "conversation_key" |> box
              x |> readHex "nonce" |> box
              x.Value<string>("plaintext") |> box
              x.Value<string>("payload") |> box
            |])

    [<Theory>]
    [<MemberData(nameof(ConversationKeys))>]
    let ``Conversation Key (valid)`` (sec1: ECPrivKey) (pub2 : ECXOnlyPubKey) (expectedConversationKey : byte[]) =
        let sharedKey = EncryptedPayload.sharedKey pub2 sec1
        let conversationKey = EncryptedPayload.conversationKey sharedKey
        should equal expectedConversationKey conversationKey

    [<Theory>]
    [<MemberData(nameof(MessageKeys))>]
    let ``Message Key (valid)`` (conversationKey : byte[]) (nonce : byte[]) (expectedChachaKey : byte[]) (expectedChachaNonce : byte[]) (expectedAuthKey : byte[]) =
        let keys = EncryptedPayload.messageKeys conversationKey nonce
        should equal (expectedChachaKey, expectedChachaNonce , expectedAuthKey) keys

    [<Theory>]
    [<MemberData(nameof(PadLengths))>]
    let ``Calculate padding (valid)`` (unpaddedLen : int) (paddedLen : int) =
        should equal paddedLen (EncryptedPayload.calculatePaddedLen unpaddedLen)

    [<Theory>]
    [<MemberData(nameof(EncryptDecrypts))>]
    let ``Encryption and decryption (valid)`` (sec1 : ECPrivKey) (sec2 : ECPrivKey) (expectedConversationKey : byte[]) (nonce : byte[]) (expectedPlainText : string) (expectedPayload : string) =
        let sharedKey = EncryptedPayload.sharedKey (sec2 |> Key.getPubKey) sec1
        let conversationKey = EncryptedPayload.conversationKey sharedKey
        should equal expectedConversationKey conversationKey
        let payload = EncryptedPayload.encrypt conversationKey expectedPlainText nonce
        should equal expectedPayload payload
        let plainText = EncryptedPayload.decrypt conversationKey expectedPayload
        should equal expectedPlainText plainText

