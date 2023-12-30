**NIP-44 implementation in Go**

---

**DISCLAIMER - READ BEFORE USING**

**This library does not make sure yet that the secp256k1 keys you want to use for the conversation key are valid, protected against twist attacks and not contain any other weaknesses as mentioned in the [NIP-44 security audit](https://cure53.de/audit-report_nip44-implementations.pdf).**

**If you really want to use this library before this is fixed, you need to make sure that the keys you use with `GenerateConversationKey` are not affected yourself.**

See [documentation of `secp256k1.PrivKeyFromBytes`](https://pkg.go.dev/github.com/decred/dcrd/dcrec/secp256k1/v4#PrivKeyFromBytes) and comment in `nip44.GenerateConversationkey`:

```
func GenerateConversationKey(sendPrivkey *secp256k1.PrivateKey, recvPubkey *secp256k1.PublicKey) []byte {
    // TODO: Make sure keys are not invalid or weak since the secp256k1 package does not.
    // See documentation of secp256k1.PrivKeyFromBytes:
    // ================================================================================
    // | WARNING: This means passing a slice with more than 32 bytes is truncated and |
    // | that truncated value is reduced modulo N.  Further, 0 is not a valid private |
    // | key.  It is up to the caller to provide a value in the appropriate range of  |
    // | [1, N-1].  Failure to do so will either result in an invalid private key or  |
    // | potentially weak private keys that have bias that could be exploited.        |
    // ================================================================================
    // -- https://pkg.go.dev/github.com/decred/dcrd/dcrec/secp256k1/v4#PrivKeyFromBytes
```

---

NIP-44 specification: https://github.com/nostr-protocol/nips/blob/master/44.md

To use as library: `go get -u git.ekzyis.com/ekzyis/nip44`

To run tests, clone repository and then run `go test`.

