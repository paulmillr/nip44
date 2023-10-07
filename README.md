# nip44 implementations

Collection of NIP44 implementations in different languages.

NIP 44 is spec for [nostr](https://nostr.com) that aims to add secure encrypted payloads.
It can be used to implement end-to-end encrypted direct messaging, among other things.

The spec [has not been merged yet](https://github.com/nostr-protocol/nips/pull/746).
For now it is available at: [spec.md](./spec.md).

## Code

The code was copied from:

- Go (MIT): https://git.ekzyis.com/ekzyis/nip44
- JavaScript / TypeScript (public domain): https://github.com/nostr-protocol/nips
- Rust (MIT): https://github.com/mikedilger/nip44


## Performance

Benchmarks without getConversationKey (ECDH):

- Rust: 16B x 670,000 ops/sec @ 1.35µs/op, 512B x 500,000 ops/sec @ 2µs/op
- JS: 16B x 46,446 ops/sec @ 21µs/op, 512B x 14,821 ops/sec @ 67µs/op

## Test vectors

Check out `javascript/nip44.vectors.json`
