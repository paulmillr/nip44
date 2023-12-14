# Testing

## How to generate valid test vectors

## How to generate invalid test vectors

unknown encryption version # => make # first char
unknown encryption version 0 => encrypt, concatBytes(new Uint8Array([0])
invalid base64 => replace fifth base64 character with "ф"
invalid MAC 1 => replace mac with different mac
invalid MAC 2 => replace mac with zeros
zero-length plaintext => ...
65536b plaintext => ...
invalid padding 1 => make `unpadded.length !== unpaddedLen` fail
invalid padding 2 => make `padded.length !== 2 + u.calcPaddedLen(unpaddedLen)` fail
invalid padding 3 =>
invalid nonce length of 31b
invalid mac length of 31b

unpaddedLen < u.minPlaintextSize ||
unpaddedLen > u.maxPlaintextSize ||
unpadded.length !== unpaddedLen ||
padded.length !== 2 + u.calcPaddedLen(unpaddedLen)
