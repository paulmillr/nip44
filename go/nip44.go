package nip44

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

var (
	MaxPlaintextSize = 65536 - 128 // 64kb - 128
)

type EncryptOptions struct {
	Salt    []byte
	Version int
}

func Encrypt(conversationKey []byte, plaintext string, options *EncryptOptions) (string, error) {
	var (
		version    int = 2
		salt       []byte
		enc        []byte
		nonce      []byte
		auth       []byte
		padded     []byte
		ciphertext []byte
		hmac_      []byte
		concat     []byte
		err        error
	)
	if options.Version != 0 {
		version = options.Version
	}
	if options.Salt != nil {
		salt = options.Salt
	} else {
		if salt, err = randomBytes(32); err != nil {
			return "", err
		}
	}
	if version != 2 {
		return "", errors.New("unknown version")
	}
	if len(salt) != 32 {
		return "", errors.New("salt must be 32 bytes")
	}
	if enc, nonce, auth, err = messageKeys(conversationKey, salt); err != nil {
		return "", err
	}
	if padded, err = pad(plaintext); err != nil {
		return "", err
	}
	if ciphertext, err = chacha20_(enc, nonce, []byte(padded)); err != nil {
		return "", err
	}
	hmac_ = sha256Hmac(auth, ciphertext)
	concat = append(concat, []byte{byte(version)}...)
	concat = append(concat, salt...)
	concat = append(concat, ciphertext...)
	concat = append(concat, hmac_...)
	return base64.StdEncoding.EncodeToString(concat), nil
}

func Decrypt(conversationKey []byte, ciphertext string) (string, error) {
	var (
		version     int = 2
		decoded     []byte
		dLen        int
		salt        []byte
		ciphertext_ []byte
		hmac_       []byte
		enc         []byte
		nonce       []byte
		auth        []byte
		padded      []byte
		unpaddedLen uint16
		unpadded    []byte
		err         error
	)
	if ciphertext[0:1] == "#" {
		return "", errors.New("unknown version")
	}
	if decoded, err = base64.StdEncoding.DecodeString(ciphertext); err != nil {
		return "", errors.New("invalid base64")
	}
	if version = int(decoded[0]); version != 2 {
		return "", errors.New("unknown version")
	}
	dLen = len(decoded)
	salt, ciphertext_, hmac_ = decoded[1:33], decoded[33:dLen-32], decoded[dLen-32:]
	if enc, nonce, auth, err = messageKeys(conversationKey, salt); err != nil {
		return "", err
	}
	if !bytes.Equal(hmac_, sha256Hmac(auth, ciphertext_)) {
		return "", errors.New("invalid hmac")
	}
	if padded, err = chacha20_(enc, nonce, ciphertext_); err != nil {
		return "", err
	}
	unpaddedLen = binary.BigEndian.Uint16(padded[0:2])
	unpadded = padded[2 : unpaddedLen+2]
	if len(unpadded) == 0 || len(unpadded) != int(unpaddedLen) || len(padded) != 2+calcPadding(int(unpaddedLen)) {
		return "", errors.New("invalid padding")
	}
	return string(unpadded), nil
}

func GenerateConversationKey(sendPrivkey *secp256k1.PrivateKey, recvPubkey *secp256k1.PublicKey) []byte {
	return secp256k1.GenerateSharedSecret(sendPrivkey, recvPubkey)
}

func chacha20_(key []byte, nonce []byte, message []byte) ([]byte, error) {
	var (
		cipher *chacha20.Cipher
		dst    = make([]byte, len(message))
		err    error
	)
	if cipher, err = chacha20.NewUnauthenticatedCipher(key, nonce); err != nil {
		return nil, err
	}
	cipher.XORKeyStream(dst, message)
	return dst, nil
}

func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func sha256Hmac(key []byte, ciphertext []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(ciphertext)
	return h.Sum(nil)
}

func messageKeys(conversationKey []byte, salt []byte) ([]byte, []byte, []byte, error) {
	var (
		r     io.Reader
		enc   []byte = make([]byte, 32)
		nonce []byte = make([]byte, 12)
		auth  []byte = make([]byte, 32)
		err   error
	)
	r = hkdf.New(sha256.New, conversationKey, salt, []byte("nip44-v2"))
	if _, err = io.ReadFull(r, enc); err != nil {
		return nil, nil, nil, err
	}
	if _, err = io.ReadFull(r, nonce); err != nil {
		return nil, nil, nil, err
	}
	if _, err = io.ReadFull(r, auth); err != nil {
		return nil, nil, nil, err
	}
	return enc, nonce, auth, nil
}

func pad(s string) ([]byte, error) {
	var (
		sb      []byte
		sbLen   int
		padding int
		result  []byte
	)
	sb = []byte(s)
	sbLen = len(sb)
	if sbLen < 1 || sbLen >= MaxPlaintextSize {
		return nil, errors.New("plaintext should be between 1b and 64kB")
	}
	padding = calcPadding(sbLen)
	result = make([]byte, 2)
	binary.BigEndian.PutUint16(result, uint16(sbLen))
	result = append(result, sb...)
	result = append(result, make([]byte, padding-sbLen)...)
	return result, nil
}

func calcPadding(sLen int) int {
	var (
		nextPower int
		chunk     int
	)
	if sLen <= 32 {
		return 32
	}
	nextPower = 1 << int(math.Floor(math.Log2(float64(sLen-1)))+1)
	chunk = int(math.Max(32, float64(nextPower/8)))
	return chunk * int(math.Floor(float64((sLen-1)/chunk))+1)
}
