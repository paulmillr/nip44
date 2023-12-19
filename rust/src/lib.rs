use base64::Engine;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use secp256k1::ecdh::shared_secret_point;
use secp256k1::{Parity, PublicKey, SecretKey, XOnlyPublicKey};
use sha2::Sha256;

mod error;
pub use error::Error;

#[cfg(test)]
mod tests;

struct MessageKeys([u8; 76]);

impl MessageKeys {
    #[inline]
    pub fn zero() -> MessageKeys {
        MessageKeys([0; 76])
    }

    #[inline]
    pub fn encryption(&self) -> [u8; 32] {
        self.0[0..32].try_into().unwrap()
    }

    #[inline]
    pub fn nonce(&self) -> [u8; 12] {
        self.0[32..44].try_into().unwrap()
    }

    #[inline]
    pub fn auth(&self) -> [u8; 32] {
        self.0[44..76].try_into().unwrap()
    }
}

/// A conversation key is the long-term secret that two nostr identities share.
fn get_shared_point(private_key_a: SecretKey, x_only_public_key_b: XOnlyPublicKey) -> [u8; 32] {
    let pubkey = PublicKey::from_x_only_public_key(x_only_public_key_b, Parity::Even);
    let mut ssp = shared_secret_point(&pubkey, &private_key_a)
        .as_slice()
        .to_owned();
    ssp.resize(32, 0); // toss the Y part
    ssp.try_into().unwrap()
}

pub fn get_conversation_key(
    private_key_a: SecretKey,
    x_only_public_key_b: XOnlyPublicKey,
) -> [u8; 32] {
    let shared_point = get_shared_point(private_key_a, x_only_public_key_b);
    let (convo_key, _hkdf) =
        Hkdf::<Sha256>::extract(Some("nip44-v2".as_bytes()), shared_point.as_slice());
    convo_key.into()
}

fn get_message_keys(conversation_key: &[u8; 32], nonce: &[u8; 32]) -> Result<MessageKeys, Error> {
    let hk: Hkdf<Sha256> = match Hkdf::from_prk(conversation_key) {
        Ok(hk) => hk,
        Err(_) => return Err(Error::HkdfLength(conversation_key.len())),
    };
    let mut message_keys: MessageKeys = MessageKeys::zero();
    if hk.expand(&nonce[..], &mut message_keys.0).is_err() {
        return Err(Error::HkdfLength(message_keys.0.len()));
    }
    Ok(message_keys)
}

fn calc_padding(len: usize) -> usize {
    if len < 32 {
        return 32;
    }
    let nextpower = 1 << ((len - 1).ilog2() + 1);
    let chunk = if nextpower <= 256 { 32 } else { nextpower / 8 };
    if len <= 32 {
        32
    } else {
        chunk * (((len - 1) / chunk) + 1)
    }
}

fn pad(unpadded: &str) -> Result<Vec<u8>, Error> {
    let len: usize = unpadded.len();
    if len < 1 {
        return Err(Error::MessageIsEmpty);
    }
    if len > 65536 - 128 {
        return Err(Error::MessageIsTooLong);
    }

    let mut padded: Vec<u8> = Vec::new();
    padded.extend_from_slice(&(len as u16).to_be_bytes());
    padded.extend_from_slice(unpadded.as_bytes());
    padded.extend(std::iter::repeat(0).take(calc_padding(len) - len));
    Ok(padded)
}

/// Encrypt a plaintext message with a conversation key.
/// The output is a base64 encoded string that can be placed into message contents.
#[inline]
pub fn encrypt(conversation_key: &[u8; 32], plaintext: &str) -> Result<String, Error> {
    encrypt_inner(conversation_key, plaintext, None)
}

fn encrypt_inner(
    conversation_key: &[u8; 32],
    plaintext: &str,
    override_random_nonce: Option<&[u8; 32]>,
) -> Result<String, Error> {
    let nonce = match override_random_nonce {
        Some(nonce) => nonce.to_owned(),
        None => {
            let mut nonce: [u8; 32] = [0; 32];
            OsRng.fill_bytes(&mut nonce);
            nonce
        }
    };

    let keys = get_message_keys(conversation_key, &nonce)?;
    let mut buffer = pad(plaintext)?;
    let mut cipher = ChaCha20::new(&keys.encryption().into(), &keys.nonce().into());
    cipher.apply_keystream(&mut buffer);
    let mut mac = Hmac::<Sha256>::new_from_slice(&keys.auth())?;
    mac.update(&nonce);
    mac.update(&buffer);
    let mac_bytes = mac.finalize().into_bytes();

    let mut pre_base64: Vec<u8> = vec![2];
    pre_base64.extend_from_slice(&nonce);
    pre_base64.extend_from_slice(&buffer);
    pre_base64.extend_from_slice(&mac_bytes);

    Ok(base64::engine::general_purpose::STANDARD.encode(&pre_base64))
}

/// Decrypt the base64 encrypted contents with a conversation key
pub fn decrypt(conversation_key: &[u8; 32], base64_ciphertext: &str) -> Result<String, Error> {
    if base64_ciphertext.as_bytes()[0] == b'#' {
        return Err(Error::UnsupportedFutureVersion);
    }
    let binary_ciphertext: Vec<u8> =
        base64::engine::general_purpose::STANDARD.decode(base64_ciphertext)?;
    let version = binary_ciphertext[0];
    if version != 2 {
        return Err(Error::UnknownVersion);
    }
    let dlen = binary_ciphertext.len();
    let nonce = &binary_ciphertext[1..33];
    let mut buffer = binary_ciphertext[33..dlen - 32].to_owned();
    let mac = &binary_ciphertext[dlen - 32..dlen];
    let keys = get_message_keys(conversation_key, &nonce.try_into().unwrap())?;
    let mut calculated_mac = Hmac::<Sha256>::new_from_slice(&keys.auth())?;
    calculated_mac.update(&nonce);
    calculated_mac.update(&buffer);
    let calculated_mac_bytes = calculated_mac.finalize().into_bytes();
    if !constant_time_eq::constant_time_eq(mac, calculated_mac_bytes.as_slice()) {
        return Err(Error::InvalidMac);
    }
    let mut cipher = ChaCha20::new(&keys.encryption().into(), &keys.nonce().into());
    cipher.apply_keystream(&mut buffer);
    let unpadded_len = u16::from_be_bytes(buffer[0..2].try_into().unwrap()) as usize;
    if buffer.len() < 2 + unpadded_len {
        return Err(Error::InvalidPadding);
    }
    let unpadded = &buffer[2..2 + unpadded_len];
    if unpadded.is_empty() {
        return Err(Error::MessageIsEmpty);
    }
    if unpadded.len() != unpadded_len {
        return Err(Error::InvalidPadding);
    }
    if buffer.len() != 2 + calc_padding(unpadded_len) {
        return Err(Error::InvalidPadding);
    }
    Ok(String::from_utf8(unpadded.to_vec())?)
}
