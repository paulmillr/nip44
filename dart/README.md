# NIP-44 Dart Library

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/chebizarro/dart-nip44/blob/main/LICENSE)

A Dart implementation of [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md), providing encryption and decryption functionalities for the [Nostr](https://nostr.com/) protocol.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Encrypting a Message](#encrypting-a-message)
  - [Decrypting a Message](#decrypting-a-message)
- [Examples](#examples)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [License](#license)

## Introduction

NIP-44 specifies a protocol for end-to-end encrypted messages in the Nostr network. This library provides Dart developers with an easy-to-use interface to implement NIP-44 encryption and decryption in their applications.

## Features

- Encrypt messages according to the NIP-44 specification.
- Decrypt messages encrypted with NIP-44.
- Generate conversation keys using Elliptic Curve Diffie-Hellman (ECDH).
- Compatible with other NIP-44 implementations in different languages.

## Installation

Add the following to your `pubspec.yaml`:

```yaml
dependencies:
  git:
    url: https://github.com/chebizarrp/dart-nip44.git
    ref: master

```

Then run:

```bash
dart pub get
```

## Usage

### Import the Package

```dart
import 'package:nip44/nip44.dart';
```

### Encrypting a Message

```dart
import 'package:nip44/nip44.dart';

void main() async {
  String plaintext = 'Hello, Nostr!';
  String senderPrivateKey = 'your_private_key_hex';
  String recipientPublicKey = 'recipient_public_key_hex';

  String encryptedMessage = await Nip44.encryptMessage(
    plaintext,
    senderPrivateKey,
    recipientPublicKey,
  );

  print('Encrypted Message: $encryptedMessage');
}
```

### Decrypting a Message

```dart
import 'package:nip44/nip44.dart';

void main() async {
  String encryptedMessage = 'encrypted_message_from_sender';
  String recipientPrivateKey = 'your_private_key_hex';
  String senderPublicKey = 'sender_public_key_hex';

  String decryptedMessage = await Nip44.decryptMessage(
    encryptedMessage,
    recipientPrivateKey,
    senderPublicKey,
  );

  print('Decrypted Message: $decryptedMessage');
}
```

## Examples

You can find more examples in the [`example`](https://github.com/chebizarro/dart-nip44/tree/main/example) directory.


## API Reference

### `Nip44` Class

- **encryptMessage(String plaintext, String senderPrivateKey, String recipientPublicKey)**

  Encrypts a plaintext message using the NIP-44 specification.

- **decryptMessage(String encryptedMessage, String recipientPrivateKey, String senderPublicKey)**

  Decrypts an encrypted message using the NIP-44 specification.

## Contributing

Contributions are welcome! Please read the [contribution guidelines](https://github.com/chebizarro/dart-nip44/blob/main/CONTRIBUTING.md) first.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/chebizarro/dart-nip44/blob/main/LICENSE) file for details.
