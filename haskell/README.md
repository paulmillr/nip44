# haskell nip44 implementation

extracted from the nostr client futr

see the [futr](https://github.com/futrnostr/futr) repo for the main project.

# Setup

## GHCUp

You can grab GHCUp from the [GHCUp website](https://www.haskell.org/ghcup/).

```bash
sudo apt-get install build-essential zlib1g-dev
curl --proto '=https' --tlsv1.2 -sSf https://get-ghcup.haskell.org | sh
ghcup install ghc 9.6.6
ghcup install cabal 3.10.3.0
ghcup set ghc 9.6.6
ghcup set cabal 3.10.3.0
```

## secp256k1 (from source)

```bash
sudo apt-get install autoconf autogen automake libtool
git clone https://github.com/bitcoin-core/secp256k1 && \
    cd secp256k1 && \
    git checkout v0.5.1 && \
    ./autogen.sh && \
    ./configure --enable-module-schnorrsig --enable-module-extrakeys --enable-module-ecdh --enable-experimental --enable-module-recovery && \
    make && \
    make install && \
    cd ..
```

# Running the tests

```bash
cabal run tests
```

## License

Released under GPLv3.

See [License File](LICENSE).
