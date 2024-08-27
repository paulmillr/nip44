﻿
# noscrypt  

<h4 align="left">
  <a href="https://github.com/VnUgE/noscrypt/blob/master/LICENSE">
    <img src="https://img.shields.io/badge/license-LGPL2.1-green.svg" alt="LGPL2.1" />
  </a>
  <a href="https://github.com/VnUgE/noscrypt/tags">
    <img src="https://img.shields.io/github/v/tag/vnuge/noscrypt" alt="Latest tag"/>
  </a>
  <a href="https://github.com/VnUgE/noscrypt/commits">
    <img src="https://img.shields.io/github/last-commit/vnuge/noscrypt/master" alt="Latest commit"/>
  </a>
</h4>

*A compact, C90 cross-platform, cryptography library built specifically for nostr*

## What is noscrypt?
A high-level C utility library built specifically for nostr cryptography operations such as those defined in NIP-01 and the new NIP-44. It was designed to simplify the operations that the secp256k1 library was used for, along with data encryption for the new sepc. It is also being built embedded in mind.  

API Example:
```C
NCValidateSecretKey()
NCGetPublicKey()
NCSignData()
NCVerifyData()
NCEncrypt()
NCDecrypt()
NCComputeMac()
NCVerifyMac()
... extended functions
```

## Motivation
At the time of building this project I have not come across any C-only libraries that exposed functionality for nostr specific cryptography. IMO it is easy to use the secp256k1 library [incorrectly](https://www.vaughnnugent.com/Blog/d9ab8a46cfa8d6bd59cf048fec8d73ffc44f881c). In the process of building [NVault](https://github.com/VnUgE/NVault) NIP-44 came out in December and I realized my libraries were falling short for my needs for proper and safe nostr cryptographic operations, and I needed to start over and start with a good base that has all the basic  functionality built with trusted and tested libraries.  

I wanted a compact and efficient utility library that was portable across systems and runtimes. I will primarily be using this library in a .NET environment, but would like to make a hardware signer sometime. 

### Testing
Testing is an will be important to a cryptography library, I take that responsibility seriously. There are some basic api validation and correctness tests that can be built into an executable called nctest. Full automated testing suite is done in C# interop as part of my [NVault](https://github.com/vnuge/nvault) package. This includes testing against the official nip44 [vector file](https://github.com/paulmillr/nip44/blob/main/nip44.vectors.json). I'm very dependency adverse so native C90 testing using only stdlibs can get gross in a hurry. It will likely happen in the future but not right now. 

### Hardness
- Time sensitive verification always uses fixed time comparison
- No explicit/dynamic memory allocations (in core library)
- Public API function input validation is on by default
- All stack allocated structures are securely zeroed before return
- Stack protection is enabled by default for GCC and MSVC compilers
- Schnorr signatures are validated before the signing function returns
- Carefully selected, widley used, tested, and audited dependencies


## Platform Support
The following table lists the supported platforms and cryptography libraries that noscrypt supports. This will expand in the future. You are free to choose and specify the location of these libraries if you desire during build time, otherwise safe defaults are attempted on your platform.

| Arch | Support | Notes | Tested |
| ----- | ---------- | ------- | ------- |
| Windows | OpenSSL (3.0), Mbed-TLS, BCrypt | NT 6.1 + | ✅ |
| Linux   | OpenSSL (3.0), Mbed-TLS         | GCC only | ✅ |
| FreeBSD | OpenSSL (3.0), Mbed-TLS         | GCC Only |    |


## Getting started
GitHub and Codeberg are only mirrors for my projects. Extended documentation, pre-compiled binaries and source code bundles are always available on my website, along with PGP signatures and checksums.    

[__Project homepage__](https://www.vaughnnugent.com/resources/software/modules/noscrypt)  
[__Startup & Install Guide__](https://www.vaughnnugent.com/resources/software/articles/62ca932f68b8e0b1b99dca6e1c9ffe5538205efb)  
[__Extended Documentation__](https://www.vaughnnugent.com/resources/software/articles?tags=docs,_noscrypt)    

### Super quick start
If you are in a hurry to try out noscrypt these steps will get you by. Otherwise website documentation is authoritative and I encourage you read the docs.

#### Prerequisites
- Supported operating system and compiler from table above
- [CMake](https://cmake.org/download) build system
- [Taskfile.dev](https://taskfile.dev) to execute build recipe

```shell
mkdir noscrypt/ && cd noscrypt/
wget https://www.vaughnnugent.com/public/resources/software/builds/noscrypt/<master-git-hash>/noscrypt/noscrypt-src.tgz
tar -xzf noscrypt-src.tgz
task
sudo task install
```

## Notes
#### Builds
Build packages on my website are "manual" I use an internal tool called *vnbuild* that just does the work of preparing a package, but I have to run it myself.  

#### Branches
There are currently 2 branches I use because of my build process. `develop` and `master`. All changes happen in develop, then are merged to master when I feel like they are stable enough. After some testing and time, a tag and release will become available.   

#### Windows Dlls
msvc pre-compiled packages available for download on the website package page. I have not compatibility tested them yet so they should only support Windows NT version 1904 (10/Server 2016 and later) running amd64 processors. 

## License
The software in this repository is licensed to you under the GNU Lesser GPL v2.1 or later. `SPDX-License-Identifier: LGPL-2.1-or-later` see the [LICENSE](LICENSE) file for more details.    

## Donations
If you feel so inclined to support me an this project, donations are welcome and much appreciated. LNURL coming soon.

BTC On-Chain: ``bc1qgj4fk6gdu8lnhd4zqzgxgcts0vlwcv3rqznxn9``  

I am also a member of [GitCitadel](https://next.nostrudel.ninja/#/wiki/topic/gitcitadel-project) so feel free to [send some sats](https://geyser.fund/project/gitcitadel) that way too!

