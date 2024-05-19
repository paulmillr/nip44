# noscrypt
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

There are no functions that handle key generation, because secp256k1 simply requires a 32byte random number that needs to only be validated. I assume most applications will prefer and or have better random number generators than I can assume. Use your preferred or platform CSRNG.  

## Motivation
At the time of building this project I have not come across any C-only libraries that exposed functionality for nostr specific cryptography. IMO it is easy to use the secp256k1 library incorrectly. In the process of building [NVault](https://github.com/VnUgE/NVault) NIP-44 came out in December and I realized my libraries were falling short for my needs for proper and safe nostr cryptographic operations, and I needed to start over and start with a good base that has all the basic  functionality built with trusted and tested libraries.  

I wanted a compact and efficient utility library that was portable across systems and runtimes. I will primarily be using this library in a .NET environment, but would like to make a hardware signer sometime. 

### Testing
Testing is an will be important to a cryptography library, I take that responsibility seriously. There are some basic api validation and correctness tests that can be built into an executable called nctest. Full automated testing suite is done in C# interop as part of my [NVault](https://github.com/vnuge/nvault) package. This includes testing against the official nip44 [vector file](https://github.com/paulmillr/nip44/blob/main/nip44.vectors.json). I'm very dependency adverse so native C90 testing using only stdlibs can get gross in a hurry. It will likely happen in the future but not right now. 

### Hardness
- Time sensitive verification always uses fixed time comparison
- No explicit/dynamic memory allocations
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


## Packages and Docs
GitHub is simply a mirror for my projects. Extended documentation, pre-compiled binaries and source code bundles are always available on my website, along with PGP signatures and checksums.    

[Docs and Articles](https://www.vaughnnugent.com/resources/software/articles?tags=docs,_noscrypt)  
[Builds and Source](https://www.vaughnnugent.com/resources/software/modules/noscrypt)  

### Getting the package
There are 3 ways to get the source code to build this project.  
1. Download the signed `noscrypt-src.tgz` package from my website above (recommended)
2. Clone the GitHub repo `git clone https://github.com/VnUgE/noscrypt.git`  
3. Download a github archive or release when they are available  

## Building
Please see extended documentation for all custom build configurations and tips. For now, here is enough to get most developers going. 

### CMake
```shell
cmake -S . -Bbuild/ -DCMAKE_BUILD_TYPE=Release
```

#### Enable built-in tets and debug mode
```shell
cmake -S . -Bbuild/test -DCMAKE_BUILD_TYPE=Debug -DNC_BUILD_TESTS=ON
```

#### Specify the crypto library
```shell
cmake -S . -Bbuild/ -DCMAKE_BUILD_TYPE=Release -DCRYPTO_LIB=<openssl | mbedtls | bcrypt>
```

### Easy mode
A [Taskfile](https://taskfile.dev) file is included for easy building if you wish to build in easy mode! Use the `task --list-all` to see all available commands. The default command `task` will build the library in release mode using defaults. You may specify extra cmake build variables using the `USER_ARGS` variable on the command line.

## Notes
#### Builds
Build packages on my website are "manual" I use an internal tool called *vnbuild* that just does the work of preparing a package, but I have to run it myself.  

#### Branches
There are currently 2 branches I use because of my build process. `develop` and `master`. All changes happen in develop, then are merged to master when I feel like they are stable enough. After some testing and time, a tag and release will become available.   

#### Windows Dlls
You may notice that I have msvc pre-compiled packages available for download. I have not compatibility tested them yet so they should only support Windows 10/Server version 1904 running amd64 processors. 

## License
The software in this repository is licensed to you under the GNU Lesser GPL v2.1 or later. `SPDX-License-Identifier: LGPL-2.1-or-later` see the [LICENSE](LICENSE) file for more details.    

## Donations
If you feel so inclined to support me an this project, donations are welcome and much appreciated.   

BTC On-Chain: ``bc1qgj4fk6gdu8lnhd4zqzgxgcts0vlwcv3rqznxn9``  

