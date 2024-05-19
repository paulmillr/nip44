# Monocypher 

This is a vendored copy of the Monocypher library, for portable fallback functionality. It primarily provides ChaCha20x encryption and secure memset functionality. They are only used a fallback when the crypto system does not provide a suitable implementation.

## Notices
At the moment this library is an unchanged vendored copy of the original source code found here: https://monocypher.org/

I may make modifications or trim the library down to only include the necessary functions in the future.

## Build details
Unless disabled during generation, the CMake setup will include a static library target and link to it. 

## License
The original repository is dual licensed under BSD 2-Clause and CC0. I am choosing the BSD 2-Clause license for this repository. The license text is included in the `LICENSE` file.

#### Original Authors
Copyright (c) 2017-2023, Loup Vaillant Copyright (c) 2017-2019, Michael Savage Copyright (c) 2017-2023, Fabio Scotoni All rights reserved.