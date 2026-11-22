## Intel Unnati Industrial Training Program 2024

This project was developed in the context of the Intel® Unnati Industrial Training Program, a project-based training program for students from Indian colleges and universities in the Intel Unnati community. The program centers on industry-relevant challenges using emerging technologies, with guidance from Intel and industry mentors.

UDP Party is a C++ client/server chat prototype exploring cryptographic communication. Its crypto components relate to the program's “Cryptography Simulation with mbedTLS/OpenSSL” challenge theme. The repository does not specify the team's assigned problem statement.

For program details, see the [Intel® Unnati Industrial Training Program](https://www.intel.in/content/www/in/en/corporate/unnati/industrial-training-program.html).

## Features represented in the source

- UDP-based client and server sessions, with per-session IDs and message counters.
- A rule-based ELIZA responder with keyword matching, canned responses, and simple pronoun substitutions.
- An OpenSSL wrapper containing SHA-256 HMAC, HKDF-SHA-256, AES-256-GCM, Diffie–Hellman, RSA signing/verification, and X.509 certificate handling code.
- A standalone crypto test program with test cases for HMAC, symmetric encryption, RSA signatures, Diffie–Hellman, and certificate checks.

These are source-level capabilities and intended behaviors; they have not been verified by a build or test run for this README.

## Technology and dependencies

| Area | Repository evidence |
| --- | --- |
| Language | C++ |
| Networking | UDP sockets through the Windows Winsock API or POSIX socket APIs |
| Cryptography | OpenSSL implementation in `implementation/crypto_wrapper_openssl.cpp`; an mbedTLS source file is also present but is incomplete |
| Build configurations | GNU Makefiles and Visual Studio C++ project/solution files |
| Randomness | `Utils::generateRandom` uses the x86 RDRAND intrinsic |

There is no package-manager manifest or dependency installer. OpenSSL is required for the OpenSSL configuration. The GNU Makefile expects OpenSSL under `/usr/local/openssl` by default, while the Visual Studio project references `C:\Program Files\OpenSSL-Win64`. The mbedTLS Makefile option refers to a local `mbedtls` directory, which is not included in this repository.

## Architecture

1. `implementation/main.cpp` parses command-line options. With no `-ip` option it starts the server; with `-ip` it starts the client.
2. `ServerSession` listens for UDP traffic and tracks child sessions. A new session begins with the client's hello message; the server responds and assigns a session ID.
3. The client and server session classes share message framing, session state, and crypto-related operations through `Session`.
4. The server creates an `Eliza` instance for a new session and routes received text to it. The client reads text from standard input and displays server responses.
5. `Socket` implements UDP send/receive. `CryptoWrapper` provides the cryptographic API used by session setup and message protection.

The protocol code describes a SIGMA-style handshake: exchange ephemeral Diffie–Hellman public values, exchange certificates and signatures, check the peer certificate against a configured identity, and derive a session key. The OpenSSL wrapper contains AES-GCM encryption and decryption routines for data messages. See [Limitations](#limitations) for important gaps between this design and a verified implementation.

## Repository structure

```text
.
├── README.md
├── Presentation.pptx
├── Report.docx
├── Video.mp4
└── implementation/
    ├── .gitattributes
    ├── .gitignore
    ├── Makefile
    ├── udp_party.sln
    ├── udp_party.vcxproj
    ├── main.cpp
    ├── client.cpp
    ├── client.h
    ├── client_session.cpp
    ├── client_session.h
    ├── server.cpp
    ├── server.h
    ├── server_session.cpp
    ├── server_session.h
    ├── session.cpp
    ├── session.h
    ├── session_internals.h
    ├── sockets.cpp
    ├── sockets.h
    ├── types.cpp
    ├── types.h
    ├── utils.cpp
    ├── utils.h
    ├── eliza.cpp
    ├── eliza.h
    ├── crypto_wrapper.h
    ├── crypto_wrapper_openssl.cpp
    ├── crypto_wrapper_mbedtls.cpp
    ├── crypto_wrapper_empty.cpp
    ├── params.txt
    ├── alice.crt
    ├── alice.csr
    ├── alice.key
    ├── bob.crt
    ├── bob.csr
    ├── bob.key
    ├── rootCA.crt
    ├── rootCA.key
    └── crypto_test/
        ├── Makefile
        ├── crypto_test.vcxproj
        ├── main.cpp
        ├── alice.crt
        ├── alice.csr
        ├── alice.key
        ├── bob.crt
        ├── bob.csr
        ├── bob.key
        ├── rootCA.crt
        └── rootCA.key
```

### Main components

| Files | Responsibility |
| --- | --- |
| [`main.cpp`](implementation/main.cpp), [`client.cpp`](implementation/client.cpp), [`server.cpp`](implementation/server.cpp) | CLI parsing and top-level client/server loops |
| [`client_session.cpp`](implementation/client_session.cpp), [`server_session.cpp`](implementation/server_session.cpp), [`session.cpp`](implementation/session.cpp) | Handshake state, message exchange, session lifecycle, and payload handling |
| [`sockets.cpp`](implementation/sockets.cpp) | UDP socket creation, binding, sending, and receiving |
| [`crypto_wrapper.h`](implementation/crypto_wrapper.h), [`crypto_wrapper_openssl.cpp`](implementation/crypto_wrapper_openssl.cpp) | Crypto API and OpenSSL implementation |
| [`crypto_wrapper_mbedtls.cpp`](implementation/crypto_wrapper_mbedtls.cpp), [`crypto_wrapper_empty.cpp`](implementation/crypto_wrapper_empty.cpp) | Additional backend source files; neither provides a usable alternative in its current state |
| [`eliza.cpp`](implementation/eliza.cpp), [`eliza.h`](implementation/eliza.h) | Rule-based conversation responses |
| [`utils.cpp`](implementation/utils.cpp), [`types.cpp`](implementation/types.cpp) | Random generation, file/buffer helpers, memory cleanup, and byte-buffer ownership |
| [`crypto_test/main.cpp`](implementation/crypto_test/main.cpp) | Standalone crypto test cases |
| [`params.txt`](implementation/params.txt) | Example server and client invocation syntax |

The root-level presentation, report, and video are present as binary files. Their contents were not inspected, so this README does not characterize their subject matter.

## Build configuration

The repository contains build descriptions but no build was run as part of this documentation-only change.

### GNU Make

From the repository root, the main Makefile declares an OpenSSL build as:

```sh
make -C implementation CRYPTO=openssl
```

The Makefile also names `mbedtls` and `ipp_crypto` options. These options should not be assumed to work: the mbedTLS directory is absent, and the IPP Crypto wrapper is not present as a usable implementation. The OpenSSL source uses `fopen_s`, and the Makefile's OpenSSL directory is platform-specific, so a GNU/Linux build is not established by the repository configuration alone.

### Visual Studio

Open [`implementation/udp_party.sln`](implementation/udp_party.sln) in Visual Studio. The project specifies the v143 toolset and Windows 10 SDK. Its OpenSSL include and library paths are hard-coded to `C:\Program Files\OpenSSL-Win64`; the `OPENSSL` preprocessor definition is set for the main project's Debug x64 configuration. Other configurations do not declare the same crypto setup, so they should not be presumed buildable.

## Configuration and usage

The executable accepts the following options:

| Option | Meaning |
| --- | --- |
| `-ip` | Remote server IPv4 address; its presence selects client mode |
| `-port` | UDP port |
| `-key` | Private-key file |
| `-pwd` | Optional private-key password |
| `-cert` | Local certificate file |
| `-root` | Root CA certificate file |
| `-peer` | Expected remote peer identity |

Run the program from `implementation/` so the example certificate and key paths resolve. The checked-in `params.txt` shows the intended peer names and port. The following example substitutes a placeholder for the key password rather than reproducing the value in that file:

**Terminal 1 — server**

```powershell
.\udp_party.exe -port 60000 -key alice.key -pwd YOUR_KEY_PASSWORD -cert alice.crt -root rootCA.crt -peer Bob.com
```

**Terminal 2 — client**

```powershell
.\udp_party.exe -ip 127.0.0.1 -port 60000 -key bob.key -pwd YOUR_KEY_PASSWORD -cert bob.crt -root rootCA.crt -peer Alice.com
```

The server binds to `127.0.0.1` in `server_session.cpp`, so the checked-in implementation is limited to loopback communication; the example does not demonstrate communication between separate hosts. The command-line password option is passed to the private-key reader. Do not reuse the repository's key material or put real credentials in shared shell history or process command lines.

## Tests

`implementation/crypto_test/` contains a standalone test program and Makefile, but there is no repository-level test runner or CI configuration. The test source includes cases for HMAC, AES-GCM round-trip, RSA signing and verification, Diffie–Hellman shared-secret agreement, and certificate validation. Its Diffie–Hellman test contains a malformed qualified call (`CryptoWrapper::CryptoWrapper::startDh`), and the crypto backends/configurations have other incomplete paths. Test results are therefore undocumented and should not be inferred from the presence of the test source.

## Limitations

- The mbedTLS and default/empty crypto source files are enclosed in block comments; the mbedTLS file also contains unfinished placeholder constants. They are not functional backend implementations as checked in.
- `Session::deriveMacKey` is defined but is not called before `_macKey` is used to calculate certificate MACs in the handshake. The handshake therefore cannot be treated as a verified, working authenticated protocol.
- The OpenSSL signing functions use SHA-256 digest-sign/verify calls, but the code does not explicitly configure RSA-PSS padding despite the wrapper API's PSS naming.
- The Makefile and Visual Studio configurations select crypto backends differently and contain platform-specific dependency paths. A successful build has not been established.
- The sample key and certificate files include private-key files. They are repository fixtures, not production credentials; replace them with locally generated test material for any experiment and keep private keys/passwords confidential.
- The server binds to loopback only. No deployment configuration, performance results, or end-to-end validation evidence is present.
- No top-level `LICENSE` file was found. [`eliza.cpp`](implementation/eliza.cpp) carries an MIT notice for the Eliza rendition it contains; the licensing status of the rest of the repository is undocumented.

## Supporting files

- [Presentation.pptx](Presentation.pptx)
- [Report.docx](Report.docx)
- [Video.mp4](Video.mp4)