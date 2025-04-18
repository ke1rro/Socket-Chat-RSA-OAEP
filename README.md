# Implementation of chat application in python sockets

## Features

- Chat application with non blocking threads
- Rivest-Shamir-Adleman encryption (RSA) and key handshake
- OAEP

## Work Allocation

- Nazar Mykhailischuk - Miller–Rabin primality test, RSA
- Nikita Lenyk - chat structure, OAEP, RSA


## Protocol design
![alt text](<protocol_design.svg>)

The project is build within five layers

1. **Transport Layer** - communication layers between sockets

2. **Security Layer** - RSA encryption with OAEP padding

3. **Application Layer** - Client and server side implementations

4. **Protocol Layer** - Message Integrity test and serialization

5. **Message Transport Layer** - Handles the reliable messages over TCP sockets

### Transport Layer

The `FrameLayer` class is responsible for adding a Header, which allows to set a dynamic buffer size when receiving messages.

- Header format: 4 byte unsigned int MSB

- Pack method adds length prefix of the message payload

! The frame Layer exactly after RSA + OAEP encryption

### Security Layer

Uses RSA - asymmetric encryption with several features

#### Key Generation

- Prime Number Generation: Uses Milller-Rabin primality test to generate secure primes

- Prime Numbers Separation: Ensures $p$ and $q$ differ by at least **256 bits**

- Standart public exponent is set to $e = 65537$

As the plain RSA is deterministic. Sercurity Layer uses **OAEP (Optimal Asymmetric Encryption Padding)**. It adds random data to the original message before encryption, making each encrypted message unique. This prevents attacks based on the analysis of ciphertexts and other vulnerabilities.

### OAEP Math Structure

OAEP - transforms a message $m$ into padded message $M$ by following this steps

1. Input data block
    - Message $m$ of length $\text{mLen}$

    - Maximum message length is $k - 2\times\text{hLen} - 2$, where:
$k$ is the RSA modulus byte length: $k = \lceil\log_256(n)\rceil$
$\text{hLen}$ is the hash function output length (32 bytes for SHA-256)

2. General Data Block
    - Compute $\text{lHash} = \text{Hash}(L)$ where $L$ is an optional label (usually empty)

    - Create padding string $\text{PS}$ of zeros: $\text{PS} = 0^{k-\text{mLen}-2\times\text{hLen}-2}$

    - Construct $\text{DB} = \text{lHash} \mathbin\Vert \text{PS} \mathbin\Vert 0x01 \mathbin\Vert m$

    ! This will be first separator block

3. Random seed generation $r$
    - Generate random seed $r$ of length $\text{hLen}$ bytes

4. Mask generation MGF1
    - Compute $\text{dbMask} = \text{MGF1}(r, k-\text{hLen}-1)$

    - Create $\text{maskedDB} = \text{DB} \oplus \text{dbMask}$

5. Masking seed
    - Compute $\text{seedMask} = \text{MGF1}(\text{maskedDB}, \text{hLen})$

    - Create $\text{maskedSeed} = r \oplus \text{seedMask}$

6. Final Encoding:

    - $\text{EM} = 0x00 \mathbin\Vert \text{maskedSeed} \mathbin\Vert \text{maskedDB}$

7. RSA Encryption:

    - Convert $\text{EM}$ to integer $m$
    Compute $c = m^e \mod n$

### Message Integrity test

1. Creates the message hash with fixed-size(32 bytes) by SHA256 of the message payload.

2. When sending the message:
    Includes:

    - 4-byte Header containing the digest length

    - The digest (SHA256 hash)

    - The actual message data

3. Output [digest_length (4-bytest)][digest (32 bytes)][payload]


4. Integrity test

    1. Get the length from the Header

    2. Extract the original digest

    3. Extract the payload

    4. Recalculate the hash with SHA256 of received payload

    5. Compare the received hash with the new one from step *4*

    6. If the match the message integrity is passed

    ! The hash comparison uses HMAC module `compare_digest` to avoid timing atacks

### Message flow

User types message in CLI
Text is converted to bytes and wrapped in `SecureMessage` with SHA-256 digest
Message is serialized (digest length + digest + payload)
Serialized message is encrypted using server's public key with RSA-OAEP
Encrypted data is framed (length header + content)
Frame is transmitted over TCP socket

#### Server

Server receives encrypted data with Header
Header is parsed to extract encrypted payload
Payload is decrypted using server's private key
Decrypted data is deserialized to `SecureMessage`
Integrity is verified by checking SHA-256 digest
Server processes message and prepares broadcast

#### Broadcasting to Clients

Server creates new `SecureMessage` with formatted text
For each client connection:
Message is serialized
Serialized data is encrypted with client's specific public key
Encrypted data is framed and sent to that client

#### Client

Client receives encrypted data with Header
Header is parsed to extract encrypted payload
Payload is decrypted using client's private key
Decrypted data is deserialized to `SecureMessage`
Integrity is verified by checking SHA-256 digest
Message is displayed to user

---

## Sources

OAEP
- https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding

- https://medium.com/asecuritysite-when-bob-met-alice/so-how-does-padding-work-in-rsa-6b34a123ca1f

- https://www.freecodecamp.org/news/the-cryptography-handbook-rsa-algorithm/?utm_source=chatgpt.com

MGF1 (mask generation)
- https://en.wikipedia.org/wiki/Mask_generation_function

Miller–Rabin primality test
- https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test

- https://www.youtube.com/watch?v=8i0UnX7Snkc&ab_channel=NesoAcademy

Padding Methods
- https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method

RSA
- https://asecuritysite.com/node/node_rsa

- https://www.dcode.fr/rsa-cipher?utm_source=chatgpt.com

- https://www.youtube.com/watch?v=nvcssTsiavg&ab_channel=TechWithNikola

- https://legacy.cryptool.org/en/cto/rsa-visual

PKCS
- https://www.rfc-editor.org/rfc/rfc8017#section-9.2
