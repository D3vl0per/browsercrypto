# BrowserCrypto

A Go library for cryptographic operations compatible with browser-based cryptography. This library provides a bridge between Go's cryptographic functions and Web Cryptography API, enabling seamless encryption, decryption, signing, and key exchange between Go backend and JavaScript frontend applications.

## Features

- **Key Management**: Generate, load, and manage cryptographic keys in JWK (JSON Web Key) format
- **Elliptic Curve Cryptography**: Support for X25519 (for key exchange) and Ed25519 (for signing)
- **Data Conversion**: Convert between Go byte arrays and JavaScript Uint8Array format
- **Encryption & Decryption**: Secure data exchange between browser and server
- **Compression**: Compress and decompress data for efficient transmission over the network
- **Digital Signatures**: Sign and verify data using Ed25519
- **Key Derivation**: Derive shared secrets for secure communication

## Installation

```bash
go getgithub.com/D3vl0per/browsercrypto
```

## Usage

### Key Generation

```go
// Generate a new X25519 private key for key exchange
var privateKey browsercrypto.PrivateKey
err := privateKey.GenerateKey(browsercrypto.X25519)
if err != nil {
    // handle error
}

// Generate a new Ed25519 private key for signing
var signingKey browsercrypto.PrivateKey
err = signingKey.GenerateKey(browsercrypto.Ed25519)
if err != nil {
    // handle error
}
```

### Key Exchange

```go
// Derive a shared secret using X25519
sharedSecret, err := browsercrypto.DeriveKey(recipientPublicKey, senderPrivateKey)
if err != nil {
    // handle error
}
```

### Encryption and Decryption

```go
import (
    "github.com/D3vl0per/crypt/symmetric"
)

// Create a cipher instance (e.g., AES-GCM)
// github.com/D3vl0per/crypt/symmetric package contains various ciphers
cipher := symmetric.NewAESGCM()

// Encrypt data
ciphertext, err := browsercrypto.Encrypt(recipientPublicKey, senderPrivateKey, plaintext, cipher)
if err != nil {
    // handle error
}

// Decrypt data
plaintext, err := browsercrypto.Decrypt(senderPublicKey, recipientPrivateKey, ciphertext, cipher)
if err != nil {
    // handle error
}
```

### Digital Signatures

```go
// Sign data
signature, err := browsercrypto.Sign(privateKey, data)
if err != nil {
    // handle error
}

// Verify signature
valid, err := browsercrypto.Verify(publicKey, signature, data)
if err != nil {
    // handle error
}
```

### Data Conversion

```go
// Convert Go byte array to JavaScript Uint8Array format
jsArray, err := browsercrypto.ByteArrayToUint8Array(goByteArray)
if err != nil {
    // handle error
}

// Convert JavaScript Uint8Array format to Go byte array
goArray, err := browsercrypto.Uint8ArrayToByteArray(jsArrayString)
if err != nil {
    // handle error
}
```

## Browser Compatibility

This library is designed to work with the Web Cryptography API in modern browsers. The key formats and cryptographic operations are compatible with JavaScript implementations using:

- `crypto.subtle` for encryption/decryption
- `crypto.sign` and `crypto.verify` for digital signatures
- JWK format for key exchange

## Security Considerations
  
This project includes cryptographic operations that have not been independently audited. While every effort has been made to ensure the correctness and security of these operations, they are provided "as is". The author cannot guarantee their security and cannot be held responsible for any consequences arising from their use. If you use these package in your own projects, you do so at your own risk.
  
It is strongly recommended that you seek an independent security review if you plan to use them in a production environment.
  