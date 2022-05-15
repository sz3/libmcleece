## libmcleece

A command line tool and C interface to encrypt/decrypt files using the Classic McEliece "post-quantum", code-based asymmetric key exchange scheme.

libmcleece's default behavior is to use hybrid key exchange -- using the Classic McEliece KEM, and libsodium's `crypto_box_seal` (`x25519`) -- to generate a shared secret for a libsodium `crypto_box` (`xsalsa20poly1305`).

The [actual McEliece implementation](./src/third_party_lib/mceliece6960119f) is from the Classic McEliece NIST submission:
https://classic.mceliece.org/nist.html

The submission is not a standard yet!

## Build

* Dependencies:
	* libssl-dev
	* libsodium-dev

```
cmake .
make -j4 install
```

By default, build products (the library, the headers, and the cli) are installed into the project's `dist/` subdirectory. To install to a different directory, e.g. `/usr`, modify the cmake step:
```
cmake . -DCMAKE_INSTALL_PREFIX=/usr
```

## Basic usage

#### 1. generate a public/private key pair.

* with the cli:
```
mcleececli keypair --key-path=/tmp/key
```
   * this will generate `/tmp/key.sk` and `/tmp/key.pk`. The secret key will be password protected (there will be a prompt) -- keep it secret! Keep it safe!

* with the C api:
```
mcleece_keypair_to_file(
    "/tmp/key", 8, // length of "/tmp/key"
    "password", 8,  // length of "password" -- I recommend a stronger password than "password"
    mcleece_MODE_CRYPTO_BOX
)
```

#### 2. encrypt a message for a specific public key (only the corresponding secret key will be able to decrypt it):

* with the cli:
```
mcleececli encrypt /path/to/srcfile --key-path=/tmp/key > encoded.bin
```
   * encryption will need `/tmp/key.pk` to exist in the above example.

* with the C api:
```
mcleece_encrypt_file(
    "/tmp/key", 8,
    "/path/to/srcfile", 16,
    "encoded.bin", 11,
    mcleece_MODE_CRYPTO_BOX
)
```

#### 3. decrypt a message

* with the cli:
```
mcleececli decrypt encoded.bin --key-path=/tmp/key > decoded_file_path
```
   * decryption will expect both `/tmp/key.sk` and `/tmp/key.pk` to exist in the above example -- and will also prompt for the password for /tmp/key.sk.

* with the C api:
```
mcleece_decrypt_file(
    "/tmp/key", 8,
    "password", 8,
    "encoded.bin", 11,
    "decoded_file_path", 17,
    mcleece_MODE_CRYPTO_BOX
)
```

## Advanced usage

In addition to the file-level APIs described above, there are also APIs to match the libsodium `crypto_box_seal` API:
```
int mcleece_crypto_box_keypair(unsigned char* pubk, unsigned char* secret);
int mcleece_crypto_box_seal(unsigned char* ciphertext_out, const unsigned char* msg, unsigned msg_length, unsigned char* recipient_pubk);
int mcleece_crypto_box_seal_open(unsigned char* decrypted_out, const unsigned char* ciphertext, unsigned ciphertext_length, unsigned char* recipient_pubk, unsigned char* recipient_secret);

int mcleece_simple_keypair(unsigned char* pubk, unsigned char* secret);
int mcleece_simple_encrypt(unsigned char* ciphertext_out, const unsigned char* msg, unsigned msg_length, unsigned char* recipient_pubk);
int mcleece_simple_decrypt(unsigned char* decrypted_out, const unsigned char* ciphertext, unsigned ciphertext_length, unsigned char* recipient_secret);
```

Each set of APIs is meant to be used independently. That is, a keypair from `mcleece_crypto_box_keypair` will not work with `mcleece_simple` calls, and vice versa.

Explanation:
* `mcleece_crypto_box` functions are modified libsodium `crypto_box_seal` operations. This means that even if something is awry with libmcleece's PQC, theoretically the encrypted payload will still be as secure as `crypto_box_seal` is. (that is: pretty good, unless your adversary has a powerful quantum computer)
   * `mcleece_crypto_box` is the default behavior for the cli.
* `mcleece_crypto_box` keypairs are larger, since they contain two keypairs. Specifically, the x25519 (public/private) key bytes are prepended in front of the Classic McEliece key bytes.
* `mcleece_simple` functions do not use x25519 -- the shared secret is only protected by Classic McEliece.


## C++ API
It is not (yet?) collected in a single-header, but the core of libmcleece are a handful of header-only C++ libraries. These can also be used, though I'm not sure how stable the API is yet... 

