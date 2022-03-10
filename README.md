## libmcleece

A command line tool and C interface to encrypt/decrypt files using the Classic McEliece "post-quantum", code-based asymmetric key exchange scheme. `xsalsa20poly1305` (via libsodium) is used as the symmetric cipher. In addition, libmcleece's default behavior is to first encrypt all messages with libsodium's `crypto_box_seal`, providing further protection (e.g. in case I screwed something up).

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
int mcleece_simple_keypair(unsigned char* pubk, unsigned char* secret);
int mcleece_simple_encrypt(unsigned char* ciphertext_out, const unsigned char* msg, unsigned msg_length, unsigned char* recipient_pubk);
int mcleece_simple_decrypt(unsigned char* decrypted_out, const unsigned char* ciphertext, unsigned ciphertext_length, unsigned char* recipient_secret);

int mcleece_crypto_box_keypair(unsigned char* pubk, unsigned char* secret);
int mcleece_crypto_box_seal(unsigned char* ciphertext_out, const unsigned char* msg, unsigned msg_length, unsigned char* recipient_pubk);
int mcleece_crypto_box_seal_open(unsigned char* decrypted_out, const unsigned char* ciphertext, unsigned ciphertext_length, unsigned char* recipient_pubk, unsigned char* recipient_secret);
```

Each set of APIs is meant to be used independently. That is, a keypair from `mcleece_crypto_box_keypair` will not work with `mcleece_simple` calls, and vice versa.

The differences are:
* `mcleece_crypto_box` operations have two layers of encryption. The first is libsodium's `crypto_box` (hence the name), the output of which is then wrapped in a `mcleece_simple` call. The `mcleece_simple` calls, therefore, are a single layer of encryption.
   * since PQC is new and exciting (even if Classic McEliece is fairly old-fashioned and safe), using the extra x25519 layer is probably a good idea, and as such, it is the default behavior for the cli.
* `mcleece_crypto_box` keypairs are larger, since they contain two keypairs. Specifically, the x25519 key bytes are prepended in front of the Classic McEliece key bytes.
* `mcleece_crypto_box_seal` and `mcleece_crypto_box_seal_open` *allocate extra memory* for the intermediate (libsodium) layer.

## `mcleece_inplace_crypto_box_seal`
As a workaround to the extra memory allocation in the standard `mcleece_crypto_box_seal` implementation, an alternative API is supported:
```
int mcleece_inplace_crypto_box_seal(unsigned char* buff, unsigned msg_and_header_length, unsigned char* scratch, unsigned char* recipient_pubk);
int mcleece_inplace_crypto_box_seal_open(unsigned char* buff, unsigned ciphertext_length, unsigned char* scratch, unsigned char* recipient_pubk, unsigned char* recipient_secret);
```

These functions are meant to be used in conjunction with `mcleece_crypto_box_keypair`. Here's how they work:
* `mcleece_inplace_crypto_box_seal(msg_buff, msg_size + mcleece_crypto_box_MESSAGE_HEADER_SIZE, scratch, pubk);`
   * special attention must be given to the size of the buffer pointed to by `msg_buff`. Because the encrypted output will be written back to this buffer -- and because the encrypted output will be an extra `mcleece_crypto_box_MESSAGE_HEADER_SIZE` bytes long, the *input* message buffer will need to be oversized to make room. For example, if the input message is "hello", instead of `msg_and_header_length` being 5, it will be `5+mcleece_crypto_box_MESSAGE_HEADER_SIZE` -- the expected ciphertext length.
   * `scratch` must be a distinct buffer from `msg_buff`, and must have room for `msg_size + mcleece_crypto_box_INNER_MESSAGE_HEADER_SIZE` bytes.
   * after the call is complete -- if it returns 0 (no errors) -- msg_buff will contain `msg_and_header_length` bytes of encrypted data.
* `mcleece_inplace_crypto_box_seal_open(msg_buff, ciphertext_length, scratch, pubk, secret);`
   * the `*_seal_open` call behaves the same -- ciphertext_length should be the same as msg_and_header_length above, but since you presumably have all the bytes, no special adjustment is needed for msg_buff.
   * where special attention is still needed is for `scratch` -- the size of the buffer here is `ciphertext_length - mcleece_simple_MESSAGE_HEADER_SIZE`, or `ciphertext_length - mcleece_crypto_box_MESSAGE_HEADER_SIZE + mcleece_crypto_box_INNER_MESSAGE_HEADER_SIZE` -- which should be identical. (obviously, make sure ciphertext_length is larger than the header size!)
   * after this call is complete -- if it returns 0 (no errors) -- the first `ciphertext_length - mcleece_crypto_box_MESSAGE_HEADER_SIZE` bytes of msg_buff will contain the decrypted data.
* Example code using these functions can be found in the tests, and also in the "file level" libmcleece APIs.

## C++ API
It is not (yet?) collected in a single-header, but the core of libmcleece are a handful of header-only C++ libraries. These can also be used, though I'm not sure how stable the API is yet... 

