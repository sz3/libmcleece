## libmcleece

A command line tool and C interface to encrypt/decrypt files using the Classic McEliece "post-quantum", code-based asymmetric key exchange scheme. `xsalsa20poly1305` (via libsodium) is used as the symmetric cipher.

The [actual McEliece implementation](https://github.com/sz3/libmcleece/tree/master/src/third_party_lib/mceliece8192128) is from the Classic McEliece NIST submission:
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

By default, build products (the library, the headers, and the cli) are installed into the projects `dist/` subdirectory. To install to a different directory, e.g. `/usr`, modify the cmake step:
```
cmake . -DCMAKE_INSTALL_PREFIX=/usr
```

## Usage

#### 1. generate a public/private key pair.

* with the cli:
```
mcleececli generate-keypair --key-path=/tmp/key
```

* with the C api:
```
mcleece_generate_keypair(
    "/tmp/key", 8, // length of "/tmp/key"
    "password", 8  // length of "password"
)
```

#### 2. encrypt a message for a specific public key (only the corresponding secret key will be able to decrypt it):

* with the cli:
```
mcleececli encrypt /path/to/srcfile --key-path=/tmp/key.pk > encoded.bin
```

* with the C api:
```
mcleece_encrypt(
    "/tmp/key.pk", 11,      // length of "/tmp/key.pk"
    "/path/to/srcfile", 16, // length of "/path/to/srcfile"
    "encoded.bin", 11,      // length of "encoded.bin"
    0                       // mcleece_flag_rawbinary or mcleece_flag_base64.
)
```

#### 3. decrypt a message

* with the cli:
```
mcleececli decrypt encoded.bin --key-path=/tmp/key.sk > decoded_file_path
```

* with the C api:
```
mcleece_decrypt(
    "/tmp/key.sk", 11,       // length of "/tmp/key.sk"
    "password", 8            // length of "password"
    "encoded.bin", 11,       // length of "encoded.bin"
    "decoded_file_path", 17, // length of "decoded_file_path"
    0                        // mcleece_flag_rawbinary or mcleece_flag_base64.
)
```


