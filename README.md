## libmcleece

Command line tool -- and library -- to encrypt/decrypt messages using the Classic McEliece "post-quantum", code-based asymmetric key exchange scheme. You can use it to encrypt email contents, probably.

The code is from the Classic McEliece NIST submission:
https://classic.mceliece.org/nist.html

The submission is not a standard yet!

## Design goals

1. generate public/private key pair
2. encrypt message using public key. Output baseNN (64?) encoded message of the sort you might send in an email.
3. decrypt message using private key. Output plain text.

Key exchange, message signing, [...], are out of scope... for *this* project.

