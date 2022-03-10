/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#ifndef LIBMCLEECE_API_H
#define LIBMCLEECE_API_H

#ifdef __cplusplus
extern "C" {
#endif

extern const unsigned mcleece_simple_PUBLIC_KEY_SIZE;
extern const unsigned mcleece_simple_SECRET_KEY_SIZE;
extern const unsigned mcleece_simple_MESSAGE_HEADER_SIZE;

extern const unsigned mcleece_crypto_box_PUBLIC_KEY_SIZE;
extern const unsigned mcleece_crypto_box_SODIUM_PUBLIC_KEY_SIZE;
extern const unsigned mcleece_crypto_box_SECRET_KEY_SIZE;
extern const unsigned mcleece_crypto_box_SODIUM_MESSAGE_HEADER_SIZE;
extern const unsigned mcleece_crypto_box_MESSAGE_HEADER_SIZE;

extern const int mcleece_MODE_SIMPLE;
extern const int mcleece_MODE_CRYPTO_BOX;

int mcleece_simple_keypair(unsigned char* pubk, unsigned char* secret);
int mcleece_crypto_box_keypair(unsigned char* pubk, unsigned char* secret);

int mcleece_simple_encrypt(unsigned char* ciphertext_out, const unsigned char* msg, unsigned msg_length, unsigned char* recipient_pubk);
int mcleece_simple_decrypt(unsigned char* decrypted_out, const unsigned char* ciphertext, unsigned ciphertext_length, unsigned char* recipient_secret);

int mcleece_crypto_box_seal(unsigned char* ciphertext_out, const unsigned char* msg, unsigned msg_length, unsigned char* recipient_pubk);
int mcleece_crypto_box_seal_open(unsigned char* decrypted_out, const unsigned char* ciphertext, unsigned ciphertext_length, unsigned char* recipient_pubk, unsigned char* recipient_secret);

int mcleece_inplace_crypto_box_seal(unsigned char* buff, unsigned msg_and_header_length, unsigned char* scratch, unsigned char* recipient_pubk);
int mcleece_inplace_crypto_box_seal_open(unsigned char* buff, unsigned ciphertext_length, unsigned char* scratch, unsigned char* recipient_pubk, unsigned char* recipient_secret);

int mcleece_keypair_to_file(const char* keypath, unsigned keypath_len, const char* pw, unsigned pw_length, int mode);

int mcleece_encrypt_file(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len, int mode);
int mcleece_encrypt_stdout(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len, int mode);

int mcleece_decrypt_file(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len, int mode);
int mcleece_decrypt_stdout(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len, int mode);

#ifdef __cplusplus
}
#endif

#endif // LIBMCLEECE_API_H
