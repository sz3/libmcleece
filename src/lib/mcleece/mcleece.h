/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#ifndef LIBMCLEECE_API_H
#define LIBMCLEECE_API_H

#ifdef __cplusplus
extern "C" {
#endif

static const int mcleece_flag_rawbinary = 0;
static const int mcleece_flag_base64 = 1;

unsigned mcleece_public_key_size(void);
unsigned mcleece_secret_key_size(void);
unsigned mcleece_session_header_size(void);

int mcleece_keypair(unsigned char* pubk, unsigned char* secret);
int mcleece_keypair_to_file(const char* keypath, unsigned keypath_len, const char* pw, unsigned pw_length);

int mcleece_encrypt(unsigned char* ciphertext, const unsigned char* msg, unsigned msg_length, unsigned char* recipient_pubk);
int mcleece_decrypt(unsigned char* decrypted, const unsigned char* ciphertext, unsigned ciphertext_length, unsigned char* recipient_secret);

int mcleece_encrypt_file(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len, int flags);
int mcleece_encrypt_stdout(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len, int flags);

int mcleece_decrypt_file(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len, int flags);
int mcleece_decrypt_stdout(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len, int flags);

#ifdef __cplusplus
}
#endif

#endif // LIBMCLEECE_API_H
