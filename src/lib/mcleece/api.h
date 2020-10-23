#ifndef LIBMCLEECE_API_H
#define LIBMCLEECE_API_H

#ifdef __cplusplus
extern "C" {
#endif

int generate_keypair(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length);

int encrypt(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len);
int encrypt_b64(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len);
int encrypt_stdout(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len);
int encrypt_stdout_b64(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len);

int decrypt(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len);
int decrypt_b64(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len);
int decrypt_stdout(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len);
int decrypt_stdout_b64(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len);

#ifdef __cplusplus
}
#endif

#endif // LIBMCLEECE_API_H
