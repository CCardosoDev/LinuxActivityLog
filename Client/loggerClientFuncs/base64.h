#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

char* b64encode(const unsigned char *input, int length);
//char* b64decode(unsigned char *input, int length);
char *b64decode(unsigned char *input, int length, int *outLen);
