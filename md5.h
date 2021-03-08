#ifndef MD5_H
#define MD5_H

#include <stdint.h>

# ifdef  __cplusplus
extern "C" {
# endif

/* rfc1321 */        
/* MD5 context */
typedef struct
{
	uint32_t state[4];
	uint32_t count[2];
	unsigned char buffer[64];
}MD5_CTX;

void MD5Init(MD5_CTX *context);
void MD5Update(MD5_CTX *context,unsigned char *input,unsigned int inputlen);
void MD5Final(MD5_CTX *context,unsigned char digest[16]);

# ifdef  __cplusplus
extern "C" {
# endif


#endif /* end of #ifndef MD5_H */

