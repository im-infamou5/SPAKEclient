/*#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include "crypto.h"

using namespace Crypto::Emulator;

AES::AES()
{
	memset(&aes_ctx, 0, sizeof(EVP_CIPHER_CTX));
}

AES::~AES()
{
	EVP_CIPHER_CTX_cleanup(&aes_ctx);
}

void AES::AESInitKey(unsigned char* key, unsigned char* iv, bool is_encrypt)
{
	if (is_encrypt){
		EVP_CIPHER_CTX_init(&aes_ctx);
		EVP_EncryptInit_ex(&aes_ctx, EVP_aes_128_cbc(), NULL, key, iv);
	}
	else
	{
		EVP_CIPHER_CTX_init(&aes_ctx);
		EVP_DecryptInit_ex(&aes_ctx, EVP_aes_128_cbc(), NULL, key, iv);
	}
}

unsigned char* AES::AESEncrypt(unsigned char *src, size_t srclen, size_t *dstlen)
{
	int cipher_length = srclen + AES_BLOCK_SIZE, final_length = 0;
	unsigned char *dst = reinterpret_cast<unsigned char*>(malloc(cipher_length));
	EVP_EncryptInit_ex(&aes_ctx, NULL, NULL, NULL, NULL);
	EVP_EncryptUpdate(&aes_ctx, dst, &cipher_length, src, srclen);
	EVP_EncryptFinal_ex(&aes_ctx, dst + cipher_length, &final_length);
	*dstlen = cipher_length + final_length;
	return dst;
}

unsigned char* AES::AESDecrypt(unsigned char *src, size_t srclen, size_t *dstlen)
{
	int output_length = srclen, final_length = 0;
	unsigned char *dst = reinterpret_cast<unsigned char*>(malloc(output_length + AES_BLOCK_SIZE));
	EVP_DecryptInit_ex(&aes_ctx, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(&aes_ctx, dst, &output_length, src, srclen);
	EVP_DecryptFinal_ex(&aes_ctx, dst + output_length, &final_length);
	*dstlen = output_length + final_length;
	return dst;
}

void AES::Free(void* p)
{
	if (p)
	{
		free(p);
	}
}


unsigned char* SHA256::hash(unsigned char* buffer, size_t bufSize, size_t& size) 
{
	unsigned char* digest = new unsigned char[SHA256_DIGEST_LENGTH];
	size = SHA256_DIGEST_LENGTH;

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, buffer, bufSize);
	SHA256_Final(digest, &sha256);

	return digest;
}

unsigned char* HMAC::Compute(const char* key, const char* message) 
{
	//key		"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
	//data		"\x48\x69\x20\x54\x68\x65\x72\x65";
	//expected	"\x49\x2c\xe0\x20\xfe\x25\x34\xa5\x78\x9d\xc3\x84\x88\x06\xc7\x8f\x4f\x67\x11\x39\x7f\x08\xe7\xe7\xa1\x2c\xa5\xa4\x48\x3c\x8a\xa6";
	unsigned char* result;
	unsigned int result_len = 32;
	int i;

	result = (unsigned char*)malloc(sizeof(char) * result_len);

	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();

	HMAC_Init_ex(hmac_ctx, (void*)key, strlen(key),EVP_sha256(), NULL);
	HMAC_Init_ex(hmac_ctx, key, 16, EVP_sha256(), NULL);
	HMAC_Update(hmac_ctx, (unsigned char *) message, 8);
	HMAC_Final(hmac_ctx, result, &result_len);
	memset(hmac_ctx, 0, sizeof(hmac_ctx)); 	//HMAC_CTX_reset(hmac_ctx);

	return result;

}*/