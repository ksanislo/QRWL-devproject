#include <citrus/app.hpp>
#include <citrus/core.hpp>

#include <mbedtls/base64.h>

#include "mega.h"
#include "common.h"

using namespace ctr;

static u32 *aeskey, *aesiv;

int decodeMegaFileKey(char* str)
{
	u32 *aeskey_32 = (u32*) aeskey;
	u32 *aesiv_32 = (u32*) aesiv;
	int len = strlen(str);
	int newlen = len + ((len * 3) & 0x03);
	int i;
	size_t olen;
	u8 *buf;

	//Remove URL base64 encoding, and pad with =
	for(i = 0; i < newlen; i++){
		if(str[i] == '-')
			str[i] = '+';
		else if(str[i] == '_')
			str[i] = '/';

		if (i >= len)
			str[i] = '=';
	}

	buf = (u8*)malloc(256/8);
	int ret = mbedtls_base64_decode((unsigned char*)buf, (256/8), &olen, (const unsigned char*)str, newlen);
	aeskey_32[3] = ((buf[0]<<24)|(buf[1]<<16)|(buf[2]<<8)|(buf[3]<<0))^((buf[16]<<24)|(buf[17]<<16)|(buf[18]<<8)|(buf[19]<<0));
	aeskey_32[2] = ((buf[4]<<24)|(buf[5]<<16)|(buf[6]<<8)|(buf[7]<<0))^((buf[20]<<24)|(buf[21]<<16)|(buf[22]<<8)|(buf[23]<<0));
	aeskey_32[1] = ((buf[8]<<24)|(buf[9]<<16)|(buf[10]<<8)|(buf[11]<<0))^((buf[24]<<24)|(buf[25]<<16)|(buf[26]<<8)|(buf[27]<<0));
	aeskey_32[0] = ((buf[12]<<24)|(buf[13]<<16)|(buf[14]<<8)|(buf[15]<<0))^((buf[28]<<24)|(buf[29]<<16)|(buf[30]<<8)|(buf[31]<<0));
	aesiv_32[3] = ((buf[16]<<24)|(buf[17]<<16)|(buf[18]<<8)|(buf[19]<<0));
	aesiv_32[2] = ((buf[20]<<24)|(buf[21]<<16)|(buf[22]<<8)|(buf[23]<<0));
	aesiv_32[1] = 0;
	aesiv_32[0] = 0;

	free(buf);
	return ret;
}

int doMegaInstall (char *url){
        //app::App app;
        Result ret=0;

	char *ptr, *locptr, *keyptr;

	// Allocate space for 128 bit AES key and 128 bit AES IV
	aeskey = (u32*)malloc(128 / 8);
	aesiv = (u32*)malloc(128 / 8);

        printf("Processing %s\n",url);

	// Allocate URL length+4 bytes since we may need to pad with =
	u8 *buf = (u8*)malloc(strlen(url)+4);
	strcpy((char*)buf, url);
	ptr = strchr((const char *)buf, '#');
	if (ptr[1] != '!'){
		printf("URL not supported\n");
		goto stop;
	}
	locptr = strchr((const char *)ptr, '!');
	locptr++[0] = (char)NULL; // end prev string
	keyptr = strchr((const char *)locptr, '!');
	keyptr++[0] = (char)NULL; // end prev string

	// Decode the URL for our AES key
	decodeMegaFileKey(keyptr);

	printf("key: 0x%08lx%08lx%08lx%08lx\n", aeskey[3], aeskey[2], aeskey[1], aeskey[0]);
	printf("iv: 0x%08lx%08lx%08lx%08lx\n", aesiv[3], aesiv[2], aesiv[1], aesiv[0]);

stop:
	free(aeskey);
	free(aesiv);
	free(buf);
	return ret;
}

