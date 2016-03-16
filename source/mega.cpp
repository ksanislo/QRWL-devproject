#include <citrus/app.hpp>
#include <citrus/core.hpp>

#include <mbedtls/base64.h>

#include "aes.h"
#include "mega.h"
#include "common.h"

using namespace ctr;

int base64KeyDecode(void *aeskey, void *aesiv, char* str)
{
	int len = strlen(str);
	int newlen = len + ((len * 3) & 0x03);
	int i;
	size_t olen;

	//Remove URL base64 encoding, and pad with =
	for(i = 0; i < newlen; i++){
		if(str[i] == '-')
			str[i] = '+';
		else if(str[i] == '_')
			str[i] = '/';

		if (i >= len)
			str[i] = '=';
	}

	int ret = mbedtls_base64_decode((unsigned char*)aeskey, 32, &olen, (const unsigned char*)str, newlen);

	return ret;
}

int doMegaInstall (char *url){
        //app::App app;
        Result ret=0;

	char *ptr, *locptr, *keyptr;
	u8 *aeskey, *aesiv;

        printf("Processing %s\n",url);

	// Allocate +4 bytes since we may need to pad with =
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

	// Allocate space for 128 bit AES key
	aeskey = (u8*)malloc(128 / 8);

	// And 128 bits for our starting IV
	aesiv = (u8*)malloc(128 / 8);

	// Decode the URL for our AES key
	base64KeyDecode(aeskey, aesiv, keyptr);

//	printf("%s\n%s\n", locptr, keyptr);

	free(aeskey);
	free(aesiv);
stop:
	free(buf);
	return ret;
}

