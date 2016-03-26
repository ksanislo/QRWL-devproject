#include <citrus/app.hpp>
#include <citrus/hid.hpp>
#include <citrus/core.hpp>

#include <mbedtls/base64.h>
#include <mbedtls/aes.h>

extern "C" {
#include <jsmn.h>
}

#include "mega.h"
#include "common.h"

using namespace ctr;

static u8 *megaInstallKey, *megaInstallIV;
static httpcContext context;

uint64_t swap_uint64( uint64_t val ) {
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
    return (val << 32) | (val >> 32);
}

int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
	if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
			strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}


// TODO: This needs rebuilt with the new func()s
int decodeMegaAttributes(char *buf, u8 *aeskey, char *filename) {
	int i, r, c;
	int len = strlen(buf);
	size_t olen;
	unsigned char zeroiv[16]={0};
	char *jsonbuf;
	jsmn_parser p;
	jsmntok_t t[128]; // We expect no more than 128 tokens

	for(c = 0; c < len + ((len * 3) & 0x03); c++){
		if(buf[c] == '-')
			buf[c] = '+';
		else if(buf[c] == '_')
			buf[c] = '/';
		if (c >= len)
			buf[c] = '=';
	}

	strcpy(filename, buf); // store in our return filename for temp space

	mbedtls_base64_decode(NULL, 0, &olen, (const unsigned char*)filename, strlen(filename));
	mbedtls_base64_decode((unsigned char*)buf, olen, &olen, (const unsigned char*)filename, strlen(filename));

	mbedtls_aes_context aes;
	mbedtls_aes_setkey_dec( &aes, aeskey, 128 );
	jsonbuf = (char*)malloc(olen);
	mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, olen, &zeroiv[0], (unsigned char*) buf, (unsigned char*) jsonbuf);
	printf("json: %s\n", jsonbuf);
	mbedtls_aes_free( &aes );
	if(strncmp("MEGA", jsonbuf, 4)!=0){
		printf("MEGA magic string not found.\nDecryption key bad/missing?\n");
		return 1;
	}
	jsonbuf+=4; // Bypass header.

	r = jsmn_parse(&p, jsonbuf, strlen(jsonbuf), t, sizeof(t)/sizeof(t[0]));
	if (r < 0) {
		printf("Failed to parse JSON: %d\n", r);
		return 1;
	}

	if (r < 1 || t[0].type != JSMN_OBJECT) {
		printf("Object expected\n");
		return 1;
	}

	for (i = 1; i < r; i++) {
		if (jsoneq(jsonbuf, &t[i], "n") == 0) {
			strncpy(filename,jsonbuf + t[i+1].start,t[i+1].end-t[i+1].start);
			filename[t[i+1].end-t[i+1].start] = (char)NULL;
			i++;
		}
	}

	free(jsonbuf-4); // Free the original jsonbuf 
	return 0;
}

int parseMegaFolderResponse(char *jsonString, u8 *aeskey, char *url) {
	return 0;
}

int parseMegaFileResponse(char *jsonString, char *url, u8 *aeskey, char *filename, u32 *size) {
	int i, r;
	char *buf;
	jsmn_parser p;
	jsmntok_t t[128]; /* We expect no more than 128 tokens */

	jsmn_init(&p);
	r = jsmn_parse(&p, jsonString, strlen(jsonString), t, sizeof(t)/sizeof(t[0]));
	if (r < 0) {
		printf("Failed to parse JSON: %d\n", r);
		return 1;
	}

	/* Assume the top-level element is an object */
	if (r < 1 || t[0].type != JSMN_ARRAY) {
		printf("Array expected\n");
		return 1;
	}

	/* Loop over all keys of the root object */
	for (i = 2; i < r; i++) {
		if (jsoneq(jsonString, &t[i], "s") == 0) { // size
			*size = strtoul(jsonString + t[i+1].start, NULL, 10);
			i++;
		} else if (jsoneq(jsonString, &t[i], "at") == 0) { // filename
			// This will be base64 encoded, allocate with padding.
			buf=(char*)malloc(t[i+1].end-t[i+1].start + 1 + ((t[i+1].end-t[i+1].start * 3) & 0x03) );
			memset(buf,0,t[i+1].end-t[i+1].start + 1 + ((t[i+1].end-t[i+1].start * 3) & 0x03));
			strncpy(buf,jsonString + t[i+1].start,t[i+1].end-t[i+1].start);
			buf[t[i+1].end-t[i+1].start + ((t[i+1].end-t[i+1].start * 3) & 0x03)] = (char)NULL;
			decodeMegaAttributes(buf, aeskey, filename);
			free(buf);
			i++;
		} else if (jsoneq(jsonString, &t[i], "g") == 0) { // url
			strncpy(url,jsonString + t[i+1].start,t[i+1].end-t[i+1].start);
			url[t[i+1].end-t[i+1].start] = (char)NULL;
			i++;
		}
	}
	return 0;
}

int fetchMegaData(void *buf, u32 bufSize, u32 *bufFill, u8 *aeskey, u8 *aesiv){
        Result ret = 0;
	u32 downloadpos = 0;
	u64 *aesiv_64 = (u64*) aesiv;

	char *startptr, *endptr;
	u32 startpos = 0;
	u32 decodepos = 0;
	size_t chunksize = 0;

	size_t offset=0;

	unsigned char stream_block[16];
	u8 *dlbuf;
	
	u8 *contentrange = (u8*)malloc(256);
	if(httpcGetResponseHeader(&context, (char*)"Content-Range", (char*)contentrange, 256)==0){ 
		startptr = strchr((char *)contentrange, ' ');
		startptr++[0] = (char)NULL; // end string
		endptr = strchr((char *)startptr, '-');
		endptr[0] = (char)NULL; // end string
		startpos = atol(startptr);
	}
	free(contentrange);

	ret = httpcGetDownloadSizeState(&context, &downloadpos, NULL);
	if(ret!=0){
		goto stop;
	}
	startpos += downloadpos;	

	dlbuf = (u8*)malloc(bufSize);
	memset(dlbuf, 0, bufSize);

	ret = httpcDownloadData(&context, dlbuf, bufSize, bufFill);
	if(ret!=0 && ret != (s32)HTTPC_RESULTCODE_DOWNLOADPENDING){
		goto stop;
	}

	mbedtls_aes_context aes;
	mbedtls_aes_setkey_enc( &aes, aeskey, 128 );

	aesiv_64[1] = swap_uint64((u64)startpos/16); // Set our IV block location.
	offset = startpos % 16; // Set our starting block offset

	if(offset != 0){ // If we have an offset, we need to pre-fill stream_block
		mbedtls_aes_crypt_ecb( &aes, MBEDTLS_AES_ENCRYPT, aesiv, stream_block );
		aesiv_64[1] = swap_uint64(((u64)startpos/16) + 1); // Bump counter
	}

	for (decodepos = 0;  decodepos < *bufFill ; decodepos+=0x1000) { // AES decrypt in 4K blocks
		chunksize = (((*bufFill - decodepos) < 0x1000) ? (*bufFill - decodepos) : 0x1000 );
		mbedtls_aes_crypt_ctr( &aes, chunksize, &offset, aesiv, stream_block, dlbuf+decodepos, (unsigned char*)buf+decodepos );
		if (decodepos + chunksize == *bufFill) break;
	}

	mbedtls_aes_free( &aes );
	free(dlbuf);

stop:
	return ret;
}

int fetchMegaDataCallback(void *buf, u32 bufSize, u32 *bufFill){
	return fetchMegaData(buf, bufSize, bufFill, megaInstallKey, megaInstallIV);
}


char* base64urldecode(char *str, size_t *olen){
	int i;
	int len = strlen(str);
        int newlen = len + ((len * 3) & 0x03);
	char *buf;
	
	buf = (char*)malloc(newlen+1);
	strcpy(buf,str);
	
	// Pad as needed.
	for(i = 0; i < newlen; i++){
		if(buf[i] == '-')
			buf[i] = '+';
		else if(buf[i] == '_')
			buf[i] = '/';

		if (i >= len)
			buf[i] = '=';
	}
	buf[newlen] = 0;

	//printf("buf: %s\nlen: %i\nnewlen: %i\n", buf, len, newlen);
	mbedtls_base64_decode(NULL, 0, olen, (const unsigned char*)buf, newlen);
	//printf("olen: %u\n", *olen);
	mbedtls_base64_decode((unsigned char*)str, *olen, olen, (const unsigned char*)buf, newlen);
	str[*olen] = 0; // string terminator

	free(buf);
	return str;
}

char* decryptBufferCBC(char *str, size_t bufSize, u8 *aeskey) {
	unsigned char zeroiv[16]={0};
	
        mbedtls_aes_context aes;
        mbedtls_aes_setkey_dec( &aes, aeskey, 128 );
        char *buf = (char*)malloc(bufSize);
	strncpy(buf, str, bufSize);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, bufSize, &zeroiv[0], (unsigned char*) buf, (unsigned char*) str);
        mbedtls_aes_free( &aes );
	free(buf);
	return str;
}

char* decodeMegaAESKey(char *str, u8 *aeskey, u8 *aesiv, u8 *folderkey)
{
	u64 *aeskey_64 = (u64*) aeskey;
	u64 *aesiv_64 = (u64*) aesiv;
	size_t len = 0;
	u64 *str_64;

	base64urldecode(str, &len);
	//printf(" str: %s\n", str);

	if(folderkey!=NULL){
		str = decryptBufferCBC(str, len, folderkey);
	}

	str_64 = (u64*) str;
	aeskey_64[0] = str_64[0] ^ str_64[2];
	aeskey_64[1] = str_64[1] ^ str_64[3];
	aesiv_64[0] = str_64[2];
	aesiv_64[1] = 0;

	return str;
}

int decodeMegaURL (char *url, int *nodeType, char *nodeId, u8 *aeskey, u8 *aesiv){
	Result ret=0;
	char *ptr, *locptr, *keyptr, *keybuf;

	*nodeType=MEGA_NODETYPE_UNDEF;

	u8 *buf = (u8*)malloc(strlen(url)+1);
	strcpy((char*)buf, url);
	ptr = strchr((const char *)buf, '#');
	if (ptr[1] == 'F') { *nodeType=MEGA_NODETYPE_FOLDER; } else { *nodeType=MEGA_NODETYPE_FILE; }
	locptr = strchr((const char *)ptr, '!');
	locptr++[0] = (char)NULL; // end prev string
	keyptr = strchr((const char *)locptr, '!');
	keyptr++[0] = (char)NULL; // end prev string

	keybuf = (char*)malloc(strlen(keyptr)+1);
	strcpy(nodeId, locptr);
	strcpy(keybuf, keyptr);
	free(buf);

	//printf("keybuf: %s\n", keybuf);
	decodeMegaAESKey(keybuf, aeskey, aesiv, NULL);

	free(keybuf);
	return ret;
}

int getMegaTitleId (char *url, u8 *aeskey, u8 *aesiv, app::App *app){
        Result ret=0;

	u8 *buf;
	u32 bufFill;
	u32 statuscode;

	ret=httpcOpenContext(&context, HTTPC_METHOD_GET, url, 0);
	ret=httpcSetSSLOpt(&context, 1<<9);
	ret=httpcAddRequestHeaderField(&context, (char*)"Range", (char*)"bytes=11292-11299");
	ret=httpcBeginRequest(&context);
	httpcGetResponseStatusCode(&context, &statuscode, 0);

	buf = (u8*)malloc(8);
	fetchMegaData(buf, 8, &bufFill, aeskey, aesiv);
	app->titleId = ((u64)buf[0]<<56|(u64)buf[1]<<48|(u64)buf[2]<<40|(u64)buf[3]<<32|(u64)buf[4]<<24|(u64)buf[5]<<16|(u64)buf[6]<<8|(u64)buf[7]);
	httpcCloseContext(&context);
	free(buf);
	return ret;
}

int doMegaInstallCIA (char *url, u8 *aeskey, u8 *aesiv, app::App *app){
        Result ret=0;
	u32 statuscode;

	// Set up global keys for the callback.
	megaInstallKey = aeskey;
	megaInstallIV = aesiv;

	ret=httpcOpenContext(&context, HTTPC_METHOD_GET, url, 0);
	ret=httpcSetSSLOpt(&context, 1<<9);
	ret=httpcBeginRequest(&context);
	httpcGetResponseStatusCode(&context, &statuscode, 0); 
	app::install(app->mediaType, &fetchMegaDataCallback, app->size, &onProgress);
	httpcCloseContext(&context);
	return ret;
}

int requestMegaNodeInfo (char **buf, int *nodeType, char *nodeId, u8 *aeskey, u8 *aesiv){
	Result ret=0;

	u8 *req;
	u32 bufSize = 0;
	u32 bufLen;
	int reqlen;
	char *requrl;

	req = (u8*)calloc(256, 1);
	requrl = (char*)calloc(256, 1);
	if(*nodeType == MEGA_NODETYPE_FOLDER) {
		sprintf(requrl, "https://g.api.mega.co.nz/cs?n=%s", nodeId);
		reqlen = sprintf((char*)req, "[{\"a\":\"f\",\"c\":1,\"ca\":1,\"r\":1}]");
	} else if (*nodeType == MEGA_NODETYPE_FILE) {
		sprintf(requrl, "https://g.api.mega.co.nz/cs");
		reqlen = sprintf((char*)req, "[{\"a\":\"g\",\"g\":1,\"p\":\"%s\"}]", nodeId);
	} else {
		printf("ERR: Mega nodeType is unknown.");
		goto stop;
	}

	//printf("url: %s \npost: %s\npost length: %u\n", requrl, req, reqlen);

	httpcOpenContext(&context, HTTPC_METHOD_POST, requrl, 0);
	httpcSetSSLOpt(&context, 1<<9);
	httpcAddPostDataRaw(&context, (u32*)req, reqlen);

	httpcBeginRequest(&context);

	do { // Grow the buffer as required.
		bufSize += 0x1000;
		*buf = (char*)realloc(*buf, bufSize);
		ret = httpcDownloadData(&context, (u8*)*buf+(bufSize-0x1000), 0x1000, &bufLen);
	} while (ret==(int)HTTPC_RESULTCODE_DOWNLOADPENDING);
	if (0x1000 - bufLen == 0) { // Download ends on exact block end.
		bufSize += 0x1000; // Allocate one more time for \0
                *buf = (char*)realloc(*buf, bufSize);
	}

	//printf("buf: %s\n", *buf);

	httpcCloseContext(&context);

	stop:
	free(req);
	free(requrl);
	return ret;
}

int doMegaInstall (char *url){
	app::App app;
	Result ret=0;
	int nodeType = 0;

	u8 *aeskey, *aesiv;

	char *nodeId;
	nodeId = (char*)malloc(64);

	// Allocate space for 128 bit AES key and 128 bit AES IV
	aeskey = (u8*)malloc(128 / 8);
	aesiv = (u8*)malloc(128 / 8);

	printf("Processing %s\n",url);

	decodeMegaURL(url, &nodeType, nodeId, aeskey, aesiv);

	char *buf = (char*)malloc(0x1000); 
	requestMegaNodeInfo(&buf, &nodeType, nodeId, aeskey, aesiv);

	//printf ("buf: %s\n", buf);
	char *filename = (char*)malloc(0x1000);
	u32 filesize = 0;
	parseMegaFileResponse(buf, url, aeskey, filename, &filesize);
	//printf("file: %s\n", filename);
	free(buf);
	free(filename);

//	return 0;

	ret = getMegaTitleId(url, aeskey, aesiv, &app);
	if(ret!=0)return ret;

	if(app.titleId>>48 != 0x4){ // 3DS titleId
		printf("Not a 3DS .cia file.\n");
		return -1;
	}

	printf("titleId: 0x%016llx\n", app.titleId);
	if (app.titleId == TITLEID) printf("This .cia matches our titleId, direct\ninstall and uninstall disabled.\n");
	printf("Press B to cancel\n");
	if (app.titleId != TITLEID && app::installed(app)) printf("      X to uninstall\n");
	if (app.titleId != TITLEID) printf("      A to install\n");

	while (core::running()){
		hid::poll();

		if (hid::pressed(hid::BUTTON_X) && app.titleId != TITLEID && app::installed(app)){
			printf("Uninstalling...");
			app::uninstall(app);
			printf("done.\n");
			return 0;
		}

		if (hid::pressed(hid::BUTTON_A) && app.titleId != TITLEID && ! app::installed(app)){
			ret = doMegaInstallCIA(url, aeskey, aesiv, &app);
			if(ret!=0)return ret;

			printf("titleId: 0x%016llx\nInstall finished.\n", app.titleId);
			return ret;
		}

		if (hid::pressed(hid::BUTTON_B))
			break;
	}
	free(nodeId);
	free(aeskey);
	free(aesiv);
	return 0;
}

