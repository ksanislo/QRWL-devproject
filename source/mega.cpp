#include <citrus/app.hpp>
#include <citrus/hid.hpp>
#include <citrus/core.hpp>

#include <mbedtls/base64.h>
#include <mbedtls/aes.h>

extern "C" {
#include <jansson.h>
}

#include "mega.h"
#include "common.h"

using namespace ctr;

static u8 *megaInstallKey, *megaInstallIV;
static httpcContext context;
FILE *logfile;

uint64_t swap_uint64( uint64_t val ) {
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
    return (val << 32) | (val >> 32);
}

int parseMegaFileAttributes(char *buf, char *filename) {
	json_t *data, *n;
	json_error_t error;

	if(strncmp("MEGA", buf, 4)!=0){
		printf("MEGA magic string not found.\nDecryption key bad/missing?\n");
		return 1;
	}
	buf+=4; // Skip over MEGA magic.


	data = json_loads(buf, 0, &error);

	if (!data) {
		printf("Failed to parse JSON: %s\n", error.text);
		filename[0] = 0; //end string
//svcSleepThread(5000000000);
		return 1;
	}

	n = json_object_get(data, "n");
	strcpy(filename, json_string_value(n));

	//printf("filename: %s\n", filename);

	json_decref(data);
	return 0;
}

int parseMegaFolderResponse(char *buf, u8 *aeskey, void *folderList) {
	fileList myList;
	char *enckey, *attributes;
	size_t i, olen;
	json_t *root, *rootdata, *f, *data;
	json_error_t error;

	root = json_loads(buf, 0, &error);

	if (!root) {
		printf("Failed to parse JSON: %s\n", error.text);
		return 1;
	}

	enckey = (char*)malloc(0x100);
	attributes = (char*)malloc(0x400);

	rootdata = json_array_get(root, 0);
	f = json_object_get(rootdata, "f");
	for(i = 0; i < json_array_size(f); i++) {
		//json_t *a, *h, *k, *p, *s, *t, *ts, *u;
		json_t *a, *h, *k, *s, *t, *ts;

		data = json_array_get(f, i);

		t = json_object_get(data, "t");
                if(json_integer_value(t) == MEGA_NODETYPE_FILE){

			k = json_object_get(data, "k");
			strcpy(enckey, strchr(json_string_value(k), ':')+1);
			decodeMegaAESKey(decryptBufferECB(decodeURLbase64(enckey, &olen), olen, aeskey), &myList.aeskey[0], &myList.aesiv[0]);
			
			a = json_object_get(data, "a");
			strcpy(attributes, json_string_value(a));
			//parseMegaFileAttributes(decryptStringCBC(decodeURLbase64(attributes, &olen), olen, myList.aeskey), myList.fileName);
			decodeURLbase64(attributes, &olen);
			decryptStringCBC(attributes, olen, myList.aeskey);
			parseMegaFileAttributes(attributes, myList.fileName);

			h = json_object_get(data, "h");
			strcpy(myList.nodeId, json_string_value(h));

			s = json_object_get(data, "s");
			myList.size = json_integer_value(s);

			ts = json_object_get(data, "ts");
			myList.timeStamp = json_integer_value(ts);

			printf("filename: %s\nnodeId: %s\nsize: %llu\ntime: %lu\n", myList.fileName, myList.nodeId, myList.size, myList.timeStamp);
		}

		printf("count: %u\n", json_object_size(data));
	}

	free(enckey);
	free(attributes);


	json_decref(root);
	return 0;
}

int parseMegaFileResponse(char *buf, char *url, char *attributes, u32 *size) {
	size_t i;
	json_t *root;
	json_error_t error;

	root = json_loads(buf, 0, &error);

	if (!root) {
		fprintf(logfile,"Failed to parse JSON: %s\n", error.text);
		return 1;
	}

	if(!json_is_array(root)){
		printf("error: root is not an array\n");
		goto stop;
	}

	for(i = 0; i < json_array_size(root); i++) {
		json_t *data, *s, *at, *g;

		data = json_array_get(root, i);
		if(!json_is_object(data)) {
			printf("error: commit data %d is not an object\n", i + 1);
			goto stop;
		}

		s = json_object_get(data, "s");
		*size = json_integer_value(s);

		at = json_object_get(data, "at");
		strcpy(attributes, json_string_value(at));

		g = json_object_get(data, "g");
		strcpy(url, json_string_value(g));

		//printf("s-at-g: %lu, %s, %s\n", *size, attributes, url);
	}

	stop:
	json_decref(root);
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


char* decodeURLbase64(char *str, size_t *olen){
	int i;
	int len = strlen(str);
        int newlen = len + ((len * 3) & 0x03);
	char *buf;
	
	buf = (char*)malloc(newlen+1);
	strcpy(buf,str);
	
	// Pad as needed.
	for(i = 0; i < newlen; i++){
		if(buf[i] == '-')
			buf[i] = '+'; //+
		else if(buf[i] == '_')
			buf[i] = '/';

		if (i >= len)
			buf[i] = '=';
	}
	buf[newlen] = 0;
	mbedtls_base64_decode((unsigned char*)str, 0x1000, olen, (const unsigned char*)buf, newlen);

	free(buf);
	return str;
}

char* decryptStringCBC(char *str, size_t bufSize, u8 *aeskey) {
	decryptBufferCBC(str, bufSize, aeskey);
	str[bufSize] = 0; // NULL terminate
	return str;
}

char* decryptBufferCBC(char *str, size_t bufSize, u8 *aeskey) {
	unsigned char zeroiv[16]={0};
        mbedtls_aes_context aes;
        mbedtls_aes_setkey_dec( &aes, aeskey, 128 );
        char *buf = (char*)malloc(bufSize);
	memcpy(buf, str, bufSize);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, bufSize, &zeroiv[0], (unsigned char*) buf, (unsigned char*) str);
        mbedtls_aes_free( &aes );
	free(buf);
	return str;
}

char* decryptBufferECB(char *str, size_t bufSize, u8 *aeskey) {
	size_t i;
        mbedtls_aes_context aes;
        mbedtls_aes_setkey_dec( &aes, aeskey, 128 );
        char *buf = (char*)malloc(bufSize);
	memcpy(buf, str, bufSize);
	for(i = 0; i < bufSize; i+=16) {
		mbedtls_aes_crypt_ecb( &aes, MBEDTLS_AES_DECRYPT, (unsigned char*)buf+i, (unsigned char*)str+i);
	}
        mbedtls_aes_free( &aes );
	free(buf);
	return str;
}

char* decodeMegaAESKey(char *str, u8 *aeskey, u8 *aesiv) {
	u64 *aeskey_64 = (u64*) aeskey;
	u64 *aesiv_64 = (u64*) aesiv;
	u64 *str_64;

	str_64 = (u64*) str;
	aeskey_64[0] = str_64[0] ^ str_64[2];
	aeskey_64[1] = str_64[1] ^ str_64[3];
	aesiv_64[0] = str_64[2];
	aesiv_64[1] = 0;

	return str;
}

int decodeMegaURL(char *url, int *nodeType, char *nodeId, u8 *aeskey, u8 *aesiv) {
	Result ret=0;
	size_t olen=0;
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
	decodeURLbase64(keybuf, &olen);
	if(*nodeType==MEGA_NODETYPE_FILE){
		decodeMegaAESKey(keybuf, aeskey, aesiv);
	} else {
		memcpy(aeskey, keybuf, 16);
	}
	free(keybuf);
	return ret;
}

int getMegaTitleId (char *url, u8 *aeskey, u8 *aesiv, app::App *app){
        Result ret=0;

	u8 *buf;
	u32 bufFill;
	u32 statuscode;

	ret=httpcOpenContext(&context, HTTPC_METHOD_GET, url, 0);
	ret=httpcSetSSLOpt(&context, SSLCOPT_DisableVerify);
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
	ret=httpcSetSSLOpt(&context, SSLCOPT_DisableVerify);
	ret=httpcBeginRequest(&context);
	httpcGetResponseStatusCode(&context, &statuscode, 0); 
	app::install(app->mediaType, &fetchMegaDataCallback, app->size, &onProgress);
	httpcCloseContext(&context);
	return ret;
}

int requestMegaNodeInfo (char **buf, int *nodeType, char *nodeId){
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
	httpcSetSSLOpt(&context, SSLCOPT_DisableVerify);
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

	logfile = fopen("output.txt","w+");

	printf("Processing %s\n",url);

	decodeMegaURL(url, &nodeType, nodeId, aeskey, aesiv);

	char *buf = (char*)malloc(0x1000); 
	requestMegaNodeInfo(&buf, &nodeType, nodeId);

	//printf ("buf: %s\n", buf);

if(nodeType == MEGA_NODETYPE_FOLDER){
	parseMegaFolderResponse(buf, aeskey, NULL);
	return 0;
}

	char *attributes = (char*)malloc(0x1000);
	u32 filesize = 0;
	parseMegaFileResponse(buf, url, attributes, &filesize);
	app.size = filesize;
	app.mediaType = fs::SD;
	free(buf);

	size_t olen;
	char *filename = (char*)malloc(0x1000);
	parseMegaFileAttributes(decryptStringCBC(decodeURLbase64(attributes, &olen), olen, aeskey), filename);
	//printf("file: %s\nsize: %lu\n", filename, filesize);
	free(filename);
	free(attributes);

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
	fclose(logfile);
	free(nodeId);
	free(aeskey);
	free(aesiv);
	return 0;
}

