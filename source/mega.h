#include <citrus/app.hpp>

extern "C" {
#include <jsmn.h>
}

#define MEGA_NODETYPE_FILE 0
#define MEGA_NODETYPE_FOLDER 1
#define MEGA_NODETYPE_UNDEF 2

using namespace ctr;

typedef struct {
	char nodeId[32];
	char fileName[260];
	u64 size;
	u32 timeStamp;
	unsigned char aeskey[32];
	unsigned char aesiv[32];
	u64 titleId;
} fileList;

uint64_t swap_uint64( uint64_t val );
int jsoneq(const char *json, jsmntok_t *tok, const char *s);
int decodeMegaAttributes(char *buf, char *filename);
int parseMegaFolderResponse(char *jsonString, char *url);
int parseMegaFileResponse(char *jsonString, char *url, char *filename, u32 *size);
int fetchMegaData(void *buf, u32 bufSize, u32 *bufFill, u8 *aeskey, u8 *aesiv);
int fetchMegaDataCallback(void *buf, u32 bufSize, u32 *bufFill);
char* decodeURLbase64(char *str, size_t *olen);
char* decryptStringCBC(char *str, size_t bufSize, u8 *aeskey);
char* decryptBufferCBC(char *str, size_t bufSize, u8 *aeskey);
char* decryptBufferECB(char *str, size_t bufSize, u8 *aeskey);
char* decodeMegaAESKey(char *str, u8 *aeskey, u8 *aesiv);
int decodeMegaURL (char *url, int *nodeType, char *nodeId, u8 *aeskey, u8 *aesiv);
int getMegaTitleId (char *url, u8 *aeskey, u8 *aesiv, app::App *app);
int doMegaInstallCIA (char *url, u8 *aeskey, u8 *aesiv, app::App *app);
int requestMegaNodeInfo (char **buf, int *nodeType, char *nodeId);
int doMegaInstall (char *url);
