#include <citrus/app.hpp>
#include <citrus/core.hpp>
#include <citrus/fs.hpp>
#include <citrus/gpu.hpp>
#include <citrus/hid.hpp>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

extern "C" {
#include <quirc.h>
}

extern "C" {
u32 __stacksize__ = 0x40000;
}

using namespace ctr;

bool onProgress(u64 pos, u64 size) {
        printf("pos: %" PRId64 "-%" PRId64 "\n", pos, size);
        gpu::flushBuffer();
        hid::poll();
        return !hid::pressed(hid::BUTTON_B);
}

Result http_getinfo(char *url, app::App *app) {
	Result ret=0;
	u32 statuscode=0;
	httpcContext context;

        app->mediaType = fs::SD;
	app->size = 0;
	app->titleId = 0x0000000000000000;

	ret = httpcOpenContext(&context, HTTPC_METHOD_GET, url, 0);
        if(ret!=0)return ret;

        // We should /probably/ make sure Range: is supported
	// before we try to do this, but these 8 bytes are the titleId
	ret = httpcAddRequestHeaderField(&context, (char*)"Range", (char*)"bytes=11292-11299");
        if(ret!=0)return ret;

	ret = httpcBeginRequest(&context);
	if(ret!=0)return ret;

	ret = httpcGetResponseStatusCode(&context, &statuscode, 0);
	if(ret!=0)return ret;

	if(statuscode!=206)return -2; // 206 Partial Content

	u8 *buf = (u8*)malloc(8); // Allocate u8*8 == u64
	if(buf==NULL)return -1;
	memset(buf, 0, 8); // Zero out

	ret=httpcDownloadData(&context, buf, 8, NULL);
        // Safely convert our 8 byte string into a u64
	app->titleId = ((u64)buf[0] << 56 | (u64)buf[1] << 48 | (u64)buf[2] << 40 | (u64)buf[3] << 32 | (u64)buf[4] << 24 | (u64)buf[5] << 16 | (u64)buf[6] << 8 | (u64)buf[7]);
	free(buf);

        buf = (u8*)malloc(64);

        if(httpcGetResponseHeader(&context, (char*)"Content-Range", (char*)buf, 64)==0){
		char *ptr = strchr((const char *)buf, 47);
		app->size = atoll(&ptr[1]);
        }
        free(buf);


	ret = httpcCloseContext(&context);
        if(ret!=0)return ret;

	return 0;
}

Result http_download(char *url, app::App *app) {
	Result ret=0;
	httpcContext context;
	u32 statuscode=0;
        u32 contentsize=0, downloadsize=0;
	char *buf;

	ret = httpcOpenContext(&context, HTTPC_METHOD_GET, url, 0);
        if(ret!=0)return ret;

        ret = httpcAddRequestHeaderField(&context, (char*)"Accept-Encoding", (char*)"gzip, deflate");
        if(ret!=0)return ret;

	ret = httpcBeginRequest(&context);
	if(ret!=0)return ret;

	ret = httpcGetResponseStatusCode(&context, &statuscode, 0);
	if(ret!=0)return ret;

	if(statuscode!=200)return -2;

	ret=httpcGetDownloadSizeState(&context, &downloadsize, &contentsize);
	if(ret!=0)return ret;

        buf = (char*)malloc(16);
	if(buf==NULL)return -1;
	memset(buf, 0, 16);

	if(httpcGetResponseHeader(&context, (char*)"Content-Encoding", (char*)buf, 16)==0){
                printf("Content-Encoding: %s\n", buf);
        }

        app::install(app->mediaType, &context, app->size, &onProgress);

	free(buf);

	ret = httpcCloseContext(&context);
	if(ret!=0)return ret;

	return ret;
}

#define WIDTH 640
#define HEIGHT 480
#define WAIT_TIMEOUT 300000000ULL

void takePicture(u16 *buf) {
	u32 bufSize;
	printf("CAMU_GetMaxBytes: 0x%08X\n", (unsigned int) CAMU_GetMaxBytes(&bufSize, WIDTH, HEIGHT));
	printf("CAMU_SetTransferBytes: 0x%08X\n", (unsigned int) CAMU_SetTransferBytes(PORT_CAM1, bufSize, WIDTH, HEIGHT));

	printf("CAMU_Activate: 0x%08X\n", (unsigned int) CAMU_Activate(SELECT_OUT1));

	Handle camReceiveEvent = 0;

	printf("CAMU_ClearBuffer: 0x%08X\n", (unsigned int) CAMU_ClearBuffer(PORT_CAM1));
	//printf("CAMU_SynchronizeVsyncTiming: 0x%08X\n", (unsigned int) CAMU_SynchronizeVsyncTiming(SELECT_OUT1, SELECT_OUT2));

	printf("CAMU_StartCapture: 0x%08X\n", (unsigned int) CAMU_StartCapture(PORT_CAM1));

	printf("CAMU_SetReceiving: 0x%08X\n", (unsigned int) CAMU_SetReceiving(&camReceiveEvent, (u8*)buf, PORT_CAM1, WIDTH * HEIGHT * 2, (s16) bufSize));
	printf("svcWaitSynchronization: 0x%08X\n", (unsigned int) svcWaitSynchronization(camReceiveEvent, WAIT_TIMEOUT));
	//printf("CAMU_PlayShutterSound: 0x%08X\n", (unsigned int) CAMU_PlayShutterSound(SHUTTER_SOUND_TYPE_NORMAL));

	printf("CAMU_StopCapture: 0x%08X\n", (unsigned int) CAMU_StopCapture(PORT_CAM1));

	svcCloseHandle(camReceiveEvent);

	printf("CAMU_Activate: 0x%08X\n", (unsigned int) CAMU_Activate(SELECT_NONE));

}

void writePictureToIntensityMap(void *fb, void *img, u16 width, u16 height) {
        u8 *fb_8 = (u8*) fb;
        u16 *img_16 = (u16*) img;
        for(u32 i = 0; i < width * height; i++) {
                u16 data = img_16[i];
                uint8_t b = ((data >> 11) & 0x1F) << 3;
                uint8_t g = ((data >> 5) & 0x3F) << 2;
                uint8_t r = (data & 0x1F) << 3;
                fb_8[i] = (r + g + b) / 3;
        }
}

int main(int argc, char **argv)
{
	Result ret=0;

        core::init(argc);
	httpcInit();
	camInit();

	consoleInit(GFX_BOTTOM,NULL);

	app::App app;

	//Change this to your own URL.
	char *url = (char*)"http://3ds.intherack.com/devproject.cia";
/*
	printf("Downloading %s\n",url);
	gpu::flushBuffer();

	ret = http_getinfo(url, &app);
	if(ret!=0)return ret;

	if(app.titleId != 0 && app::installed(app)) { // Check if we have a titleId to remove
		printf("Uninstalling titleId: 0x%llx\n", app.titleId);
		gpu::flushBuffer();
		app::uninstall(app);
	}

	ret = http_download(url, &app);
	if(ret!=0)return ret;

	printf("titleId: 0x%llx\nInstall finished.\nPress START to close.\n", app.titleId);
	gpu::flushBuffer();
*/

	printf("CAMU_SetSize: 0x%08X\n", (unsigned int) CAMU_SetSize(SELECT_OUT1, SIZE_VGA, CONTEXT_A));
	printf("CAMU_SetOutputFormat: 0x%08X\n", (unsigned int) CAMU_SetOutputFormat(SELECT_OUT1, OUTPUT_RGB_565, CONTEXT_A));

	printf("CAMU_SetNoiseFilter: 0x%08X\n", (unsigned int) CAMU_SetNoiseFilter(SELECT_OUT1, true));
	printf("CAMU_SetAutoExposure: 0x%08X\n", (unsigned int) CAMU_SetAutoExposure(SELECT_OUT1, true));
	printf("CAMU_SetAutoWhiteBalance: 0x%08X\n", (unsigned int) CAMU_SetAutoWhiteBalance(SELECT_OUT1, true));
	//printf("CAMU_SetEffect: 0x%08X\n", (unsigned int) CAMU_SetEffect(SELECT_OUT1, EFFECT_MONO, CONTEXT_A));

	printf("CAMU_SetTrimming: 0x%08X\n", (unsigned int) CAMU_SetTrimming(PORT_CAM1, false));


	u16 *camBuf = (u16*)malloc(WIDTH * HEIGHT * 2);
	if(!camBuf) {
		printf("Failed to allocate memory!");
		return 0;
	}

	struct quirc *qr;

	qr = quirc_new();
	if (!qr) {
		printf("Failed to allocate memory");
		return 0;
	}

	if (quirc_resize(qr, WIDTH, HEIGHT) < 0) {
		printf("Failed to allocate video memory");
		return 0;
	}

	// Main loop
	while (core::running())
	{
		hid::poll();

		// Your code goes here

		if (hid::pressed(hid::BUTTON_START))
			break; // break in order to return to hbmenu

		if (hid::pressed(hid::BUTTON_R)) {
			takePicture(camBuf);

			int w=WIDTH, h=HEIGHT;

			u8 *image = (u8*)quirc_begin(qr, &w, &h);
			writePictureToIntensityMap(image, camBuf, WIDTH, HEIGHT);
			quirc_end(qr);

			int num_codes = quirc_count(qr);
			printf("num_codes: %i\n", num_codes);
			gpu::flushBuffer();
			for (int i = 0; i < num_codes; i++) {
				struct quirc_code code;
				struct quirc_data data;
				quirc_decode_error_t err;

				quirc_extract(qr, i, &code);

				err = quirc_decode(&code, &data);
				if (err)
					printf("DECODE FAILED: %s\n", quirc_strerror(err));
				else
					printf("Data: %s\n", data.payload);
			}
		}

		// Flush and swap framebuffers
		gpu::flushBuffer();
		gpu::swapBuffers(true);
	}

	quirc_destroy(qr);

	free(camBuf);

	// Exit services
	camExit();
	httpcExit();
	core::exit();

	return 0;
}

