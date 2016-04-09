#include <citrus/app.hpp>
#include <3ds.h>

using namespace ctr;

Result http_getinfo(char *url, app::App *app);
Result http_download(char *url, app::App *app);
int doWebInstall (char *url);

