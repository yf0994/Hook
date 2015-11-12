#ifndef __ELFPAYLOAD__H__
#define __ELFPAYLOAD__H__


#include <android/log.h>

#define LOGTAG "INJECT"

#define LOGE(fmt, args...) __android_log_print(ANDROID_LOG_ERROR, LOGTAG, fmt, ##args);

int hook_entry(char * a);

#endif