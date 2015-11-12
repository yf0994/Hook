#include "elfpayload.h"
#include <jni.h>
#include "elfhook.h"

int hook_entry(char * a){

	LOGE("hook_entry %s\n", a);

	hook_func((void*)ioctl, (void**)&real_ioctl, (void*)new_ioctl, LIBBINDER_PATH);
	return 0;
}
