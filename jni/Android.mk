LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog -lEGL
LOCAL_ARM_MODE := arm
LOCAL_MODULE := inject
LOCAL_SRC_FILES := inject.c
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE := payload
LOCAL_SRC_FILES := elfhook.c \
				elfpayload.c
LOCAL_LDLIBS := -llog
	
include $(BUILD_SHARED_LIBRARY)
