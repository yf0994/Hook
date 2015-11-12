#ifndef __ELFHOOK_H__
#define __ELFHOOK_H__

#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <linux/binder.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "elfpayload.h"

#define LIBBINDER_PATH  "/system/lib/libbinder.so"
#define LIBJAVACORE_PATH  "/system/lib/libjavacore.so"
#define LIBDVM_PATH  "/system/lib/libdvm.so"
#define LIBNETUTILS_PATH  "/system/lib/libnetutils.so"
typedef __u32 binder_size_t;

int (*real_ioctl) (int __fd, unsigned long int __request, void * arg);
int new_ioctl (int __fd, unsigned long int __request, void * arg);
//int (*real_connect)(int sockfd, struct sockaddr * serv_addr, int addrlen) = NULL;
//int (*real_sendto)(int s, const void * msg, int len, unsigned int flags, const struct sockaddr * to, int tolen) = NULL;

int hook_func(void* func, void** real_func, void* new_func, char* libpath);

#endif