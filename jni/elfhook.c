#include "elfhook.h"
#include <linux/binder.h>


void hexdump(void *_data, size_t len)
{
    unsigned char *data = _data;
    size_t count;
    for (count = 0; count < len; count++) {
        if ((count & 15) == 0)
            fprintf(stderr,"%04zu:", count);
        fprintf(stderr," %02x %c", *data,
                (*data < 32) || (*data > 126) ? '.' : *data);
        data++;
        if ((count & 15) == 15)
            fprintf(stderr,"\n");
    }
    if ((count & 15) != 0)
        fprintf(stderr,"\n");
}

void chardump(void* _data, size_t len, char* buffer){
	unsigned char* data = _data;
	size_t count;
	for(count = 0; count < len; count++){
		// if((count & 15) == 0)
		// 	LOGE("%04zu:", count);
		if(((*data >= 65) && (*data <= 90)) || ((*data >= 97) && (*data <= 122)) || (*data == 46)) {
			*buffer = *data;
			buffer ++;
		}
		data++;
		// if((count & 15) != 0)
		// 	LOGE("\n");
	}
}

void binder_dump_txn(struct binder_transaction_data *txn)
{
    struct flat_binder_object *obj;
    binder_size_t *offs = (binder_size_t *)(uintptr_t)txn->data.ptr.offsets;
    size_t count = txn->offsets_size / sizeof(binder_size_t);
    LOGE("target %x  cookie %x  code %x  flags %d",
            (uint64_t)txn->target.ptr, (uint64_t)txn->cookie, txn->code, txn->flags);
    // LOGE("  pid %8d  uid %8d  data %x  offs %d",
    //         txn->sender_pid, txn->sender_euid, (uint64_t)txn->data_size, (uint64_t)txn->offsets_size);
    char* buffer = (char*)malloc(txn -> data_size);
    chardump((void *)(uintptr_t)txn->data.ptr.buffer, txn->data_size, buffer);
    LOGE("[%s]", buffer);
    // fprintf(stderr,"  target %016x"PRIx64"  cookie %016x"PRIx64"  code %08x  flags %08x\n",
            // (uint64_t)txn->target.ptr, (uint64_t)txn->cookie, txn->code, txn->flags);
    // fprintf(stderr,"  pid %8d  uid %8d  data %"PRIu64"  offs %"PRIu64"\n",
    //         txn->sender_pid, txn->sender_euid, (uint64_t)txn->data_size, (uint64_t)txn->offsets_size);
    // hexdump((void *)(uintptr_t)txn->data.ptr.buffer, txn->data_size);
    while (count--) {
        obj = (struct flat_binder_object *) (((char*)(uintptr_t)txn->data.ptr.buffer) + *offs++);
        // fprintf(stderr,"  - type %08x  flags %08x  ptr %016"PRIx64"  cookie %016"PRIx64"\n",
        //         obj->type, obj->flags, (uint64_t)obj->binder, (uint64_t)obj->cookie);v 
    }
}

int new_ioctl (int __fd, unsigned long int __request, void * arg)
{
	LOGE("ioctl called \n");
	int ret = -1;

	if (__request == BINDER_WRITE_READ){
		int dir = _IOC_DIR(__request);    //获取传输方向 
		int type = _IOC_TYPE(__request);  //获取类型 
		int nr = _IOC_NR(__request);      //获取类型命令
		int size = _IOC_SIZE(__request);  //获取传输数据大小
		// LOGE("dir : %d, type : %d, nr : %d, size : %d", dir, type, nr, size);
		struct binder_write_read* bwr = (struct binder_write_read*)arg;
		signed long write_size = bwr->write_size;  
        signed long read_size = bwr->read_size;  
		// LOGE("write_size:%ld -------- read_size:%ld", write_size, read_size);
		if(write_size > 0){
			void* tmp = bwr -> write_buffer;
			// LOGE("write_buffer size:%d --- %d\n", sizeof(bwr -> write_buffer), write_size);
			int j = 0;
			for(j = 0; j < bwr -> write_size; j = j+4){
				uint32_t code = *(uint32_t *)tmp;
				tmp += 4;
				switch(code){
					case BC_TRANSACTION:{
						struct binder_transaction_data *txn = (struct binder_transaction_data*)tmp;
						binder_dump_txn(txn);
					}
					break;
					case BC_REPLY:

					break;
				}
			}
		}
		if(read_size > 0){
			void* tmp = bwr -> read_buffer;

		}
	}

	ret = (*real_ioctl)(__fd, __request, arg);
	return ret;
}

void* get_module_base(pid_t pid, const char* module_name)
{
	FILE *fp;
	long addr = 0;
	char *pch;
	char filename[32];
	char line[1024];

	if (pid < 0) {
		/* self process */
		snprintf(filename, sizeof(filename), "/proc/self/maps", pid);
	} else {
		snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	}

	fp = fopen(filename, "r");

	if (fp != NULL) {
		while (fgets(line, sizeof(line), fp)) {
			if (strstr(line, module_name)) {
				pch = strtok( line, "-" );
				addr = strtoul( pch, NULL, 16 );

				if (addr == 0x8000)
					addr = 0;
				break;
			}
		}

		fclose(fp) ;
	}

	return (void *)addr;
}

int hook_func(void* func, void** real_func, void* new_func, char* libpath)
{

	*real_func = func;
	// LOGD_C("real_func = %p\n", *real_func);
	void * base_addr = get_module_base(getpid(), libpath);
	// LOGD_C("libpath = %s, address = %p\n", libpath, base_addr);

	int fd;
	fd = open(libpath, O_RDONLY);
	if (-1 == fd) {
		// LOGD_C("error\n");
		return -1;
	}

	Elf32_Ehdr ehdr;
	read(fd, &ehdr, sizeof(Elf32_Ehdr));

	unsigned long shdr_addr = ehdr.e_shoff;
	int shnum = ehdr.e_shnum;
	int shent_size = ehdr.e_shentsize;
	unsigned long stridx = ehdr.e_shstrndx;

	Elf32_Shdr shdr;
	lseek(fd, shdr_addr + stridx * shent_size, SEEK_SET);
	read(fd, &shdr, shent_size);

	char * string_table = (char *)malloc(shdr.sh_size);
	lseek(fd, shdr.sh_offset, SEEK_SET);
	read(fd, string_table, shdr.sh_size);
	lseek(fd, shdr_addr, SEEK_SET);

	int i;
	uint32_t out_addr = 0;
	uint32_t out_size = 0;
	uint32_t got_item = 0;
	int32_t got_found = 0;

	for (i = 0; i < shnum; i++) {
		read(fd, &shdr, shent_size);
		if (shdr.sh_type == SHT_PROGBITS) {
			int name_idx = shdr.sh_name;
			// LOGD_C("String Tale: %s\n", &(string_table[name_idx]), sizeof(string_table));
			if (strcmp(&(string_table[name_idx]), ".got.plt") == 0
					|| strcmp(&(string_table[name_idx]), ".got") == 0) {
				out_addr = base_addr + shdr.sh_addr;
				out_size = shdr.sh_size;
				// LOGD_C("out_addr = %p, out_size = %lx\n", out_addr, out_size);

				uint32_t toadr = (uint32_t) base_addr + shdr.sh_addr;
				// LOGD_C("toadr = %p, out_size = %lx\n", toadr, out_size);

				for (i = 0; i < out_size; i += 4) {
					got_item = *(uint32_t *)(out_addr + i);
					//LOGD_C("got_item = %p\n, real_ioctl= %p\n", got_item, real_ioctl);
					if (got_item  == (uint32_t) *real_func) {
						// LOGD_C("Found func \n");
						got_found = 1;
						LOGE("Found func");
						uint32_t page_size = getpagesize();
						uint32_t entry_page_start = (out_addr + i) & (~(page_size - 1));
						mprotect((uint32_t *)entry_page_start, page_size, PROT_READ | PROT_WRITE);
						*(uint32_t *)(out_addr + i) = (uint32_t) new_func;

						break;
					} else if (got_item == (uint32_t) new_func) {
						// LOGD_C("Already hooked\n");
						break;
					}
				}
				if (got_found)
					break;
			}
		}
	}

	free(string_table);
	close(fd);
	return 1;
}
