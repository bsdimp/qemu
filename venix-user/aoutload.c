/* Code for loading Venix executables. */

#include "qemu/osdep.h"
#include "qemu.h"

#if 0
#define TARGET_NGROUPS 32

/* ??? This should really be somewhere else.  */
abi_long memcpy_to_target(abi_ulong dest, const void *src,
                          unsigned long len)
{
    void *host_ptr;

    host_ptr = lock_user(VERIFY_WRITE, dest, len, 0);
    if (!host_ptr)
        return -TARGET_EFAULT;
    memcpy(host_ptr, src, len);
    unlock_user(host_ptr, dest, 1);
    return 0;
}

static int count(char ** vec)
{
    int         i;

    for(i = 0; *vec; i++) {
        vec++;
    }

    return(i);
}
#endif


int loader_exec(const char * filename, char ** argv, char ** envp,
                struct target_pt_regs * regs, struct image_info *infop)
{
    int fd = -1;
    struct venix_exec hdr;
    char *memory = NULL;
    abi_ulong offset, segment;

    // Need to map things into target memory
    // need to set infop stuff

    printf("Loading %s\n", filename);
    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        return -errno;
    }

    if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        goto errout;
    }
    printf("Magic is 0%o\n", hdr.a_magic);
    if (hdr.a_magic != OMAGIC && hdr.a_magic != NMAGIC) {
        printf("Bad Magic Number\n");
        errno = EINVAL;
        goto errout;
    }

    memory = malloc(1 << 20);	// 8086 has 1MB space, so just allocate it
    if (memory == NULL) {
        errno = ENOMEM;
        goto errout;
    }
    memset(memory, 0, 1 << 20);

    segment = 0x60;
    offset = segment << 4;
    // Read Text
    if (read(fd, memory + offset, hdr.a_text) != hdr.a_text) {
        goto errout;
    }
    // Read Data
    if (read(fd, memory + offset + hdr.a_text + hdr.a_stack,
             hdr.a_data) != hdr.a_data) {
        goto errout;
    }

    infop->start_brk = offset + hdr.a_text + hdr.a_stack + hdr.a_data + hdr.a_bss;
    /*
     * For NMAGIC binaries, the 'break' address doesn't include the text section,
     * so adjust that after we've marked all the memory in use.
     */
    if (hdr.a_magic == NMAGIC) {
        infop->start_brk -= hdr.a_text;
    }

    return 0;
errout:
    free(memory);
    close(fd);
    return -errno;
}
