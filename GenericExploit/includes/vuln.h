#ifndef VULN_H
#define VULN_H

#include "exploit.h"
#include <stdint.h>

int init_vuln();
uintptr_t alloc_vuln(xploit_t * xploit);
int trigger_vuln(xploit_t * xploit, char * pool_header_content, uintptr_t pool_header_size);
int free_vuln();

#endif