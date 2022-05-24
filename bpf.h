/*
MIT License

Copyright (c) 2022 Khhs167

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


#ifndef BIN_PACK_FORM_H
#define BIN_PACK_FORM_H

#define BPF_HEADER_CHECKSUM_CORRECT (171)
#define BPF_HEADER_STRING ("bpf")
#define BPF_TRUE (1)
#define BPF_FALSE (0)

#ifndef BPF_API
    #define BPF_API static inline
#endif

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

typedef struct{
    uint8_t bpf_file_header[4];
    uint8_t bpf_file_version;
    uint8_t checksum; // For basic encryption. This should always result to the value 171
    uint32_t file_blocks;
    uint32_t data_size;
} bpf_header_t;

typedef struct
{
    uint32_t file_name_hash;
    uint32_t pointer_location;
    uint32_t pointer_size;
} bpf_block_t;

typedef struct
{
    bpf_header_t header;
    bpf_block_t* blocks;
    uint8_t* data;
} bpf_file_t;

typedef struct {
    char* data;
    uint32_t size;
} bpf_file_data_t;

//BPF_API bpf_file_data_t bpf_serialize_file(bpf_file_t file);
BPF_API bpf_file_t bpf_deserialize_memory(char* data);
BPF_API bpf_file_t bpf_deserialize_file(const char* path);
BPF_API bpf_file_t bpf_generate_file(char** file_names, unsigned int file_c, unsigned int* file_sizes, unsigned char** file_data);
BPF_API unsigned int bpf_file_name_hash (char *str);
BPF_API void bpf_free_file(bpf_file_t file);
BPF_API int bpf_verify_file(bpf_file_t file);
BPF_API bpf_file_data_t bpf_read(bpf_file_t file, const char* name);

#endif

#if defined(BPF_IMPLEMENT)
#define BPF_IMPLEMENT

BPF_API bpf_file_data_t bpf_read(bpf_file_t file, const char* name){
    uint32_t hash = bpf_file_name_hash((char*)name);
    for(int i = 0; i < file.header.file_blocks; i++){
        bpf_block_t block = file.blocks[i];
        if(block.file_name_hash == hash){
            //data_ptr += block.pointer_location;
            bpf_file_data_t data = {};
            data.size = block.pointer_size;
            data.data = (char*)malloc(block.pointer_size);
            for(int j = block.pointer_location; j < block.pointer_location + block.pointer_size; j++){
                if(j >= file.header.data_size)
                    continue;
                data.data[j] = file.data[j];
            }
            return data;
        }
    }
    bpf_file_data_t data_blank = {};
    return data_blank;
}

BPF_API void bpf_free_file(bpf_file_t file){
    free(file.blocks);
    free(file.data);
}

BPF_API int bpf_verify_file(bpf_file_t file){
    if(file.header.checksum != BPF_HEADER_CHECKSUM_CORRECT)
        return BPF_FALSE;
    return BPF_TRUE;
}

BPF_API void bpf_free_file_data(bpf_file_data_t file){
    free(file.data);
}

BPF_API bpf_file_t bpf_deserialize_memory(char* data){
    char* p = data;
    bpf_file_t file = {};

    memcpy(&file.header, p, sizeof(bpf_header_t));
    p += sizeof(bpf_header_t);

    file.blocks = (bpf_block_t*)malloc(sizeof(bpf_block_t) * file.header.file_blocks);
    for(int i = 0; i < file.header.file_blocks; i++){
        bpf_block_t block = {};
        memcpy(&block, p, sizeof(block));
        p += sizeof(block);
        file.blocks[i] = block;
    }
    file.data = (uint8_t*)malloc(file.header.data_size);
    memcpy(file.data, p, file.header.data_size);
    
    return file;
}

BPF_API bpf_file_data_t bpf_serialize_file(bpf_file_t file){
    bpf_file_data_t data = {};
    data.size = sizeof(bpf_header_t);
    data.size += sizeof(bpf_block_t) * file.header.file_blocks;
    data.size += file.header.data_size;

    data.data = (char*)malloc(data.size);
    char *p = data.data;

    memcpy(p, &file.header, sizeof(bpf_header_t));
    p += sizeof(bpf_header_t);

    for(int i = 0; i < file.header.file_blocks; i++){
        bpf_block_t block = file.blocks[i];
        memcpy(p, &block, sizeof(bpf_block_t));
        p += sizeof(bpf_block_t);
    }
    memcpy(p, file.data, file.header.data_size);
    return data;
}

BPF_API bpf_file_t bpf_generate_file(char** file_names, unsigned int file_c, unsigned int* file_sizes, unsigned char** file_data){
    unsigned int data_size = 0;
    for(int i = 0; i < file_c; i++){
        data_size += file_sizes[i];
    }


    bpf_file_t file = {};
    bpf_header_t header = {};

    header.bpf_file_header[0] = 'b';
    header.bpf_file_header[1] = 'p';
    header.bpf_file_header[2] = 'f';
    header.bpf_file_header[3] = 0;
    header.bpf_file_version =  0x10;
    header.checksum = BPF_HEADER_CHECKSUM_CORRECT;
    header.file_blocks = file_c;
    header.data_size = data_size;

    file.header = header;

    file.blocks = (bpf_block_t*)malloc(sizeof(bpf_block_t) * file_c);

    unsigned char* data = (unsigned char*)malloc(data_size);
    unsigned int data_pointer = 0;
    for(unsigned int i = 0; i < file_c; i++){
        bpf_block_t block = {};
        block.file_name_hash = bpf_file_name_hash(file_names[i]);
        block.pointer_location = data_pointer;
        block.pointer_size = file_sizes[i];
        file.blocks[i] = block;

        for (unsigned int j = 0; j < file_sizes[i]; j++)
        {
            data[data_pointer] = file_data[i][j];
            data_pointer++;
        }
    }
    file.data = data;

    return file;
}

#if !defined(BPF_HASH_OVERRIDE)

#define BPF_HASH_MULT 37
unsigned int bpf_file_name_hash(char *str)
{
   unsigned int h;
   unsigned char *p;

   h = 0;
   for (p = (unsigned char*)str; *p != '\0'; p++)
      h = BPF_HASH_MULT * h + *p;
   return h; // or, h % ARRAY_SIZE;
}
#endif
#endif
