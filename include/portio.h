#ifndef PORTIO_H
#define PORTIO_H

#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#if defined(_WIN32) || defined(_WIN64)
    typedef __int64 file_offset_t;
    #define portable_fseek _fseeki64
    #define portable_ftell _ftelli64
#else
#include <sys/types.h>
    typedef off_t file_offset_t;
    #define portable_fseek fseeko
    #define portable_ftell ftello
#endif

char* read_entire_file(const char*, size_t*);

#endif //PORTIO_H
