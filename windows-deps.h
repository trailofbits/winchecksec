#pragma once
#include <stdint.h>
#define EXPORT

// winnt.h
typedef void *HANDLE;
typedef wchar_t         WCHAR;
typedef const WCHAR    *PCWSTR,     *LPCWSTR;

typedef uint8_t     BYTE;
typedef uint32_t    DWORD;


#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE           0x0040
#define IMAGE_FILE_RELOCS_STRIPPED	                    0x0001
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY        0x0080
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT              0x0100
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION           0x0200
#define IMAGE_DLLCHARACTERISTICS_NO_SEH                 0x0400

// winerror.h
#define ERROR_SUCCESS                                      0

// guiddef.h
typedef struct _GUID
{
    unsigned int   Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char  Data4[ 8 ];
} GUID;


// From Ghidra
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF               0x4000

