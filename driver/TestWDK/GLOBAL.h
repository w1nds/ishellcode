#pragma once


#include <ntdef.h>
#include <ntifs.h>
#include <Ntstrsafe.h>
#include "WDKExt/Wdk.h"


#define LOG_TAG "ishellcode"
#define MYDEBUG

#ifdef MYDEBUG
#define debug_msg(fmt,...) DbgPrint("[%s]%s[%d]:"fmt,LOG_TAG,__FILE__,__LINE__,##__VA_ARGS__)
#else
#define debug_msg(fmt,...)
#endif // DEBUG

#define MY_POOL_TAG 'enoB'

void* RtlAllocateMemory(bool InZeroMemory, SIZE_T InSize);
void RtlFreeMemory(void* InPointer);
NTSTATUS RtlSuperCopyMemory(IN VOID UNALIGNED* Destination, IN CONST VOID UNALIGNED* Source, IN ULONG Length);
