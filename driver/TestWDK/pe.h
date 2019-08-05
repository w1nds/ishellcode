#ifndef _PE_H
#define _PE_H

#include "GLOBAL.h"

#define PE_ERROR_VALUE (ULONG)-1

class PE
{
public:
    static PVOID GetPageBase(PVOID lpHeader, ULONG* Size, PVOID ptr);
    static ULONG GetExportOffset(const unsigned char* FileData, ULONG FileSize, const char* ExportName);
};

#endif