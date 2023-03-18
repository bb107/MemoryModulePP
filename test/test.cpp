#include "../MemoryModule/stdafx.h"
#include "../MemoryModule/LoadDllMemoryApi.h"
#include <cstdio>

//PMMP_GLOBAL_DATA MmpGlobalDataPtr = *(PMMP_GLOBAL_DATA*)GetProcAddress(GetModuleHandleA("MemoryModule.dll"), "MmpGlobalDataPtr");

static PVOID ReadDllFile(LPCSTR FileName) {
    LPVOID buffer;
    size_t size;
    FILE* f;
    fopen_s(&f, FileName, "rb");
    if (!f)return 0;
    _fseeki64(f, 0, SEEK_END);
    if (!(size = _ftelli64(f))) {
        fclose(f);
        return 0;
    }
    _fseeki64(f, 0, SEEK_SET);
    fread(buffer = new char[size], 1, size, f);
    fclose(f);
    return buffer;
}

static void DisplayStatus() {
    printf(
        "MemoryModulePP [Version %d.%d]\n\n\tMmpFeatures = %08X\n\n\tLdrpModuleBaseAddressIndex = %p\n\tNtdllLdrEntry = %p\n\tRtlRbInsertNodeEx = %p\n\tRtlRbRemoveNode = %p\n\n\tLdrpInvertedFunctionTable = %p\n\n\tLdrpHashTable = %p\n\n",
        MmpGlobalDataPtr->MajorVersion,
        MmpGlobalDataPtr->MinorVersion,
        MmpGlobalDataPtr->MmpFeatures,
        MmpGlobalDataPtr->MmpBaseAddressIndex->LdrpModuleBaseAddressIndex,
        MmpGlobalDataPtr->MmpBaseAddressIndex->NtdllLdrEntry,
        MmpGlobalDataPtr->MmpBaseAddressIndex->_RtlRbInsertNodeEx,
        MmpGlobalDataPtr->MmpBaseAddressIndex->_RtlRbRemoveNode,
        MmpGlobalDataPtr->MmpInvertedFunctionTable->LdrpInvertedFunctionTable,
        MmpGlobalDataPtr->MmpLdrEntry->LdrpHashTable
    );
}

int test() {
    LPVOID buffer = ReadDllFile("a.dll");

    HMODULE hm = LoadLibraryMemory(buffer);
    FARPROC fp = GetProcAddress(hm, "GdiplusTest");
    bool c = true;
    while (c) {
        fp();
    }
    
    return 0;
}

int main() {
    DisplayStatus();
    test();

    WaitForSingleObject(NtCurrentProcess(), INFINITE);

    return 0;
}
