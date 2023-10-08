#include "../MemoryModule/stdafx.h"
#include "../MemoryModule/LoadDllMemoryApi.h"
#include <cstdio>

//PMMP_GLOBAL_DATA MmpGlobalDataPtr = *(PMMP_GLOBAL_DATA*)GetProcAddress(GetModuleHandleA("MemoryModule.dll"), "MmpGlobalDataPtr");

static void DisplayStatus() {
    printf(
        "\
MemoryModulePP [Version %d.%d%s]\n\n\t\
MmpFeatures = %08X\n\n\t\
LdrpModuleBaseAddressIndex = %p\n\t\
NtdllLdrEntry = %p\n\t\
RtlRbInsertNodeEx = %p\n\t\
RtlRbRemoveNode = %p\n\n\t\
LdrpInvertedFunctionTable = %p\n\n\t\
LdrpHashTable = %p\n\n\
",
        MmpGlobalDataPtr->MajorVersion,
        MEMORY_MODULE_GET_MINOR_VERSION(MmpGlobalDataPtr->MinorVersion),
        MEMORY_MODULE_IS_PREVIEW(MmpGlobalDataPtr->MinorVersion) ? " Preview" : "",
        MmpGlobalDataPtr->MmpFeatures,
        MmpGlobalDataPtr->MmpBaseAddressIndex->LdrpModuleBaseAddressIndex,
        MmpGlobalDataPtr->MmpBaseAddressIndex->NtdllLdrEntry,
        MmpGlobalDataPtr->MmpBaseAddressIndex->_RtlRbInsertNodeEx,
        MmpGlobalDataPtr->MmpBaseAddressIndex->_RtlRbRemoveNode,
        MmpGlobalDataPtr->MmpInvertedFunctionTable->LdrpInvertedFunctionTable,
        MmpGlobalDataPtr->MmpLdrEntry->LdrpHashTable
    );
}

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

PVOID ReadDllFile2(LPCSTR FileName) {
    CHAR path[MAX_PATH + 4];
    DWORD len = GetModuleFileNameA(nullptr, path, sizeof(path));

    if (len) {
        while (len && path[len] != '\\') --len;

        if (len) {
            strcpy_s(&path[len + 1], sizeof(path) - len - 1, FileName);
            return ReadDllFile(path);
        }
    }

    return nullptr;
}

#define LIBRARY_PATH "\\\\DESKTOP-1145141919810\\Debug\\"

HMODULE WINAPI MyLoadLibrary(LPCSTR lpModuleName) {
    HMODULE hModule;
    PVOID buffer;

    if (0 == _stricmp(lpModuleName, "CTestClassLibrary1.dll")) {
        buffer = ReadDllFile(LIBRARY_PATH"CTestClassLibrary1.dll");
    }
    else if (0 == _stricmp(lpModuleName, "CTestClassLibrary2.dll")) {
        buffer = ReadDllFile(LIBRARY_PATH"CTestClassLibrary2.dll");
    }
    else if (0 == _stricmp(lpModuleName, "CTestClassLibrary1Dep.dll")) {
        buffer = ReadDllFile(LIBRARY_PATH"CTestClassLibrary1Dep.dll");
    }
    else {
        return nullptr;
    }

    hModule = LoadLibraryMemoryExA(buffer, 0, lpModuleName, nullptr, 0);
    delete[]buffer;
    return hModule;
}

VOID TestImportTableResolver() {
    
    //
    // Register the import table resolver.
    //
    HANDLE hResolver = MmRegisterImportTableResolver(MyLoadLibrary, FreeLibraryMemory);

    //
    //                  |-> CTestClassLibrary1.dll -> CTestClassLibrary1Dep.dll
    // CTestClient.dll -|
    //                  |-> CTestClassLibrary2.dll
    //
    
    PVOID Client = ReadDllFile2("CTestClient.dll");
    HMODULE hm = LoadLibraryMemoryEx(Client, 0, TEXT("CTestClient.dll"), nullptr, 0);
    delete[]Client;

    if (hm) {
        auto pfn = GetProcAddress(hm, "TestProc");
        if (pfn) {
            pfn();
        }

        FreeLibraryMemory(hm);
    }

    MmRemoveImportTableResolver(hResolver);
}

int main() {
    DisplayStatus();
    TestImportTableResolver();

    return 0;
}
