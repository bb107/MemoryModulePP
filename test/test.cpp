#include "../MemoryModule/stdafx.h"
#include "../MemoryModule/LoadDllMemoryApi.h"
#include <cstdio>
#pragma comment(lib,"ntdll.lib")

PMMP_GLOBAL_DATA MmpGlobalDataPtr;

decltype(&LdrLoadDllMemoryExW)__LdrLoadDllMemoryExW;
decltype(&LdrUnloadDllMemory)__LdrUnloadDllMemory;

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

    buffer = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    fread(buffer, 1, size, f);
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

int test() {
    LPVOID buffer = ReadDllFile2("a.dll");

    HMODULE hModule = nullptr;
    FARPROC pfn = nullptr;

    typedef int(*_exception)(int code);
    _exception exception = nullptr;
    HRSRC hRsrc;
    DWORD SizeofRes;
    HGLOBAL gRes;
    char str[10];

    if (!NT_SUCCESS(__LdrLoadDllMemoryExW(&hModule, nullptr, 0, buffer, 0, L"kernel64", nullptr))) goto end;

    //forward export
    pfn = (decltype(pfn))(GetProcAddress(hModule, "Socket")); //ws2_32.WSASocketW
    pfn = (decltype(pfn))(GetProcAddress(hModule, "VerifyTruse")); //wintrust.WinVerifyTrust

    //exception
    exception = (_exception)GetProcAddress(hModule, "exception");
    if (exception) {
        for (int i = 0; i < 5; ++i)exception(i);
    }

    //tls
    pfn = GetProcAddress(hModule, "thread");
    if (pfn && pfn()) {
        printf("thread test failed.\n");
    }

    //resource
    if (!LoadStringA(hModule, 101, str, 10)) {
        printf("load string failed.\n");
    }
    else {
        printf("%s\n", str);
    }
    if (!(hRsrc = FindResourceA(hModule, MAKEINTRESOURCEA(102), "BINARY"))) {
        printf("find binary resource failed.\n");
    }
    else {
        if ((SizeofRes = SizeofResource(hModule, hRsrc)) != 0x10) {
            printf("invalid res size.\n");
        }
        else {
            if (!(gRes = LoadResource(hModule, hRsrc))) {
                printf("load res failed.\n");
            }
            else {
                if (!LockResource(gRes))printf("lock res failed.\n");
                else {
                    printf("resource test success.\n");
                }
            }
        }
    }

end:
    __LdrUnloadDllMemory(hModule);
    VirtualFree(buffer, 0, MEM_RELEASE);
    return 0;
}

ULONG_PTR ReflectiveLoaderOffset() {
    ULONG_PTR offset = 0;

    auto hm = LoadLibrary(L"MemoryModule.dll");
    if (hm) {
        auto pfn = GetProcAddress(hm, "ReflectiveLoader");
        offset = ULONG_PTR(pfn) - ULONG_PTR(hm);

        auto header = RtlImageNtHeader(hm);
        auto section = IMAGE_FIRST_SECTION(header);
        for (int i = 0; i < header->FileHeader.NumberOfSections; ++i, ++section) {
            if (offset >= section->VirtualAddress && offset < section->VirtualAddress + section->SizeOfRawData) {
                offset = ULONG_PTR(pfn) - (ULONG_PTR(hm) + section->VirtualAddress) + section->PointerToRawData;
                break;
            }
        }
    }

    return offset;
}

typedef ULONG_PTR(WINAPI* LOADER)(PVOID);

int main() {
    printf("%08x\n", ReflectiveLoaderOffset());
    auto buffer = ReadDllFile2("MemoryModule.dll");
    auto loader = LOADER(ULONG_PTR(buffer) + 0x96e0); //ReflectiveLoaderOffset() -> 0x96e0
    auto hm = (HMODULE)loader(buffer);

    MmpGlobalDataPtr = *(PMMP_GLOBAL_DATA*)GetProcAddress(hm, "MmpGlobalDataPtr");
    __LdrLoadDllMemoryExW = (decltype(&LdrLoadDllMemoryExW))GetProcAddress(hm, "LdrLoadDllMemoryExW");
    __LdrUnloadDllMemory = (decltype(&LdrUnloadDllMemory))GetProcAddress(hm, "LdrUnloadDllMemory");
    
    DisplayStatus();
    test();

    return 0;
}
