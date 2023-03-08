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

    HMEMORYMODULE m1 = nullptr, m2 = m1;
    HMODULE hModule = nullptr;
    FARPROC pfn = nullptr;
    DWORD MemoryModuleFeatures = 0;

    typedef int(*_exception)(int code);
    _exception exception = nullptr;
    HRSRC hRsrc;
    DWORD SizeofRes;
    HGLOBAL gRes;
    char str[10];

    LdrQuerySystemMemoryModuleFeatures(&MemoryModuleFeatures);
    if (MemoryModuleFeatures != MEMORY_FEATURE_ALL) {
        printf("not support all features on this version of windows.\n");
    }

    if (!NT_SUCCESS(LdrLoadDllMemoryExW(&m1, nullptr, 0, buffer, 0, L"kernel64", nullptr))) goto end;
    LoadLibraryW(L"wininet.dll");
    if (!NT_SUCCESS(LdrLoadDllMemoryExW(&m2, nullptr, 0, buffer, 0, L"kernel128", nullptr))) goto end;

    //forward export
    hModule = (HMODULE)m1;
    pfn = (decltype(pfn))(GetProcAddress(hModule, "Socket")); //ws2_32.WSASocketW
    pfn = (decltype(pfn))(GetProcAddress(hModule, "VerifyTruse")); //wintrust.WinVerifyTrust
    hModule = (HMODULE)m2;
    pfn = (decltype(pfn))(GetProcAddress(hModule, "Socket"));
    pfn = (decltype(pfn))(GetProcAddress(hModule, "VerifyTruse"));

    //exception
    hModule = (HMODULE)m1;
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
    delete[]buffer;
    if (m1)LdrUnloadDllMemory(m1);
    FreeLibrary(LoadLibraryW(L"wininet.dll"));
    FreeLibrary(GetModuleHandleW(L"wininet.dll"));
    if (m2)LdrUnloadDllMemory(m2);

    return 0;
}

void test_uef() {
    auto buffer = ReadDllFile("a.dll");

    HMODULE hm = LoadLibraryMemory(buffer);
    auto pfn = GetProcAddress(hm, "unhandled_exception");

    auto result = pfn();
    if (result == 1234) {
        printf("mmpp success\n");
    }

    return;
}

void Tp() {
    auto pool = CreateThreadpool(nullptr);
    if (pool) {

        SetThreadpoolThreadMaximum(pool, 1);
        SetThreadpoolThreadMinimum(pool, 1);

        Sleep(1000);

        CloseThreadpool(pool);
    }
}

int main() {

    DisplayStatus();
    test();
    
    Tp();

    WaitForSingleObject(NtCurrentProcess(), INFINITE);

    return 0;
}
