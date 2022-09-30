#include "../MemoryModule/stdafx.h"
#include <cstdio>
#pragma warning(disable:4996)

static PVOID ReadDllFile(LPCSTR FileName) {
    LPVOID buffer;
    size_t size;
    FILE* f = fopen(FileName, "rb");
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

int test_a_dll() {
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

int test_user32() {
    HMODULE hModule;
    NTSTATUS status;
    PVOID buffer = ReadDllFile("C:\\Windows\\System32\\user32.dll");
    if (!buffer) return 0;

    hModule = GetModuleHandleA("user32.dll");
    if (hModule)return 0;

    status = LdrLoadDllMemoryExW(
        &hModule,                               // ModuleHandle
        nullptr,                                // LdrEntry
        0,                                      // Flags
        buffer,                                 // Buffer
        0,                                      // Reserved
        L"user32.dll",                          // DllBaseName
        L"C:\\Windows\\System32\\user32.dll"    // DllFullName
    );
    if (NT_SUCCESS(status) && status != STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {

        auto _MessageBoxW = (decltype(&MessageBoxW))GetProcAddress(hModule, "MessageBoxW");
        _MessageBoxW(nullptr, L"Hello, from memory user32!", L"Caption", MB_OK);

        //
        // After calling MessageBox, we can't free it.
        // 
        //LdrUnloadDllMemory(hModule);
    }

    return 0;
}

void test() {

    NTSTATUS status;
    HANDLE hSection;
    OBJECT_ATTRIBUTES oa;
    LARGE_INTEGER li;
    UNICODE_STRING us;
    SECTION_BASIC_INFORMATION sbi;
    PVOID BaseAddress = 0;
    SIZE_T ViewSize = 0;

    li.QuadPart = 0x1000;

    RtlInitUnicodeString(&us, L"\\Sessions\\2\\BaseNamedObjects\\SectionTest");

    InitializeObjectAttributes(&oa, &us, 0, nullptr, nullptr);

    status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        &oa,
        &li,
        PAGE_READWRITE,
        SEC_COMMIT | SEC_BASED,
        nullptr
    );

    if (NT_SUCCESS(status)) {

        status = NtQuerySection(
            hSection,
            SECTION_INFORMATION_CLASS::SectionBasicInformation,
            &sbi,
            sizeof(sbi),
            nullptr
        );

        status = NtMapViewOfSection(
            hSection,
            NtCurrentProcess(),
            &BaseAddress,
            0,
            0,
            nullptr,
            &ViewSize,
            ViewUnmap,
            0,
            PAGE_READWRITE
        );
        if (NT_SUCCESS(status)) {

            status = NtQuerySection(
                hSection,
                SECTION_INFORMATION_CLASS::SectionBasicInformation,
                &sbi,
                sizeof(sbi),
                nullptr
            );

            status = NtUnmapViewOfSection(
                NtCurrentProcess(),
                BaseAddress
            );
        }

        NtClose(hSection);
    }

}

int main() {
    test();
    return 0;
}
