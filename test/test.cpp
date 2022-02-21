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

int main() {
    HMEMORYMODULE hModule;
    NTSTATUS status;
    PVOID buffer = ReadDllFile("ManagedLib_x64.dll");

    if (!buffer) {
        return 0;
    }

    status = LdrLoadDllMemoryExW(
        &hModule,                   // ModuleHandle
        nullptr,                    // LdrEntry
        LOAD_FLAGS_HOOK_DOT_NET,    // Flags
        buffer,                     // Buffer
        0,                          // Reserved
        nullptr,                    // DllBaseName
        nullptr                     // DllFullName
    );
    if (NT_SUCCESS(status) && status != STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {
        int result = 0;
        typedef VOID(WINAPI* func)(LPCSTR);

        func f = (func)GetProcAddress(hModule, "ManagedExportFunc");
        if (f)f("Hello World!");

        LdrUnloadDllMemory(hModule);
    }

    return 0;
}
