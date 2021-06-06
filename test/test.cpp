#include "../MemoryModule/LoadDllMemoryApi.h"
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
    PVOID buffer = ReadDllFile("a.dll");

    if (!buffer) {
        return 0;
    }

    status = LdrLoadDllMemoryExW(
        &hModule,   // ModuleHandle
        nullptr,    // LdrEntry
        0,          // Flags
        buffer,     // Buffer
        0,          // Reserved
        nullptr,    // DllBaseName
        nullptr     // DllFullName
    );
    if (NT_SUCCESS(status)) {
        auto thread = GetProcAddress(MemoryModuleToModule(hModule), "thread");
        if (thread) {
            if (thread() != 0) {
                printf("tls failed\n");
            }
        }

        LdrUnloadDllMemory(hModule);
    }

    return 0;
}
