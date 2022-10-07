#include "../MemoryModule/stdafx.h"
#include <cstdio>

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

int __stdcall test_user32() {
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
