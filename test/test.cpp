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

VOID NTAPI MmpInitialize();

DWORD NTAPI Thread(PVOID) {
    
    return 0;
}

int main() {

    MmpInitialize();

    HMODULE hModule = LoadLibrary(L"a.dll");
    if (hModule) {

        HANDLE hThread = CreateThread(nullptr, 0, Thread, nullptr, 0, nullptr);
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }

        FreeLibrary(hModule);
    }

    return 0;
}
