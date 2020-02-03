#include "../MemoryModule/NativeFunctionsInternal.h"
#include <cstdio>

int main() {
    LPVOID buffer;
    size_t size;
    FILE* f = fopen("d.dll", "rb");
    if (!f)return 0;
    _fseeki64(f, 0, SEEK_END);
    if (!(size = _ftelli64(f))) {
        fclose(f);
        return 0;
    }
    _fseeki64(f, 0, SEEK_SET);
    fread(buffer = new char[size], 1, size, f);
    fclose(f);
    
    HMEMORYMODULE m1 = nullptr, m2 = m1, _m1 = m1;
    char name[MAX_PATH]{};
    HMODULE hModule = nullptr;
    FARPROC test = nullptr;
    typedef int(*_exception)(int type);
    _exception exception = nullptr;
    
    if (!NT_SUCCESS(NtLoadDllMemoryExW(&m1, nullptr, 0, buffer, size, L"kernel64", nullptr))) goto end;
    if (!NT_SUCCESS(NtLoadDllMemoryExW(&_m1, nullptr, 0, buffer, size, L"kernel64.dll", nullptr))) goto end;
    if (!NT_SUCCESS(NtLoadDllMemoryExW(&m2, nullptr, 0, buffer, size, L"kernel128.dll", L"\\?\\kernel512.dll"))) goto end;
    
    hModule = GetModuleHandleA("kernel64.dll");
    GetModuleFileNameA(hModule, name, MAX_PATH);
    if (hModule)test = GetProcAddress(hModule, "test");
    printf("m1:\n\tHMEMORYMODULE\t= 0x%p\n\tHMODULE\t\t= 0x%p\n\tModuleFileName\t= %s\n\ttest\t\t= 0x%p\n\n", m1, hModule, name, test);
    if (test)test();
    
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)test, &hModule);
    GetModuleFileNameA(hModule, name, MAX_PATH);
    test = GetProcAddress(hModule, "test");
    printf("_m1:\n\tHMEMORYMODULE\t= 0x%p\n\tHMODULE\t\t= 0x%p\n\tModuleFileName\t= %s\n\ttest\t\t= 0x%p\n\n", _m1, hModule, name, test);
    if (test)test();

    hModule = GetModuleHandleA("kernel128");
    GetModuleFileNameA(hModule, name, MAX_PATH);
    if (hModule)exception = (_exception)GetProcAddress(hModule, "exception");
    printf("m2:\n\tHMEMORYMODULE\t= 0x%p\n\tHMODULE\t\t= 0x%p\n\tModuleFileName\t= %s\n\ttest\t\t= 0x%p\n\n", m2, hModule, name, test);
    if (exception) {
        exception(0);
        exception(1);
        exception(2);
        exception(3);
    }

end:
    delete[]buffer;
    if (m1)NtUnloadDllMemory(m1);
    if (_m1)NtUnloadDllMemory(_m1);
    if (m2)NtUnloadDllMemory(m2);
    return 0;
}

