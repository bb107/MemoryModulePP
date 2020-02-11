#include "../MemoryModule/NativeFunctionsInternal.h"
//#include "../MemoryModule/LoadDllMemoryApi.h"
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#include <cstdio>
#pragma warning(disable:4996)

int main() {
    LPVOID buffer;
    size_t size;
    FILE* f = fopen("a.dll", "rb");
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
    PWSTR t;
    DWORD tableSize;
    DWORD offset = 0, index = 0;
    HRSRC res;
    HGLOBAL hRes;
    PWSTR str;
    
    if (!NT_SUCCESS(NtLoadDllMemoryExW(&m1, nullptr, 0, buffer, size, L"kernel64", nullptr))) goto end;
    //if (!NT_SUCCESS(NtLoadDllMemoryExW(&_m1, nullptr, 0, buffer, size, L"kernel64.dll", nullptr))) goto end;
    //if (!NT_SUCCESS(NtLoadDllMemoryExW(&m2, nullptr, 0, buffer, size, L"kernel128.dll", L"\\?\\kernel512.dll"))) goto end;

    //Load string using FindResource
    hModule = (HMODULE)m1;
    //if (!(res = FindResourceW(hModule, MAKEINTRESOURCEW((101 >> 4) + 1), MAKEINTRESOURCEW(6))))goto end;
    //if (!(hRes = LoadResource(hModule, res)))goto end;
    //if (!(t = (PWSTR)LockResource(hRes)))goto end;
    //tableSize = SizeofResource(hModule, res);
    //while (offset < tableSize) {
    //    if (index == 101 % 0x10) {
    //        if (t[offset] != 0x0000) {
    //            str = &t[offset + 1];
    //            wprintf(L"Size = %d, String = %s\n", t[offset], str);
    //        }
    //        break;
    //    }
    //    offset += t[offset] + 1;
    //    index++;
    //}
    //
    //hModule = GetModuleHandleA("kernel64.dll");
    //GetModuleFileNameA(hModule, name, MAX_PATH);
    //if (hModule)test = GetProcAddress(hModule, "thread");
    //printf("m1:\n\tHMEMORYMODULE\t= 0x%p\n\tHMODULE\t\t= 0x%p\n\tModuleFileName\t= %s\n\ttest\t\t= 0x%p\n\n", m1, hModule, name, test);
    //if (test) test();
    
    //GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)test, &hModule);
    //GetModuleFileNameA(hModule, name, MAX_PATH);
    //test = GetProcAddress(hModule, "test");
    //printf("_m1:\n\tHMEMORYMODULE\t= 0x%p\n\tHMODULE\t\t= 0x%p\n\tModuleFileName\t= %s\n\ttest\t\t= 0x%p\n\n", _m1, hModule, name, test);
    //if (test)test();

    //hModule = GetModuleHandleA("kernel128");
    //GetModuleFileNameA(hModule, name, MAX_PATH);
    if (hModule)exception = (_exception)GetProcAddress(hModule, "exception");
    //printf("m2:\n\tHMEMORYMODULE\t= 0x%p\n\tHMODULE\t\t= 0x%p\n\tModuleFileName\t= %s\n\ttest\t\t= 0x%p\n\n", m2, hModule, name, test);
    if (exception) {
        DebugBreak();
        exception(0);
        exception(1);
        exception(2);
        exception(3);
    }

end:
    delete[]buffer;
    if (m1)NtUnloadDllMemory(m1);
    //if (_m1)NtUnloadDllMemory(_m1);
    //if (m2)NtUnloadDllMemory(m2);
    return 0;
}


//#include <cstdio>
//#include "../MemoryModule/NativeFunctionsInternal.h"
//
//bool c;
//static thread_local int x = -1;
//
//DWORD WINAPI Thread(PVOID) {
//	printf("[1] x = %d\n", x);
//	x = 0;
//	c = true;
//	while (c)Sleep(100);
//	return x;
//}
//
//int main() {
//	x = 1;
//	c = false;
//	HANDLE hThread = CreateThread(nullptr, 0, Thread, nullptr, 0, nullptr);
//	DWORD ex = 0;
//	if (hThread) {
//		while (!c)Sleep(100);
//		printf("[0] x = %d\n", x);
//		c = false;
//		WaitForSingleObject(hThread, 0xffffffff);
//		GetExitCodeThread(hThread, &ex);
//		CloseHandle(hThread);
//		printf("[0] Exit = %d\n", ex);
//	}
//
//	PLIST_ENTRY entry = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
//	PLDR_DATA_TABLE_ENTRY_WIN7 data = nullptr;
//
//	while (entry != entry->Flink) {
//		entry = entry->Flink;
//		data = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY_WIN7, InLoadOrderLinks);
//	}
//
//	return 0;
//}

//#include "../MemoryModule/Native.h"
//#include <cstdio>
//
//static thread_local int x = 0xffccffdd;
//
//DWORD WINAPI Thread(PVOID) {
//    printf("[1] ThreadLocalStoragePointer = %p\n", NtCurrentTeb()->ThreadLocalStoragePointer);
//    return x == 0xffccffdd ? 0 : 1;
//}
//
//int main() {
//    x = 2;
//    printf("[0] ThreadLocalStoragePointer = %p\n", NtCurrentTeb()->ThreadLocalStoragePointer);
//    HANDLE hThread = CreateThread(nullptr, 0, Thread, nullptr, 0, nullptr);
//    DWORD ret = -1;
//    if (hThread) {
//        WaitForSingleObject(hThread, 0xffffffff);
//        GetExitCodeThread(hThread, &ret);
//        CloseHandle(hThread);
//        return ret;
//    }
//    return -1;
//}
