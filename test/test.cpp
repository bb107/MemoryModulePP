//#include "../MemoryModule/NativeFunctionsInternal.h"
#include "../MemoryModule/LoadDllMemoryApi.h"
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#include <cstdio>
#pragma warning(disable:4996)

int main() {
    //return ((int(*)(int))GetProcAddress(LoadLibraryW(L"a.dll"), "exception"))(0);
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
    
    HMEMORYMODULE m1 = nullptr, m2 = m1;
    HMODULE hModule = nullptr;
    FARPROC pfn = nullptr;
    DWORD MemoryModuleFeatures = 0;

    typedef int(* _exception)(int code);
    _exception exception = nullptr;
    HRSRC hRsrc;
    DWORD SizeofRes;
    HGLOBAL gRes;
    char str[10];

    NtQuerySystemMemoryModuleFeatures(&MemoryModuleFeatures);
    if (MemoryModuleFeatures != MEMORY_FEATURE_ALL) {
        printf("not support all features on this version of windows.\n");
    }
    
    if (!NT_SUCCESS(NtLoadDllMemoryExW(&m1, nullptr, 0, buffer, 0, L"kernel64", nullptr))) goto end;
    LoadLibraryW(L"wininet.dll");
    if (!NT_SUCCESS(NtLoadDllMemoryExW(&m2, nullptr, 0, buffer, 0, L"kernel128", nullptr))) goto end;

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
        for (int i = 0; i < 4; ++i)exception(i);
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
    if (m1)NtUnloadDllMemory(m1);
    FreeLibrary(GetModuleHandleW(L"wininet.dll"));
    if (m2)NtUnloadDllMemory(m2);

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
