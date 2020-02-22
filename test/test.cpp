#include "../MemoryModule/NativeFunctionsInternal.h"
//#include "../MemoryModule/LoadDllMemoryApi.h"
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#include <cstdio>
#pragma warning(disable:4996)
PLDR_DATA_TABLE_ENTRY_WIN10_2 RtlFindDllLdrEntry(LPCWSTR DllName) {
    PLIST_ENTRY head = &NtCurrentPeb()->Ldr->InMemoryOrderModuleList, entry = head->Flink;
    PLDR_DATA_TABLE_ENTRY_WIN10_2 cur = nullptr;
    while (entry != head) {
        cur = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY_WIN10_2, InMemoryOrderLinks);
        entry = entry->Flink;
        if (!wcsicmp(DllName, cur->BaseDllName.Buffer))return cur;
    }
    return nullptr;
}
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

    HMEMORYMODULE m1 = nullptr, m2 = m1;
    HMODULE hModule = nullptr;
    FARPROC pfn = nullptr;

    if (!NT_SUCCESS(NtLoadDllMemoryExW(&m1, nullptr, 0, buffer, size, L"kernel64", nullptr))) goto end;
    if (!NT_SUCCESS(NtLoadDllMemoryExW(&m2, nullptr, 0, buffer, size, L"kernel128", nullptr))) goto end;
    hModule = (HMODULE)m1;
    pfn = (decltype(pfn))(GetProcAddress(hModule, "Socket")); //ws2_32.WSASocketW
    pfn = (decltype(pfn))(GetProcAddress(hModule, "VerifyTruse")); //wintrust.WinVerifyTrust
    hModule = (HMODULE)m2;
    pfn = (decltype(pfn))(GetProcAddress(hModule, "Socket"));
    pfn = (decltype(pfn))(GetProcAddress(hModule, "VerifyTruse"));
    printf("pfn = %p\n", pfn);

end:
    delete[]buffer;
    if (m1)NtUnloadDllMemory(m1);
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
