#include <Windows.h>
#include <cstdio>

typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(_In_ PVOID ThreadParameter);

#define NtCurrentProcess() (HANDLE)-1

#ifdef _WIN64
#define NtCurrentThreadLocalStoragePointer() *(LPVOID*)(LPBYTE(NtCurrentTeb()) + 0x58)
#else
#define NtCurrentThreadLocalStoragePointer() *(LPVOID*)(LPBYTE(NtCurrentTeb()) + 0x2C)
#endif

typedef struct _CLIENT_ID {
    VOID* UniqueProcess;
    VOID* UniqueThread;
}CLIENT_ID, * PCLIENT_ID;

extern "C"
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserThread(
    _In_ HANDLE Process,
    _In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    _In_ BOOLEAN CreateSuspended,
    _In_opt_ ULONG ZeroBits,
    _In_opt_ SIZE_T MaximumStackSize,
    _In_opt_ SIZE_T CommittedStackSize,
    _In_ PUSER_THREAD_START_ROUTINE StartAddress,
    _In_opt_ PVOID Parameter,
    _Out_opt_ PHANDLE Thread,
    _Out_opt_ PCLIENT_ID ClientId
);

static thread_local int x = 0xffccffdd;
NTSTATUS WINAPI Thread(PVOID) {
    printf("[1] ThreadLocalStoragePointer = %p\n", NtCurrentThreadLocalStoragePointer());
    return x == 0xffccffdd ? 0 : 1;
}

int thread() {
    x = 2;
    printf("[0] ThreadLocalStoragePointer = %p\n", NtCurrentThreadLocalStoragePointer());
    HANDLE hThread;// = CreateThread(nullptr, 0, Thread, nullptr, 0, nullptr);
    RtlCreateUserThread(NtCurrentProcess(), nullptr, FALSE, 0, 0, 0, Thread, nullptr, &hThread, nullptr);
    DWORD ret = -1;
    if (hThread) {
        WaitForSingleObject(hThread, 0xffffffff);
        GetExitCodeThread(hThread, &ret);
        CloseHandle(hThread);
        return ret;
    }
    return -1;
}