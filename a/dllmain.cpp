// dllmain.cpp : Defines the entry point for the DLL application.
#include <cstdio>
#include <exception>
#include <Windows.h>
#include <string>
#include <stdexcept>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wintrust.lib")
#pragma comment(lib,"ntdll.lib")

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

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        printf("DLL_PROCESS_ATTACH\n"); break;
    case DLL_THREAD_ATTACH:
        printf("DLL_THREAD_ATTACH\n"); break;
    case DLL_THREAD_DETACH:
        printf("DLL_THREAD_DETACH\n"); break;
    case DLL_PROCESS_DETACH:
        printf("DLL_PROCESS_DETACH\n"); break;
    }
    return TRUE;
}

/*
    exception type
    0   int
    1   char
    2   std::exception
    ... DWORD64
*/

int exception(int exception_type) {
    //int a = 0;
    //__try {
    //    *(PDWORD)(nullptr) = -1;
    //    a = 2;
    //}
    //__except (EXCEPTION_EXECUTE_HANDLER) {
    //    printf("-----------\n");
    //    getchar();
    //    a = 1;
    //}
    try {
        switch (exception_type) {
        case 0:
            throw 0;
        case 1:
            throw '1';
        case 2:
            throw std::exception("2");
        case 3:
        {
            std::string s = "foo";
            s.at(10);
        }
        default:
            throw (DWORD64)-1;
        }
        return 0;
    }
    catch (int val) {
        printf("exception code = %d\n", val);
        return val;
    }
    catch (char val) {
        printf("exception code = %c\n", val);
        return val - '0';
    }
    catch (const std::out_of_range& e) {
        printf("%s\n", e.what());
        return 3;
    }
    catch (std::exception val) {
        printf("exception code = %s\n", val.what());
        return 2;
    }
    catch (...) {
        printf("exception catched!!\n");
        return 0;
    }
    //return a;
}

int __test__() {
    printf("HelloWorld!\n");
    return 0;
}

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

DWORD Value;
volatile LPDWORD lpAddr;

LONG WINAPI Filter(_In_ struct _EXCEPTION_POINTERS* ExceptionInfo) {

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) {

        lpAddr = &Value;

        //  +++++++
        // begin compiler specific
        //  +++++++
        
        //ExceptionInfo->ContextRecord->Rip -= 7;
        ExceptionInfo->ContextRecord->Rax = (ULONG_PTR)lpAddr;

        //  +++++++
        // end compiler specific
        //  +++++++

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

int unhandled_exception() {
    auto filter = SetUnhandledExceptionFilter(Filter);
    auto ff = SetUnhandledExceptionFilter(filter);

    if (ff != Filter) {
        printf("%p\t%p\t%p\nfailed\n", filter, ff, Filter);
        return 0;
    }

    filter = SetUnhandledExceptionFilter(Filter);
    lpAddr = nullptr;
    *lpAddr = 1;
    SetUnhandledExceptionFilter(filter);

    return 1234;
}
