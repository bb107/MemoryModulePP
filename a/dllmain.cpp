// dllmain.cpp : Defines the entry point for the DLL application.
#include <cstdio>
#include <exception>
#include "../MemoryModule/Native.h"
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wintrust.lib")
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
DWORD WINAPI Thread(PVOID) {
    printf("[1] ThreadLocalStoragePointer = %p\n", NtCurrentTeb()->ThreadLocalStoragePointer);
    return x == 0xffccffdd ? 0 : 1;
}

int thread() {
    x = 2;
    printf("[0] ThreadLocalStoragePointer = %p\n", NtCurrentTeb()->ThreadLocalStoragePointer);
    HANDLE hThread = CreateThread(nullptr, 0, Thread, nullptr, 0, nullptr);
    DWORD ret = -1;
    if (hThread) {
        WaitForSingleObject(hThread, 0xffffffff);
        GetExitCodeThread(hThread, &ret);
        CloseHandle(hThread);
        return ret;
    }
    return -1;
}

