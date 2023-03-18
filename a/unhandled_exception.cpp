#include <Windows.h>
#include <cstdio>

#ifdef _WIN64
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
#endif

int unhandled_exception() {
#ifdef _WIN64
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
#endif

    return 1234;
}
