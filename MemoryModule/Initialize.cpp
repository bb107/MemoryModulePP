#include "stdafx.h"
#include <wchar.h>

BOOLEAN MmpBuildSectionName(_Out_ PUNICODE_STRING SectionName) {
	WCHAR buffer[128];

	wsprintfW(buffer, L"\\Sessions\\%d\\BaseNamedObjects\\MMPP%d", NtCurrentPeb()->SessionId, (unsigned int)NtCurrentProcessId());
	return RtlCreateUnicodeString(SectionName, buffer);
}

VOID InitializeLockHeld() {
    NTSTATUS status;
    HANDLE hSection;
    OBJECT_ATTRIBUTES oa;
    LARGE_INTEGER li;
    UNICODE_STRING us{};

    li.QuadPart = 0x1000;

    do {

        if (!MmpBuildSectionName(&us))break;

        InitializeObjectAttributes(&oa, &us, 0, nullptr, nullptr);

        status = NtCreateSection(
            &hSection,
            SECTION_ALL_ACCESS,
            &oa,
            &li,
            PAGE_READWRITE,
            SEC_COMMIT | SEC_BASED,
            nullptr
        );
        if (!NT_SUCCESS(status)) {
            if (status != STATUS_OBJECT_NAME_COLLISION) break;

            status = NtOpenSection(
                &hSection,
                SECTION_ALL_ACCESS,
                &oa
            );
            if (!NT_SUCCESS(status))break;
        }

        PVOID BaseAddress = 0;
        SIZE_T ViewSize = 0;
        status = NtMapViewOfSection(
            hSection,
            NtCurrentProcess(),
            &BaseAddress,
            0,
            0,
            nullptr,
            &ViewSize,
            ViewUnmap,
            0,
            PAGE_READWRITE
        );

    } while (false);

    RtlFreeUnicodeString(&us);
}
