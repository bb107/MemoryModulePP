#include "stdafx.h"

#if (!MMPP_USE_TLS)

static bool stdcall;
static PVOID LdrpHandleTlsData;
static PVOID LdrpReleaseTlsEntry;

static NTSTATUS NTAPI RtlFindLdrpHandleTlsData() {
	NTSTATUS status = STATUS_SUCCESS;
	LPCVOID Feature = nullptr;
	BYTE Size = 0;
	WORD OffsetOfFunctionBegin = 0;

	switch (MmpGlobalDataPtr->NtVersions.MajorVersion) {
	case 10: {
		if (MmpGlobalDataPtr->NtVersions.MinorVersion)return STATUS_NOT_SUPPORTED;

		if (MmpGlobalDataPtr->NtVersions.BuildNumber >= 22621) {
#ifdef _WIN64
			Feature = "\x39\x1D\x23\xFC\x17\x00\x74\x37\x44\x8D\x43\x09\x44\x39\x81\x0C\x01\x00\x00\x74\x2A";
			Size = 22;
			OffsetOfFunctionBegin = 0x43;
#else
			return STATUS_NOT_SUPPORTED;
#endif
		}
		//
		// Add more conditions here.
		//
		// else if (MmpGlobalDataPtr->NtVersions.BuildNumber >= XXXXXXXXX)
		else {
			return STATUS_NOT_SUPPORTED;
		}

		break;
	}
	case 6: {
		switch (MmpGlobalDataPtr->NtVersions.MinorVersion) {
			//8.1
		case 3: {
#ifdef _WIN64
			Size = 10;
			OffsetOfFunctionBegin = 0x43;
			Feature = "\x44\x8d\x43\x09\x4c\x8d\x4c\x24\x38";
#else
			Size = 8;
			OffsetOfFunctionBegin = 0x1B;
			Feature = "\x50\x6a\x09\x6a\x01\x8b\xc1";
#endif
			break;
		}
			  //8
		case 2: {
#ifdef _WIN64
			Size = 9;
			OffsetOfFunctionBegin = 0x49;
			Feature = "\x48\x8b\x79\x30\x45\x8d\x66\x01";
#else
			Size = 7;
			OffsetOfFunctionBegin = 0xC;
			Feature = "\x8b\x45\x08\x89\x45\xa0";
#endif
			break;
		}
			  //7
		case 1: {
#ifdef _WIN64
			Size = 12;
			OffsetOfFunctionBegin = 0x27;
			Feature = "\x41\xb8\x09\x00\x00\x00\x48\x8d\x44\x24\x38";
#else
			Size = 9;
			OffsetOfFunctionBegin = 0x14;
			Feature = "\x74\x20\x8d\x45\xd4\x50\x6a\x09";
#endif
			break;
		}
		default:return STATUS_NOT_SUPPORTED;
		}
		break;
	}

	default: {
		return STATUS_NOT_SUPPORTED;
	}
	}

	SEARCH_CONTEXT SearchContext{ SearchContext.SearchPattern = LPBYTE(Feature),SearchContext.PatternSize = Size - 1 };
	if (!NT_SUCCESS(RtlFindMemoryBlockFromModuleSection(HMODULE(MmpGlobalDataPtr->MmpBaseAddressIndex->NtdllLdrEntry->DllBase), ".text", &SearchContext)))
		return STATUS_NOT_SUPPORTED;

	LdrpHandleTlsData = SearchContext.Result - OffsetOfFunctionBegin;
	return status;
}

static NTSTATUS NTAPI RtlFindLdrpReleaseTlsEntry() {
	NTSTATUS status = STATUS_SUCCESS;
	LPCVOID Feature = nullptr;
	BYTE Size = 0;
	WORD OffsetOfFunctionBegin = 0;

	switch (MmpGlobalDataPtr->NtVersions.MajorVersion) {
	case 10: {
		if (MmpGlobalDataPtr->NtVersions.MinorVersion) return STATUS_NOT_SUPPORTED;

		if (MmpGlobalDataPtr->NtVersions.BuildNumber >= 22621) {
#ifdef _WIN64
			Feature = "\x74\x34\x48\x8B\x08\x48\x39\x41\x08\x75\x65\x48\x8B\x40\x08\x48\x39\x18\x75\x5C\x48\x89\x08";
			Size = 24;
			OffsetOfFunctionBegin = 0x2F;
#else
			return STATUS_NOT_SUPPORTED;
#endif
		}
		//
		// Add more conditions here.
		//
		// else if (MmpGlobalDataPtr->NtVersions.BuildNumber >= XXXXXXXXX)
		else {
			return STATUS_NOT_SUPPORTED;
		}

		break;
	}
	default:
		return STATUS_NOT_SUPPORTED;
	}

	SEARCH_CONTEXT SearchContext{ SearchContext.SearchPattern = LPBYTE(Feature),SearchContext.PatternSize = Size - 1 };
	if (!NT_SUCCESS(RtlFindMemoryBlockFromModuleSection(HMODULE(MmpGlobalDataPtr->MmpBaseAddressIndex->NtdllLdrEntry->DllBase), ".text", &SearchContext)))
		return STATUS_NOT_SUPPORTED;

	LdrpReleaseTlsEntry = SearchContext.Result - OffsetOfFunctionBegin;
	return status;
}

BOOL NTAPI MmpTlsInitialize() {
	if (!NT_SUCCESS(RtlFindLdrpHandleTlsData()) ||
		!NT_SUCCESS(RtlFindLdrpReleaseTlsEntry())) {

		LdrpHandleTlsData = nullptr;
		LdrpReleaseTlsEntry = nullptr;

		MmpGlobalDataPtr->MmpFeatures &= ~MEMORY_FEATURE_LDRP_HANDLE_TLS_DATA;
		return FALSE;
	}

	stdcall = !RtlIsWindowsVersionOrGreater(6, 3, 0);
	return TRUE;
}

NTSTATUS NTAPI MmpReleaseTlsEntry(_In_ PLDR_DATA_TABLE_ENTRY lpModuleEntry) {
	typedef NTSTATUS(__stdcall* STDCALL)(PLDR_DATA_TABLE_ENTRY, PVOID*);
	typedef NTSTATUS(__thiscall* THISCALL)(PLDR_DATA_TABLE_ENTRY, PVOID*);

	union {
		STDCALL stdcall;
		THISCALL thiscall;

		PVOID ptr;
	}fp;
	fp.ptr = LdrpReleaseTlsEntry;

	if (fp.ptr) {
		return stdcall ? fp.stdcall(lpModuleEntry, nullptr) : fp.thiscall(lpModuleEntry, nullptr);
	}
	else {
		return STATUS_NOT_SUPPORTED;
	}
}

NTSTATUS NTAPI MmpHandleTlsData(_In_ PLDR_DATA_TABLE_ENTRY lpModuleEntry) {
	typedef NTSTATUS(__stdcall* STDCALL)(PLDR_DATA_TABLE_ENTRY);
	typedef NTSTATUS(__thiscall* THISCALL)(PLDR_DATA_TABLE_ENTRY);

	union {
		STDCALL stdcall;
		THISCALL thiscall;

		PVOID ptr;
	}fp;
	fp.ptr = LdrpHandleTlsData;

	if (fp.ptr) {
		return stdcall ? fp.stdcall(lpModuleEntry) : fp.thiscall(lpModuleEntry);
	}
	else {
		return STATUS_NOT_SUPPORTED;
	}
}

#endif
