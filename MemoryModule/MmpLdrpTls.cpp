#include "stdafx.h"

#if (!MMPP_USE_TLS)

static bool stdcall;
static PVOID LdrpHandleTlsData;
static PVOID LdrpReleaseTlsEntry;

static NTSTATUS NTAPI RtlFindLdrpHandleTlsDataOld() {
	NTSTATUS status = STATUS_SUCCESS;
	LPCVOID Feature = nullptr;
	BYTE Size = 0;
	WORD OffsetOfFunctionBegin = 0;

	switch (MmpGlobalDataPtr->NtVersions.MajorVersion) {
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

static NTSTATUS NTAPI RtlFindLdrpHandleTlsData10() {
	LPVOID DllBase = MmpGlobalDataPtr->MmpBaseAddressIndex->NtdllLdrEntry->DllBase;
#ifdef _WIN64
	// search for LdrpHandleTls string literal
	SEARCH_CONTEXT SearchContext{ SearchContext.SearchPattern = LPBYTE("LdrpHandleTlsData\x00"), SearchContext.PatternSize = 18 };
	if (!NT_SUCCESS(RtlFindMemoryBlockFromModuleSection(HMODULE(DllBase), ".rdata", &SearchContext)))
		return STATUS_NOT_SUPPORTED;
	LPBYTE StringOffset = SearchContext.Result;

	SearchContext.Result = nullptr;
	SearchContext.PatternSize = 3;
	SearchContext.SearchPattern = LPBYTE("\x48\x8D\x15");
	LPBYTE ExceptionBlock = nullptr;

	// Search for lea rdx,[rip+0x????]
	// ???? is the relative offset from RIP to LdrpHandleTls string literal
	while (NT_SUCCESS(RtlFindMemoryBlockFromModuleSection(HMODULE(DllBase), ".text", &SearchContext))) {
		DWORD InsOff = *(DWORD*)(SearchContext.Result + 3);
		if (StringOffset == SearchContext.Result + InsOff + 7) {
			ExceptionBlock = SearchContext.Result;
			break;
		}
	}
	if (!ExceptionBlock) return STATUS_NOT_SUPPORTED;

	// Search back for exception block function header
	while (*ExceptionBlock != 0xcc) {
		// Normally ~13 bytes, but just in case...
		if (SearchContext.Result - ExceptionBlock > 0x50) return STATUS_NOT_SUPPORTED;
		ExceptionBlock--;
	}
	ExceptionBlock++;

	// search for C_SCOPE_TABLE
	union Converter {
		BYTE Bytes[4];
		DWORD Dword;
	};
	Converter ExceptionBlockAddress{}; // { .Dword = DWORD(ExceptionBlock - LPBYTE(DllBase)) };
	ExceptionBlockAddress.Dword = DWORD(ExceptionBlock - LPBYTE(DllBase));

	SearchContext.Result = nullptr;
	SearchContext.PatternSize = 4;
	SearchContext.SearchPattern = ExceptionBlockAddress.Bytes;
	if (!NT_SUCCESS(RtlFindMemoryBlockFromModuleSection(HMODULE(DllBase), ".rdata", &SearchContext)))
		return STATUS_NOT_SUPPORTED;

	// C_SCOPE_TABLE$$Begin
	LPDWORD LdrpHandleTlsBlock = LPDWORD(*(LPDWORD)(SearchContext.Result - 8) + LPBYTE(DllBase));
	// Pad to 0x04
	LdrpHandleTlsBlock = LPDWORD(LONGLONG(LdrpHandleTlsBlock) / 0x04 * 0x04);
	LPDWORD LdrpHandleTlsBlockBackup = LdrpHandleTlsBlock;

	// Search back for LdrpHandleTls
	// Search up for 4 consecutive 0xCC
	while (*LdrpHandleTlsBlock != 0xcccccccc) {
		// Normally ~0x140 bytes
		if (LdrpHandleTlsBlockBackup - LdrpHandleTlsBlock > 0x400) return STATUS_NOT_SUPPORTED;
		LdrpHandleTlsBlock--;
	}
	LdrpHandleTlsBlock++;
	LdrpHandleTlsData = LdrpHandleTlsBlock;
	return STATUS_SUCCESS;
#else
	return STATUS_NOT_SUPPORTED;
#endif
}

static NTSTATUS NTAPI RtlFindLdrpHandleTlsData() {
	if (MmpGlobalDataPtr->NtVersions.MajorVersion >= 10) {
		return RtlFindLdrpHandleTlsData10();
	}
	else {
		return RtlFindLdrpHandleTlsDataOld();
	}
}

static NTSTATUS NTAPI RtlFindLdrpReleaseTlsEntry() {
	NTSTATUS status = STATUS_SUCCESS;
	LPCVOID Feature = nullptr;
	BYTE Size = 0;
	WORD OffsetOfFunctionBegin = 0;

	switch (MmpGlobalDataPtr->NtVersions.MajorVersion) {
	case 10: {
		if (MmpGlobalDataPtr->NtVersions.MinorVersion) return STATUS_NOT_SUPPORTED;

#ifdef _WIN64
		Feature = "\x48\x89\x5c\x24\x08\x57\x48\x83\xec\x20\x48\x8b\xfa\x48\x8b\xd9\x48\x85\xd2\x75\x0c";
		Size = 21;
#else
		return STATUS_NOT_SUPPORTED;
#endif
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

VOID NTAPI MmpTlsCleanup() {
	;
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
