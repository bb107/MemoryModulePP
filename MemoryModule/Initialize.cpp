#include "stdafx.h"
#include <wchar.h>

PMMP_GLOBAL_DATA MmpGlobalDataPtr;

BOOLEAN MmpBuildSectionName(_Out_ PUNICODE_STRING SectionName) {
	WCHAR buffer[128];

	swprintf_s(buffer, L"\\Sessions\\%d\\BaseNamedObjects\\MMPP*%08X", NtCurrentPeb()->SessionId, (unsigned int)(ULONG_PTR)NtCurrentProcessId());
	return RtlCreateUnicodeString(SectionName, buffer);
}

PRTL_RB_TREE FindLdrpModuleBaseAddressIndex() {
    PRTL_RB_TREE LdrpModuleBaseAddressIndex = nullptr;
    PLDR_DATA_TABLE_ENTRY_WIN10 nt10 = decltype(nt10)(MmpGlobalDataPtr->MmpBaseAddressIndex->NtdllLdrEntry);
    PRTL_BALANCED_NODE node = nullptr;
    if (!nt10 || !RtlIsWindowsVersionOrGreater(6, 2, 0))return nullptr;
    node = &nt10->BaseAddressIndexNode;
    while (node->ParentValue & (~7)) node = decltype(node)(node->ParentValue & (~7));

    if (!node->Red) {
        BYTE count = 0;
        PRTL_RB_TREE tmp = nullptr;
        SEARCH_CONTEXT SearchContext{};
        SearchContext.MemoryBuffer = &node;
        SearchContext.BufferLength = sizeof(size_t);
        while (NT_SUCCESS(RtlFindMemoryBlockFromModuleSection((HMODULE)nt10->DllBase, ".data", &SearchContext))) {
            if (count++)return nullptr;
            tmp = (decltype(tmp))SearchContext.MemoryBlockInSection;
        }
        if (count && tmp && tmp->Root && tmp->Min) {
            LdrpModuleBaseAddressIndex = tmp;
        }
    }

    return LdrpModuleBaseAddressIndex;
}

static __forceinline bool IsModuleUnloaded(PLDR_DATA_TABLE_ENTRY entry) {
	if (RtlIsWindowsVersionOrGreater(6, 2, 0)) {
		return PLDR_DATA_TABLE_ENTRY_WIN8(entry)->DdagNode->State == LdrModulesUnloaded;
	}
	else {
		return entry->DllBase == nullptr;
	}
}

#ifndef _WIN64
PVOID FindLdrpInvertedFunctionTable32() {
	// _RTL_INVERTED_FUNCTION_TABLE						x86
	//		Count										+0x0	????????
	//		MaxCount									+0x4	0x00000200
	//		Overflow									+0x8	0x00000000(Win7) ????????(Win10)
	//		NextEntrySEHandlerTableEncoded				+0xc	0x00000000(Win10) ++++++++(Win7)
	// _RTL_INVERTED_FUNCTION_TABLE_ENTRY[0]			+0x10	ntdll.dll(win10) or The smallest base module
	//		ImageBase									+0x10	++++++++
	//		ImageSize									+0x14	++++++++
	//		SEHandlerCount								+0x18	++++++++
	//		NextEntrySEHandlerTableEncoded				+0x1c	++++++++(Win10) ????????(Win7)
	//	_RTL_INVERTED_FUNCTION_TABLE_ENTRY[1] ...		...
	// ......
	HMODULE hModule = nullptr, hNtdll = GetModuleHandleW(L"ntdll.dll");
	PIMAGE_NT_HEADERS NtdllHeaders = RtlImageNtHeader(hNtdll), ModuleHeaders = nullptr;
	_RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32 entry{};
	LPCSTR lpSectionName = ".data";
	SEARCH_CONTEXT SearchContext{ SearchContext.MemoryBuffer = &entry,SearchContext.BufferLength = sizeof(entry) };
	PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InMemoryOrderModuleList,
		ListEntry = ListHead->Flink;
	PLDR_DATA_TABLE_ENTRY CurEntry = nullptr;
	DWORD SEHTable, SEHCount;
	BYTE Offset = 0x20;	//sizeof(_RTL_INVERTED_FUNCTION_TABLE_ENTRY)*2

	if (RtlIsWindowsVersionOrGreater(6, 3, 0)) lpSectionName = ".mrdata";
	else if (!RtlIsWindowsVersionOrGreater(6, 2, 0)) Offset = 0xC;

	while (ListEntry != ListHead) {
		CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		ListEntry = ListEntry->Flink;
		if (IsModuleUnloaded(CurEntry))continue;					//skip unloaded module
		if (IsValidMemoryModuleHandle((HMEMORYMODULE)CurEntry->DllBase))continue;  //skip our memory module.
		if (CurEntry->DllBase == hNtdll && Offset == 0x20)continue;	//Win10 skip first entry, if the base of ntdll is smallest.
		hModule = (HMODULE)(hModule ? min(hModule, CurEntry->DllBase) : CurEntry->DllBase);
	}
	ModuleHeaders = RtlImageNtHeader(hModule);
	if (!hModule || !ModuleHeaders || !hNtdll || !NtdllHeaders)return nullptr;

	RtlCaptureImageExceptionValues(hModule, &SEHTable, &SEHCount);
	entry = { RtlEncodeSystemPointer((PVOID)SEHTable),(DWORD)hModule,ModuleHeaders->OptionalHeader.SizeOfImage,(PVOID)SEHCount };

	while (NT_SUCCESS(RtlFindMemoryBlockFromModuleSection(hNtdll, lpSectionName, &SearchContext))) {
		PRTL_INVERTED_FUNCTION_TABLE_WIN7_32 tab = decltype(tab)(SearchContext.OutBufferPtr - Offset);

		//Note: Same memory layout for RTL_INVERTED_FUNCTION_TABLE_ENTRY in Windows 10 x86 and x64.
		if (RtlIsWindowsVersionOrGreater(6, 2, 0) && tab->MaxCount == 0x200 && !tab->NextEntrySEHandlerTableEncoded) return tab;
		else if (tab->MaxCount == 0x200 && !tab->Overflow) return tab;
	}

	return nullptr;
}

#define FindLdrpInvertedFunctionTable FindLdrpInvertedFunctionTable32
#else
PVOID FindLdrpInvertedFunctionTable64() {
	// _RTL_INVERTED_FUNCTION_TABLE						x64
	//		Count										+0x0	????????
	//		MaxCount									+0x4	0x00000200
	//		Epoch										+0x8	????????
	//		OverFlow									+0xc	0x00000000
	// _RTL_INVERTED_FUNCTION_TABLE_ENTRY[0]			+0x10	ntdll.dll(win10) or The smallest base module
	//		ExceptionDirectory							+0x10	++++++++
	//		ImageBase									+0x18	++++++++
	//		ImageSize									+0x20	++++++++
	//		ExceptionDirectorySize						+0x24	++++++++
	//	_RTL_INVERTED_FUNCTION_TABLE_ENTRY[1] ...		...
	// ......
	HMODULE hModule = nullptr, hNtdll = GetModuleHandleW(L"ntdll.dll");
	PIMAGE_NT_HEADERS NtdllHeaders = RtlImageNtHeader(hNtdll), ModuleHeaders = nullptr;
	_RTL_INVERTED_FUNCTION_TABLE_ENTRY_64 entry{};
	LPCSTR lpSectionName = ".data";
	PIMAGE_DATA_DIRECTORY dir = nullptr;
	SEARCH_CONTEXT SearchContext{ SearchContext.MemoryBuffer = &entry,SearchContext.BufferLength = sizeof(entry) };

	//Windows 8
	if (RtlVerifyVersion(6, 2, 0, RTL_VERIFY_FLAGS_MAJOR_VERSION | RTL_VERIFY_FLAGS_MINOR_VERSION)) {
		hModule = hNtdll;
		ModuleHeaders = NtdllHeaders;
		//lpSectionName = ".data";
	}
	//Windows 8.1 ~ Windows 10
	else if (RtlIsWindowsVersionOrGreater(6, 3, 0)) {
		hModule = hNtdll;
		ModuleHeaders = NtdllHeaders;
		lpSectionName = ".mrdata";
	}
	else {
		PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList,
			ListEntry = ListHead->Flink;
		PLDR_DATA_TABLE_ENTRY CurEntry = nullptr;
		while (ListEntry != ListHead) {
			CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			ListEntry = ListEntry->Flink;
			//Make sure the smallest base address is not our memory module
			if (IsValidMemoryModuleHandle((HMEMORYMODULE)CurEntry->DllBase))continue;
			hModule = (HMODULE)(hModule ? min(hModule, CurEntry->DllBase) : CurEntry->DllBase);
		}
		ModuleHeaders = RtlImageNtHeader(hModule);
	}

	if (!hModule || !ModuleHeaders || !hNtdll || !NtdllHeaders)return nullptr;
	dir = &ModuleHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	entry = {
		dir->Size ? decltype(entry.ExceptionDirectory)((size_t)hModule + dir->VirtualAddress) : nullptr ,
		(PVOID)hModule, ModuleHeaders->OptionalHeader.SizeOfImage,dir->Size
	};

	while (NT_SUCCESS(RtlFindMemoryBlockFromModuleSection(hNtdll, lpSectionName, &SearchContext))) {
		PRTL_INVERTED_FUNCTION_TABLE_64 tab = decltype(tab)(SearchContext.OutBufferPtr - 0x10);
		if (RtlIsWindowsVersionOrGreater(6, 2, 0) && tab->MaxCount == 0x200 && !tab->Overflow) return tab;
		else if (tab->MaxCount == 0x200 && !tab->Epoch) return tab;
	}

	return nullptr;
}

#define FindLdrpInvertedFunctionTable FindLdrpInvertedFunctionTable64
#endif

PLIST_ENTRY FindLdrpHashTable() {
	PLIST_ENTRY list = nullptr;
	PLIST_ENTRY head = &NtCurrentPeb()->Ldr->InInitializationOrderModuleList, entry = head->Flink;
	PLDR_DATA_TABLE_ENTRY CurEntry = nullptr;
	while (head != entry) {
		CurEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, LDR_DATA_TABLE_ENTRY::InInitializationOrderLinks);
		entry = entry->Flink;
		if (CurEntry->HashLinks.Flink == &CurEntry->HashLinks)continue;
		list = CurEntry->HashLinks.Flink;
		if (list->Flink == &CurEntry->HashLinks) {
			list = (decltype(list))((size_t)CurEntry->HashLinks.Flink - LdrHashEntry(CurEntry->BaseDllName) * sizeof(_LIST_ENTRY));
			break;
		}
		list = nullptr;
	}
	return list;
}

VOID InitializeWindowsVersion() {

	WINDOWS_VERSION version = WINDOWS_VERSION::invalid;
	DWORD MajorVersion, MinorVersion, BuildNumber, LdrDataTableEntrySize;

	RtlGetNtVersionNumbers(
		&MajorVersion,
		&MinorVersion,
		&BuildNumber
	);
	if (BuildNumber & 0xf0000000)BuildNumber &= 0xffff;

	switch (MajorVersion) {
	case 5: {
		if ((MinorVersion == 1 && BuildNumber == 2600) ||
			(MinorVersion == 2 && BuildNumber == 3790)) {
			version = WINDOWS_VERSION::xp;
			LdrDataTableEntrySize = sizeof(LDR_DATA_TABLE_ENTRY_XP);
		}

		break;
	}

	case 6: {
		switch (MinorVersion) {
		case 0: {
			switch (BuildNumber) {
			case 6000:
			case 6001:
			case 6002:
				version = WINDOWS_VERSION::vista;
				LdrDataTableEntrySize = sizeof(LDR_DATA_TABLE_ENTRY_VISTA);
				break;
			}
			break;
		}

		case 1: {
			switch (BuildNumber) {
			case 7600:
			case 7601:
				version = WINDOWS_VERSION::win7;
				LdrDataTableEntrySize = sizeof(LDR_DATA_TABLE_ENTRY_WIN7);
				break;
			}
			break;
		}

		case 2: {
			if (BuildNumber == 9200) {
				version = WINDOWS_VERSION::win8;
				LdrDataTableEntrySize = sizeof(LDR_DATA_TABLE_ENTRY_WIN8);
			}
			break;
		}

		case 3: {
			if (BuildNumber == 9600) {
				version = WINDOWS_VERSION::winBlue;
				LdrDataTableEntrySize = sizeof(LDR_DATA_TABLE_ENTRY_WINBLUE);
			}
			break;
		}

		}
		break;
	}

	case 10: {
		if (MinorVersion)break;

		if (BuildNumber >= 10240) {
			if (BuildNumber >= 14393) {
				if (BuildNumber >= 15063) {
					if (BuildNumber >= 22000) {
						// [22000, ?)
						version = WINDOWS_VERSION::win11;
						LdrDataTableEntrySize = sizeof(LDR_DATA_TABLE_ENTRY_WIN11);
					}
					else {
						// [15063, 22000)
						version = WINDOWS_VERSION::win10_2;
						LdrDataTableEntrySize = sizeof(LDR_DATA_TABLE_ENTRY_WIN10_2);
					}
				}
				else {
					//  [13494, 15063)
					version = WINDOWS_VERSION::win10_1;
					LdrDataTableEntrySize = sizeof(LDR_DATA_TABLE_ENTRY_WIN10_1);
				}
			}
			else {
				// [10240, 14393)
				version = WINDOWS_VERSION::win10;
				LdrDataTableEntrySize = sizeof(LDR_DATA_TABLE_ENTRY_WIN10);
			}
		}

		break;
	}

	}

	MmpGlobalDataPtr->WindowsVersion = version;
	if (version != WINDOWS_VERSION::invalid) {
		MmpGlobalDataPtr->NtVersions.MajorVersion = MajorVersion;
		MmpGlobalDataPtr->NtVersions.MinorVersion = MinorVersion;
		MmpGlobalDataPtr->NtVersions.BuildNumber = BuildNumber;
		MmpGlobalDataPtr->LdrDataTableEntrySize = (WORD)LdrDataTableEntrySize;
	}

}

NTSTATUS MmpAllocateGlobalData() {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE hSection = nullptr;
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

			HANDLE hSection2;
			status = NtOpenSection(
				&hSection2,
				SECTION_ALL_ACCESS,
				&oa
			);
			if (!NT_SUCCESS(status))break;

			SECTION_BASIC_INFORMATION sbi{};
			status = NtQuerySection(
				hSection2,
				SECTION_INFORMATION_CLASS::SectionBasicInformation,
				&sbi,
				sizeof(sbi),
				nullptr
			);

			NtClose(hSection2);
			MmpGlobalDataPtr = (PMMP_GLOBAL_DATA)sbi.BaseAddress;
			break;
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
		if (!NT_SUCCESS(status))break;

		MmpGlobalDataPtr = (PMMP_GLOBAL_DATA)BaseAddress;

	} while (false);

	RtlFreeUnicodeString(&us);

	if (NT_SUCCESS(status)) {
		status = hSection ? status : STATUS_ALREADY_INITIALIZED;
	}
	else {
		if (hSection)NtClose(hSection);
	}

	return status;
}

NTSTATUS InitializeLockHeld() {
    NTSTATUS status;

    do {

		status = MmpAllocateGlobalData();
		if (!NT_SUCCESS(status)) {
			if (status == STATUS_ALREADY_INITIALIZED) {
				if ((MmpGlobalDataPtr->MajorVersion < MEMORY_MODULE_MAJOR_VERSION) ||
					(MmpGlobalDataPtr->MajorVersion == MEMORY_MODULE_MAJOR_VERSION && MmpGlobalDataPtr->MinorVersion < MEMORY_MODULE_MINOR_VERSION)) {
					status = STATUS_NOT_SUPPORTED;
				}
				else {
					status = STATUS_SUCCESS;
				}
			}

			break;
		}

        MmpGlobalDataPtr->MajorVersion = MEMORY_MODULE_MAJOR_VERSION;
        MmpGlobalDataPtr->MinorVersion = MEMORY_MODULE_MINOR_VERSION;

		GetSystemInfo(&MmpGlobalDataPtr->SystemInfo);

		InitializeWindowsVersion();
		if (MmpGlobalDataPtr->WindowsVersion == WINDOWS_VERSION::invalid) {
			NtUnmapViewOfSection(NtCurrentProcess(), MmpGlobalDataPtr);
			status = STATUS_NOT_SUPPORTED;
			break;
		}

		MmpGlobalDataPtr->MmpBaseAddressIndex = (PMMP_BASE_ADDRESS_INDEX_DATA)((LPBYTE)MmpGlobalDataPtr + sizeof(MMP_GLOBAL_DATA));
		MmpGlobalDataPtr->MmpInvertedFunctionTable = (PMMP_INVERTED_FUNCTION_TABLE_DATA)((LPBYTE)MmpGlobalDataPtr->MmpBaseAddressIndex + sizeof(MMP_BASE_ADDRESS_INDEX_DATA));
		MmpGlobalDataPtr->MmpLdrEntry = (PMMP_LDR_ENTRY_DATA)((LPBYTE)MmpGlobalDataPtr->MmpInvertedFunctionTable + sizeof(MMP_INVERTED_FUNCTION_TABLE_DATA));
		MmpGlobalDataPtr->MmpTls = (PMMP_TLS_DATA)((LPBYTE)MmpGlobalDataPtr->MmpLdrEntry + sizeof(MMP_LDR_ENTRY_DATA));
		MmpGlobalDataPtr->MmpDotNet = (PMMP_DOT_NET_DATA)((LPBYTE)MmpGlobalDataPtr->MmpTls + sizeof(MMP_TLS_DATA));

		MmpGlobalDataPtr->MmpBaseAddressIndex->NtdllLdrEntry = RtlFindLdrTableEntryByBaseName(L"ntdll.dll");
        MmpGlobalDataPtr->MmpBaseAddressIndex->LdrpModuleBaseAddressIndex = FindLdrpModuleBaseAddressIndex();

		HMODULE hNtdll = (HMODULE)MmpGlobalDataPtr->MmpBaseAddressIndex->NtdllLdrEntry->DllBase;
		MmpGlobalDataPtr->MmpLdrEntry->_RtlRbInsertNodeEx = decltype(&RtlRbInsertNodeEx)(GetProcAddress(hNtdll, "RtlRbInsertNodeEx"));
		MmpGlobalDataPtr->MmpLdrEntry->_RtlRbRemoveNode = decltype(&RtlRbRemoveNode)(GetProcAddress(hNtdll, "RtlRbRemoveNode"));

		MmpGlobalDataPtr->MmpLdrEntry->LdrpHashTable = FindLdrpHashTable();

		MmpGlobalDataPtr->MmpInvertedFunctionTable->LdrpInvertedFunctionTable = FindLdrpInvertedFunctionTable();

        MmpGlobalDataPtr->MmpFeatures = MEMORY_FEATURE_SUPPORT_VERSION | MEMORY_FEATURE_LDRP_HEAP | MEMORY_FEATURE_LDRP_HANDLE_TLS_DATA | MEMORY_FEATURE_LDRP_RELEASE_TLS_ENTRY;
        if (MmpGlobalDataPtr->MmpBaseAddressIndex->LdrpModuleBaseAddressIndex)MmpGlobalDataPtr->MmpFeatures |= MEMORY_FEATURE_MODULE_BASEADDRESS_INDEX;
        if (MmpGlobalDataPtr->MmpLdrEntry->LdrpHashTable)MmpGlobalDataPtr->MmpFeatures |= MEMORY_FEATURE_LDRP_HASH_TABLE;
        if (MmpGlobalDataPtr->MmpInvertedFunctionTable->LdrpInvertedFunctionTable)MmpGlobalDataPtr->MmpFeatures |= MEMORY_FEATURE_INVERTED_FUNCTION_TABLE;

		MmpTlsInitialize();

		MmpGlobalDataPtr->MmpDotNet->Initialized = MmpGlobalDataPtr->MmpDotNet->PreHooked = FALSE;

    } while (false);

    return status;
}

NTSTATUS NTAPI Initialize() {
    NTSTATUS status;

    RtlAcquirePebLock();
    status = InitializeLockHeld();
    RtlReleasePebLock();

    return status;
}

#ifdef _USRDLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		return NT_SUCCESS(Initialize());
	}

	return TRUE;
}
#else
const NTSTATUS Initializer = Initialize();
#endif
