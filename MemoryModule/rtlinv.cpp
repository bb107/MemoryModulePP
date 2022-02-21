#include "stdafx.h"

int NTAPI RtlCaptureImageExceptionValues(PVOID BaseAddress, PDWORD SEHandlerTable, PDWORD SEHandlerCount);

static __forceinline bool NTAPI RtlIsModuleUnloaded(PLDR_DATA_TABLE_ENTRY entry) {
	if (RtlIsWindowsVersionOrGreater(6, 2, 0)) {
		return PLDR_DATA_TABLE_ENTRY_WIN8(entry)->DdagNode->State == LdrModulesUnloaded;
	}
	else {
		return entry->DllBase == nullptr;
	}
}

static VOID NTAPI RtlpInsertInvertedFunctionTable(IN PRTL_INVERTED_FUNCTION_TABLE InvertedTable, IN PVOID ImageBase, IN ULONG SizeOfImage) {
#ifdef _WIN64
	ULONG CurrentSize;
	PIMAGE_RUNTIME_FUNCTION_ENTRY FunctionTable;
	ULONG Index;
	ULONG SizeOfTable = 0;
	bool IsWin8OrGreater = RtlIsWindowsVersionOrGreater(6, 2, 0);

	Index = (ULONG)IsWin8OrGreater;
	CurrentSize = InvertedTable->Count;
	if (CurrentSize != InvertedTable->MaxCount) {
		if (CurrentSize != 0) {
			while (Index < CurrentSize) {
				if (ImageBase < InvertedTable->Entries[Index].ImageBase)break;
				++Index;
			}

			if (Index != CurrentSize) {
				RtlMoveMemory(&InvertedTable->Entries[Index + 1],
					&InvertedTable->Entries[Index],
					(CurrentSize - Index) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY));
			}
		}

		FunctionTable = (decltype(FunctionTable))RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &SizeOfTable);
		InvertedTable->Entries[Index].ExceptionDirectory = FunctionTable;
		InvertedTable->Entries[Index].ImageBase = ImageBase;
		InvertedTable->Entries[Index].ImageSize = SizeOfImage;
		InvertedTable->Entries[Index].ExceptionDirectorySize = SizeOfTable;
		InvertedTable->Count++;
	}
	else {
		IsWin8OrGreater ? (InvertedTable->Overflow = TRUE) : (InvertedTable->Epoch = TRUE);
	}

#else
	DWORD ptr, count;
	bool IsWin8OrGreater = RtlIsWindowsVersionOrGreater(6, 2, 0);
	ULONG Index = IsWin8OrGreater ? 1 : 0;

	if (InvertedTable->Count == InvertedTable->MaxCount) {
		if (IsWin8OrGreater)InvertedTable->NextEntrySEHandlerTableEncoded = TRUE;
		else InvertedTable->Overflow = TRUE;
		return;
	}
	while (Index < InvertedTable->Count) {
		if (ImageBase < (IsWin8OrGreater ?
			((PRTL_INVERTED_FUNCTION_TABLE_ENTRY_64)&InvertedTable->Entries[Index])->ImageBase :
			InvertedTable->Entries[Index].ImageBase))
			break;
		Index++;
	}
	if (Index != InvertedTable->Count) {
		if (IsWin8OrGreater) {
			RtlMoveMemory(&InvertedTable->Entries[Index + 1], &InvertedTable->Entries[Index],
				(InvertedTable->Count - Index) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY));
		}
		else {
			RtlMoveMemory(&InvertedTable->Entries[Index].NextEntrySEHandlerTableEncoded,
				Index ? &InvertedTable->Entries[Index - 1].NextEntrySEHandlerTableEncoded : (PVOID)&InvertedTable->NextEntrySEHandlerTableEncoded,
				(InvertedTable->Count - Index) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY));
		}
	}

	RtlCaptureImageExceptionValues(ImageBase, &ptr, &count);
	if (IsWin8OrGreater) {
		//memory layout is same as x64
		PRTL_INVERTED_FUNCTION_TABLE_ENTRY_64 entry = (decltype(entry))&InvertedTable->Entries[Index];
		entry->ExceptionDirectory = (PIMAGE_RUNTIME_FUNCTION_ENTRY)RtlEncodeSystemPointer((PVOID)ptr);
		entry->ExceptionDirectorySize = count;
		entry->ImageBase = ImageBase;
		entry->ImageSize = SizeOfImage;
	}
	else {
		if (Index) InvertedTable->Entries[Index - 1].NextEntrySEHandlerTableEncoded = RtlEncodeSystemPointer((PVOID)ptr);
		else InvertedTable->NextEntrySEHandlerTableEncoded = (DWORD)RtlEncodeSystemPointer((PVOID)ptr);
		InvertedTable->Entries[Index].ImageBase = ImageBase;
		InvertedTable->Entries[Index].ImageSize = SizeOfImage;
		InvertedTable->Entries[Index].SEHandlerCount = count;
	}

	++InvertedTable->Count;
#endif
	return;
}

static VOID NTAPI RtlpRemoveInvertedFunctionTable(IN PRTL_INVERTED_FUNCTION_TABLE InvertedTable, IN PVOID ImageBase) {
	ULONG CurrentSize;
	ULONG Index;
	//bool need = RtlIsWindowsVersionOrGreater(6, 2, 0);
	bool IsWin8OrGreater = RtlIsWindowsVersionOrGreater(6, 2, 0);

	CurrentSize = InvertedTable->Count;
	for (Index = 0; Index < CurrentSize; Index += 1) {
		if (ImageBase == (IsWin8OrGreater ?
			((PRTL_INVERTED_FUNCTION_TABLE_ENTRY_64)&InvertedTable->Entries[Index])->ImageBase :
			InvertedTable->Entries[Index].ImageBase))
			break;
	}

	if (Index != CurrentSize) {
		//if (need)_InterlockedIncrement(&InvertedTable->Epoch);
		if (CurrentSize != 1) {
#ifdef _WIN64
			RtlMoveMemory(&InvertedTable->Entries[Index],
				&InvertedTable->Entries[Index + 1],
				(CurrentSize - Index - 1) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY));
#else
			if (IsWin8OrGreater) {
				RtlMoveMemory(&InvertedTable->Entries[Index], &InvertedTable->Entries[Index + 1],
					(CurrentSize - Index) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY));
			}
			else {
				RtlMoveMemory(
					Index ? &InvertedTable->Entries[Index - 1].NextEntrySEHandlerTableEncoded : (PVOID)&InvertedTable->NextEntrySEHandlerTableEncoded,
					&InvertedTable->Entries[Index].NextEntrySEHandlerTableEncoded,
					(CurrentSize - Index) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY));
			}
#endif
		}
		InvertedTable->Count--;
		//if (need)_InterlockedIncrement(&InvertedTable->Epoch);
	}

	if (InvertedTable->Count != InvertedTable->MaxCount) {
		if (IsWin8OrGreater) {
			PRTL_INVERTED_FUNCTION_TABLE_64(InvertedTable)->Overflow = FALSE;
		}
		else {
			PRTL_INVERTED_FUNCTION_TABLE_WIN7_32(InvertedTable)->Overflow = FALSE;
		}
	}

	return;
}

int NTAPI RtlCaptureImageExceptionValues(PVOID BaseAddress, PDWORD SEHandlerTable, PDWORD SEHandlerCount) {
	PIMAGE_LOAD_CONFIG_DIRECTORY pLoadConfigDirectory;
	PIMAGE_COR20_HEADER pCor20;
	ULONG Size;

	//check if no seh
	if (RtlImageNtHeader(BaseAddress)->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) {
		*SEHandlerTable = *SEHandlerCount = -1;
		return 0;
	}

	//get seh table and count
	pLoadConfigDirectory = (decltype(pLoadConfigDirectory))RtlImageDirectoryEntryToData(BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &Size);
	if (pLoadConfigDirectory) {
		if (Size == 0x40 && pLoadConfigDirectory->Size >= 0x48u) {
			if (pLoadConfigDirectory->SEHandlerTable && pLoadConfigDirectory->SEHandlerCount) {
				*SEHandlerTable = pLoadConfigDirectory->SEHandlerTable;
				return *SEHandlerCount = pLoadConfigDirectory->SEHandlerCount;
			}
		}
	}

	//is .net core ?
	pCor20 = (decltype(pCor20))RtlImageDirectoryEntryToData(BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, &Size);
	*SEHandlerTable = *SEHandlerCount = ((pCor20 && pCor20->Flags & 1) ? -1 : 0);
	return 0;
}

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
		if (RtlIsModuleUnloaded(CurEntry))continue;					//skip unloaded module
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


PVOID NTAPI RtlFindLdrpInvertedFunctionTable() {
	static PVOID LdrpInvertedFunctionTable = FindLdrpInvertedFunctionTable();
	return LdrpInvertedFunctionTable;
}
static NTSTATUS NTAPI RtlProtectMrdata(IN SIZE_T Protect) {
	static PVOID MrdataBase = nullptr;
	static SIZE_T size = 0;
	NTSTATUS status;
	PVOID tmp;
	SIZE_T tmp_len;
	ULONG old;

	if (!MrdataBase) {
		MEMORY_BASIC_INFORMATION mbi{};
		status = NtQueryVirtualMemory(GetCurrentProcess(), RtlFindLdrpInvertedFunctionTable(), MemoryBasicInformation, &mbi, sizeof(mbi), nullptr);
		if (!NT_SUCCESS(status))return status;
		MrdataBase = mbi.BaseAddress;
		size = mbi.RegionSize;
	}

	tmp = MrdataBase;
	tmp_len = size;
	return NtProtectVirtualMemory(GetCurrentProcess(), &tmp, &tmp_len, Protect, &old);
}

NTSTATUS NTAPI RtlInsertInvertedFunctionTable(IN PVOID BaseAddress, IN size_t ImageSize) {
	static auto table = PRTL_INVERTED_FUNCTION_TABLE(RtlFindLdrpInvertedFunctionTable());
	if (!table)return STATUS_NOT_SUPPORTED;
	bool need_virtual_protect = RtlIsWindowsVersionOrGreater(6, 3, 0);
	NTSTATUS status;

	if (need_virtual_protect) {
		status = RtlProtectMrdata(PAGE_READWRITE);
		if (!NT_SUCCESS(status))return status;
	}
	RtlpInsertInvertedFunctionTable(table, BaseAddress, ImageSize);
	if (need_virtual_protect) {
		status = RtlProtectMrdata(PAGE_READONLY);
		if (!NT_SUCCESS(status))return status;
	}
	return (RtlIsWindowsVersionOrGreater(6, 2, 0) ? PRTL_INVERTED_FUNCTION_TABLE_64(table)->Overflow : PRTL_INVERTED_FUNCTION_TABLE_WIN7_32(table)->Overflow) ?
		STATUS_NO_MEMORY : STATUS_SUCCESS;
}

NTSTATUS NTAPI RtlRemoveInvertedFunctionTable(IN PVOID ImageBase) {
	static auto table = PRTL_INVERTED_FUNCTION_TABLE(RtlFindLdrpInvertedFunctionTable());
	bool need_virtual_protect = RtlIsWindowsVersionOrGreater(6, 3, 0);
	NTSTATUS status;

	if (need_virtual_protect) {
		status = RtlProtectMrdata(PAGE_READWRITE);
		if (!NT_SUCCESS(status))return status;
	}
	RtlpRemoveInvertedFunctionTable(table, ImageBase);
	if (need_virtual_protect) {
		status = RtlProtectMrdata(PAGE_READONLY);
		if (!NT_SUCCESS(status))return status;
	}

	return STATUS_SUCCESS;
}
