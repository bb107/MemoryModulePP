#include "stdafx.h"
#include <cstddef>

static NTSTATUS RtlFreeDependencies(_In_ PLDR_DATA_TABLE_ENTRY_WIN10 LdrEntry) {
	_LDR_DDAG_NODE* DependentDdgeNode = nullptr;
	PLDR_DATA_TABLE_ENTRY_WIN10 ModuleEntry = nullptr;
	_LDRP_CSLIST* head = (decltype(head))LdrEntry->DdagNode->Dependencies, * entry = head;
	HANDLE heap = NtCurrentPeb()->ProcessHeap;
	BOOL IsWin8 = RtlIsWindowsVersionInScope(6, 2, 0, 6, 3, -1);
	if (!LdrEntry->DdagNode->Dependencies)return STATUS_SUCCESS;

	//find all dependencies and free
	do {
		DependentDdgeNode = entry->Dependent.DependentDdagNode;
		if (DependentDdgeNode->Modules.Flink->Flink != &DependentDdgeNode->Modules) __fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
		ModuleEntry = decltype(ModuleEntry)((size_t)DependentDdgeNode->Modules.Flink - offsetof(_LDR_DATA_TABLE_ENTRY_WIN8, NodeModuleLink));
		if (ModuleEntry->DdagNode != DependentDdgeNode) __fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
		if (!DependentDdgeNode->IncomingDependencies) __fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
		_LDRP_CSLIST::_LDRP_CSLIST_INCOMMING* _last = DependentDdgeNode->IncomingDependencies, * _entry = _last;
		_LDR_DDAG_NODE* CurrentDdagNode;
		ULONG State = 0;
		PVOID Cookies;

		//Acquire LoaderLock
		do {
			if (!NT_SUCCESS(LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, &State, &Cookies))) __fastfail(FAST_FAIL_FATAL_APP_EXIT);
		} while (State != LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED);

		do {
			CurrentDdagNode = (decltype(CurrentDdagNode))((size_t)_entry->IncommingDdagNode & ~1);
			if (CurrentDdagNode == LdrEntry->DdagNode) {
				//node is head
				if (_entry == DependentDdgeNode->IncomingDependencies) {
					//only one node in list
					if (_entry->NextIncommingEntry == (PSINGLE_LIST_ENTRY)DependentDdgeNode->IncomingDependencies) {
						DependentDdgeNode->IncomingDependencies = nullptr;
					}
					else {
						//find the last node in the list
						PSINGLE_LIST_ENTRY i = _entry->NextIncommingEntry;
						while (i->Next != (PSINGLE_LIST_ENTRY)_entry)i = i->Next;
						i->Next = _entry->NextIncommingEntry;
						DependentDdgeNode->IncomingDependencies = (_LDRP_CSLIST::_LDRP_CSLIST_INCOMMING*)_entry->NextIncommingEntry;
					}
				}
				//node is not head
				else {
					_last->NextIncommingEntry = _entry->NextIncommingEntry;
				}
				break;
			}

			//save the last entry
			if (_last != _entry)_last = (decltype(_last))_last->NextIncommingEntry;
			_entry = (decltype(_entry))_entry->NextIncommingEntry;
		} while (_entry != _last);
		//free LoaderLock
		LdrUnlockLoaderLock(0, Cookies);
		entry = (decltype(entry))entry->Dependent.NextDependentEntry;

		//free it
		if (IsWin8) {
			//Update win8 dep count
			_LDR_DDAG_NODE_WIN8* win8_node = (decltype(win8_node))ModuleEntry->DdagNode;
			if (!win8_node->DependencyCount)__fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
			--win8_node->DependencyCount;
			if (!ModuleEntry->DdagNode->LoadCount && win8_node->ReferenceCount == 1 && !win8_node->DependencyCount) {
				win8_node->LoadCount = 1;
				LdrUnloadDll(ModuleEntry->DllBase);
			}
		}
		else {
			LdrUnloadDll(ModuleEntry->DllBase);
		}
		RtlFreeHeap(heap, 0, LdrEntry->DdagNode->Dependencies);

		//lookup next dependent.
		LdrEntry->DdagNode->Dependencies = (_LDRP_CSLIST::_LDRP_CSLIST_DEPENDENT*)(entry == head ? nullptr : entry);
	} while (entry != head);

	return STATUS_SUCCESS;
}

PLDR_DATA_TABLE_ENTRY NTAPI RtlAllocateDataTableEntry(_In_ PVOID BaseAddress) {
	PLDR_DATA_TABLE_ENTRY LdrEntry = nullptr;
	PIMAGE_NT_HEADERS NtHeader;
	HANDLE heap = NtCurrentPeb()->ProcessHeap;

	/* Make sure the header is valid */
	if (NtHeader = RtlImageNtHeader(BaseAddress)) {
		/* Allocate an entry */
		LdrEntry = (PLDR_DATA_TABLE_ENTRY)RtlAllocateHeap(heap, HEAP_ZERO_MEMORY, MmpGlobalDataPtr->LdrDataTableEntrySize);
	}

	/* Return the entry */
	return LdrEntry;
}

BOOL NTAPI RtlInitializeLdrDataTableEntry(
	_Out_ PLDR_DATA_TABLE_ENTRY LdrEntry,
	_In_ DWORD dwFlags,
	_In_ PVOID BaseAddress,
	_In_ UNICODE_STRING& DllBaseName,
	_In_ UNICODE_STRING& DllFullName) {
	RtlZeroMemory(LdrEntry, MmpGlobalDataPtr->LdrDataTableEntrySize);
	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(BaseAddress);
	if (!headers)return FALSE;
	HANDLE heap = NtCurrentPeb()->ProcessHeap;
	bool FlagsProcessed = false;

	bool CorImage = false, CorIL = false;
	auto& com = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
	if (com.Size && com.VirtualAddress) {
		CorImage = true;

		auto cor = PIMAGE_COR20_HEADER(LPBYTE(BaseAddress) + com.VirtualAddress);
		if (cor->Flags & ReplacesCorHdrNumericDefines::COMIMAGE_FLAGS_ILONLY) {
			CorIL = true;
		}
	}

	switch (MmpGlobalDataPtr->WindowsVersion) {
	case WINDOWS_VERSION::win11: {
		auto entry = (PLDR_DATA_TABLE_ENTRY_WIN11)LdrEntry;
		entry->CheckSum = headers->OptionalHeader.CheckSum;
	}
		
	case WINDOWS_VERSION::win10:
	case WINDOWS_VERSION::win10_1:
	case WINDOWS_VERSION::win10_2: {
		auto entry = (PLDR_DATA_TABLE_ENTRY_WIN10)LdrEntry;
		entry->ReferenceCount = 1;
	}
	case WINDOWS_VERSION::win8:
	case WINDOWS_VERSION::winBlue: {
		auto entry = (PLDR_DATA_TABLE_ENTRY_WIN8)LdrEntry;
		BOOL IsWin8 = RtlIsWindowsVersionInScope(6, 2, 0, 6, 3, -1);
		NtQuerySystemTime(&entry->LoadTime);
		entry->OriginalBase = headers->OptionalHeader.ImageBase;
		entry->BaseNameHashValue = LdrHashEntry(DllBaseName, false);
		entry->LoadReason = LoadReasonDynamicLoad;
		if (!NT_SUCCESS(RtlInsertModuleBaseAddressIndexNode(LdrEntry, BaseAddress)))return FALSE;
		if (!(entry->DdagNode = (decltype(entry->DdagNode))
			RtlAllocateHeap(heap, HEAP_ZERO_MEMORY, IsWin8 ? sizeof(_LDR_DDAG_NODE_WIN8) : sizeof(_LDR_DDAG_NODE))))return FALSE;

		entry->NodeModuleLink.Flink = &entry->DdagNode->Modules;
		entry->NodeModuleLink.Blink = &entry->DdagNode->Modules;
		entry->DdagNode->Modules.Flink = &entry->NodeModuleLink;
		entry->DdagNode->Modules.Blink = &entry->NodeModuleLink;
		entry->DdagNode->State = LdrModulesReadyToRun;
		entry->DdagNode->LoadCount = 1;
		if (IsWin8) ((_LDR_DDAG_NODE_WIN8*)(entry->DdagNode))->ReferenceCount = 1;
		entry->ImageDll = entry->LoadNotificationsSent = entry->EntryProcessed =
			entry->InLegacyLists = entry->InIndexes = entry->ProcessAttachCalled = true;
		entry->InExceptionTable = !(dwFlags & LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION);
		entry->CorImage = CorImage;
		entry->CorILOnly = CorIL;

		FlagsProcessed = true;
	}

	case WINDOWS_VERSION::win7: {
		if (MmpGlobalDataPtr->LdrDataTableEntrySize == sizeof(LDR_DATA_TABLE_ENTRY_WIN7)) {
			auto entry = (PLDR_DATA_TABLE_ENTRY_WIN7)LdrEntry;
			entry->OriginalBase = headers->OptionalHeader.ImageBase;
			NtQuerySystemTime(&entry->LoadTime);
		}
	}
	case WINDOWS_VERSION::vista: {
		if (MmpGlobalDataPtr->LdrDataTableEntrySize == sizeof(LDR_DATA_TABLE_ENTRY_VISTA) ||
			MmpGlobalDataPtr->LdrDataTableEntrySize == sizeof(LDR_DATA_TABLE_ENTRY_WIN7)) {
			auto entry = (PLDR_DATA_TABLE_ENTRY_VISTA)LdrEntry;
			InitializeListHead(&entry->ForwarderLinks);
			InitializeListHead(&entry->StaticLinks);
			InitializeListHead(&entry->ServiceTagLinks);
		}
	}
	case WINDOWS_VERSION::xp: {
		LdrEntry->DllBase = BaseAddress;
		LdrEntry->SizeOfImage = headers->OptionalHeader.SizeOfImage;
		LdrEntry->TimeDateStamp = headers->FileHeader.TimeDateStamp;
		LdrEntry->BaseDllName = DllBaseName;
		LdrEntry->FullDllName = DllFullName;
		LdrEntry->EntryPoint = (PLDR_INIT_ROUTINE)((size_t)BaseAddress + headers->OptionalHeader.AddressOfEntryPoint);
		LdrEntry->ObsoleteLoadCount = 1;
		if (!FlagsProcessed) {
			LdrEntry->Flags = LDRP_IMAGE_DLL | LDRP_ENTRY_INSERTED | LDRP_ENTRY_PROCESSED | LDRP_PROCESS_ATTACH_CALLED;
			if (CorImage)LdrEntry->Flags |= LDRP_COR_IMAGE;
		}
		InitializeListHead(&LdrEntry->HashLinks);
		return TRUE;
	}
	default:return FALSE;
	}
}

BOOL NTAPI RtlFreeLdrDataTableEntry(_In_ PLDR_DATA_TABLE_ENTRY LdrEntry) {
	HANDLE heap = NtCurrentPeb()->ProcessHeap;
	switch (MmpGlobalDataPtr->WindowsVersion) {
	case WINDOWS_VERSION::win11:
	case WINDOWS_VERSION::win10:
	case WINDOWS_VERSION::win10_1:
	case WINDOWS_VERSION::win10_2:
	case WINDOWS_VERSION::win8:
	case WINDOWS_VERSION::winBlue: {
		auto entry = (PLDR_DATA_TABLE_ENTRY_WIN10)LdrEntry;
		RtlFreeDependencies(entry);
		RtlFreeHeap(heap, 0, entry->DdagNode);
		RtlRemoveModuleBaseAddressIndexNode(LdrEntry);
	}
	case WINDOWS_VERSION::win7:
	case WINDOWS_VERSION::vista: {
		if (MmpGlobalDataPtr->LdrDataTableEntrySize == sizeof(LDR_DATA_TABLE_ENTRY_VISTA) ||
			MmpGlobalDataPtr->LdrDataTableEntrySize == sizeof(LDR_DATA_TABLE_ENTRY_WIN7)) {
			PLDR_DATA_TABLE_ENTRY_VISTA entry = (decltype(entry))LdrEntry;
			PLIST_ENTRY head = &entry->ForwarderLinks, next = head->Flink;
			while (head != next) {
				PLDR_DATA_TABLE_ENTRY dep = *(decltype(&dep))((size_t*)next + 2);
				LdrUnloadDll(dep->DllBase);
				next = next->Flink;
				RtlFreeHeap(heap, 0, next->Blink);
			}
		}
	}
	case WINDOWS_VERSION::xp: {
		RtlFreeHeap(heap, 0, LdrEntry->BaseDllName.Buffer);
		RtlFreeHeap(heap, 0, LdrEntry->FullDllName.Buffer);
		RemoveEntryList(&LdrEntry->InLoadOrderLinks);
		RemoveEntryList(&LdrEntry->InMemoryOrderLinks);
		RemoveEntryList(&LdrEntry->InInitializationOrderLinks);
		RemoveEntryList(&LdrEntry->HashLinks);
		RtlFreeHeap(heap, 0, LdrEntry);
		return TRUE;
	}
	default:return FALSE;
	}
}

NTSTATUS NTAPI RtlUpdateReferenceCount(
	_Inout_ PMEMORYMODULE pModule,
	_In_ DWORD Flags) {
	if (Flags != FLAG_REFERENCE && Flags != FLAG_DEREFERENCE)return STATUS_INVALID_PARAMETER_2;

	if (pModule->dwReferenceCount == 0xffffffff)return STATUS_SUCCESS;

	if (PLDR_DATA_TABLE_ENTRY(pModule->LdrEntry)->ObsoleteLoadCount == 0xffff) {
		pModule->dwReferenceCount = 0xffffffff;
		return STATUS_SUCCESS;
	}

	if (Flags == FLAG_REFERENCE) {
		++pModule->dwReferenceCount;
	}
	else {
		if (pModule->dwReferenceCount)--pModule->dwReferenceCount;
	}

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI RtlGetReferenceCount(
	_In_ PMEMORYMODULE pModule,
	_Out_ PULONG Count) {

	*Count = pModule->dwReferenceCount;

	return STATUS_SUCCESS;
}

VOID NTAPI RtlInsertMemoryTableEntry(_In_ PLDR_DATA_TABLE_ENTRY LdrEntry) {
	PPEB_LDR_DATA PebData = NtCurrentPeb()->Ldr;
	PLIST_ENTRY LdrpHashTable = MmpGlobalDataPtr->MmpLdrEntry->LdrpHashTable;
	ULONG i;

	/* Insert into hash table */
	i = LdrHashEntry(LdrEntry->BaseDllName);
	InsertTailList(&LdrpHashTable[i], &LdrEntry->HashLinks);

	/* Insert into other lists */
	InsertTailList(&PebData->InLoadOrderModuleList, &LdrEntry->InLoadOrderLinks);
	InsertTailList(&PebData->InMemoryOrderModuleList, &LdrEntry->InMemoryOrderLinks);
	InsertTailList(&PebData->InInitializationOrderModuleList, &LdrEntry->InInitializationOrderLinks);
}

PLDR_DATA_TABLE_ENTRY NTAPI RtlFindLdrTableEntryByHandle(_In_ PVOID BaseAddress) {
	PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList, ListEntry = ListHead->Flink;
	PLDR_DATA_TABLE_ENTRY CurEntry;
	while (ListEntry != ListHead) {
		CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		ListEntry = ListEntry->Flink;
		if (CurEntry->DllBase == BaseAddress) {
			return CurEntry;
		}
	}
	return nullptr;
}

PLDR_DATA_TABLE_ENTRY NTAPI RtlFindLdrTableEntryByBaseName(_In_z_ PCWSTR BaseName) {
	PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList, ListEntry = ListHead->Flink;
	PLDR_DATA_TABLE_ENTRY CurEntry;
	while (ListEntry != ListHead) {
		CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		ListEntry = ListEntry->Flink;
		if (!_wcsnicmp(BaseName, CurEntry->BaseDllName.Buffer, (CurEntry->BaseDllName.Length / sizeof(wchar_t)) - 4) ||
			!_wcsnicmp(BaseName, CurEntry->BaseDllName.Buffer, CurEntry->BaseDllName.Length / sizeof(wchar_t))) {
			return CurEntry;
		}
	}
	return nullptr;
}

ULONG NTAPI LdrHashEntry(_In_ UNICODE_STRING& DllBaseName, _In_ BOOL ToIndex) {
	ULONG result = 0;

	switch (MmpGlobalDataPtr->WindowsVersion) {
	case WINDOWS_VERSION::xp:
		result = RtlUpcaseUnicodeChar(DllBaseName.Buffer[0]) - 'A';
		break;

	case WINDOWS_VERSION::vista:
		result = RtlUpcaseUnicodeChar(DllBaseName.Buffer[0]) - 1;
		break;

	case WINDOWS_VERSION::win7:
		for (USHORT i = 0; i < (DllBaseName.Length / sizeof(wchar_t)); ++i)
			result += 0x1003F * RtlUpcaseUnicodeChar(DllBaseName.Buffer[i]);
		break;

	default:
		RtlHashUnicodeString(&DllBaseName, TRUE, HASH_STRING_ALGORITHM_DEFAULT, &result);
		break;
	}

	if (ToIndex)result &= (LDR_HASH_TABLE_ENTRIES - 1);
	return result;
}
