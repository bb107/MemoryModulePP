#include "stdafx.h"
#include <cstddef>

static NTSTATUS NTAPI RtlFreeDependencies(IN PLDR_DATA_TABLE_ENTRY_WIN10 LdrEntry) {
	_LDR_DDAG_NODE* DependentDdgeNode = nullptr;
	PLDR_DATA_TABLE_ENTRY_WIN10 ModuleEntry = nullptr;
	_LDRP_CSLIST* head = (decltype(head))LdrEntry->DdagNode->Dependencies, * entry = head;
	HANDLE heap = NtCurrentPeb()->ProcessHeap;
	const static bool IsWin8 = RtlIsWindowsVersionInScope(6, 2, 0, 6, 3, -1);
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

PLDR_DATA_TABLE_ENTRY NTAPI RtlAllocateDataTableEntry(IN PVOID BaseAddress) {
	PLDR_DATA_TABLE_ENTRY LdrEntry = nullptr;
	PIMAGE_NT_HEADERS NtHeader;
	HANDLE heap = NtCurrentPeb()->ProcessHeap;

	/* Make sure the header is valid */
	if (NtHeader = RtlImageNtHeader(BaseAddress)) {
		/* Allocate an entry */
		LdrEntry = (PLDR_DATA_TABLE_ENTRY)RtlAllocateHeap(heap, HEAP_ZERO_MEMORY, LdrpDataTableEntrySize());
	}

	/* Return the entry */
	return LdrEntry;
}

bool NTAPI RtlInitializeLdrDataTableEntry(
	OUT PLDR_DATA_TABLE_ENTRY LdrEntry,
	IN DWORD dwFlags,
	IN PVOID BaseAddress,
	IN UNICODE_STRING& DllBaseName,
	IN UNICODE_STRING& DllFullName) {
	RtlZeroMemory(LdrEntry, LdrpDataTableEntrySize());
	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(BaseAddress);
	if (!headers)return false;
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

	switch (NtWindowsVersion()) {
	case win10:
	case win10_1:
	case win10_2: {
		auto entry = (PLDR_DATA_TABLE_ENTRY_WIN10)LdrEntry;
		entry->ReferenceCount = 1;
	}
	case win8:
	case win8_1: {
		auto entry = (PLDR_DATA_TABLE_ENTRY_WIN8)LdrEntry;
		const static bool IsWin8 = RtlIsWindowsVersionInScope(6, 2, 0, 6, 3, -1);
		NtQuerySystemTime(&entry->LoadTime);
		entry->OriginalBase = headers->OptionalHeader.ImageBase;
		entry->BaseNameHashValue = LdrHashEntry(DllBaseName, false);
		entry->LoadReason = LoadReasonDynamicLoad;
		if (!NT_SUCCESS(RtlInsertModuleBaseAddressIndexNode(LdrEntry, BaseAddress)))return false;
		if (!(entry->DdagNode = (decltype(entry->DdagNode))
			RtlAllocateHeap(heap, HEAP_ZERO_MEMORY, IsWin8 ? sizeof(_LDR_DDAG_NODE_WIN8) : sizeof(_LDR_DDAG_NODE))))return false;
		//RtlInitializeListEntry(&entry->NodeModuleLink);
		//RtlInitializeListEntry(&entry->DdagNode->Modules);
		//RtlInitializeSingleEntry(&entry->DdagNode->CondenseLink);
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

	case win7: {
		if (LdrpDataTableEntrySize() == sizeof(LDR_DATA_TABLE_ENTRY_WIN7)) {
			auto entry = (PLDR_DATA_TABLE_ENTRY_WIN7)LdrEntry;
			entry->OriginalBase = headers->OptionalHeader.ImageBase;
			NtQuerySystemTime(&entry->LoadTime);
		}
	}
	case vista: {
		if (LdrpDataTableEntrySize() == sizeof(LDR_DATA_TABLE_ENTRY_VISTA) ||
			LdrpDataTableEntrySize() == sizeof(LDR_DATA_TABLE_ENTRY_WIN7)) {
			auto entry = (PLDR_DATA_TABLE_ENTRY_VISTA)LdrEntry;
			RtlInitializeListEntry(&entry->ForwarderLinks);
			RtlInitializeListEntry(&entry->StaticLinks);
			RtlInitializeListEntry(&entry->ServiceTagLinks);
		}
	}
	case xp: {
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
		RtlInitializeListEntry(&LdrEntry->HashLinks);
		return true;
	}
	default:return false;
	}
}

bool NTAPI RtlFreeLdrDataTableEntry(IN PLDR_DATA_TABLE_ENTRY LdrEntry) {
	HANDLE heap = NtCurrentPeb()->ProcessHeap;
	switch (NtWindowsVersion()) {
	case win10:
	case win10_1:
	case win10_2:
	case win8:
	case win8_1: {
		auto entry = (PLDR_DATA_TABLE_ENTRY_WIN10)LdrEntry;
		RtlFreeDependencies(entry);
		RtlFreeHeap(heap, 0, entry->DdagNode);
		RtlRemoveModuleBaseAddressIndexNode(LdrEntry);
	}
	case win7:
	case vista: {
		if (LdrpDataTableEntrySize() == sizeof(LDR_DATA_TABLE_ENTRY_VISTA) ||
			LdrpDataTableEntrySize() == sizeof(LDR_DATA_TABLE_ENTRY_WIN7)) {
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
	case xp: {
		RtlFreeHeap(heap, 0, LdrEntry->BaseDllName.Buffer);
		RtlFreeHeap(heap, 0, LdrEntry->FullDllName.Buffer);
		RemoveEntryList(&LdrEntry->InLoadOrderLinks);
		RemoveEntryList(&LdrEntry->InMemoryOrderLinks);
		RemoveEntryList(&LdrEntry->InInitializationOrderLinks);
		RemoveEntryList(&LdrEntry->HashLinks);
		RtlFreeHeap(heap, 0, LdrEntry);
		return true;
	}
	default:return false;
	}
}

NTSTATUS NTAPI RtlUpdateReferenceCount(IN OUT PMEMORYMODULE pModule, IN DWORD Flags) {
	if (Flags != FLAG_REFERENCE && Flags != FLAG_DEREFERENCE)return STATUS_INVALID_PARAMETER_2;

	if (Flags == FLAG_REFERENCE && pModule->dwReferenceCount != 0xffffffff)
		++pModule->dwReferenceCount;
	if (Flags == FLAG_DEREFERENCE && pModule->dwReferenceCount)
		--pModule->dwReferenceCount;

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI RtlGetReferenceCount(IN PMEMORYMODULE pModule, OUT PULONG Count) {

	*Count = pModule->dwReferenceCount;

	return STATUS_SUCCESS;
}

VOID NTAPI RtlInsertMemoryTableEntry(IN PLDR_DATA_TABLE_ENTRY LdrEntry) {
	PPEB_LDR_DATA PebData = NtCurrentPeb()->Ldr;
	PLIST_ENTRY LdrpHashTable = MmpGlobalDataPtr->MmpLdrEntry.LdrpHashTable;
	ULONG i;

	/* Insert into hash table */
	i = LdrHashEntry(LdrEntry->BaseDllName);
	InsertTailList(&LdrpHashTable[i], &LdrEntry->HashLinks);

	/* Insert into other lists */
	InsertTailList(&PebData->InLoadOrderModuleList, &LdrEntry->InLoadOrderLinks);
	InsertTailList(&PebData->InMemoryOrderModuleList, &LdrEntry->InMemoryOrderLinks);
	InsertTailList(&PebData->InInitializationOrderModuleList, &LdrEntry->InInitializationOrderLinks);
}

VOID NTAPI RtlRbInsertNodeEx(IN PRTL_RB_TREE Tree, IN PRTL_BALANCED_NODE Parent, IN BOOLEAN Right, OUT PRTL_BALANCED_NODE Node) {
	decltype(&RtlRbInsertNodeEx)_RtlRbInsertNodeEx = decltype(_RtlRbInsertNodeEx)(RtlGetNtProcAddress("RtlRbInsertNodeEx"));
	if (!_RtlRbInsertNodeEx)return;
	return _RtlRbInsertNodeEx(Tree, Parent, Right, Node);
}

VOID NTAPI RtlRbRemoveNode(IN PRTL_RB_TREE Tree, IN PRTL_BALANCED_NODE Node) {
	decltype(&RtlRbRemoveNode)_RtlRbRemoveNode = decltype(_RtlRbRemoveNode)(RtlGetNtProcAddress("RtlRbRemoveNode"));
	if (!_RtlRbRemoveNode)return;
	return _RtlRbRemoveNode(Tree, Node);
}

PLDR_DATA_TABLE_ENTRY NTAPI RtlFindLdrTableEntryByHandle(PVOID BaseAddress) {
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

PLDR_DATA_TABLE_ENTRY NTAPI RtlFindLdrTableEntryByBaseName(PCWSTR BaseName) {
	PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList, ListEntry = ListHead->Flink;
	PLDR_DATA_TABLE_ENTRY CurEntry;
	while (ListEntry != ListHead) {
		CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		ListEntry = ListEntry->Flink;
		if (!wcsnicmp(BaseName, CurEntry->BaseDllName.Buffer, (CurEntry->BaseDllName.Length / sizeof(wchar_t)) - 4) ||
			!wcsnicmp(BaseName, CurEntry->BaseDllName.Buffer, CurEntry->BaseDllName.Length / sizeof(wchar_t))) {
			return CurEntry;
		}
	}
	return nullptr;
}

ULONG NTAPI LdrHashEntry(IN UNICODE_STRING& str, IN bool _xor) {
	ULONG result = 0;
	if (RtlIsWindowsVersionOrGreater(6, 2, 0)) {
		RtlHashUnicodeString(&str, TRUE, HASH_STRING_ALGORITHM_DEFAULT, &result);
	}
	else {
		for (USHORT i = 0; i < (str.Length / sizeof(wchar_t)); ++i)
			result += 0x1003F * RtlUpcaseUnicodeChar(str.Buffer[i]);
	}
	if (_xor)result &= (LDR_HASH_TABLE_ENTRIES - 1);
	return result;
}

size_t NTAPI LdrpDataTableEntrySize() {
	static size_t size = 0;
	if (size)return size;

	switch (NtWindowsVersion()) {
	case xp:return size = sizeof(LDR_DATA_TABLE_ENTRY_XP);
	case vista:return size = sizeof(LDR_DATA_TABLE_ENTRY_VISTA);
	case win7:return size = sizeof(LDR_DATA_TABLE_ENTRY_WIN7);
	case win8:return size = sizeof(LDR_DATA_TABLE_ENTRY_WIN8);
	case win8_1:return size = sizeof(LDR_DATA_TABLE_ENTRY_WIN8_1);
	case win10:return size = sizeof(LDR_DATA_TABLE_ENTRY_WIN10);
	case win10_1:return size = sizeof(LDR_DATA_TABLE_ENTRY_WIN10_1);
	case win10_2:return size = sizeof(LDR_DATA_TABLE_ENTRY_WIN10_2);
	default:return size = sizeof(LDR_DATA_TABLE_ENTRY_WIN10_2);
	}
}
