#include "stdafx.h"
#include <random>

#define InsertTailList(ListHead,Entry) {\
	 PLIST_ENTRY _EX_Blink;\
	 PLIST_ENTRY _EX_ListHead;\
	 _EX_ListHead = (ListHead);\
	 _EX_Blink = _EX_ListHead->Blink;\
	 (Entry)->Flink = _EX_ListHead;\
	 (Entry)->Blink = _EX_Blink;\
	 _EX_Blink->Flink = (Entry);\
	 _EX_ListHead->Blink = (Entry);\
}

static PRTL_RB_TREE NTAPI RtlFindLdrpModuleBaseAddressIndex() {
	static PRTL_RB_TREE LdrpModuleBaseAddressIndex = nullptr;
	if (LdrpModuleBaseAddressIndex)return LdrpModuleBaseAddressIndex;

	PLDR_DATA_TABLE_ENTRY_WIN10 nt10 = decltype(nt10)(RtlFindNtdllLdrEntry());
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
static NTSTATUS NTAPI RtlInsertModuleBaseAddressIndexNode(IN PLDR_DATA_TABLE_ENTRY DataTableEntry, IN PVOID BaseAddress) {
	static auto LdrpModuleBaseAddressIndex = RtlFindLdrpModuleBaseAddressIndex();
	if (!LdrpModuleBaseAddressIndex)return STATUS_UNSUCCESSFUL;

	PLDR_DATA_TABLE_ENTRY_WIN8 LdrNode = decltype(LdrNode)((size_t)LdrpModuleBaseAddressIndex - offsetof(LDR_DATA_TABLE_ENTRY_WIN8, BaseAddressIndexNode));
	bool bRight = false;
	const auto i = offsetof(LDR_DATA_TABLE_ENTRY_WIN8, BaseAddressIndexNode);
	while (true) {
		if (BaseAddress < LdrNode->DllBase) {
			if (!LdrNode->BaseAddressIndexNode.Left)break;
			LdrNode = decltype(LdrNode)((size_t)LdrNode->BaseAddressIndexNode.Left - offsetof(LDR_DATA_TABLE_ENTRY_WIN8, BaseAddressIndexNode));
		}
		else if (BaseAddress > LdrNode->DllBase) {
			if (!LdrNode->BaseAddressIndexNode.Right) {
				bRight = true;
				break;
			}
			LdrNode = decltype(LdrNode)((size_t)LdrNode->BaseAddressIndexNode.Right - offsetof(LDR_DATA_TABLE_ENTRY_WIN8, BaseAddressIndexNode));
		}
		else {
			LdrNode->DdagNode->LoadCount++;
			if (RtlIsWindowsVersionOrGreater(10, 0, 0)) {
				PLDR_DATA_TABLE_ENTRY_WIN10(LdrNode)->ReferenceCount++;
			}
			return STATUS_SUCCESS;
		}
	}

	RtlRbInsertNodeEx(LdrpModuleBaseAddressIndex, &LdrNode->BaseAddressIndexNode, bRight, &PLDR_DATA_TABLE_ENTRY_WIN8(DataTableEntry)->BaseAddressIndexNode);
	return STATUS_SUCCESS;
}
static NTSTATUS NTAPI RtlRemoveModuleBaseAddressIndexNode(IN PLDR_DATA_TABLE_ENTRY DataTableEntry) {
	static auto tree{ RtlFindLdrpModuleBaseAddressIndex() };
	if (!tree->Root)return STATUS_UNSUCCESSFUL;
	RtlRbRemoveNode(tree, &PLDR_DATA_TABLE_ENTRY_WIN8(DataTableEntry)->BaseAddressIndexNode);
	return STATUS_SUCCESS;
}

static NTSTATUS NTAPI RtlFreeDependencies(IN PLDR_DATA_TABLE_ENTRY_WIN10 LdrEntry) {
	_LDR_DDAG_NODE* DependentDdgeNode = nullptr;
	PLDR_DATA_TABLE_ENTRY_WIN10 ModuleEntry = nullptr;
	_LDRP_CSLIST* head = (decltype(head))LdrEntry->DdagNode->Dependencies, *entry = head;
	const static bool IsWin8 = RtlIsWindowsVersionInScope(6, 2, 0, 6, 3, -1);
	if (!LdrEntry->DdagNode->Dependencies)return STATUS_SUCCESS;
	
	//find all dependencies and free
	do {
		DependentDdgeNode = entry->Dependent.DependentDdagNode;
		if (DependentDdgeNode->Modules.Flink->Flink != &DependentDdgeNode->Modules) __fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
		ModuleEntry = decltype(ModuleEntry)((size_t)DependentDdgeNode->Modules.Flink - offsetof(_LDR_DATA_TABLE_ENTRY_WIN8, NodeModuleLink));
		if (ModuleEntry->DdagNode != DependentDdgeNode) __fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
		if (!DependentDdgeNode->IncomingDependencies) __fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
		_LDRP_CSLIST::_LDRP_CSLIST_INCOMMING* _last = DependentDdgeNode->IncomingDependencies, *_entry = _last;
		_LDR_DDAG_NODE* CurrentDdagNode;
		size_t State = 0, Cookies;

		//Acquire LoaderLock
		do {
			if (!NT_SUCCESS(LdrLockLoaderLock(LOCK_NO_WAIT_IF_BUSY, &State, &Cookies))) __fastfail(FAST_FAIL_FATAL_APP_EXIT);
		} while (State != LOCK_STATE_ENTERED);

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
		RtlFreeLdrpHeap(LdrEntry->DdagNode->Dependencies);

		//lookup next dependent.
		LdrEntry->DdagNode->Dependencies = (_LDRP_CSLIST::_LDRP_CSLIST_DEPENDENT*)(entry == head ? nullptr : entry);
	} while (entry != head);

	return STATUS_SUCCESS;
}
static bool NTAPI RtlInitializeLdrDataTableEntry(
	OUT PLDR_DATA_TABLE_ENTRY LdrEntry,
	IN DWORD dwFlags,
	IN PVOID BaseAddress,
	IN UNICODE_STRING &DllBaseName,
	IN UNICODE_STRING &DllFullName) {
	RtlZeroMemory(LdrEntry, LdrpDataTableEntrySize());
	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(BaseAddress);
	if (!headers)return false;
	bool FlagsProcessed = false;

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
			RtlAllocateLdrpHeap(IsWin8 ? sizeof(_LDR_DDAG_NODE_WIN8) : sizeof(_LDR_DDAG_NODE))))return false;
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
		LdrEntry->EntryPoint = (PVOID)((size_t)BaseAddress + headers->OptionalHeader.AddressOfEntryPoint);
		LdrEntry->LoadCount = 1;
		if (!FlagsProcessed) LdrEntry->Flags = LDRP_IMAGE_DLL | LDRP_ENTRY_INSERTED | LDRP_ENTRY_PROCESSED | LDRP_PROCESS_ATTACH_CALLED;
		RtlInitializeListEntry(&LdrEntry->HashLinks);
		return true;
	}
	default:return false;
	}
}
static bool NTAPI RtlFreeLdrDataTableEntry(IN PLDR_DATA_TABLE_ENTRY LdrEntry) {
	switch (NtWindowsVersion()) {
	case win10:
	case win10_1:
	case win10_2:
	case win8:
	case win8_1: {
		auto entry = (PLDR_DATA_TABLE_ENTRY_WIN10)LdrEntry;
		RtlFreeDependencies(entry);
		RtlFreeLdrpHeap(entry->DdagNode);
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
				RtlFreeLdrpHeap(next->Blink);
			}
		}
	}
	case xp: {
		RtlFreeLdrpHeap(LdrEntry->BaseDllName.Buffer);
		RtlFreeLdrpHeap(LdrEntry->FullDllName.Buffer);
		RemoveEntryList(&LdrEntry->InLoadOrderLinks);
		RemoveEntryList(&LdrEntry->InMemoryOrderLinks);
		RemoveEntryList(&LdrEntry->InInitializationOrderLinks);
		RemoveEntryList(&LdrEntry->HashLinks);
		RtlFreeLdrpHeap(LdrEntry);
		return true;
	}
	default:return false;
	}
}

#define FLAG_REFERENCE		0
#define FLAG_DEREFERENCE	1
static NTSTATUS NTAPI RtlUpdateReferenceCount(IN OUT PLDR_DATA_TABLE_ENTRY LdrEntry, IN DWORD Flags) {
	if (Flags != FLAG_REFERENCE && Flags != FLAG_DEREFERENCE)return STATUS_INVALID_PARAMETER_2;
	switch (NtWindowsVersion()) {
	case xp:
	case vista:
	case win7: {
		if (Flags == FLAG_REFERENCE && LdrEntry->LoadCount != 0xffff)
			++LdrEntry->LoadCount;
		if (Flags == FLAG_DEREFERENCE && LdrEntry->LoadCount)
			--LdrEntry->LoadCount;
		break;
	}
	case win8:
	case win8_1:
	case win10:
	case win10_1:
	case win10_2: {
		auto entry = (PLDR_DATA_TABLE_ENTRY_WIN10)LdrEntry;
		if (Flags == FLAG_REFERENCE) {
			if (entry->ObsoleteLoadCount != 0xffff)++entry->ObsoleteLoadCount;
			if (entry->DdagNode->LoadCount != 0xffffffff)++entry->DdagNode->LoadCount;
		}
		if (Flags == FLAG_DEREFERENCE) {
			if (entry->ObsoleteLoadCount)--entry->ObsoleteLoadCount;
			if (entry->DdagNode->LoadCount)--entry->DdagNode->LoadCount;
		}
		break;
	}
	default:return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}
static NTSTATUS NTAPI RtlGetReferenceCount(IN PLDR_DATA_TABLE_ENTRY LdrEntry, OUT PULONG Count) {
	switch (NtWindowsVersion()) {
	case xp:
	case vista:
	case win7: {
		*Count = LdrEntry->LoadCount;
		break;
	}
	case win8:
	case win8_1:
	case win10:
	case win10_1:
	case win10_2: {
		auto entry = (PLDR_DATA_TABLE_ENTRY_WIN8)LdrEntry;
		*Count = entry->DdagNode->LoadCount == entry->ObsoleteLoadCount ? entry->ObsoleteLoadCount : entry->DdagNode->LoadCount;
		break;
	}
	default:return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}

static bool NTAPI RtlResolveDllNameUnicodeString(
	IN PCWSTR DllName OPTIONAL, IN PCWSTR DllFullName OPTIONAL,
	OUT PUNICODE_STRING BaseDllName, OUT PUNICODE_STRING FullDllName) {

	std::random_device random;
	size_t Length = 0;
	size_t FullLength = 0;
	PWSTR _DllName = nullptr, _DllFullName = _DllName;
	bool result = false;
	if (DllName) {
		bool add = false;
		if ((Length = wcslen(DllName)) <= 4 || wcsnicmp(DllName + Length - 4, L".dll", 4)) {
			add = true;
			Length += 4;
		}
		_DllName = new wchar_t[++Length];
		wcscpy(_DllName, DllName);
		if (add)wcscat(_DllName, L".DLL");
	}
	else {
		Length = 16 + 4 + 1; //hex(ULONG64) + ".dll" + '\0'
		_DllName = new wchar_t[Length];
		swprintf(_DllName, L"%016llX.DLL", ((ULONG64)random() << 32) | random());
	}
	if (DllFullName) {
		bool add = false;
		FullLength = wcslen(DllFullName);
		if (DllName && !wcsstr(DllFullName, DllName) && wcsnicmp(DllFullName + FullLength - 4, L".dll", 4)) {
			add = true;
			FullLength += Length;
		}
		wcscpy(_DllFullName = new wchar_t[++FullLength], DllFullName);
		if (add) wsprintfW(_DllFullName, L"%s\\%s", _DllFullName, _DllName);
	}
	else {
		FullLength = 16 + 1 + Length; //hex(ULONG64) + '\\' + _DllName
		swprintf(_DllFullName = new wchar_t[FullLength], L"%016llX\\%s", ((ULONG64)random() << 32) | random(), _DllName);
	}
	FullLength *= sizeof(wchar_t);
	Length *= sizeof(wchar_t);

	/* Allocate space for full DLL name */
	if (!(FullDllName->Buffer = (PWSTR)RtlAllocateLdrpHeap(FullLength))) goto end;
	FullDllName->Length = FullLength - sizeof(wchar_t);
	FullDllName->MaximumLength = FullLength;
	wcscpy(FullDllName->Buffer, _DllFullName);

	/* Construct base DLL name */
	BaseDllName->Length = Length - sizeof(wchar_t);
	BaseDllName->MaximumLength = Length;
	BaseDllName->Buffer = (PWSTR)RtlAllocateLdrpHeap(Length);
	if (!BaseDllName->Buffer) {
		RtlFreeLdrpHeap(BaseDllName->Buffer);
		goto end;
	}
	wcscpy(BaseDllName->Buffer, _DllName);
	result = true;
end:
	delete[]_DllName;
	delete[]_DllFullName;
	return result;
}

static PLDR_DATA_TABLE_ENTRY NTAPI RtlAllocateDataTableEntry(IN PVOID BaseAddress) {
	PLDR_DATA_TABLE_ENTRY LdrEntry = nullptr;
	PIMAGE_NT_HEADERS NtHeader;

	/* Make sure the header is valid */
	if (NtHeader = RtlImageNtHeader(BaseAddress)) {
		/* Allocate an entry */
		LdrEntry = (decltype(LdrEntry))RtlAllocateLdrpHeap(LdrpDataTableEntrySize());
	}

	/* Return the entry */
	return LdrEntry;
}

static VOID NTAPI RtlInsertMemoryTableEntry(IN PLDR_DATA_TABLE_ENTRY LdrEntry) {
	PPEB_LDR_DATA PebData = NtCurrentPeb()->Ldr;
	PLIST_ENTRY LdrpHashTable = RtlFindLdrpHashTable();
	ULONG i;

	/* Insert into hash table */
	i = LdrHashEntry(LdrEntry->BaseDllName);
	InsertTailList(&LdrpHashTable[i], &LdrEntry->HashLinks);

	/* Insert into other lists */
	InsertTailList(&PebData->InLoadOrderModuleList, &LdrEntry->InLoadOrderLinks);
	InsertTailList(&PebData->InMemoryOrderModuleList, &LdrEntry->InMemoryOrderLinks);
	InsertTailList(&PebData->InInitializationOrderModuleList, &LdrEntry->InInitializationOrderLinks);
}

static NTSTATUS NTAPI LdrMapDllMemory(IN HMEMORYMODULE ViewBase, IN DWORD dwFlags, IN PCWSTR DllName OPTIONAL,
	IN PCWSTR lpFullDllName OPTIONAL, OUT PLDR_DATA_TABLE_ENTRY* DataTableEntry OPTIONAL) {

	UNICODE_STRING FullDllName, BaseDllName;
	PIMAGE_NT_HEADERS NtHeaders;
	PLDR_DATA_TABLE_ENTRY LdrEntry;

	if (!(NtHeaders = RtlImageNtHeader(ViewBase))) return STATUS_INVALID_IMAGE_FORMAT;

	if (!(LdrEntry = RtlAllocateDataTableEntry(ViewBase))) return STATUS_NO_MEMORY;

	if (!RtlResolveDllNameUnicodeString(DllName, lpFullDllName, &BaseDllName, &FullDllName)) {
		RtlFreeLdrpHeap(LdrEntry);
		return STATUS_NO_MEMORY;
	}

	if (!RtlInitializeLdrDataTableEntry(LdrEntry, dwFlags, ViewBase, BaseDllName, FullDllName)) {
		RtlFreeLdrpHeap(LdrEntry);
		RtlFreeLdrpHeap(BaseDllName.Buffer);
		RtlFreeLdrpHeap(FullDllName.Buffer);
		return STATUS_UNSUCCESSFUL;
	}

	RtlInsertMemoryTableEntry(LdrEntry);
	if (DataTableEntry)*DataTableEntry = LdrEntry;
	return STATUS_SUCCESS;
}

#ifndef _INLINE_INTERNALS
static __forceinline WORD CalcCheckSum(DWORD StartValue, LPVOID BaseAddress, DWORD WordCount) {
	LPWORD Ptr = (LPWORD)BaseAddress;
	DWORD Sum = StartValue;
	for (DWORD i = 0; i < WordCount; i++) {
		Sum += *Ptr;
		if (HIWORD(Sum) != 0) Sum = LOWORD(Sum) + HIWORD(Sum);
		Ptr++;
	}
	return (WORD)(LOWORD(Sum) + HIWORD(Sum));
}
BOOLEAN __forceinline WINAPI CheckSumBufferedFile(LPVOID BaseAddress, DWORD BufferLength) {
	PIMAGE_NT_HEADERS header = RtlImageNtHeader(BaseAddress);
	DWORD CalcSum = CalcCheckSum(0, BaseAddress, (BufferLength + 1) / sizeof(WORD));
	DWORD HdrSum = header->OptionalHeader.CheckSum;
	if (!HdrSum)return TRUE;

	if (!header) return FALSE;
	if (LOWORD(CalcSum) >= LOWORD(HdrSum)) CalcSum -= LOWORD(HdrSum);
	else CalcSum = ((LOWORD(CalcSum) - LOWORD(HdrSum)) & 0xFFFF) - 1;
	if (LOWORD(CalcSum) >= HIWORD(HdrSum)) CalcSum -= HIWORD(HdrSum);
	else CalcSum = ((LOWORD(CalcSum) - HIWORD(HdrSum)) & 0xFFFF) - 1;
	CalcSum += BufferLength;
	return HdrSum == CalcSum;
}
#endif
BOOLEAN NTAPI RtlIsValidImageBuffer(PVOID Buffer) {
	
	BOOLEAN result = FALSE;
	__try {
		union {
			PIMAGE_NT_HEADERS32 nt32;
			PIMAGE_NT_HEADERS64 nt64;
			PIMAGE_NT_HEADERS nt;
		}headers;
		headers.nt = RtlImageNtHeader(Buffer);
		PIMAGE_SECTION_HEADER sections = nullptr;
		size_t SizeofImage = 0;

		if (!headers.nt) {
			return FALSE;
		}

		switch (headers.nt->OptionalHeader.Magic) {
		case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
			sections = PIMAGE_SECTION_HEADER((char*)&headers.nt32->OptionalHeader + headers.nt32->FileHeader.SizeOfOptionalHeader);
			SizeofImage = headers.nt32->OptionalHeader.SizeOfHeaders;
			ProbeForRead(sections, headers.nt32->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
			for (WORD i = 0; i < headers.nt32->FileHeader.NumberOfSections; ++i, ++sections)
				SizeofImage += sections->SizeOfRawData;

			//Signature size
			SizeofImage += headers.nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
			break;
		case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
			sections = PIMAGE_SECTION_HEADER((char*)&headers.nt64->OptionalHeader + headers.nt64->FileHeader.SizeOfOptionalHeader);
			SizeofImage = headers.nt64->OptionalHeader.SizeOfHeaders;
			ProbeForRead(sections, headers.nt64->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
			for (WORD i = 0; i < headers.nt64->FileHeader.NumberOfSections; ++i, ++sections)
				SizeofImage += sections->SizeOfRawData;
			SizeofImage += headers.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
			break;
		default:
			return FALSE;
		}
		IMAGE_FIRST_SECTION(headers.nt32);
		ProbeForRead(Buffer, SizeofImage);
		result = CheckSumBufferedFile(Buffer, SizeofImage);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		SetLastError(RtlNtStatusToDosError(GetExceptionCode()));
	}
	return result;
}

BOOL NTAPI LdrpExecuteTLS(PMEMORYMODULE module) {
	unsigned char* codeBase = module->codeBase;
	PIMAGE_TLS_DIRECTORY tls;
	PIMAGE_TLS_CALLBACK* callback;
	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(codeBase);
	PIMAGE_DATA_DIRECTORY directory = &headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (directory->VirtualAddress == 0) return TRUE;

	tls = (PIMAGE_TLS_DIRECTORY)(codeBase + directory->VirtualAddress);
	callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
	if (callback) {
		while (*callback) {
			(*callback)((LPVOID)codeBase, DLL_PROCESS_ATTACH, nullptr);
			callback++;
		}
	}
	return TRUE;
}

BOOL NTAPI LdrpCallInitializers(PMEMORYMODULE module, DWORD dwReason) {
	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(module->codeBase);

	if (headers->OptionalHeader.AddressOfEntryPoint) {
		__try {
			// notify library about attaching to process
			if (((DllEntryProc)(module->codeBase + headers->OptionalHeader.AddressOfEntryPoint))((HINSTANCE)module->codeBase, dwReason, 0)) {
				module->initialized = TRUE;
				return TRUE;
			}
			SetLastError(ERROR_DLL_INIT_FAILED);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			SetLastError(RtlNtStatusToDosError(GetExceptionCode()));
		}

		return FALSE;
	}

	return TRUE;
}

NTSTATUS NTAPI LdrLoadDllMemory(OUT HMEMORYMODULE* BaseAddress, IN LPVOID BufferAddress, IN size_t BufferSize) {
	return LdrLoadDllMemoryExW(BaseAddress, nullptr, LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS, BufferAddress, BufferSize, nullptr, nullptr);
}

NTSTATUS NTAPI LdrLoadDllMemoryExW(
	OUT HMEMORYMODULE* BaseAddress,
	OUT PVOID* LdrEntry OPTIONAL,
	IN DWORD dwFlags,
	IN LPVOID BufferAddress,
	IN size_t BufferSize,
	IN LPCWSTR DllName OPTIONAL,
	IN LPCWSTR DllFullName OPTIONAL) {
	PMEMORYMODULE module = nullptr;
	NTSTATUS status = STATUS_SUCCESS;
	PLDR_DATA_TABLE_ENTRY ModuleEntry = nullptr;
	PIMAGE_NT_HEADERS headers = nullptr;

	if (BufferSize)return STATUS_INVALID_PARAMETER_5;
	__try {
		*BaseAddress = nullptr;
		if (LdrEntry)*LdrEntry = nullptr;
		if (!(dwFlags & LOAD_FLAGS_PASS_IMAGE_CHECK) && !RtlIsValidImageBuffer(BufferAddress))status = STATUS_INVALID_IMAGE_FORMAT;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}
	if (!NT_SUCCESS(status))return status;

	if (dwFlags & LOAD_FLAGS_NOT_MAP_DLL) {
		dwFlags &= LOAD_FLAGS_NOT_MAP_DLL;
		DllName = DllFullName = nullptr;
	}
	if (dwFlags & LOAD_FLAGS_USE_DLL_NAME && (!DllName || !DllFullName))return STATUS_INVALID_PARAMETER_3;

	if (DllName) {
		PLIST_ENTRY ListHead, ListEntry;
		PLDR_DATA_TABLE_ENTRY CurEntry;
		PIMAGE_NT_HEADERS h1 = RtlImageNtHeader(BufferAddress), h2 = nullptr;
		if (!h1)return STATUS_INVALID_IMAGE_FORMAT;
		ListEntry = (ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList)->Flink;
		while (ListEntry != ListHead) {
			CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			ListEntry = ListEntry->Flink;
			/* Check if it's being unloaded */
			if (!CurEntry->InMemoryOrderLinks.Flink) continue;
			/* Check if name matches */
			if (!wcsnicmp(DllName, CurEntry->BaseDllName.Buffer, (CurEntry->BaseDllName.Length / sizeof(wchar_t)) - 4) ||
				!wcsnicmp(DllName, CurEntry->BaseDllName.Buffer, CurEntry->BaseDllName.Length / sizeof(wchar_t))) {
				/* Let's compare their headers */
				if (!(h2 = RtlImageNtHeader(CurEntry->DllBase)))continue;
				if (!(module = MapMemoryModuleHandle((HMEMORYMODULE)CurEntry->DllBase)))continue;
				if ((h1->OptionalHeader.SizeOfCode == h2->OptionalHeader.SizeOfCode) &&
					(h1->OptionalHeader.SizeOfHeaders == h2->OptionalHeader.SizeOfHeaders)) {
					/* This is our entry!, update load count and return success */
					if (!module->UseReferenceCount || dwFlags & LOAD_FLAGS_NOT_USE_REFERENCE_COUNT)return STATUS_INVALID_PARAMETER_3;
					RtlUpdateReferenceCount(CurEntry, FLAG_REFERENCE);
					*BaseAddress = (HMEMORYMODULE)CurEntry->DllBase;
					if (LdrEntry)*LdrEntry = CurEntry;
					return STATUS_SUCCESS;
				}
			}
		}
	}

	if (!(*BaseAddress = MemoryLoadLibrary(BufferAddress))) {
		switch (GetLastError()) {
		case ERROR_BAD_EXE_FORMAT:
			return STATUS_INVALID_IMAGE_FORMAT;
		case ERROR_OUTOFMEMORY:
			return STATUS_NO_MEMORY;
		case ERROR_DLL_INIT_FAILED:
			return STATUS_DLL_INIT_FAILED;
		default:
			return STATUS_UNSUCCESSFUL;
		}
	}
	if (!(module = MapMemoryModuleHandle(*BaseAddress))) {
		__fastfail(FAST_FAIL_FATAL_APP_EXIT);
		DebugBreak();
		ExitProcess(STATUS_INVALID_ADDRESS);
		TerminateProcess(NtCurrentProcess(), STATUS_INVALID_ADDRESS);
	}
	module->loadFromNtLoadDllMemory = true;
	headers = RtlImageNtHeader(*BaseAddress);
	if (headers->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)dwFlags |= LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION;
	if (dwFlags & LOAD_FLAGS_NOT_MAP_DLL) {

		if (!LdrpExecuteTLS(module) || !LdrpCallInitializers(module, DLL_PROCESS_ATTACH)) {
			status = STATUS_DLL_INIT_FAILED;
			MemoryFreeLibrary(*BaseAddress);
		}

		return status;
	}

	status = LdrMapDllMemory(*BaseAddress, dwFlags, DllName, DllFullName, &ModuleEntry);
	if (!NT_SUCCESS(status)) {
		LdrUnloadDllMemory(*BaseAddress);
		*BaseAddress = nullptr;
		return status;
	}
	module->MappedDll = true;

	if (LdrEntry)*LdrEntry = ModuleEntry;

	if (!(dwFlags & LOAD_FLAGS_NOT_USE_REFERENCE_COUNT))module->UseReferenceCount = true;

	if (!(dwFlags & LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION)) {
		status = RtlInsertInvertedFunctionTable((PVOID)module->codeBase, headers->OptionalHeader.SizeOfImage);
		if (!NT_SUCCESS(status)) {
			LdrUnloadDllMemory(*BaseAddress);
			*BaseAddress = nullptr;
			if (LdrEntry)*LdrEntry = nullptr;
			return status;
		}
		module->InsertInvertedFunctionTableEntry = true;
	}

	if (!(dwFlags & LOAD_FLAGS_NOT_HANDLE_TLS)) {
		status = LdrpHandleTlsData(ModuleEntry);
		if (!NT_SUCCESS(status)) {
			do {
				if (dwFlags & LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS) {
					status = 0x7fffffff;
					break;
				}
				LdrUnloadDllMemory(*BaseAddress);
				*BaseAddress = nullptr;
				if (LdrEntry)*LdrEntry = nullptr;
				return status;
			} while (false);
		}
		else {
			module->TlsHandled = true;
		}
	}

	if (!LdrpExecuteTLS(module) || !LdrpCallInitializers(module, DLL_PROCESS_ATTACH)) {
		status = STATUS_DLL_INIT_FAILED;
		LdrUnloadDllMemory(*BaseAddress);
	}

	return status;
}

NTSTATUS NTAPI LdrLoadDllMemoryExA(
	OUT HMEMORYMODULE* BaseAddress,
	OUT PVOID* LdrEntry OPTIONAL,
	IN DWORD dwFlags,
	IN LPVOID BufferAddress,
	IN size_t BufferSize,
	IN LPCSTR DllName OPTIONAL,
	IN LPCSTR DllFullName OPTIONAL){
	LPWSTR _DllName = nullptr, _DllFullName = nullptr;
	size_t size;
	NTSTATUS status;
	if (DllName) {
		size = strlen(DllName) + 1;
		_DllName = new wchar_t[size];
		mbstowcs(_DllName, DllName, size);
	}
	if (DllFullName) {
		size = strlen(DllFullName) + 1;
		_DllFullName = new wchar_t[size];
		mbstowcs(_DllFullName, DllFullName, size);
	}
	status = LdrLoadDllMemoryExW(BaseAddress, LdrEntry, dwFlags, BufferAddress, BufferSize, _DllName, _DllFullName);
	if (_DllName)delete[]_DllName;
	if (_DllFullName)delete[]_DllFullName;
	return status;
}

NTSTATUS NTAPI LdrUnloadDllMemory(IN HMEMORYMODULE BaseAddress) {
	__try {
		ProbeForRead(BaseAddress, sizeof(size_t));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}
	
	PLDR_DATA_TABLE_ENTRY CurEntry;
	ULONG count = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PMEMORYMODULE module = MapMemoryModuleHandle(BaseAddress);

	//Not a memory module loaded via LdrLoadDllMemory
	if (!module || !module->loadFromNtLoadDllMemory)return STATUS_INVALID_HANDLE;

	//Mapping dll failed
	if (module->loadFromNtLoadDllMemory && !module->MappedDll) {
		module->underUnload = true;
		return MemoryFreeLibrary(BaseAddress) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
	}

	if (CurEntry = RtlFindLdrTableEntryByHandle(BaseAddress)) {
		PIMAGE_NT_HEADERS headers = RtlImageNtHeader(BaseAddress);
		if (headers->OptionalHeader.SizeOfImage == CurEntry->SizeOfImage) {
			if (module->UseReferenceCount) {
				status = RtlGetReferenceCount(CurEntry, &count);
				if (!NT_SUCCESS(status))return status;
			}
			if (!(count & ~1)) {
				module->underUnload = true;
				if (module->initialized) {
					DllEntryProc DllEntry = (DllEntryProc)(LPVOID)(module->codeBase + headers->OptionalHeader.AddressOfEntryPoint);
					(*DllEntry)((HINSTANCE)module->codeBase, DLL_PROCESS_DETACH, 0);
				}
				if (module->MappedDll) {
					if (module->InsertInvertedFunctionTableEntry) {
						status = RtlRemoveInvertedFunctionTable(BaseAddress);
						if (!NT_SUCCESS(status))__fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
					}
					if (module->TlsHandled) {
						
						status = LdrpReleaseTlsEntry(CurEntry);
						if (!NT_SUCCESS(status)) __fastfail(FAST_FAIL_FATAL_APP_EXIT);
					}
					if (!RtlFreeLdrDataTableEntry(CurEntry))__fastfail(FAST_FAIL_FATAL_APP_EXIT);
				}
				if (!MemoryFreeLibrary(BaseAddress))__fastfail(FAST_FAIL_FATAL_APP_EXIT);
				return STATUS_SUCCESS;
			}
			else {
				return RtlUpdateReferenceCount(CurEntry, FLAG_DEREFERENCE);
			}
		}
	}

	return STATUS_INVALID_HANDLE;
}

__declspec(noreturn)
VOID NTAPI LdrUnloadDllMemoryAndExitThread(IN HMEMORYMODULE BaseAddress, IN DWORD dwExitCode) {
	LdrUnloadDllMemory(BaseAddress);
	RtlExitUserThread(dwExitCode);
}

NTSTATUS NTAPI LdrQuerySystemMemoryModuleFeatures(OUT PDWORD pFeatures) {
	static DWORD features = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PVOID pfn = nullptr;
	bool value = false;
	__try {
		if (features) {
			*pFeatures = features;
			return status;
		} 

		if (RtlFindLdrpModuleBaseAddressIndex())features |= MEMORY_FEATURE_MODULE_BASEADDRESS_INDEX;
		if (RtlFindLdrpHeap())features |= MEMORY_FEATURE_LDRP_HEAP;
		if (RtlFindLdrpHashTable())features |= MEMORY_FEATURE_LDRP_HASH_TABLE;
		if (RtlFindLdrpInvertedFunctionTable())features |= MEMORY_FEATURE_INVERTED_FUNCTION_TABLE;
		if (NT_SUCCESS(RtlFindLdrpHandleTlsData(&pfn, &value)) && pfn)features |= MEMORY_FEATURE_LDRP_HANDLE_TLS_DATA;
		if (NT_SUCCESS(RtlFindLdrpReleaseTlsEntry(&pfn, &value) && pfn))features |= MEMORY_FEATURE_LDRP_RELEASE_TLS_ENTRY;
		if (features)features |= MEMORY_FEATURE_SUPPORT_VERSION;
		*pFeatures = features;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}
	return status;
}



