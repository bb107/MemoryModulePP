#include "NativeFunctionsInternal.h"
#include <random>
#pragma warning(disable:6328)
#pragma warning(disable:4267)
#pragma warning(disable:26812)
#ifndef _WIN64
SIZE_T NTAPI _RtlCompareMemory(
	const VOID* Source1,
	const VOID* Source2,
	SIZE_T     Length) {
	return decltype(&_RtlCompareMemory)(RtlGetNtProcAddress("RtlCompareMemory"))(Source1, Source2, Length);
}
#define RtlCompareMemory _RtlCompareMemory
#endif

#define RTL_VERIFY_FLAGS_MAJOR_VERSION	0
#define RTL_VERIFY_FLAGS_MINOR_VERSION	1
#define RTL_VERIFY_FLAGS_BUILD_NUMBERS	2
#define RTL_VERIFY_FLAGS_DEFAULT		RTL_VERIFY_FLAGS_MAJOR_VERSION|RTL_VERIFY_FLAGS_MINOR_VERSION|RTL_VERIFY_FLAGS_BUILD_NUMBERS
static bool NTAPI RtlVerifyVersion(IN DWORD MajorVersion, IN DWORD MinorVersion OPTIONAL, IN DWORD BuildNumber OPTIONAL, IN BYTE Flags) {
	DWORD Versions[3];
	RtlGetNtVersionNumbers(Versions, Versions + 1, Versions + 2);
	if (Versions[0] == MajorVersion &&
		((Flags & RTL_VERIFY_FLAGS_MINOR_VERSION) ? Versions[1] == MinorVersion : true) &&
		((Flags & RTL_VERIFY_FLAGS_BUILD_NUMBERS) ? Versions[2] == BuildNumber : true))return true;
	return false;
}
static bool NTAPI RtlIsWindowsVersionOrGreater(IN DWORD MajorVersion, IN DWORD MinorVersion, IN DWORD BuildNumber) {
	static DWORD Versions[3]{};
	if (!Versions[0])RtlGetNtVersionNumbers(Versions, Versions + 1, Versions + 2);

	if (Versions[0] == MajorVersion) {
		if (Versions[1] == MinorVersion) return Versions[2] >= BuildNumber;
		else return (Versions[1] > MinorVersion);
	}
	else return Versions[0] > MajorVersion;
}
static bool NTAPI RtlIsWindowsVersionInScope(
	IN DWORD MinMajorVersion, IN DWORD MinMinorVersion, IN DWORD MinBuildNumber,
	IN DWORD MaxMajorVersion, IN DWORD MaxMinorVersion, IN DWORD MaxBuildNumber) {
	return RtlIsWindowsVersionOrGreater(MinMajorVersion, MinMinorVersion, MinBuildNumber) && 
		!RtlIsWindowsVersionOrGreater(MaxMajorVersion, MaxMinorVersion, MaxBuildNumber);
}

static PLDR_DATA_TABLE_ENTRY NTAPI RtlFindLdrTableEntryByHandle(PVOID BaseAddress) {
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
static PLDR_DATA_TABLE_ENTRY NTAPI RtlFindLdrTableEntryByBaseName(PCWSTR BaseName) {
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
#define RtlFindNtdllLdrEntry()	RtlFindLdrTableEntryByBaseName(L"ntdll.dll")

static ULONG NTAPI LdrHashEntry(IN const UNICODE_STRING& str, IN bool _xor = true) {
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

static HANDLE NTAPI RtlFindtLdrpHeap() {
	PLIST_ENTRY ListHead, ListEntry;
	PLDR_DATA_TABLE_ENTRY CurEntry;
	MEMORY_BASIC_INFORMATION mbi{};
	static HANDLE result = nullptr;
	if (result)return result;

	ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
	ListEntry = ListHead->Flink;
	if (ListHead == ListEntry)return result;
	CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
	NtQueryVirtualMemory(NtCurrentProcess(), CurEntry, MemoryBasicInformation, &mbi, sizeof(mbi), (PSIZE_T)&ListHead);
	return result = mbi.AllocationBase;
}
static PLIST_ENTRY NTAPI RtlFindLdrpHashTable() {
	static PLIST_ENTRY list = nullptr;
	if (list) return list;

	PLDR_DATA_TABLE_ENTRY CurEntry = RtlFindNtdllLdrEntry();
	if (!CurEntry)return list;

	if (CurEntry->HashLinks.Flink == &CurEntry->HashLinks)return list;
	list = (decltype(list))((size_t)CurEntry->HashLinks.Flink - LdrHashEntry(CurEntry->BaseDllName) * sizeof(_LIST_ENTRY));
	return list;
}

static PVOID NTAPI NtAllocateLdrpHeap(IN size_t size) {
	HANDLE heap = RtlFindtLdrpHeap();
	if (!heap)return nullptr;

	return RtlAllocateHeap(heap, HEAP_ZERO_MEMORY, size);
}
static BOOL NTAPI NtFreeLdrpHeap(IN PVOID buffer) {
	HANDLE LdrpHeap = RtlFindtLdrpHeap();
	if (!LdrpHeap)return FALSE;
	return RtlFreeHeap(LdrpHeap, 0, buffer);
}

static VOID NTAPI NtInitializeListEntry(OUT PLIST_ENTRY entry) {
	entry->Blink = entry->Flink = entry;
}
static VOID NTAPI NtInitializeSingleEntry(OUT PSINGLE_LIST_ENTRY entry) {
	entry->Next = entry;
}
FORCEINLINE BOOLEAN NTAPI RemoveEntryList(IN PLIST_ENTRY Entry) {
	PLIST_ENTRY OldFlink;
	PLIST_ENTRY OldBlink;

	OldFlink = Entry->Flink;
	OldBlink = Entry->Blink;

	OldFlink->Blink = OldBlink;
	OldBlink->Flink = OldFlink;
	return (BOOLEAN)(OldFlink == OldBlink);
}

static WINDOWS_VERSION NTAPI NtWindowsVersion() {
	static WINDOWS_VERSION version = null;
	DWORD versions[3]{};
	if (version)return version;
	RtlGetNtVersionNumbers(versions, versions + 1, versions + 2);

	switch (versions[0]) {
	case 5: {
		switch (versions[1]) {
		case 1:return version = versions[2] == 2600 ? xp : invalid;
		case 2:return version = versions[2] == 3790 ? xp : invalid;
		default:break;
		}
		break;
	}
		  break;
	case 6: {
		switch (versions[1]) {
		case 0: {
			switch (versions[2]) {
			case 6000:
			case 6001:
			case 6002:
				return version = vista;
			default:
				break;
			}
			break;
		}
			  break;
		case 1: {
			switch (versions[2]) {
			case 7600:
			case 7601:
				return version = win7;
			default:
				break;
			}
			break;
		}
			  break;
		case 2: {
			if (versions[2] == 9200)return version = win8;
			break;
		}
			  break;
		case 3: {
			if (versions[2] == 9600)return version = win8_1;
			break;
		}
			  break;
		default:
			break;
		}
		break;
	}
		  break;
	case 10: {
		if (versions[1])break;
		switch (versions[2]) {
		case 10240:
		case 10586: return version = win10;
		case 14393: return version = win10_1;
		case 15063:
		case 16299:
		case 17134:
		case 17763:
		case 18362:return version = win10_2;
		default:if (RtlIsWindowsVersionOrGreater(versions[0], versions[1], 15063))return version = win10_2;
			break;
		}
		break;
	}
		  break;
	default:
		break;
	}
	return version = invalid;
}
static size_t NTAPI NtLdrDataTableEntrySize() {
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

static PRTL_BALANCED_NODE NTAPI RtlFindLdrpModuleBaseAddressIndex() {
	static PRTL_BALANCED_NODE LdrpModuleBaseAddressIndex = nullptr;
	if (LdrpModuleBaseAddressIndex)return LdrpModuleBaseAddressIndex;

	PLDR_DATA_TABLE_ENTRY ntdll = RtlFindNtdllLdrEntry();
	PLDR_DATA_TABLE_ENTRY_WIN10 nt10 = decltype(nt10)(ntdll);

	if (!ntdll || !RtlIsWindowsVersionOrGreater(6, 2, 0))return nullptr;
	LdrpModuleBaseAddressIndex = &nt10->BaseAddressIndexNode;
	while (LdrpModuleBaseAddressIndex->ParentValue) {
		LdrpModuleBaseAddressIndex = decltype(LdrpModuleBaseAddressIndex)(LdrpModuleBaseAddressIndex->ParentValue & (~7));
	}
	if (LdrpModuleBaseAddressIndex->Red)LdrpModuleBaseAddressIndex = nullptr;
	return LdrpModuleBaseAddressIndex;
}
static NTSTATUS NTAPI NtInsertModuleBaseAddressIndexNode(IN PLDR_DATA_TABLE_ENTRY DataTableEntry, IN PVOID BaseAddress) {
	static auto LdrpModuleBaseAddressIndex = RtlFindLdrpModuleBaseAddressIndex();
	if (!LdrpModuleBaseAddressIndex)return STATUS_UNSUCCESSFUL;

	PLDR_DATA_TABLE_ENTRY_WIN8 LdrNode = decltype(LdrNode)((size_t)LdrpModuleBaseAddressIndex - offsetof(LDR_DATA_TABLE_ENTRY_WIN8, BaseAddressIndexNode));
	RTL_RB_TREE tree{ LdrpModuleBaseAddressIndex };
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

	RtlRbInsertNodeEx(&tree, &LdrNode->BaseAddressIndexNode, bRight, &PLDR_DATA_TABLE_ENTRY_WIN8(DataTableEntry)->BaseAddressIndexNode);
	return STATUS_SUCCESS;
}
static NTSTATUS NTAPI NtRemoveModuleBaseAddressIndexNode(IN PLDR_DATA_TABLE_ENTRY DataTableEntry) {
	static RTL_RB_TREE tree{ RtlFindLdrpModuleBaseAddressIndex() };
	if (!tree.Root)return STATUS_UNSUCCESSFUL;

	RtlRbRemoveNode(&tree, &PLDR_DATA_TABLE_ENTRY_WIN8(DataTableEntry)->BaseAddressIndexNode);
	return STATUS_SUCCESS;
}

static NTSTATUS NTAPI NtFreeDependencies(IN PLDR_DATA_TABLE_ENTRY_WIN10 LdrEntry) {
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
		NtFreeLdrpHeap(LdrEntry->DdagNode->Dependencies);

		//lookup next dependent.
		LdrEntry->DdagNode->Dependencies = (_LDRP_CSLIST::_LDRP_CSLIST_DEPENDENT*)(entry == head ? nullptr : entry);
	} while (entry != head);

	return STATUS_SUCCESS;
}
static bool NTAPI NtInitializeLdrDataTableEntry(
	OUT PLDR_DATA_TABLE_ENTRY LdrEntry,
	IN DWORD dwFlags,
	IN PVOID BaseAddress,
	IN UNICODE_STRING &DllBaseName,
	IN UNICODE_STRING &DllFullName) {
	RtlZeroMemory(LdrEntry, NtLdrDataTableEntrySize());
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
		if (!NT_SUCCESS(NtInsertModuleBaseAddressIndexNode(LdrEntry, BaseAddress)))return false;
		if (!(entry->DdagNode = (decltype(entry->DdagNode))
			NtAllocateLdrpHeap(IsWin8 ? sizeof(_LDR_DDAG_NODE_WIN8) : sizeof(_LDR_DDAG_NODE))))return false;
		//NtInitializeListEntry(&entry->NodeModuleLink);
		//NtInitializeListEntry(&entry->DdagNode->Modules);
		//NtInitializeSingleEntry(&entry->DdagNode->CondenseLink);
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
		if (NtLdrDataTableEntrySize() == sizeof(LDR_DATA_TABLE_ENTRY_WIN7)) {
			auto entry = (PLDR_DATA_TABLE_ENTRY_WIN7)LdrEntry;
			entry->OriginalBase = headers->OptionalHeader.ImageBase;
			NtQuerySystemTime(&entry->LoadTime);
		}
	}
	case vista: {
		if (NtLdrDataTableEntrySize() == sizeof(LDR_DATA_TABLE_ENTRY_VISTA) ||
			NtLdrDataTableEntrySize() == sizeof(LDR_DATA_TABLE_ENTRY_WIN7)) {
			auto entry = (PLDR_DATA_TABLE_ENTRY_VISTA)LdrEntry;
			NtInitializeListEntry(&entry->ForwarderLinks);
			NtInitializeListEntry(&entry->StaticLinks);
			NtInitializeListEntry(&entry->ServiceTagLinks);
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
		NtInitializeListEntry(&LdrEntry->HashLinks);
		return true;
	}
	default:return false;
	}
}
static bool NTAPI NtFreeLdrDataTableEntry(IN PLDR_DATA_TABLE_ENTRY LdrEntry) {
	switch (NtWindowsVersion()) {
	case win10:
	case win10_1:
	case win10_2:
	case win8:
	case win8_1: {
		auto entry = (PLDR_DATA_TABLE_ENTRY_WIN10)LdrEntry;
		NtFreeDependencies(entry);
		NtFreeLdrpHeap(entry->DdagNode);
		NtRemoveModuleBaseAddressIndexNode(LdrEntry);
	}
	case win7:
	case vista:
	case xp: {
		NtFreeLdrpHeap(LdrEntry->BaseDllName.Buffer);
		NtFreeLdrpHeap(LdrEntry->FullDllName.Buffer);
		RemoveEntryList(&LdrEntry->InLoadOrderLinks);
		RemoveEntryList(&LdrEntry->InMemoryOrderLinks);
		RemoveEntryList(&LdrEntry->InInitializationOrderLinks);
		RemoveEntryList(&LdrEntry->HashLinks);
		NtFreeLdrpHeap(LdrEntry);
		return true;
	}
	default:return false;
	}
}

#define FLAG_REFERENCE		0
#define FLAG_DEREFERENCE	1
static NTSTATUS NTAPI NtUpdateReferenceCount(IN OUT PLDR_DATA_TABLE_ENTRY LdrEntry, IN DWORD Flags) {
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
static NTSTATUS NTAPI NtGetReferenceCount(IN PLDR_DATA_TABLE_ENTRY LdrEntry, OUT PULONG Count) {
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

static bool NTAPI NtResolveDllNameUnicodeString(
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
	if (!(FullDllName->Buffer = (PWSTR)NtAllocateLdrpHeap(FullLength))) goto end;
	FullDllName->Length = FullLength - sizeof(wchar_t);
	FullDllName->MaximumLength = FullLength;
	wcscpy(FullDllName->Buffer, _DllFullName);

	/* Construct base DLL name */
	BaseDllName->Length = Length - sizeof(wchar_t);
	BaseDllName->MaximumLength = Length;
	BaseDllName->Buffer = (PWSTR)NtAllocateLdrpHeap(Length);
	if (!BaseDllName->Buffer) {
		NtFreeLdrpHeap(BaseDllName->Buffer);
		goto end;
	}
	wcscpy(BaseDllName->Buffer, _DllName);
	result = true;
end:
	delete[]_DllName;
	delete[]_DllFullName;
	return result;
}

static PLDR_DATA_TABLE_ENTRY NTAPI NtAllocateDataTableEntry(IN PVOID BaseAddress) {
	PLDR_DATA_TABLE_ENTRY LdrEntry = nullptr;
	PIMAGE_NT_HEADERS NtHeader;

	/* Make sure the header is valid */
	if (NtHeader = RtlImageNtHeader(BaseAddress)) {
		/* Allocate an entry */
		LdrEntry = (decltype(LdrEntry))NtAllocateLdrpHeap(NtLdrDataTableEntrySize());
	}

	/* Return the entry */
	return LdrEntry;
}

static VOID NTAPI NtInsertMemoryTableEntry(IN PLDR_DATA_TABLE_ENTRY LdrEntry) {
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

static NTSTATUS NTAPI NtMapDllMemory(IN HMEMORYMODULE ViewBase, IN DWORD dwFlags, IN PCWSTR DllName OPTIONAL,
	IN PCWSTR lpFullDllName OPTIONAL, OUT PLDR_DATA_TABLE_ENTRY* DataTableEntry OPTIONAL) {

	UNICODE_STRING FullDllName, BaseDllName;
	PIMAGE_NT_HEADERS NtHeaders;
	PLDR_DATA_TABLE_ENTRY LdrEntry;

	if (!(NtHeaders = RtlImageNtHeader(ViewBase))) return STATUS_INVALID_IMAGE_FORMAT;

	if (!(LdrEntry = NtAllocateDataTableEntry(ViewBase))) return STATUS_NO_MEMORY;

	if (!NtResolveDllNameUnicodeString(DllName, lpFullDllName, &BaseDllName, &FullDllName)) {
		NtFreeLdrpHeap(LdrEntry);
		return STATUS_NO_MEMORY;
	}

	if (!NtInitializeLdrDataTableEntry(LdrEntry, dwFlags, ViewBase, BaseDllName, FullDllName)) {
		NtFreeLdrpHeap(LdrEntry);
		NtFreeLdrpHeap(BaseDllName.Buffer);
		NtFreeLdrpHeap(FullDllName.Buffer);
		return STATUS_UNSUCCESSFUL;
	}

	NtInsertMemoryTableEntry(LdrEntry);
	if (DataTableEntry)*DataTableEntry = LdrEntry;
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtLoadDllMemory(OUT HMEMORYMODULE* BaseAddress, IN LPVOID BufferAddress, IN size_t BufferSize) {
	return NtLoadDllMemoryExW(BaseAddress, nullptr, LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS, BufferAddress, BufferSize, nullptr, nullptr);
}

NTSTATUS NTAPI NtLoadDllMemoryExW(
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
	UNREFERENCED_PARAMETER(BufferSize);

	__try {
		//ProbeForRead(BufferAddress, BufferSize);
		if (BufferSize)status = STATUS_INVALID_PARAMETER_5;
		*BaseAddress = nullptr;
		if (LdrEntry)*LdrEntry = nullptr;
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
				if (!(module = MapMemoryModuleHandle(CurEntry->DllBase)))continue;
				if ((h1->OptionalHeader.SizeOfCode == h2->OptionalHeader.SizeOfCode) &&
					(h1->OptionalHeader.SizeOfHeaders == h2->OptionalHeader.SizeOfHeaders)) {
					/* This is our entry!, update load count and return success */
					if (!module->UseReferenceCount || dwFlags & LOAD_FLAGS_NOT_USE_REFERENCE_COUNT)return STATUS_INVALID_PARAMETER_3;
					NtUpdateReferenceCount(CurEntry, FLAG_REFERENCE);
					*BaseAddress = CurEntry->DllBase;
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
	if (dwFlags & LOAD_FLAGS_NOT_MAP_DLL) return status;

	status = NtMapDllMemory(*BaseAddress, dwFlags, DllName, DllFullName, &ModuleEntry);
	if (!NT_SUCCESS(status)) {
		NtUnloadDllMemory(*BaseAddress);
		*BaseAddress = nullptr;
		return status;
	}
	module->MappedDll = true;

	if (LdrEntry)*LdrEntry = ModuleEntry;

	if (!(dwFlags & LOAD_FLAGS_NOT_USE_REFERENCE_COUNT))module->UseReferenceCount = true;

	if (!(dwFlags & LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION)) {
		status = RtlInsertInvertedFunctionTable((PVOID)module->codeBase, headers->OptionalHeader.SizeOfImage);
		if (!NT_SUCCESS(status)) {
			NtUnloadDllMemory(*BaseAddress);
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
				NtUnloadDllMemory(*BaseAddress);
				*BaseAddress = nullptr;
				if (LdrEntry)*LdrEntry = nullptr;
				return status;
			} while (false);
		}
	}

	return status;
}

NTSTATUS NTAPI NtLoadDllMemoryExA(
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
	status = NtLoadDllMemoryExW(BaseAddress, LdrEntry, dwFlags, BufferAddress, BufferSize, _DllName, _DllFullName);
	if (_DllName)delete[]_DllName;
	if (_DllFullName)delete[]_DllFullName;
	return status;
}

NTSTATUS NTAPI NtUnloadDllMemory(IN HMEMORYMODULE BaseAddress) {
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

	//Not a memory module loaded via NtLoadDllMemory
	if (!module || !module->loadFromNtLoadDllMemory)return STATUS_INVALID_HANDLE;

	//Mapping dll failed
	if (module->loadFromNtLoadDllMemory && !module->MappedDll) {
		module->underUnload = true;
		return MemoryFreeLibrary(BaseAddress) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
	}

	if (CurEntry = RtlFindLdrTableEntryByHandle(BaseAddress)) {
		if (RtlImageNtHeader(BaseAddress)->OptionalHeader.SizeOfImage == CurEntry->SizeOfImage) {
			if (module->UseReferenceCount) {
				status = NtGetReferenceCount(CurEntry, &count);
				if (!NT_SUCCESS(status))return status;
			}
			if (!(count & ~1)) {
				module->underUnload = true;
				if (module->MappedDll) {
					if (module->InsertInvertedFunctionTableEntry) {
						status = RtlRemoveInvertedFunctionTable(BaseAddress);
						if (!NT_SUCCESS(status))__fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
					}
					if (!NtFreeLdrDataTableEntry(CurEntry))__fastfail(FAST_FAIL_FATAL_APP_EXIT);
				}
				if (!MemoryFreeLibrary(BaseAddress))__fastfail(FAST_FAIL_FATAL_APP_EXIT);
				return STATUS_SUCCESS;
			}
			else {
				return NtUpdateReferenceCount(CurEntry, FLAG_DEREFERENCE);
			}
		}
	}

	return STATUS_INVALID_HANDLE;
}

VOID NTAPI NtUnloadDllMemoryAndExitThread(IN HMEMORYMODULE BaseAddress, IN DWORD dwExitCode) {
	NtUnloadDllMemory(BaseAddress);
	RtlExitUserThread(dwExitCode);
}




/*
	NT functions
*/
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

static VOID NTAPI RtlpInsertInvertedFunctionTable(IN PRTL_INVERTED_FUNCTION_TABLE InvertedTable, IN PVOID ImageBase, IN ULONG SizeOfImage) {
#ifdef _WIN64
	ULONG CurrentSize;
	PIMAGE_RUNTIME_FUNCTION_ENTRY FunctionTable;
	ULONG Index;
	ULONG SizeOfTable = 0;
	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(ImageBase);
	PIMAGE_DATA_DIRECTORY dir = &headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	bool need = RtlIsWindowsVersionOrGreater(6, 2, 0);

	Index = (ULONG)need;
	CurrentSize = InvertedTable->Count;
	if (CurrentSize != InvertedTable->MaxCount) {
		//if (need)_InterlockedIncrement(&InvertedTable->Epoch);
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

		FunctionTable = (decltype(FunctionTable))((size_t)ImageBase + dir->VirtualAddress);
		if (FunctionTable != RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &SizeOfTable) || SizeOfTable != dir->Size) {
			__fastfail(STATUS_BAD_DATA);
		}
		//SizeOfTable = dir->Size;

		InvertedTable->Entries[Index].ExceptionDirectory = FunctionTable;
		InvertedTable->Entries[Index].ImageBase = ImageBase;
		InvertedTable->Entries[Index].ImageSize = SizeOfImage;
		InvertedTable->Entries[Index].ExceptionDirectorySize = SizeOfTable;
		InvertedTable->Count++;
		//if (need)_InterlockedIncrement(&InvertedTable->Epoch);
	}
	else {
		need ? (InvertedTable->Overflow = TRUE) : (InvertedTable->Epoch = TRUE);
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
#ifdef _WIN64
		//InvertedTable->Overflow = FALSE;
#else
		if (IsWin8OrGreater) {
			InvertedTable->NextEntrySEHandlerTableEncoded = FALSE;
		}
		else {
			InvertedTable->Overflow = FALSE;
		}
#endif
	}

	return;
}

typedef struct _SEARCH_CONTEXT {
	union {
		IN PVOID  MemoryBuffer;
		size_t InBufferPtr;
	};
	union {
		IN DWORD BufferLength;
		size_t reserved0;
	};

	union {
		OUT PVOID  MemoryBlockInSection;
		size_t OutBufferPtr;
	};
	union {
		DWORD RemainingLength;
		size_t reserved1;
	};
}SEARCH_CONTEXT, * PSEARCH_CONTEXT;
static NTSTATUS NTAPI RtlFindMemoryBlockFromModuleSection(
	IN HMODULE hModule	OPTIONAL,
	IN LPCSTR lpSectionName	OPTIONAL,
	IN OUT PSEARCH_CONTEXT SearchContext) {

	NTSTATUS status = STATUS_SUCCESS;
	size_t begin = 0, buffer = 0;
	DWORD Length = 0, bufferLength = 0;

	__try {
		begin = SearchContext->OutBufferPtr;
		Length = SearchContext->RemainingLength;
		buffer = SearchContext->InBufferPtr;
		bufferLength = SearchContext->BufferLength;
		if (!buffer || !bufferLength) {
			SearchContext->OutBufferPtr = 0;
			SearchContext->RemainingLength = 0;
			return STATUS_INVALID_PARAMETER;
		}
		if (!begin) {
			PIMAGE_NT_HEADERS headers = RtlImageNtHeader(hModule);
			PIMAGE_SECTION_HEADER section = nullptr;
			if (!headers)return STATUS_INVALID_PARAMETER_1;
			section = IMAGE_FIRST_SECTION(headers);
			for (WORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
				if (!_stricmp(lpSectionName, (LPCSTR)section->Name)) {
					begin = SearchContext->OutBufferPtr = (size_t)hModule + section->VirtualAddress;
					Length = SearchContext->RemainingLength = section->SizeOfRawData;
					break;
				}
				++section;
			}
			if (!begin || !Length || Length < bufferLength) {
				SearchContext->OutBufferPtr = 0;
				SearchContext->RemainingLength = 0;
				return STATUS_NOT_FOUND;
			}
		}
		else {
			begin++;
			Length--;
		}
		status = STATUS_NOT_FOUND;
		for (DWORD i = 0; i < Length - bufferLength; ++begin, ++i) {
			if (RtlCompareMemory((PVOID)begin, (PVOID)buffer, bufferLength) == bufferLength) {
				SearchContext->OutBufferPtr = begin;
				SearchContext->RemainingLength -= i;
				return STATUS_SUCCESS;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}

	SearchContext->OutBufferPtr = 0;
	SearchContext->RemainingLength = 0;
	return status;
}

static __forceinline bool NTAPI RtlIsModuleUnloaded(PLDR_DATA_TABLE_ENTRY entry) {
	if (RtlIsWindowsVersionOrGreater(6, 2, 0)) {
		return PLDR_DATA_TABLE_ENTRY_WIN8(entry)->DdagNode->State == LdrModulesUnloaded;
	}
	else {
		return entry->DllBase == nullptr;
	}	
}
static PVOID FindLdrpInvertedFunctionTable32() {
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
	
	if (RtlIsWindowsVersionOrGreater(10, 0, 0)) lpSectionName = ".mrdata";
	else if (!RtlIsWindowsVersionOrGreater(6, 2, 0)) Offset = 0xC;
	
	while (ListEntry != ListHead) {
		CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		ListEntry = ListEntry->Flink;
		if (RtlIsModuleUnloaded(CurEntry))continue;					//skip unloaded module
		if (IsValidMemoryModuleHandle(CurEntry->DllBase))continue;  //skip our memory module.
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
static PVOID FindLdrpInvertedFunctionTable64() {
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
			if (IsValidMemoryModuleHandle(CurEntry->DllBase))continue;
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
#ifdef _WIN64
#define FindLdrpInvertedFunctionTable FindLdrpInvertedFunctionTable64
#else
#define FindLdrpInvertedFunctionTable FindLdrpInvertedFunctionTable32
#endif

static PVOID NTAPI RtlFindLdrpInvertedFunctionTable() {
	static PVOID LdrpInvertedFunctionTable = FindLdrpInvertedFunctionTable();
	return LdrpInvertedFunctionTable;
}
static NTSTATUS NTAPI RtlProtectMrdata(IN SIZE_T Protect) {
	static PVOID MrdataBase = nullptr;
	static SIZE_T size = 0;
	NTSTATUS status;
	PVOID tmp;
	SIZE_T tmp_len;
	SIZE_T old;

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
	bool need_virtual_protect = RtlIsWindowsVersionOrGreater(8, 3, 0);
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

#ifdef _WIN64
	if (RtlIsWindowsVersionOrGreater(6, 2, 0)) return table->Overflow ? STATUS_INVALID_ADDRESS : STATUS_SUCCESS;
	else return table->Epoch ? STATUS_INVALID_ADDRESS : STATUS_SUCCESS;
#else
	return (need_virtual_protect ? table->NextEntrySEHandlerTableEncoded : table->Overflow) ? STATUS_INVALID_ADDRESS : STATUS_SUCCESS;
#endif
}
NTSTATUS NTAPI RtlRemoveInvertedFunctionTable(IN PVOID ImageBase) {
	static auto table = PRTL_INVERTED_FUNCTION_TABLE(RtlFindLdrpInvertedFunctionTable());
	bool need_virtual_protect = RtlIsWindowsVersionOrGreater(10, 0, 0);
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

static NTSTATUS NTAPI LdrpHandleTlsDataXp(PLDR_DATA_TABLE_ENTRY LdrEntry) {
	return STATUS_NOT_SUPPORTED;
}
static NTSTATUS NTAPI RtlFindLdrpHandleTlsData(PVOID* _LdrpHandleTlsData, bool* stdcall) {
	NTSTATUS status = STATUS_SUCCESS;
	__try {
		*_LdrpHandleTlsData = nullptr;
		*stdcall = false;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}
	if (!NT_SUCCESS(status))return status;

	DWORD Versions[3]{};
	LPCVOID Feature = nullptr;
	BYTE Size = 0;
	WORD OffsetOfFunctionBegin = 0;
	RtlGetNtVersionNumbers(Versions, Versions + 1, Versions + 2);
	switch (Versions[0]) {
	case 10: {
		if (Versions[1])return STATUS_NOT_SUPPORTED;

		//RS3
		if (Versions[2] >= 16299) {
			Size = 7;
			//19H2
			if (Versions[2] >= 18363)Feature = "\x74\x33\x44\x8D\x43\x09";
			//RS5
			else if (Versions[2] >= 17763) Feature = "\x8b\xc1\x8d\x4d\xbc\x51";
			//RS4
			else if (Versions[2] >= 17134) Feature = "\x33\xf6\x85\xc0\x79\x03";
			//RS3
			else Feature = "\x8b\xc1\x8d\x4d\xac\x51";
#ifdef _WIN64
			//RS6(19H1)
			if (Versions[2] >= 18362) OffsetOfFunctionBegin = 0x46;
			//RS4
			else if (Versions[2] >= 17134) OffsetOfFunctionBegin = 0x44;
			//RS3
			else OffsetOfFunctionBegin = 0x43;
#else
			//19H2
			if (Versions[2] == 18363) {
				Feature = "\x74\x25\x8b\xc1\x8d\x4d\xbc";
				OffsetOfFunctionBegin = 0x16;
			}
			//RS6(19H1)
			else if (Versions[2] == 18362) OffsetOfFunctionBegin = 0x2E;
			//RS5
			else if (Versions[2] >= 17763) OffsetOfFunctionBegin = 0x2C;
			//RS3,4
			else OffsetOfFunctionBegin = 0x18;
#endif
			break;
		}
		//RS2
		else if (Versions[2] >= 15063) {
			Size = 7;
#ifdef _WIN64
			OffsetOfFunctionBegin = 0x43;
			Feature = "\x74\x33\x44\x8d\x43\x09";
#else
			OffsetOfFunctionBegin = 0x18;
			Feature = "\x8b\xc1\x8d\x4d\xbc\x51";
#endif
			break;
		}

		// NO BREAK
	}
	case 6: {
		switch (Versions[1]) {
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
		*_LdrpHandleTlsData = LdrpHandleTlsDataXp;
		*stdcall = true;
		return status;
	}
	}

	SEARCH_CONTEXT SearchContext{ SearchContext.MemoryBuffer = const_cast<PVOID>(Feature),SearchContext.BufferLength = Size - 1 };
	if (NT_SUCCESS(RtlFindMemoryBlockFromModuleSection(GetModuleHandleW(L"ntdll.dll"), ".text", &SearchContext)))
		SearchContext.OutBufferPtr -= OffsetOfFunctionBegin;
	if (!(*_LdrpHandleTlsData = SearchContext.MemoryBlockInSection))return STATUS_NOT_SUPPORTED;
	*stdcall = !RtlIsWindowsVersionOrGreater(6, 3, 0);
	return status;
}
NTSTATUS NTAPI LdrpHandleTlsData(IN PLDR_DATA_TABLE_ENTRY LdrEntry) {
	typedef NTSTATUS(__thiscall* _PTR_WIN8_1)(PLDR_DATA_TABLE_ENTRY LdrEntry);
	typedef NTSTATUS(__stdcall* _PTR_WIN)(PLDR_DATA_TABLE_ENTRY LdrEntry);
	union _FUNCTION_SET {
		_PTR_WIN8_1 Win8_1_OrGreater;
		_PTR_WIN	Default;
		_FUNCTION_SET() {
			this->Default = nullptr;
		}
		operator bool() {
			return this->Default != nullptr;
		}
	};
	static _FUNCTION_SET _LdrpHandleTlsData{};
	static bool stdcall = false;
	NTSTATUS status;
	if (!_LdrpHandleTlsData) {
		status = RtlFindLdrpHandleTlsData((PVOID*)&_LdrpHandleTlsData.Default, &stdcall);
		if (!NT_SUCCESS(status))return status;
	}
	return stdcall ? _LdrpHandleTlsData.Default(LdrEntry) : _LdrpHandleTlsData.Win8_1_OrGreater(LdrEntry);
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

#define MEMORY_FEATURE_SUPPORT_VERSION				0x00000001
#define MEMORY_FEATURE_MODULE_BASEADDRESS_INDEX		0x00000002
#define MEMORY_FEATURE_LDRP_HEAP					0x00000004
#define MEMORY_FEATURE_LDRP_HASH_TABLE				0x00000008
#define MEMORY_FEATURE_INVERTED_FUNCTION_TABLE		0x00000010
#define MEMORY_FEATURE_LDRP_HANDLE_TLS_DATA			0x00000020
NTSTATUS NTAPI NtQuerySystemMemoryModuleFeatures(OUT PDWORD pFeatures) {
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
		if (RtlFindtLdrpHeap())features |= MEMORY_FEATURE_LDRP_HEAP;
		if (RtlFindLdrpHashTable())features |= MEMORY_FEATURE_LDRP_HASH_TABLE;
		if (RtlFindLdrpInvertedFunctionTable())features |= MEMORY_FEATURE_INVERTED_FUNCTION_TABLE;
		if (NT_SUCCESS(RtlFindLdrpHandleTlsData(&pfn, &value)) && pfn)features |= MEMORY_FEATURE_LDRP_HANDLE_TLS_DATA;

		if (features)features |= MEMORY_FEATURE_SUPPORT_VERSION;
		*pFeatures = features;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}
	return status;
}

#ifndef _WIN64
#undef RtlCompareMemory
#endif
#undef FindLdrpInvertedFunctionTable
