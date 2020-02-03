#include "NativeFunctionsInternal.h"
#include <random>
#pragma warning(disable:6328)
#pragma warning(disable:4267)
#pragma warning(disable:26812)

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
	DWORD Versions[3];
	RtlGetNtVersionNumbers(Versions, Versions + 1, Versions + 2);
	if (Versions[0] == MajorVersion) {
		if (Versions[1] == MinorVersion) return Versions[2] >= BuildNumber;
		else return (Versions[1] > MinorVersion);
	}
	else return Versions[0] > MajorVersion;
}

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
	static HANDLE result = nullptr;
	DWORD dwHeaps = 0;
	HANDLE* hHeaps = nullptr;

	if (result)return result;
	dwHeaps = GetProcessHeaps(dwHeaps, hHeaps);
	hHeaps = new HANDLE[dwHeaps];
	ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
	ListEntry = ListHead->Flink;
	if (ListHead == ListEntry)return nullptr;
	CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
	GetProcessHeaps(dwHeaps, hHeaps);
	for (DWORD i = 0; i < dwHeaps; ++i) {
		if (HeapValidate(hHeaps[i], 0, CurEntry)) {
			result = hHeaps[i];
			break;
		}
	}
	delete[]hHeaps;
	return result;
}
static PLDR_DATA_TABLE_ENTRY NTAPI RtlFindNtdllLdrEntry() {
	PLIST_ENTRY ListHead, ListEntry;
	static PLDR_DATA_TABLE_ENTRY CurEntry = nullptr;
	if (CurEntry)return CurEntry;

	ListHead = &NtCurrentPeb()->Ldr->InInitializationOrderModuleList;
	ListEntry = ListHead->Flink;
	while (ListHead != ListEntry) {
		CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
		ListEntry = ListEntry->Flink;
		if (0 == wcsnicmp(CurEntry->BaseDllName.Buffer, L"ntdll.dll", CurEntry->BaseDllName.Length))
			return CurEntry;
	}

	return CurEntry = nullptr;
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
	auto LdrpModuleBaseAddressIndex = RtlFindLdrpModuleBaseAddressIndex();
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
	RTL_RB_TREE tree{ RtlFindLdrpModuleBaseAddressIndex() };
	if (!tree.Root)return STATUS_UNSUCCESSFUL;

	RtlRbRemoveNode(&tree, &PLDR_DATA_TABLE_ENTRY_WIN8(DataTableEntry)->BaseAddressIndexNode);
	return STATUS_SUCCESS;
}

static bool NTAPI NtInitializeLdrDataTableEntry(
	OUT PLDR_DATA_TABLE_ENTRY LdrEntry,
	IN PVOID BaseAddress,
	IN ULONG SizeofImage,
	IN DWORD TimeDateStamp,
	IN UNICODE_STRING &DllBaseName,
	IN UNICODE_STRING &DllFullName,
	IN PVOID EntryPoint) {

	RtlZeroMemory(LdrEntry, NtLdrDataTableEntrySize());
	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(BaseAddress);

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
		
		entry->OriginalBase = headers->OptionalHeader.ImageBase;
		entry->BaseNameHashValue = LdrHashEntry(DllBaseName, false);
		entry->LoadReason = LoadReasonDynamicLoad;
		if (!NT_SUCCESS(NtInsertModuleBaseAddressIndexNode(LdrEntry, BaseAddress)))return false;
		if (!(entry->DdagNode = (decltype(entry->DdagNode))NtAllocateLdrpHeap(sizeof(_LDR_DDAG_NODE))))return false;
		NtInitializeListEntry(&entry->NodeModuleLink);
		NtInitializeListEntry(&entry->DdagNode->Modules);
		NtInitializeSingleEntry(&entry->DdagNode->CondenseLink);
		entry->DdagNode->State = LdrModulesReadyToRun;
		entry->DdagNode->LoadCount = 0;
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
		LdrEntry->SizeOfImage = SizeofImage;
		LdrEntry->TimeDateStamp = TimeDateStamp;
		LdrEntry->BaseDllName = DllBaseName;
		LdrEntry->FullDllName = DllFullName;
		LdrEntry->EntryPoint = EntryPoint;
		if (headers->OptionalHeader.DllCharacteristics & IMAGE_FILE_DLL)LdrEntry->Flags |= LDRP_IMAGE_DLL;
		return true;
	}
	default:return false;
	}
}
static bool NTAPI NtFreeLdrDataTableEntry(IN PLDR_DATA_TABLE_ENTRY LdrEntry) {
	switch (NtWindowsVersion()) {
	case win10:
	case win10_1:
	case win10_2: {
		auto entry = (PLDR_DATA_TABLE_ENTRY_WIN10)LdrEntry;
		NtFreeLdrpHeap(entry->DdagNode);
	}
	case win8:
	case win8_1: {
		NtRemoveModuleBaseAddressIndexNode(LdrEntry);
	}
	case win7:
	case vista:
	case xp: {
		NtFreeLdrpHeap(LdrEntry->BaseDllName.Buffer);
		NtFreeLdrpHeap(LdrEntry->FullDllName.Buffer);
		RemoveEntryList(&LdrEntry->InLoadOrderLinks);
		RemoveEntryList(&LdrEntry->InMemoryOrderLinks);
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
}

static NTSTATUS NTAPI NtMapDllMemory(IN HMEMORYMODULE ViewBase, IN PCWSTR DllName OPTIONAL,
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

	if (!NtInitializeLdrDataTableEntry(LdrEntry, ViewBase,
		NtHeaders->OptionalHeader.SizeOfImage,
		NtHeaders->FileHeader.TimeDateStamp,
		BaseDllName, FullDllName,
		(PVOID)(NtHeaders->OptionalHeader.AddressOfEntryPoint + NtHeaders->OptionalHeader.ImageBase))) {
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
	return NtLoadDllMemoryExW(BaseAddress, nullptr, 0, BufferAddress, BufferSize, nullptr, nullptr);
}

NTSTATUS NTAPI NtLoadDllMemoryExW(
	OUT HMEMORYMODULE* BaseAddress,
	OUT PLDR_DATA_TABLE_ENTRY* LdrEntry OPTIONAL,
	IN DWORD dwFlags,
	IN LPVOID BufferAddress,
	IN size_t BufferSize,
	IN LPCWSTR DllName OPTIONAL,
	IN LPCWSTR DllFullName OPTIONAL) {
	if (IsBadReadPtr(BufferAddress, BufferSize) || IsBadWritePtr(BaseAddress, sizeof(HMEMORYMODULE)))return STATUS_ACCESS_VIOLATION;
	*BaseAddress = nullptr;
	PMEMORYMODULE module = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

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
					return STATUS_SUCCESS;
				}
			}
		}
	}

	if (!(*BaseAddress = MemoryLoadLibrary(BufferAddress, BufferSize))) {
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
		__fastfail(STATUS_INVALID_ADDRESS);
		return STATUS_INVALID_ADDRESS;
	}
	module->loadFromNtLoadDllMemory = true;
	if (dwFlags & LOAD_FLAGS_NOT_MAP_DLL) return STATUS_SUCCESS;
	status = NtMapDllMemory(*BaseAddress, DllName, DllFullName, LdrEntry);
	if (!NT_SUCCESS(status)) {
		NtUnloadDllMemory(*BaseAddress);
		*BaseAddress = nullptr;
		return status;
	}
	module->MappedDll = true;
	if (!(dwFlags & LOAD_FLAGS_NOT_USE_REFERENCE_COUNT))module->UseReferenceCount = true;
	if (dwFlags & LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION)return STATUS_SUCCESS;
	status = RtlInsertInvertedFunctionTable((PVOID)module->codeBase, RtlImageNtHeader(*BaseAddress)->OptionalHeader.SizeOfImage);
	if (!NT_SUCCESS(status)) {
		NtUnloadDllMemory(*BaseAddress);
		*BaseAddress = nullptr;
		return status;
	}
	module->InsertInvertedFunctionTableEntry = true;
	return STATUS_SUCCESS;
}

NTSTATUS NtLoadDllMemoryExA(
	OUT HMEMORYMODULE* BaseAddress,
	OUT PLDR_DATA_TABLE_ENTRY* LdrEntry OPTIONAL,
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
	if (IsBadReadPtr(BaseAddress, sizeof(size_t)))return STATUS_ACCESS_VIOLATION;
	
	PLIST_ENTRY ListHead, ListEntry;
	PLDR_DATA_TABLE_ENTRY CurEntry;
	ULONG count = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PMEMORYMODULE module = MapMemoryModuleHandle(BaseAddress);

	if (!module || !module->loadFromNtLoadDllMemory)return STATUS_INVALID_HANDLE;
	ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
	ListEntry = ListHead->Flink;
	while (ListEntry != ListHead) {
		CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		ListEntry = ListEntry->Flink;
		/* Check if it's being unloaded */
		if (!CurEntry->InMemoryOrderLinks.Flink) continue;
		/* Check if name matches */
		if (CurEntry->DllBase == BaseAddress) {
			if (RtlImageNtHeader(BaseAddress)->OptionalHeader.SizeOfImage == CurEntry->SizeOfImage) {
				if (module->UseReferenceCount) {
					status = NtGetReferenceCount(CurEntry, &count);
					if (!NT_SUCCESS(status))return status;
				}
				if (!count) {
					module->underUnload = true;
					if (module->MappedDll) {
						if (module->InsertInvertedFunctionTableEntry) {
							status = RtlRemoveInvertedFunctionTable(BaseAddress);
							if (!NT_SUCCESS(status))__fastfail(status);
						}
						if (!NtFreeLdrDataTableEntry(CurEntry))__fastfail(STATUS_NOT_SUPPORTED);
					}
					if (!MemoryFreeLibrary(BaseAddress))__fastfail(STATUS_UNSUCCESSFUL);
					return STATUS_SUCCESS;
				}
				else {
					return NtUpdateReferenceCount(CurEntry, FLAG_DEREFERENCE);
				}
			}
		}
	}

	return STATUS_INVALID_HANDLE;
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
	ULONG CurrentSize;
	PRUNTIME_FUNCTION FunctionTable;
	ULONG Index = 1;
	ULONG SizeOfTable = 0;
	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(ImageBase);
	PIMAGE_DATA_DIRECTORY dir = &headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	bool need = RtlIsWindowsVersionOrGreater(10, 0, 0);

	Index = (ULONG)need;
	CurrentSize = InvertedTable->Count;
	if (CurrentSize != InvertedTable->MaxCount) {
		if (need)_InterlockedIncrement(&InvertedTable->Epoch);
		if (CurrentSize != 0) {
			for (Index = 1; Index < CurrentSize; ++Index) {
				if (ImageBase < InvertedTable->Entries[Index].ImageBase) {
					break;
				}
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
		if (need)_InterlockedIncrement(&InvertedTable->Epoch);
	}
	else {
		need ? (InvertedTable->Overflow = TRUE) : (InvertedTable->Epoch = TRUE);
	}

	return;
}
static VOID NTAPI RtlpRemoveInvertedFunctionTable(IN PRTL_INVERTED_FUNCTION_TABLE InvertedTable, IN PVOID ImageBase) {
	ULONG CurrentSize;
	ULONG Index;
	bool need = RtlIsWindowsVersionOrGreater(6, 2, 0);

	CurrentSize = InvertedTable->Count;
	for (Index = 0; Index < CurrentSize; Index += 1) {
		if (ImageBase == InvertedTable->Entries[Index].ImageBase) {
			break;
		}
	}

	if (Index != CurrentSize) {
		if (need)_InterlockedIncrement(&InvertedTable->Epoch);
		if (CurrentSize != 1) {
			RtlMoveMemory(&InvertedTable->Entries[Index],
				&InvertedTable->Entries[Index + 1],
				(CurrentSize - Index - 1) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY));
		}
		InvertedTable->Count -= 1;
		if (need)_InterlockedIncrement(&InvertedTable->Epoch);
	}

	return;
}

static PVOID NTAPI RtlFindLdrpInvertedFunctionTable() {
	static PVOID LdrpInvertedFunctionTable = nullptr;
	if (LdrpInvertedFunctionTable)return LdrpInvertedFunctionTable;

	// _RTL_INVERTED_FUNCTION_TABLE						x64		x86
	//		Count										+0x0	+0x0	????????
	//		MaxCount									+0x4	+0x4	0x00000200
	//		Epoch										+0x8	+0x8	????????
	//		OverFlow									+0xc	+0xc	0x00000000
	// _RTL_INVERTED_FUNCTION_TABLE_ENTRY[0]			+0x10	+0x10	ntdll.dll(win10) or The smallest base module
	//		ExceptionDirectory							+0x10	+0x10	++++++++
	//		ImageBase									+0x18	+0x14	++++++++
	//		ImageSize									+0x20	+0x18	++++++++
	//		ExceptionDirectorySize						+0x24	+0x1c	++++++++
	//	_RTL_INVERTED_FUNCTION_TABLE_ENTRY[1] ...		...		...
	// ......

	HMODULE hModule = nullptr, hNtdll = GetModuleHandleW(L"ntdll.dll");
	PIMAGE_NT_HEADERS NtdllHeaders = RtlImageNtHeader(hNtdll), ModuleHeaders = nullptr;
	_RTL_INVERTED_FUNCTION_TABLE_ENTRY entry{};
	PIMAGE_DATA_DIRECTORY dir = nullptr;
	LPCSTR lpSectionName = ".data";
	PIMAGE_SECTION_HEADER section = nullptr;
	struct _SEARCH_DATA {
		PVOID BaseAddress;
		DWORD Size;
		bool operator!() {
			return !BaseAddress || !Size;
		}
		PVOID operator++() {
			(*(size_t*)&BaseAddress)++;
			return BaseAddress;
		}
		PVOID operator+=(size_t size) {
			(*(size_t*)&BaseAddress) += size;
			return BaseAddress;
		}
	}data{};
	const auto EntrySize = sizeof(entry);

	if (RtlIsWindowsVersionOrGreater(10, 0, 0)) {
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
			hModule = (HMODULE)(hModule ? min(hModule, CurEntry->DllBase) : CurEntry->DllBase);
		}
		ModuleHeaders = RtlImageNtHeader(hModule);
	}

	if (!hModule || !ModuleHeaders || !hNtdll || !NtdllHeaders)return LdrpInvertedFunctionTable;
	dir = &ModuleHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	entry = {
		dir->Size ? decltype(entry.ExceptionDirectory)((size_t)hModule + dir->VirtualAddress) : nullptr ,
		(PVOID)hModule, ModuleHeaders->OptionalHeader.SizeOfImage,dir->Size
	};
	section = IMAGE_FIRST_SECTION(NtdllHeaders);
	for (WORD i = 0; i < NtdllHeaders->FileHeader.NumberOfSections; ++i) {
		if (!_stricmp(lpSectionName, (LPCSTR)section->Name)) {
			data = { (PVOID)((size_t)hNtdll + section->VirtualAddress),section->SizeOfRawData };
			break;
		}
		++section;
	}
	if (!data || IsBadReadPtr(data.BaseAddress, data.Size))return LdrpInvertedFunctionTable;

	while (data.Size && (data.Size - EntrySize)) {
		if (RtlCompareMemory(data.BaseAddress, &entry, EntrySize) == EntrySize) {
			PRTL_INVERTED_FUNCTION_TABLE tab = decltype(tab)((size_t)data.BaseAddress - 0x10);
			if (RtlIsWindowsVersionOrGreater(6, 2, 0) && tab->MaxCount == 0x200 && !tab->Overflow) {
				return LdrpInvertedFunctionTable = tab;
			}
			else {
				if (tab->MaxCount == 0x200 && !tab->Epoch)
					return LdrpInvertedFunctionTable = tab;
			}
		}
		++data;
		--data.Size;
	}

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
	bool need_virtual_protect = RtlIsWindowsVersionOrGreater(10, 0, 0);
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

	if (RtlIsWindowsVersionOrGreater(6, 2, 0)) return table->Overflow ? STATUS_INVALID_ADDRESS : STATUS_SUCCESS;
	else return table->Epoch ? STATUS_INVALID_ADDRESS : STATUS_SUCCESS;
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
