#include "stdafx.h"
#pragma warning(disable:4996)

PLDR_DATA_TABLE_ENTRY const LdrpNtdllBase = RtlFindLdrTableEntryByBaseName(L"ntdll.dll");

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



ULONG NTAPI LdrHashEntry(IN const UNICODE_STRING& str, IN bool _xor) {
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

HANDLE NTAPI RtlFindLdrpHeap() {
	return RtlProcessHeap();
}

PLIST_ENTRY NTAPI RtlFindLdrpHashTable() {
	static PLIST_ENTRY list = nullptr;
	if (list) return list;

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

PVOID NTAPI RtlAllocateLdrpHeap(IN size_t size) {
	HANDLE heap = RtlFindLdrpHeap();
	if (!heap)return nullptr;

	return RtlAllocateHeap(heap, HEAP_ZERO_MEMORY, size);
}

BOOL NTAPI RtlFreeLdrpHeap(IN PVOID buffer) {
	HANDLE LdrpHeap = RtlFindLdrpHeap();
	if (!LdrpHeap)return FALSE;
	return RtlFreeHeap(LdrpHeap, 0, buffer);
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

