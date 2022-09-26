#include "stdafx.h"

PRTL_RB_TREE NTAPI RtlFindLdrpModuleBaseAddressIndex() {
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

NTSTATUS NTAPI RtlInsertModuleBaseAddressIndexNode(IN PLDR_DATA_TABLE_ENTRY DataTableEntry, IN PVOID BaseAddress) {
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

NTSTATUS NTAPI RtlRemoveModuleBaseAddressIndexNode(IN PLDR_DATA_TABLE_ENTRY DataTableEntry) {
	static auto tree{ RtlFindLdrpModuleBaseAddressIndex() };
	if (!tree->Root)return STATUS_UNSUCCESSFUL;
	RtlRbRemoveNode(tree, &PLDR_DATA_TABLE_ENTRY_WIN8(DataTableEntry)->BaseAddressIndexNode);
	return STATUS_SUCCESS;
}
