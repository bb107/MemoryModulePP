#include "stdafx.h"

NTSTATUS NTAPI RtlInsertModuleBaseAddressIndexNode(IN PLDR_DATA_TABLE_ENTRY DataTableEntry, IN PVOID BaseAddress) {
	auto LdrpModuleBaseAddressIndex = MmpGlobalDataPtr->LdrpModuleBaseAddressIndex;
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
	static auto tree{ MmpGlobalDataPtr->LdrpModuleBaseAddressIndex };
	if (!tree->Root)return STATUS_UNSUCCESSFUL;
	RtlRbRemoveNode(tree, &PLDR_DATA_TABLE_ENTRY_WIN8(DataTableEntry)->BaseAddressIndexNode);
	return STATUS_SUCCESS;
}
