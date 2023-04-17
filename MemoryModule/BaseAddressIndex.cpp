#include "stdafx.h"

VOID NTAPI RtlRbInsertNodeEx(
	_In_ PRTL_RB_TREE Tree,
	_In_ PRTL_BALANCED_NODE Parent,
	_In_ BOOLEAN Right,
	_Out_ PRTL_BALANCED_NODE Node) {
	RtlZeroMemory(Node, sizeof(*Node));

	if (!MmpGlobalDataPtr->MmpBaseAddressIndex->_RtlRbInsertNodeEx)return;
	return decltype(&RtlRbInsertNodeEx)(MmpGlobalDataPtr->MmpBaseAddressIndex->_RtlRbInsertNodeEx)(Tree, Parent, Right, Node);
}

VOID NTAPI RtlRbRemoveNode(
	_In_ PRTL_RB_TREE Tree,
	_In_ PRTL_BALANCED_NODE Node) {
	if (!MmpGlobalDataPtr->MmpBaseAddressIndex->_RtlRbRemoveNode)return;
	return decltype(&RtlRbRemoveNode)(MmpGlobalDataPtr->MmpBaseAddressIndex->_RtlRbRemoveNode)(Tree, Node);
}

NTSTATUS NTAPI RtlInsertModuleBaseAddressIndexNode(
	_In_ PLDR_DATA_TABLE_ENTRY DataTableEntry,
	_In_ PVOID BaseAddress) {
	auto LdrpModuleBaseAddressIndex = MmpGlobalDataPtr->MmpBaseAddressIndex->LdrpModuleBaseAddressIndex;
	if (!LdrpModuleBaseAddressIndex)return STATUS_UNSUCCESSFUL;

	PLDR_DATA_TABLE_ENTRY_WIN8 LdrNode = CONTAINING_RECORD(LdrpModuleBaseAddressIndex->Root, LDR_DATA_TABLE_ENTRY_WIN8, BaseAddressIndexNode);
	bool bRight = false;

	while (true) {
		if (BaseAddress < LdrNode->DllBase) {
			if (!LdrNode->BaseAddressIndexNode.Left)break;
			LdrNode = CONTAINING_RECORD(LdrNode->BaseAddressIndexNode.Left, LDR_DATA_TABLE_ENTRY_WIN8, BaseAddressIndexNode);
		}
		else if (BaseAddress > LdrNode->DllBase) {
			if (!LdrNode->BaseAddressIndexNode.Right) {
				bRight = true;
				break;
			}
			LdrNode = CONTAINING_RECORD(LdrNode->BaseAddressIndexNode.Right, LDR_DATA_TABLE_ENTRY_WIN8, BaseAddressIndexNode);
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

NTSTATUS NTAPI RtlRemoveModuleBaseAddressIndexNode(_In_ PLDR_DATA_TABLE_ENTRY DataTableEntry) {
	RtlRbRemoveNode(MmpGlobalDataPtr->MmpBaseAddressIndex->LdrpModuleBaseAddressIndex, &PLDR_DATA_TABLE_ENTRY_WIN8(DataTableEntry)->BaseAddressIndexNode);
	return STATUS_SUCCESS;
}
