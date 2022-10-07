#pragma once

NTSTATUS NTAPI RtlInsertModuleBaseAddressIndexNode(
	_In_ PLDR_DATA_TABLE_ENTRY DataTableEntry,
	_In_ PVOID BaseAddress
);

NTSTATUS NTAPI RtlRemoveModuleBaseAddressIndexNode(_In_ PLDR_DATA_TABLE_ENTRY DataTableEntry);
