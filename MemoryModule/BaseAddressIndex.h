#pragma once

PRTL_RB_TREE NTAPI RtlFindLdrpModuleBaseAddressIndex();

NTSTATUS NTAPI RtlInsertModuleBaseAddressIndexNode(IN PLDR_DATA_TABLE_ENTRY DataTableEntry, IN PVOID BaseAddress);

NTSTATUS NTAPI RtlRemoveModuleBaseAddressIndexNode(IN PLDR_DATA_TABLE_ENTRY DataTableEntry);
