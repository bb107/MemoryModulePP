#include "stdafx.h"

// MmpTls.cpp
NTSTATUS NTAPI MmpReleaseTlsEntry(_In_ PLDR_DATA_TABLE_ENTRY lpModuleEntry);

// MmpTls.cpp
NTSTATUS NTAPI MmpHandleTlsData(_In_ PLDR_DATA_TABLE_ENTRY lpModuleEntry);

NTSTATUS NTAPI LdrpHandleTlsData(IN PLDR_DATA_TABLE_ENTRY LdrEntry) {
	return MmpHandleTlsData(LdrEntry);
}

NTSTATUS NTAPI LdrpReleaseTlsEntry(IN PLDR_DATA_TABLE_ENTRY LdrEntry) {
	return MmpReleaseTlsEntry(LdrEntry);
}
