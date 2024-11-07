#pragma once

BOOL NTAPI MmpTlsInitialize();

VOID NTAPI MmpTlsCleanup();

NTSTATUS NTAPI MmpReleaseTlsEntry(_In_ PLDR_DATA_TABLE_ENTRY lpModuleEntry);

NTSTATUS NTAPI MmpHandleTlsData(_In_ PLDR_DATA_TABLE_ENTRY lpModuleEntry);
