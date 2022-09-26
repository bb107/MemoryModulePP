#pragma once

NTSTATUS NTAPI MmpReleaseTlsEntry(PLDR_DATA_TABLE_ENTRY lpModuleEntry);

NTSTATUS NTAPI MmpHandleTlsData(PLDR_DATA_TABLE_ENTRY lpModuleEntry);
