#pragma once

NTSTATUS NTAPI LdrpHandleTlsData(IN PLDR_DATA_TABLE_ENTRY LdrEntry);

NTSTATUS NTAPI LdrpReleaseTlsEntry(IN PLDR_DATA_TABLE_ENTRY LdrEntry);

