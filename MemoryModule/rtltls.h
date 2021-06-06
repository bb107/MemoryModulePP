#pragma once

NTSTATUS NTAPI RtlFindLdrpHandleTlsData(PVOID* _LdrpHandleTlsData, bool* stdcall);

NTSTATUS NTAPI RtlFindLdrpReleaseTlsEntry(PVOID* _LdrpReleaseTlsEntry, bool* stdcall);

NTSTATUS NTAPI LdrpHandleTlsData(IN PLDR_DATA_TABLE_ENTRY LdrEntry);

NTSTATUS NTAPI LdrpReleaseTlsEntry(IN PLDR_DATA_TABLE_ENTRY LdrEntry);

