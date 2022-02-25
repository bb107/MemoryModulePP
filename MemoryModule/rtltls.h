#pragma once
#include "stdafx.h"
enum CallType { stdcall, thiscall, fastcall };
NTSTATUS NTAPI RtlFindLdrpHandleTlsData(PVOID* _LdrpHandleTlsData, CallType & stdcall);

NTSTATUS NTAPI RtlFindLdrpReleaseTlsEntry(PVOID* _LdrpReleaseTlsEntry, CallType & stdcall);

NTSTATUS NTAPI LdrpHandleTlsData(IN PLDR_DATA_TABLE_ENTRY LdrEntry);

NTSTATUS NTAPI LdrpReleaseTlsEntry(IN PLDR_DATA_TABLE_ENTRY LdrEntry);

