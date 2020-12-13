#pragma once
#include "stdafx.h"

NTSTATUS NTAPI RtlFindLdrpHandleTlsData(PVOID* _LdrpHandleTlsData, bool* stdcall);

NTSTATUS NTAPI LdrpHandleTlsData(IN PLDR_DATA_TABLE_ENTRY LdrEntry);
