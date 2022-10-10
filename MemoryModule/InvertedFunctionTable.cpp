#include "stdafx.h"

static VOID RtlpInsertInvertedFunctionTable(
	_In_ PRTL_INVERTED_FUNCTION_TABLE InvertedTable,
	_In_ PVOID ImageBase,
	_In_ ULONG SizeOfImage) {
#ifdef _WIN64
	ULONG CurrentSize;
	PIMAGE_RUNTIME_FUNCTION_ENTRY FunctionTable;
	ULONG Index;
	ULONG SizeOfTable = 0;
	bool IsWin8OrGreater = RtlIsWindowsVersionOrGreater(6, 2, 0);

	Index = (ULONG)IsWin8OrGreater;
	CurrentSize = InvertedTable->Count;
	if (CurrentSize != InvertedTable->MaxCount) {
		if (CurrentSize != 0) {
			while (Index < CurrentSize) {
				if (ImageBase < InvertedTable->Entries[Index].ImageBase)break;
				++Index;
			}

			if (Index != CurrentSize) {
				RtlMoveMemory(&InvertedTable->Entries[Index + 1],
					&InvertedTable->Entries[Index],
					(CurrentSize - Index) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY));
			}
		}

		FunctionTable = (decltype(FunctionTable))RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &SizeOfTable);
		InvertedTable->Entries[Index].ExceptionDirectory = FunctionTable;
		InvertedTable->Entries[Index].ImageBase = ImageBase;
		InvertedTable->Entries[Index].ImageSize = SizeOfImage;
		InvertedTable->Entries[Index].ExceptionDirectorySize = SizeOfTable;
		InvertedTable->Count++;
	}
	else {
		IsWin8OrGreater ? (InvertedTable->Overflow = TRUE) : (InvertedTable->Epoch = TRUE);
	}

#else
	DWORD ptr, count;
	bool IsWin8OrGreater = RtlIsWindowsVersionOrGreater(6, 2, 0);
	ULONG Index = IsWin8OrGreater ? 1 : 0;

	if (InvertedTable->Count == InvertedTable->MaxCount) {
		if (IsWin8OrGreater)InvertedTable->NextEntrySEHandlerTableEncoded = TRUE;
		else InvertedTable->Overflow = TRUE;
		return;
	}
	while (Index < InvertedTable->Count) {
		if (ImageBase < (IsWin8OrGreater ?
			((PRTL_INVERTED_FUNCTION_TABLE_ENTRY_64)&InvertedTable->Entries[Index])->ImageBase :
			InvertedTable->Entries[Index].ImageBase))
			break;
		Index++;
	}
	if (Index != InvertedTable->Count) {
		if (IsWin8OrGreater) {
			RtlMoveMemory(&InvertedTable->Entries[Index + 1], &InvertedTable->Entries[Index],
				(InvertedTable->Count - Index) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY));
		}
		else {
			RtlMoveMemory(&InvertedTable->Entries[Index].NextEntrySEHandlerTableEncoded,
				Index ? &InvertedTable->Entries[Index - 1].NextEntrySEHandlerTableEncoded : (PVOID)&InvertedTable->NextEntrySEHandlerTableEncoded,
				(InvertedTable->Count - Index) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY));
		}
	}

	RtlCaptureImageExceptionValues(ImageBase, &ptr, &count);
	if (IsWin8OrGreater) {
		//memory layout is same as x64
		PRTL_INVERTED_FUNCTION_TABLE_ENTRY_64 entry = (decltype(entry))&InvertedTable->Entries[Index];
		entry->ExceptionDirectory = (PIMAGE_RUNTIME_FUNCTION_ENTRY)RtlEncodeSystemPointer((PVOID)ptr);
		entry->ExceptionDirectorySize = count;
		entry->ImageBase = ImageBase;
		entry->ImageSize = SizeOfImage;
	}
	else {
		if (Index) InvertedTable->Entries[Index - 1].NextEntrySEHandlerTableEncoded = RtlEncodeSystemPointer((PVOID)ptr);
		else InvertedTable->NextEntrySEHandlerTableEncoded = (DWORD)RtlEncodeSystemPointer((PVOID)ptr);
		InvertedTable->Entries[Index].ImageBase = ImageBase;
		InvertedTable->Entries[Index].ImageSize = SizeOfImage;
		InvertedTable->Entries[Index].SEHandlerCount = count;
	}

	++InvertedTable->Count;
#endif
	return;
}

static VOID RtlpRemoveInvertedFunctionTable(
	_In_ PRTL_INVERTED_FUNCTION_TABLE InvertedTable,
	_In_ PVOID ImageBase) {
	ULONG CurrentSize;
	ULONG Index;
	//bool need = RtlIsWindowsVersionOrGreater(6, 2, 0);
	bool IsWin8OrGreater = RtlIsWindowsVersionOrGreater(6, 2, 0);

	CurrentSize = InvertedTable->Count;
	for (Index = 0; Index < CurrentSize; Index += 1) {
		if (ImageBase == (IsWin8OrGreater ?
			((PRTL_INVERTED_FUNCTION_TABLE_ENTRY_64)&InvertedTable->Entries[Index])->ImageBase :
			InvertedTable->Entries[Index].ImageBase))
			break;
	}

	if (Index != CurrentSize) {
		//if (need)_InterlockedIncrement(&InvertedTable->Epoch);
		if (CurrentSize != 1) {
#ifdef _WIN64
			RtlMoveMemory(&InvertedTable->Entries[Index],
				&InvertedTable->Entries[Index + 1],
				(CurrentSize - Index - 1) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY));
#else
			if (IsWin8OrGreater) {
				RtlMoveMemory(&InvertedTable->Entries[Index], &InvertedTable->Entries[Index + 1],
					(CurrentSize - Index) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY));
			}
			else {
				RtlMoveMemory(
					Index ? &InvertedTable->Entries[Index - 1].NextEntrySEHandlerTableEncoded : (PVOID)&InvertedTable->NextEntrySEHandlerTableEncoded,
					&InvertedTable->Entries[Index].NextEntrySEHandlerTableEncoded,
					(CurrentSize - Index) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY));
			}
#endif
		}
		InvertedTable->Count--;
		//if (need)_InterlockedIncrement(&InvertedTable->Epoch);
	}

	if (InvertedTable->Count != InvertedTable->MaxCount) {
		if (IsWin8OrGreater) {
			PRTL_INVERTED_FUNCTION_TABLE_64(InvertedTable)->Overflow = FALSE;
		}
		else {
			PRTL_INVERTED_FUNCTION_TABLE_WIN7_32(InvertedTable)->Overflow = FALSE;
		}
	}

	return;
}

static NTSTATUS RtlProtectMrdata(_In_ ULONG Protect) {
	static PVOID MrdataBase = nullptr;
	static SIZE_T size = 0;
	NTSTATUS status;
	PVOID tmp;
	SIZE_T tmp_len;
	ULONG old;

	if (!MrdataBase) {
		MEMORY_BASIC_INFORMATION mbi{};
		status = NtQueryVirtualMemory(GetCurrentProcess(), MmpGlobalDataPtr->MmpInvertedFunctionTable->LdrpInvertedFunctionTable, MemoryBasicInformation, &mbi, sizeof(mbi), nullptr);
		if (!NT_SUCCESS(status))return status;
		MrdataBase = mbi.BaseAddress;
		size = mbi.RegionSize;
	}

	tmp = MrdataBase;
	tmp_len = size;
	return NtProtectVirtualMemory(GetCurrentProcess(), &tmp, &tmp_len, Protect, &old);
}

NTSTATUS NTAPI RtlInsertInvertedFunctionTable(
	_In_ PVOID BaseAddress,
	_In_ ULONG ImageSize) {
	auto table = PRTL_INVERTED_FUNCTION_TABLE(MmpGlobalDataPtr->MmpInvertedFunctionTable->LdrpInvertedFunctionTable);
	if (!table)return STATUS_NOT_SUPPORTED;
	bool need_virtual_protect = RtlIsWindowsVersionOrGreater(6, 3, 0);
	NTSTATUS status;

	if (need_virtual_protect) {
		status = RtlProtectMrdata(PAGE_READWRITE);
		if (!NT_SUCCESS(status))return status;
	}
	RtlpInsertInvertedFunctionTable(table, BaseAddress, ImageSize);
	if (need_virtual_protect) {
		status = RtlProtectMrdata(PAGE_READONLY);
		if (!NT_SUCCESS(status))return status;
	}
	return (RtlIsWindowsVersionOrGreater(6, 2, 0) ? PRTL_INVERTED_FUNCTION_TABLE_64(table)->Overflow : PRTL_INVERTED_FUNCTION_TABLE_WIN7_32(table)->Overflow) ?
		STATUS_NO_MEMORY : STATUS_SUCCESS;
}

NTSTATUS NTAPI RtlRemoveInvertedFunctionTable(_In_ PVOID ImageBase) {
	auto table = PRTL_INVERTED_FUNCTION_TABLE(MmpGlobalDataPtr->MmpInvertedFunctionTable->LdrpInvertedFunctionTable);
	bool need_virtual_protect = RtlIsWindowsVersionOrGreater(6, 3, 0);
	NTSTATUS status;

	if (need_virtual_protect) {
		status = RtlProtectMrdata(PAGE_READWRITE);
		if (!NT_SUCCESS(status))return status;
	}
	RtlpRemoveInvertedFunctionTable(table, ImageBase);
	if (need_virtual_protect) {
		status = RtlProtectMrdata(PAGE_READONLY);
		if (!NT_SUCCESS(status))return status;
	}

	return STATUS_SUCCESS;
}
