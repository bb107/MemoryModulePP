#include "stdafx.h"

#ifndef _WIN64
SIZE_T NTAPI _RtlCompareMemory(
	const VOID* Source1,
	const VOID* Source2,
	SIZE_T     Length) {
	return decltype(&_RtlCompareMemory)(RtlGetNtProcAddress("RtlCompareMemory"))(Source1, Source2, Length);
}
#define RtlCompareMemory _RtlCompareMemory
#endif

NTSTATUS NTAPI RtlFindMemoryBlockFromModuleSection(
	IN HMODULE hModule	OPTIONAL,
	IN LPCSTR lpSectionName	OPTIONAL,
	IN OUT PSEARCH_CONTEXT SearchContext) {

	NTSTATUS status = STATUS_SUCCESS;
	size_t begin = 0, buffer = 0;
	DWORD Length = 0, bufferLength = 0;

	__try {
		begin = SearchContext->OutBufferPtr;
		Length = SearchContext->RemainingLength;
		buffer = SearchContext->InBufferPtr;
		bufferLength = SearchContext->BufferLength;
		if (!buffer || !bufferLength) {
			SearchContext->OutBufferPtr = 0;
			SearchContext->RemainingLength = 0;
			return STATUS_INVALID_PARAMETER;
		}
		if (!begin) {
			PIMAGE_NT_HEADERS headers = RtlImageNtHeader(hModule);
			PIMAGE_SECTION_HEADER section = nullptr;
			if (!headers)return STATUS_INVALID_PARAMETER_1;
			section = IMAGE_FIRST_SECTION(headers);
			for (WORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
				if (!_stricmp(lpSectionName, (LPCSTR)section->Name)) {
					begin = SearchContext->OutBufferPtr = (size_t)hModule + section->VirtualAddress;
					Length = SearchContext->RemainingLength = section->Misc.VirtualSize;
					break;
				}
				++section;
			}
			if (!begin || !Length || Length < bufferLength) {
				SearchContext->OutBufferPtr = 0;
				SearchContext->RemainingLength = 0;
				return STATUS_NOT_FOUND;
			}
		}
		else {
			begin++;
			Length--;
		}
		status = STATUS_NOT_FOUND;
		for (DWORD i = 0; i < Length - bufferLength; ++begin, ++i) {
			if (RtlCompareMemory((PVOID)begin, (PVOID)buffer, bufferLength) == bufferLength) {
				SearchContext->OutBufferPtr = begin;
				--SearchContext->RemainingLength;
				return STATUS_SUCCESS;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}

	SearchContext->OutBufferPtr = 0;
	SearchContext->RemainingLength = 0;
	return status;
}


#ifndef _WIN64
#undef RtlCompareMemory
#endif
