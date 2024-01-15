#include "stdafx.h"
#include <random>
#pragma comment(lib,"ntdll.lib")

NTSTATUS NTAPI RtlResolveDllNameUnicodeString(
	_In_opt_ PCWSTR DllName,
	_In_opt_ PCWSTR DllFullName,
	_Out_ PUNICODE_STRING BaseDllName,
	_Out_ PUNICODE_STRING FullDllName) {

	std::random_device random;
	HANDLE heap = NtCurrentPeb()->ProcessHeap;
	NTSTATUS status = STATUS_SUCCESS;
	size_t length;

	RtlZeroMemory(BaseDllName, sizeof(*BaseDllName));
	RtlZeroMemory(FullDllName, sizeof(*FullDllName));

	do {

		if (DllName && *DllName) {
			bool extend = false;

			length = wcslen(DllName);
			if (length <= 4 || _wcsnicmp(DllName + length - 4, L".dll", 4)) {
				length += 4;
				extend = true;
			}

			if (++length >= 0xffff) {
				status = STATUS_OBJECT_NAME_INVALID;
				break;
			}

			BaseDllName->MaximumLength = (USHORT)(length * sizeof(WCHAR));
			BaseDllName->Length = BaseDllName->MaximumLength - sizeof(WCHAR);
			BaseDllName->Buffer = (PWSTR)RtlAllocateHeap(heap, 0, BaseDllName->MaximumLength);
			if (!BaseDllName->Buffer) {
				status = STATUS_NO_MEMORY;
				break;
			}

			swprintf_s(BaseDllName->Buffer, length, extend ? L"%s.dll" : L"%s", DllName);
		}
		else {
			DllName = nullptr;

			BaseDllName->MaximumLength = (16 + 4 + 1) * sizeof(WCHAR); //hex(ULONG64) + ".dll" + '\0'
			BaseDllName->Length = BaseDllName->MaximumLength - sizeof(WCHAR);
			BaseDllName->Buffer = (PWSTR)RtlAllocateHeap(heap, 0, BaseDllName->MaximumLength);
			if (!BaseDllName->Buffer) {
				status = STATUS_NO_MEMORY;
				break;
			}

			swprintf_s(BaseDllName->Buffer, BaseDllName->MaximumLength / sizeof(WCHAR), L"%016llX.DLL", ((ULONG64)random() << 32) | random());
		}

		if (DllFullName && *DllFullName) {
			bool extend = false, backslash = false;

			unsigned int wc = BaseDllName->Length / sizeof(WCHAR);
			length = wcslen(DllFullName);
			if (length <= wc + 1 || _wcsicmp(DllFullName + length - wc, BaseDllName->Buffer) || *(DllFullName + length - wc - 1) != '\\') {
				extend = true;

				if (DllFullName[length - 1] != '\\') {
					backslash = true;

					++length;
				}

				length += BaseDllName->Length / sizeof(WCHAR);
			}

			if (++length >= 0xffff) {
				status = STATUS_OBJECT_NAME_INVALID;
				break;
			}

			FullDllName->MaximumLength = (USHORT)(length * sizeof(WCHAR));
			FullDllName->Length = FullDllName->MaximumLength - sizeof(WCHAR);
			FullDllName->Buffer = (PWSTR)RtlAllocateHeap(heap, 0, FullDllName->MaximumLength);
			if (!FullDllName->Buffer) {
				status = STATUS_NO_MEMORY;
				break;
			}

			swprintf_s(FullDllName->Buffer, length, extend ? backslash ? L"%s\\%s" : L"%s%s" : L"%s", DllFullName, BaseDllName->Buffer);
		}
		else {
			FullDllName->MaximumLength = (16 + 1 + 1) * sizeof(WCHAR) + BaseDllName->Length; //hex(ULONG64) + '\\' + BaseDllName + '\0'
			FullDllName->Length = FullDllName->MaximumLength - sizeof(WCHAR);
			FullDllName->Buffer = (PWSTR)RtlAllocateHeap(heap, 0, FullDllName->MaximumLength);
			if (!FullDllName->Buffer) {
				status = STATUS_NO_MEMORY;
				break;
			}

			swprintf_s(FullDllName->Buffer, FullDllName->MaximumLength / sizeof(WCHAR), L"%016llX\\%s", ((ULONG64)random() << 32) | random(), BaseDllName->Buffer);
		}

	} while (false);

	if (!NT_SUCCESS(status)) {
		RtlFreeHeap(heap, 0, BaseDllName->Buffer);
		RtlFreeHeap(heap, 0, FullDllName->Buffer);

		RtlZeroMemory(BaseDllName, sizeof(*BaseDllName));
		RtlZeroMemory(FullDllName, sizeof(*FullDllName));
	}

	return status;
}

BOOL NTAPI LdrpExecuteTLS(PMEMORYMODULE module) {
	unsigned char* codeBase = module->codeBase;
	PIMAGE_TLS_DIRECTORY tls;
	PIMAGE_TLS_CALLBACK* callback;
	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(codeBase);
	PIMAGE_DATA_DIRECTORY directory = &headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (directory->VirtualAddress == 0) return TRUE;

	tls = (PIMAGE_TLS_DIRECTORY)(codeBase + directory->VirtualAddress);
	callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
	if (callback) {
		while (*callback) {
			(*callback)((LPVOID)codeBase, DLL_PROCESS_ATTACH, nullptr);
			callback++;
		}
	}
	return TRUE;
}

BOOL NTAPI LdrpCallInitializers(PMEMORYMODULE module, DWORD dwReason) {
	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(module->codeBase);

	if (headers->OptionalHeader.AddressOfEntryPoint) {
		__try {
			// notify library about attaching to process
			if (((PLDR_INIT_ROUTINE)(module->codeBase + headers->OptionalHeader.AddressOfEntryPoint))((HINSTANCE)module->codeBase, dwReason, 0)) {
				module->initialized = TRUE;

				if (dwReason == DLL_PROCESS_ATTACH) {
					if (MmpGlobalDataPtr->WindowsVersion <= WINDOWS_VERSION::winBlue) {
						PLDR_DATA_TABLE_ENTRY_WINBLUE(module->LdrEntry)->ProcessAttachCalled = TRUE;
					}
					else {
						PLDR_DATA_TABLE_ENTRY(module->LdrEntry)->Flags |= LDRP_PROCESS_ATTACH_CALLED;
					}
				}

				return TRUE;
			}
			SetLastError(ERROR_DLL_INIT_FAILED);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			SetLastError(RtlNtStatusToDosError(GetExceptionCode()));
		}

		return FALSE;
	}

	return TRUE;
}

#ifndef _WIN64
SIZE_T NTAPI _RtlCompareMemory(
	const VOID* Source1,
	const VOID* Source2,
	SIZE_T     Length) {
	return decltype(&_RtlCompareMemory)(GetProcAddress((HMODULE)MmpGlobalDataPtr->MmpBaseAddressIndex->NtdllLdrEntry->DllBase, "RtlCompareMemory"))(Source1, Source2, Length);
}
#define RtlCompareMemory _RtlCompareMemory
#endif

NTSTATUS NTAPI RtlFindMemoryBlockFromModuleSection(
	_In_ HMODULE ModuleHandle,
	_In_ LPCSTR SectionName,
	_Inout_ PSEARCH_CONTEXT SearchContext) {

	NTSTATUS status = STATUS_SUCCESS;

	__try {

		//
		// checks if no search pattern and length are provided
		//

		if (!SearchContext->SearchPattern || !SearchContext->PatternSize) {
			SearchContext->Result = nullptr;
			SearchContext->MemoryBlockSize = 0;

			status = STATUS_INVALID_PARAMETER;
			__leave;
		}

		if (SearchContext->Result) {
			++SearchContext->Result;
			--SearchContext->MemoryBlockSize;
		}
		else {

			//
			// if it is the first search, find the length and start address of the specified section
			//

			PIMAGE_NT_HEADERS headers = RtlImageNtHeader(ModuleHandle);
			PIMAGE_SECTION_HEADER section = nullptr;

			if (headers) {
				section = IMAGE_FIRST_SECTION(headers);
				for (WORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
					if (!_strnicmp(SectionName, (LPCSTR)section->Name, 8)) {
						SearchContext->Result = (LPBYTE)ModuleHandle + section->VirtualAddress;
						SearchContext->MemoryBlockSize = section->Misc.VirtualSize;
						break;
					}

					++section;
				}

				if (!SearchContext->Result || !SearchContext->MemoryBlockSize || SearchContext->MemoryBlockSize < SearchContext->PatternSize) {
					SearchContext->Result = nullptr;
					SearchContext->MemoryBlockSize = 0;
					status = STATUS_NOT_FOUND;
					__leave;
				}
			}
			else {
				status = STATUS_INVALID_PARAMETER_1;
				__leave;
			}
		}

		//
		// perform a linear search on the pattern
		//

		LPBYTE end = SearchContext->Result + SearchContext->MemoryBlockSize - SearchContext->PatternSize;
		while (SearchContext->Result <= end) {
			if (RtlCompareMemory(SearchContext->SearchPattern, SearchContext->Result, SearchContext->PatternSize) == SearchContext->PatternSize) {
				__leave;
			}

			++SearchContext->Result;
			--SearchContext->MemoryBlockSize;
		}

		//
		// if the search fails, clear the output parameters
		//

		SearchContext->Result = nullptr;
		SearchContext->MemoryBlockSize = 0;
		status = STATUS_NOT_FOUND;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}

	return status;
}


#ifndef _WIN64
#undef RtlCompareMemory
#endif


static WORD CalcCheckSum(DWORD StartValue, LPVOID BaseAddress, DWORD WordCount) {
	LPWORD Ptr = (LPWORD)BaseAddress;
	DWORD Sum = StartValue;
	for (DWORD i = 0; i < WordCount; i++) {
		Sum += *Ptr;
		if (HIWORD(Sum) != 0) Sum = LOWORD(Sum) + HIWORD(Sum);
		Ptr++;
	}
	return (WORD)(LOWORD(Sum) + HIWORD(Sum));
}

static BOOLEAN CheckSumBufferedFile(LPVOID BaseAddress, DWORD BufferLength, DWORD CheckSum) {
	DWORD CalcSum = CalcCheckSum(0, BaseAddress, (BufferLength + 1) / sizeof(WORD)), HdrSum = CheckSum;

	if (LOWORD(CalcSum) >= LOWORD(HdrSum)) CalcSum -= LOWORD(HdrSum);
	else CalcSum = ((LOWORD(CalcSum) - LOWORD(HdrSum)) & 0xFFFF) - 1;
	if (LOWORD(CalcSum) >= HIWORD(HdrSum)) CalcSum -= HIWORD(HdrSum);
	else CalcSum = ((LOWORD(CalcSum) - HIWORD(HdrSum)) & 0xFFFF) - 1;
	
	CalcSum += BufferLength;
	return HdrSum == CalcSum;
}

BOOLEAN NTAPI RtlIsValidImageBuffer(
	_In_ PVOID Buffer,
	_Out_opt_ size_t* Size) {

	BOOLEAN result = FALSE;
	__try {

		if (Size)*Size = 0;

		union {
			PIMAGE_NT_HEADERS32 nt32;
			PIMAGE_NT_HEADERS64 nt64;
			PIMAGE_NT_HEADERS nt;
		}headers;
		headers.nt = RtlImageNtHeader(Buffer);
		PIMAGE_SECTION_HEADER sections = nullptr;
		size_t SizeofImage = 0;
		DWORD CheckSum = 0;

		if (!headers.nt) return FALSE;

		switch (headers.nt->OptionalHeader.Magic) {
		case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
			sections = PIMAGE_SECTION_HEADER((char*)&headers.nt32->OptionalHeader + headers.nt32->FileHeader.SizeOfOptionalHeader);
			SizeofImage = headers.nt32->OptionalHeader.SizeOfHeaders;
			ProbeForRead(sections, headers.nt32->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
			for (WORD i = 0; i < headers.nt32->FileHeader.NumberOfSections; ++i, ++sections)
				SizeofImage += sections->SizeOfRawData;

			//Signature size
			SizeofImage += headers.nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;

			CheckSum = headers.nt32->OptionalHeader.CheckSum;

			break;
		case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
			sections = PIMAGE_SECTION_HEADER((char*)&headers.nt64->OptionalHeader + headers.nt64->FileHeader.SizeOfOptionalHeader);
			SizeofImage = headers.nt64->OptionalHeader.SizeOfHeaders;
			ProbeForRead(sections, headers.nt64->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
			for (WORD i = 0; i < headers.nt64->FileHeader.NumberOfSections; ++i, ++sections)
				SizeofImage += sections->SizeOfRawData;
			SizeofImage += headers.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;

			CheckSum = headers.nt64->OptionalHeader.CheckSum;

			break;
		default:
			return FALSE;
		}

		ProbeForRead(Buffer, SizeofImage);
		if (Size)*Size = SizeofImage;

		if (!CheckSum)return TRUE;

		result = CheckSumBufferedFile(Buffer, (DWORD)SizeofImage, CheckSum);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		SetLastError(RtlNtStatusToDosError(GetExceptionCode()));
	}
	return result;
}

BOOLEAN NTAPI VirtualAccessCheckNoException(LPCVOID pBuffer, size_t size, ACCESS_MASK protect) {
	if (size) {
		MEMORY_BASIC_INFORMATION mbi{};
		SIZE_T len = 0;
		if (!NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(), const_cast<PVOID>(pBuffer), MemoryBasicInformation, &mbi, sizeof(mbi), &len)) ||
			!(mbi.Protect & protect)) {
			return FALSE;
		}
	}
	return TRUE;
}

BOOLEAN NTAPI VirtualAccessCheck(LPCVOID pBuffer, size_t size, ACCESS_MASK protect) {
	if (!VirtualAccessCheckNoException(pBuffer, size, protect)) {
		RtlRaiseStatus(STATUS_ACCESS_VIOLATION);
		return FALSE;
	}
	return TRUE;
}

BOOL NTAPI RtlVerifyVersion(
	_In_ DWORD MajorVersion,
	_In_ DWORD MinorVersion,
	_In_ DWORD BuildNumber,
	_In_ BYTE Flags
) {
	if (MmpGlobalDataPtr->NtVersions.MajorVersion == MajorVersion &&
		((Flags & RTL_VERIFY_FLAGS_MINOR_VERSION) ? MmpGlobalDataPtr->NtVersions.MinorVersion == MinorVersion : true) &&
		((Flags & RTL_VERIFY_FLAGS_BUILD_NUMBERS) ? MmpGlobalDataPtr->NtVersions.BuildNumber == BuildNumber : true))return TRUE;
	return FALSE;
}

BOOL NTAPI RtlIsWindowsVersionOrGreater(
	_In_ DWORD MajorVersion,
	_In_ DWORD MinorVersion,
	_In_ DWORD BuildNumber
) {
	if (MmpGlobalDataPtr->NtVersions.MajorVersion == MajorVersion) {
		if (MmpGlobalDataPtr->NtVersions.MinorVersion == MinorVersion) return MmpGlobalDataPtr->NtVersions.BuildNumber >= BuildNumber;
		else return (MmpGlobalDataPtr->NtVersions.MinorVersion > MinorVersion);
	}
	else return MmpGlobalDataPtr->NtVersions.MajorVersion > MajorVersion;
}

BOOL NTAPI RtlIsWindowsVersionInScope(
	_In_ DWORD MinMajorVersion,
	_In_ DWORD MinMinorVersion,
	_In_ DWORD MinBuildNumber,

	_In_ DWORD MaxMajorVersion,
	_In_ DWORD MaxMinorVersion,
	_In_ DWORD MaxBuildNumber
) {
	return RtlIsWindowsVersionOrGreater(MinMajorVersion, MinMinorVersion, MinBuildNumber) &&
		!RtlIsWindowsVersionOrGreater(MaxMajorVersion, MaxMinorVersion, MaxBuildNumber);
}

#ifndef _WIN64
int NTAPI RtlCaptureImageExceptionValues(PVOID BaseAddress, PDWORD SEHandlerTable, PDWORD SEHandlerCount) {
	PIMAGE_LOAD_CONFIG_DIRECTORY pLoadConfigDirectory;
	PIMAGE_COR20_HEADER pCor20;
	ULONG Size;

	//check if no seh
	if (RtlImageNtHeader(BaseAddress)->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) {
		*SEHandlerTable = *SEHandlerCount = -1;
		return 0;
	}

	//get seh table and count
	pLoadConfigDirectory = (decltype(pLoadConfigDirectory))RtlImageDirectoryEntryToData(BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &Size);
	if (pLoadConfigDirectory) {
		if (Size == 0x40 && pLoadConfigDirectory->Size >= 0x48u) {
			if (pLoadConfigDirectory->SEHandlerTable && pLoadConfigDirectory->SEHandlerCount) {
				*SEHandlerTable = pLoadConfigDirectory->SEHandlerTable;
				return *SEHandlerCount = pLoadConfigDirectory->SEHandlerCount;
			}
		}
	}

	//is .net core ?
	pCor20 = (decltype(pCor20))RtlImageDirectoryEntryToData(BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, &Size);
	*SEHandlerTable = *SEHandlerCount = ((pCor20 && pCor20->Flags & 1) ? -1 : 0);
	return 0;
}
#endif
