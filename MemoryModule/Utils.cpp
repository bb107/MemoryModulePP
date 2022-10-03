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
			if (((PDLL_STARTUP_ROUTINE)(module->codeBase + headers->OptionalHeader.AddressOfEntryPoint))((HINSTANCE)module->codeBase, dwReason, 0)) {
				module->initialized = TRUE;
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


static __forceinline WORD CalcCheckSum(DWORD StartValue, LPVOID BaseAddress, DWORD WordCount) {
	LPWORD Ptr = (LPWORD)BaseAddress;
	DWORD Sum = StartValue;
	for (DWORD i = 0; i < WordCount; i++) {
		Sum += *Ptr;
		if (HIWORD(Sum) != 0) Sum = LOWORD(Sum) + HIWORD(Sum);
		Ptr++;
	}
	return (WORD)(LOWORD(Sum) + HIWORD(Sum));
}

BOOLEAN __forceinline WINAPI CheckSumBufferedFile(LPVOID BaseAddress, DWORD BufferLength) {
	PIMAGE_NT_HEADERS header = RtlImageNtHeader(BaseAddress);
	DWORD CalcSum = CalcCheckSum(0, BaseAddress, (BufferLength + 1) / sizeof(WORD));
	DWORD HdrSum = header->OptionalHeader.CheckSum;
	if (!HdrSum)return TRUE;

	if (!header) return FALSE;
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

		if (!headers.nt) {
			return FALSE;
		}

		switch (headers.nt->OptionalHeader.Magic) {
		case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
			sections = PIMAGE_SECTION_HEADER((char*)&headers.nt32->OptionalHeader + headers.nt32->FileHeader.SizeOfOptionalHeader);
			SizeofImage = headers.nt32->OptionalHeader.SizeOfHeaders;
			ProbeForRead(sections, headers.nt32->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
			for (WORD i = 0; i < headers.nt32->FileHeader.NumberOfSections; ++i, ++sections)
				SizeofImage += sections->SizeOfRawData;

			//Signature size
			SizeofImage += headers.nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
			break;
		case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
			sections = PIMAGE_SECTION_HEADER((char*)&headers.nt64->OptionalHeader + headers.nt64->FileHeader.SizeOfOptionalHeader);
			SizeofImage = headers.nt64->OptionalHeader.SizeOfHeaders;
			ProbeForRead(sections, headers.nt64->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
			for (WORD i = 0; i < headers.nt64->FileHeader.NumberOfSections; ++i, ++sections)
				SizeofImage += sections->SizeOfRawData;
			SizeofImage += headers.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
			break;
		default:
			return FALSE;
		}
		IMAGE_FIRST_SECTION(headers.nt32);
		ProbeForRead(Buffer, SizeofImage);
		if (Size)*Size = SizeofImage;
		result = CheckSumBufferedFile(Buffer, (DWORD)SizeofImage);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		SetLastError(RtlNtStatusToDosError(GetExceptionCode()));
	}
	return result;
}

FARPROC NTAPI RtlGetNtProcAddress(LPCSTR func_name) {
	return GetProcAddress(GetModuleHandleA("ntdll.dll"), func_name);
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

bool NTAPI RtlVerifyVersion(IN DWORD MajorVersion, IN DWORD MinorVersion OPTIONAL, IN DWORD BuildNumber OPTIONAL, IN BYTE Flags) {
	if (MmpGlobalDataPtr->NtVersions.MajorVersion == MajorVersion &&
		((Flags & RTL_VERIFY_FLAGS_MINOR_VERSION) ? MmpGlobalDataPtr->NtVersions.MinorVersion == MinorVersion : true) &&
		((Flags & RTL_VERIFY_FLAGS_BUILD_NUMBERS) ? MmpGlobalDataPtr->NtVersions.BuildNumber == BuildNumber : true))return true;
	return false;
}

bool NTAPI RtlIsWindowsVersionOrGreater(IN DWORD MajorVersion, IN DWORD MinorVersion, IN DWORD BuildNumber) {
	if (MmpGlobalDataPtr->NtVersions.MajorVersion == MajorVersion) {
		if (MmpGlobalDataPtr->NtVersions.MinorVersion == MinorVersion) return MmpGlobalDataPtr->NtVersions.BuildNumber >= BuildNumber;
		else return (MmpGlobalDataPtr->NtVersions.MinorVersion > MinorVersion);
	}
	else return MmpGlobalDataPtr->NtVersions.MajorVersion > MajorVersion;
}

bool NTAPI RtlIsWindowsVersionInScope(
	IN DWORD MinMajorVersion, IN DWORD MinMinorVersion, IN DWORD MinBuildNumber,
	IN DWORD MaxMajorVersion, IN DWORD MaxMinorVersion, IN DWORD MaxBuildNumber) {
	return RtlIsWindowsVersionOrGreater(MinMajorVersion, MinMinorVersion, MinBuildNumber) &&
		!RtlIsWindowsVersionOrGreater(MaxMajorVersion, MaxMinorVersion, MaxBuildNumber);
}

WINDOWS_VERSION NTAPI NtWindowsVersion() {
	static WINDOWS_VERSION version = WINDOWS_VERSION::null;
	if (version!=WINDOWS_VERSION::null)return version;

	switch (MmpGlobalDataPtr->NtVersions.MajorVersion) {
	case 5: {
		switch (MmpGlobalDataPtr->NtVersions.MinorVersion) {
		case 1:return version = MmpGlobalDataPtr->NtVersions.BuildNumber == 2600 ? WINDOWS_VERSION::xp : WINDOWS_VERSION::invalid;
		case 2:return version = MmpGlobalDataPtr->NtVersions.BuildNumber == 3790 ? WINDOWS_VERSION::xp : WINDOWS_VERSION::invalid;
		default:break;
		}
		break;
	}
		  break;
	case 6: {
		switch (MmpGlobalDataPtr->NtVersions.MinorVersion) {
		case 0: {
			switch (MmpGlobalDataPtr->NtVersions.BuildNumber) {
			case 6000:
			case 6001:
			case 6002:
				return version = WINDOWS_VERSION::vista;
			default:
				break;
			}
			break;
		}
			  break;
		case 1: {
			switch (MmpGlobalDataPtr->NtVersions.BuildNumber) {
			case 7600:
			case 7601:
				return version = WINDOWS_VERSION::win7;
			default:
				break;
			}
			break;
		}
			  break;
		case 2: {
			if (MmpGlobalDataPtr->NtVersions.BuildNumber == 9200)return version = WINDOWS_VERSION::win8;
			break;
		}
			  break;
		case 3: {
			if (MmpGlobalDataPtr->NtVersions.BuildNumber == 9600)return version = WINDOWS_VERSION::win8_1;
			break;
		}
			  break;
		default:
			break;
		}
		break;
	}
		  break;
	case 10: {
		if (MmpGlobalDataPtr->NtVersions.MinorVersion)break;
		switch (MmpGlobalDataPtr->NtVersions.BuildNumber) {
		case 10240:
		case 10586: return version = WINDOWS_VERSION::win10;
		case 14393: return version = WINDOWS_VERSION::win10_1;
		case 15063:
		case 16299:
		case 17134:
		case 17763:
		case 18362:return version = WINDOWS_VERSION::win10_2;
		default:if (RtlIsWindowsVersionOrGreater(MmpGlobalDataPtr->NtVersions.MajorVersion, MmpGlobalDataPtr->NtVersions.MinorVersion, 15063))return version = WINDOWS_VERSION::win10_2;
			break;
		}
		break;
	}
		   break;
	default:
		break;
	}
	return version = WINDOWS_VERSION::invalid;
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
