#include "stdafx.h"
#include <random>
#pragma comment(lib,"ntdll.lib")

bool NTAPI RtlResolveDllNameUnicodeString(
	IN PCWSTR DllName OPTIONAL, IN PCWSTR DllFullName OPTIONAL,
	OUT PUNICODE_STRING BaseDllName, OUT PUNICODE_STRING FullDllName) {

	std::random_device random;
	size_t Length = 0;
	size_t FullLength = 0;
	PWSTR _DllName = nullptr, _DllFullName = _DllName;
	HANDLE heap = NtCurrentPeb()->ProcessHeap;
	bool result = false;
	if (DllName) {
		bool add = false;
		if ((Length = wcslen(DllName)) <= 4 || wcsnicmp(DllName + Length - 4, L".dll", 4)) {
			add = true;
			Length += 4;
		}
		_DllName = new wchar_t[++Length];
		wcscpy(_DllName, DllName);
		if (add)wcscat(_DllName, L".DLL");
	}
	else {
		Length = 16 + 4 + 1; //hex(ULONG64) + ".dll" + '\0'
		_DllName = new wchar_t[Length];
		swprintf(_DllName, L"%016llX.DLL", ((ULONG64)random() << 32) | random());
	}
	if (DllFullName) {
		bool add = false;
		FullLength = wcslen(DllFullName);
		if (DllName && !wcsstr(DllFullName, DllName) && wcsnicmp(DllFullName + FullLength - 4, L".dll", 4)) {
			add = true;
			FullLength += Length;
		}
		wcscpy(_DllFullName = new wchar_t[++FullLength], DllFullName);
		if (add) swprintf(_DllFullName, L"%s\\%s", _DllFullName, _DllName);
	}
	else {
		FullLength = 16 + 1 + Length; //hex(ULONG64) + '\\' + _DllName
		swprintf(_DllFullName = new wchar_t[FullLength], L"%016llX\\%s", ((ULONG64)random() << 32) | random(), _DllName);
	}
	FullLength *= sizeof(wchar_t);
	Length *= sizeof(wchar_t);

	/* Allocate space for full DLL name */
	if (!(FullDllName->Buffer = (PWSTR)RtlAllocateHeap(heap, HEAP_ZERO_MEMORY, FullLength))) goto end;
	FullDllName->Length = FullLength - sizeof(wchar_t);
	FullDllName->MaximumLength = FullLength;
	wcscpy(FullDllName->Buffer, _DllFullName);

	/* Construct base DLL name */
	BaseDllName->Length = Length - sizeof(wchar_t);
	BaseDllName->MaximumLength = Length;
	BaseDllName->Buffer = (PWSTR)RtlAllocateHeap(heap, HEAP_ZERO_MEMORY, Length);
	if (!BaseDllName->Buffer) {
		RtlFreeHeap(heap, 0, BaseDllName->Buffer);
		goto end;
	}
	wcscpy(BaseDllName->Buffer, _DllName);
	result = true;
end:
	delete[]_DllName;
	delete[]_DllFullName;
	return result;
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
		result = CheckSumBufferedFile(Buffer, SizeofImage);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		SetLastError(RtlNtStatusToDosError(GetExceptionCode()));
	}
	return result;
}

FARPROC NTAPI RtlGetNtProcAddress(LPCSTR func_name) {
	return GetProcAddress(GetModuleHandleA("ntdll.dll"), func_name);
}

VOID NTAPI RtlGetNtVersionNumbersEx(OUT DWORD* MajorVersion, OUT DWORD* MinorVersion, OUT DWORD* BuildNumber) {
	static DWORD Versions[3]{ 0 };

	if (Versions[0]) goto ret;
	RtlGetNtVersionNumbers(Versions, Versions + 1, Versions + 2);
	if (Versions[2] & 0xf0000000)Versions[2] &= 0xffff;

ret:
	if (MajorVersion)*MajorVersion = Versions[0];
	if (MinorVersion)*MinorVersion = Versions[1];
	if (BuildNumber)*BuildNumber = Versions[2];
	return;
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
	DWORD Versions[3];
	RtlGetNtVersionNumbersEx(Versions, Versions + 1, Versions + 2);
	if (Versions[0] == MajorVersion &&
		((Flags & RTL_VERIFY_FLAGS_MINOR_VERSION) ? Versions[1] == MinorVersion : true) &&
		((Flags & RTL_VERIFY_FLAGS_BUILD_NUMBERS) ? Versions[2] == BuildNumber : true))return true;
	return false;
}

bool NTAPI RtlIsWindowsVersionOrGreater(IN DWORD MajorVersion, IN DWORD MinorVersion, IN DWORD BuildNumber) {
	static DWORD Versions[3]{};
	if (!Versions[0])RtlGetNtVersionNumbersEx(Versions, Versions + 1, Versions + 2);

	if (Versions[0] == MajorVersion) {
		if (Versions[1] == MinorVersion) return Versions[2] >= BuildNumber;
		else return (Versions[1] > MinorVersion);
	}
	else return Versions[0] > MajorVersion;
}

bool NTAPI RtlIsWindowsVersionInScope(
	IN DWORD MinMajorVersion, IN DWORD MinMinorVersion, IN DWORD MinBuildNumber,
	IN DWORD MaxMajorVersion, IN DWORD MaxMinorVersion, IN DWORD MaxBuildNumber) {
	return RtlIsWindowsVersionOrGreater(MinMajorVersion, MinMinorVersion, MinBuildNumber) &&
		!RtlIsWindowsVersionOrGreater(MaxMajorVersion, MaxMinorVersion, MaxBuildNumber);
}

WINDOWS_VERSION NTAPI NtWindowsVersion() {
	static WINDOWS_VERSION version = null;
	DWORD versions[3]{};
	if (version)return version;
	RtlGetNtVersionNumbersEx(versions, versions + 1, versions + 2);

	switch (versions[0]) {
	case 5: {
		switch (versions[1]) {
		case 1:return version = versions[2] == 2600 ? xp : invalid;
		case 2:return version = versions[2] == 3790 ? xp : invalid;
		default:break;
		}
		break;
	}
		  break;
	case 6: {
		switch (versions[1]) {
		case 0: {
			switch (versions[2]) {
			case 6000:
			case 6001:
			case 6002:
				return version = vista;
			default:
				break;
			}
			break;
		}
			  break;
		case 1: {
			switch (versions[2]) {
			case 7600:
			case 7601:
				return version = win7;
			default:
				break;
			}
			break;
		}
			  break;
		case 2: {
			if (versions[2] == 9200)return version = win8;
			break;
		}
			  break;
		case 3: {
			if (versions[2] == 9600)return version = win8_1;
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
		if (versions[1])break;
		switch (versions[2]) {
		case 10240:
		case 10586: return version = win10;
		case 14393: return version = win10_1;
		case 15063:
		case 16299:
		case 17134:
		case 17763:
		case 18362:return version = win10_2;
		default:if (RtlIsWindowsVersionOrGreater(versions[0], versions[1], 15063))return version = win10_2;
			break;
		}
		break;
	}
		   break;
	default:
		break;
	}
	return version = invalid;
}
