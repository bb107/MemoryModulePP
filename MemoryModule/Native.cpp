#include "stdafx.h"
#pragma warning(disable:6387)
#pragma warning(disable:26812)
#pragma comment(lib,"ntdll.lib")

FARPROC NTAPI RtlGetNtProcAddress(LPCSTR func_name) {
	return GetProcAddress(GetModuleHandleA("ntdll.dll"), func_name);
}

WCHAR NTAPI RtlUpcaseUnicodeChar(IN WCHAR Source) {
	USHORT Offset;
	if (Source < 'a') return Source;
	if (Source <= 'z') return (Source - ('a' - 'A'));
	Offset = 0;
	return Source + (SHORT)Offset;
}

VOID NTAPI RtlGetNtVersionNumbers(OUT DWORD* MajorVersion, OUT DWORD* MinorVersion, OUT DWORD* BuildNumber) {
	static DWORD Versions[3]{ 0 };
	static auto _RtlGetNtVersionNumbers = (decltype(&RtlGetNtVersionNumbers))(RtlGetNtProcAddress("RtlGetNtVersionNumbers"));

	if (Versions[0] || !_RtlGetNtVersionNumbers) goto ret;
	_RtlGetNtVersionNumbers(Versions, Versions + 1, Versions + 2);
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

