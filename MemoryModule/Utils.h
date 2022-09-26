#pragma once

typedef struct _SEARCH_CONTEXT {
	union {
		IN PVOID  MemoryBuffer;
		size_t InBufferPtr;
	};
	union {
		IN DWORD BufferLength;
		size_t reserved0;
	};

	union {
		OUT PVOID  MemoryBlockInSection;
		size_t OutBufferPtr;
	};
	union {
		DWORD RemainingLength;
		size_t reserved1;
	};
}SEARCH_CONTEXT, * PSEARCH_CONTEXT;

NTSTATUS NTAPI RtlFindMemoryBlockFromModuleSection(
	IN HMODULE hModule	OPTIONAL,
	IN LPCSTR lpSectionName	OPTIONAL,
	IN OUT PSEARCH_CONTEXT SearchContext
);

typedef BOOL(WINAPI* PDLL_STARTUP_ROUTINE)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

bool NTAPI RtlResolveDllNameUnicodeString(IN PCWSTR DllName OPTIONAL, IN PCWSTR DllFullName OPTIONAL, OUT PUNICODE_STRING BaseDllName, OUT PUNICODE_STRING FullDllName);

BOOL NTAPI LdrpExecuteTLS(PMEMORYMODULE module);

BOOL NTAPI LdrpCallInitializers(PMEMORYMODULE module, DWORD dwReason);

BOOLEAN NTAPI RtlIsValidImageBuffer(PVOID Buffer, size_t* Size);

FARPROC NTAPI RtlGetNtProcAddress(LPCSTR func_name);

VOID NTAPI RtlGetNtVersionNumbersEx(
	OUT DWORD* MajorVersion,
	OUT DWORD* MinorVersion,
	OUT DWORD* BuildNumber);

BOOLEAN NTAPI VirtualAccessCheck(LPCVOID pBuffer, size_t size, ACCESS_MASK protect);
BOOLEAN NTAPI VirtualAccessCheckNoException(LPCVOID pBuffer, size_t size, ACCESS_MASK protect);
#define ProbeForRead(pBuffer, size)			VirtualAccessCheck(pBuffer, size, PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)
#define ProbeForWrite(pBuffer, size)		VirtualAccessCheck(pBuffer, size, PAGE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)
#define ProbeForReadWrite(pBuffer, size)	VirtualAccessCheck(pBuffer, size, PAGE_EXECUTE_READWRITE | PAGE_READWRITE)
#define ProbeForExecute(pBuffer, size)		VirtualAccessCheck(pBuffer, size, PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
#define _ProbeForRead(pBuffer, size)		VirtualAccessCheckNoException(pBuffer, size, PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)
#define _ProbeForWrite(pBuffer, size)		VirtualAccessCheckNoException(pBuffer, size, PAGE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)
#define _ProbeForReadWrite(pBuffer, size)	VirtualAccessCheckNoException(pBuffer, size, PAGE_EXECUTE_READWRITE | PAGE_READWRITE)
#define _ProbeForExecute(pBuffer, size)		VirtualAccessCheckNoException(pBuffer, size, PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

#define RtlClearBit(BitMapHeader,BitNumber) RtlClearBits((BitMapHeader),(BitNumber),1)


#define RTL_VERIFY_FLAGS_MAJOR_VERSION	0
#define RTL_VERIFY_FLAGS_MINOR_VERSION	1
#define RTL_VERIFY_FLAGS_BUILD_NUMBERS	2
#define RTL_VERIFY_FLAGS_DEFAULT		RTL_VERIFY_FLAGS_MAJOR_VERSION|RTL_VERIFY_FLAGS_MINOR_VERSION|RTL_VERIFY_FLAGS_BUILD_NUMBERS

bool NTAPI RtlVerifyVersion(IN DWORD MajorVersion, IN DWORD MinorVersion OPTIONAL, IN DWORD BuildNumber OPTIONAL, IN BYTE Flags);

bool NTAPI RtlIsWindowsVersionOrGreater(IN DWORD MajorVersion, IN DWORD MinorVersion, IN DWORD BuildNumber);

bool NTAPI RtlIsWindowsVersionInScope(
	IN DWORD MinMajorVersion, IN DWORD MinMinorVersion, IN DWORD MinBuildNumber,
	IN DWORD MaxMajorVersion, IN DWORD MaxMinorVersion, IN DWORD MaxBuildNumber
);


typedef enum _WINDOWS_VERSION {
	null,
	xp,
	vista,
	win7,
	win8,
	win8_1,
	win10,
	win10_1,
	win10_2,
	invalid
}WINDOWS_VERSION;

WINDOWS_VERSION NTAPI NtWindowsVersion();
