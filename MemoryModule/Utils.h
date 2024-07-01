#pragma once

typedef struct _SEARCH_CONTEXT {

	IN LPBYTE SearchPattern;
	IN SIZE_T PatternSize;

	OUT LPBYTE Result;
	SIZE_T MemoryBlockSize;

}SEARCH_CONTEXT, * PSEARCH_CONTEXT;

NTSTATUS NTAPI RtlFindMemoryBlockFromModuleSection(
	_In_ HMODULE ModuleHandle,
	_In_ LPCSTR SectionName,
	_Inout_ PSEARCH_CONTEXT SearchContext
);

NTSTATUS NTAPI RtlResolveDllNameUnicodeString(
	_In_opt_ PCWSTR DllName,
	_In_opt_ PCWSTR DllFullName,
	_Out_ PUNICODE_STRING BaseDllName,
	_Out_ PUNICODE_STRING FullDllName
);

BOOL NTAPI LdrpExecuteTLS(PMEMORYMODULE module);

BOOL NTAPI LdrpCallInitializers(PMEMORYMODULE module, DWORD dwReason);

BOOLEAN NTAPI RtlIsValidImageBuffer(
	_In_ PVOID Buffer,
	_Out_opt_ size_t* Size
);

BOOLEAN NTAPI VirtualAccessCheck(LPCVOID pBuffer, size_t size, ACCESS_MASK protect);
BOOLEAN NTAPI VirtualAccessCheckNoException(LPCVOID pBuffer, size_t size, ACCESS_MASK protect);
#define ProbeForRead(pBuffer, size)			VirtualAccessCheck(pBuffer, size, PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE |  PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY)
#define ProbeForWrite(pBuffer, size)		VirtualAccessCheck(pBuffer, size, PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
#define ProbeForReadWrite					ProbeForWrite
#define ProbeForExecute(pBuffer, size)		VirtualAccessCheck(pBuffer, size, PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

#define _ProbeForRead(pBuffer, size)		VirtualAccessCheckNoException(pBuffer, size, PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE |  PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY)
#define _ProbeForWrite(pBuffer, size)		VirtualAccessCheckNoException(pBuffer, size, PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
#define _ProbeForReadWrite					_ProbeForWrite
#define _ProbeForExecute(pBuffer, size)		VirtualAccessCheckNoException(pBuffer, size, PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

#define RtlClearBit(BitMapHeader,BitNumber) RtlClearBits((BitMapHeader),(BitNumber),1)


#define RTL_VERIFY_FLAGS_MAJOR_VERSION	0
#define RTL_VERIFY_FLAGS_MINOR_VERSION	1
#define RTL_VERIFY_FLAGS_BUILD_NUMBERS	2
#define RTL_VERIFY_FLAGS_DEFAULT		RTL_VERIFY_FLAGS_MAJOR_VERSION|RTL_VERIFY_FLAGS_MINOR_VERSION|RTL_VERIFY_FLAGS_BUILD_NUMBERS

BOOL NTAPI RtlVerifyVersion(
	_In_ DWORD MajorVersion,
	_In_ DWORD MinorVersion,
	_In_ DWORD BuildNumber,
	_In_ BYTE Flags
);

BOOL NTAPI RtlIsWindowsVersionOrGreater(
	_In_ DWORD MajorVersion,
	_In_ DWORD MinorVersion,
	_In_ DWORD BuildNumber
);

BOOL NTAPI RtlIsWindowsVersionInScope(
	_In_ DWORD MinMajorVersion,
	_In_ DWORD MinMinorVersion,
	_In_ DWORD MinBuildNumber,

	_In_ DWORD MaxMajorVersion,
	_In_ DWORD MaxMinorVersion,
	_In_ DWORD MaxBuildNumber
);

#ifndef _WIN64
int NTAPI RtlCaptureImageExceptionValues(PVOID BaseAddress, PDWORD SEHandlerTable, PDWORD SEHandlerCount);
#endif
