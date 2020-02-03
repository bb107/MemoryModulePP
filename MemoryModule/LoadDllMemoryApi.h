#pragma once
#include <Windows.h>

typedef PVOID HMEMORYMODULE, PLDR_DATA_TABLE_ENTRY, HMEMORYRSRC;

/**
 * Load DLL from memory location with the given size.
 *
 * All dependencies are resolved using default LoadLibrary/GetProcAddress
 * calls through the Windows API.
 */
HMEMORYMODULE MemoryLoadLibrary(const void*, size_t);

/**
 * Get address of exported method. Supports loading both by name and by
 * ordinal value.
 */
FARPROC MemoryGetProcAddress(HMEMORYMODULE, LPCSTR);

/**
 * Free previously loaded DLL.
 */
bool MemoryFreeLibrary(HMEMORYMODULE);

/**
 * Find the location of a resource with the specified type and name.
 */
HMEMORYRSRC MemoryFindResource(HMEMORYMODULE, LPCTSTR, LPCTSTR);

/**
 * Find the location of a resource with the specified type, name and language.
 */
HMEMORYRSRC MemoryFindResourceEx(HMEMORYMODULE, LPCTSTR, LPCTSTR, WORD);

/**
 * Get the size of the resource in bytes.
 */
DWORD MemorySizeofResource(HMEMORYMODULE, HMEMORYRSRC);

/**
 * Get a pointer to the contents of the resource.
 */
LPVOID MemoryLoadResource(HMEMORYMODULE, HMEMORYRSRC);

/**
 * Load a string resource.
 */
int MemoryLoadString(HMEMORYMODULE, UINT, LPTSTR, int);

/**
 * Load a string resource with a given language.
 */
int MemoryLoadStringEx(HMEMORYMODULE, UINT, LPTSTR, int, WORD);

NTSTATUS NTAPI NtLoadDllMemory(
	OUT HMEMORYMODULE* BaseAddress,
	IN  LPVOID BufferAddress,
	IN  size_t BufferSize
);

/*
	NtLoadDllMemoryEx dwFlags
*/

//If this flag is specified, all subsequent flags will be ignored.
//Also, will be incompatible with Win32 API.
#define LOAD_FLAGS_NOT_MAP_DLL						0x10000000

//If this flag is specified, exception handling will not be supported.
#define LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION		0x00000001

//If this flag is specified, NtLoadDllMemory and NtUnloadDllMemory will not use reference counting.
//If you try to load the same module, it will fail. When you unload the module,
//	it will be unloaded without checking the reference count.
#define LOAD_FLAGS_NOT_USE_REFERENCE_COUNT			0x00000002

//If this flag is specified, DllName and DllFullName cannot be nullptr,
//	they can be arbitrary strings without having to be correct file names and paths.
//Otherwise, DllName and DllFullName will use random names if they are nullptr.
//For compatibility with GetModuleHandle, DllName and DllFullName should be guaranteed to always end in .dll
#define LOAD_FLAGS_USE_DLL_NAME						0x00000004

NTSTATUS NTAPI NtLoadDllMemoryExW(
	OUT HMEMORYMODULE* BaseAddress,
	OUT PLDR_DATA_TABLE_ENTRY* LdrEntry OPTIONAL,
	IN DWORD dwFlags,
	IN LPVOID BufferAddress,
	IN size_t BufferSize,
	IN LPCWSTR DllName OPTIONAL,
	IN LPCWSTR DllFullName OPTIONAL
);
NTSTATUS NTAPI NtLoadDllMemoryExA(
	OUT HMEMORYMODULE* BaseAddress,
	OUT PLDR_DATA_TABLE_ENTRY* LdrEntry OPTIONAL,
	IN DWORD dwFlags,
	IN LPVOID BufferAddress,
	IN size_t BufferSize,
	IN LPCSTR DllName OPTIONAL,
	IN LPCSTR DllFullName OPTIONAL
);

#ifdef UNICODE
#define NtLoadDllMemoryEx NtLoadDllMemoryExW
#else
#define NtLoadDllMemoryEx NtLoadDllMemoryExA
#endif


NTSTATUS NTAPI NtUnloadDllMemory(IN HMEMORYMODULE BaseAddress);
