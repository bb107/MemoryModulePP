#pragma once
#ifndef _HIDE_INTERNAL_
#include "stdafx.h"
#else
#include <Windows.h>
typedef HMODULE HMEMORYMODULE;
#endif


//Load dll from the provided buffer.
NTSTATUS NTAPI LdrLoadDllMemory(
	OUT HMEMORYMODULE* BaseAddress,     // Output module base address
	IN  LPVOID BufferAddress,           // Pointer to the dll file data buffer
	IN  size_t Reserved                 // Reserved parameter, must be 0
);

#define MEMORY_FEATURE_SUPPORT_VERSION				0x00000001
#define MEMORY_FEATURE_MODULE_BASEADDRESS_INDEX		0x00000002  /* Windows8 and greater */
#define MEMORY_FEATURE_LDRP_HEAP					0x00000004
#define MEMORY_FEATURE_LDRP_HASH_TABLE				0x00000008
#define MEMORY_FEATURE_INVERTED_FUNCTION_TABLE		0x00000010
#define MEMORY_FEATURE_LDRP_HANDLE_TLS_DATA			0x00000020
#define MEMORY_FEATURE_LDRP_RELEASE_TLS_ENTRY		0x00000040
#define MEMORY_FEATURE_ALL                          0x0000007f

//Get the implementation of the currently running operating system.
NTSTATUS NTAPI LdrQuerySystemMemoryModuleFeatures(OUT PDWORD pFeatures);


/*
	LdrLoadDllMemoryEx dwFlags
*/

//If this flag is specified, all subsequent flags will be ignored.
//Also, will be incompatible with Win32 API.
#define LOAD_FLAGS_NOT_MAP_DLL						0x10000000

//If this flag is specified, this routine will not fail even if the call to LdrpTlsData fails.
#define LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS			0x20000000

//If this flag is specified, the input image buffer will not be checked before loading.
#define LOAD_FLAGS_PASS_IMAGE_CHECK					0x40000000

//If this flag is specified, exception handling will not be supported.
#define LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION		0x00000001

//If this flag is specified, LdrLoadDllMemory and LdrUnloadDllMemory will not use reference counting.
//If you try to load the same module, it will fail. When you unload the module,
//	it will be unloaded without checking the reference count.
#define LOAD_FLAGS_NOT_USE_REFERENCE_COUNT			0x00000002

//If this flag is specified, DllName and DllFullName cannot be nullptr,
//	they can be arbitrary strings without having to be correct file names and paths.
//Otherwise, DllName and DllFullName will use random names if they are nullptr.
//For compatibility with GetModuleHandle, DllName and DllFullName should be guaranteed to always end in ".dll"
#define LOAD_FLAGS_USE_DLL_NAME						0x00000004

//Dont call LdrpHandleTlsData routine if this flag is specified.
#define LOAD_FLAGS_NOT_HANDLE_TLS					0x00000008


NTSTATUS NTAPI LdrLoadDllMemoryExW(
	OUT HMEMORYMODULE* BaseAddress,     // Output module base address
	OUT PVOID* LdrEntry OPTIONAL,       // Receive a pointer to the LDR node of the module
	IN DWORD dwFlags,                   // Flags
	IN LPVOID BufferAddress,            // Pointer to the dll file data buffer
	IN size_t Reserved,                 // Reserved parameter, must be 0
	IN LPCWSTR DllName OPTIONAL,        // Module file name
	IN LPCWSTR DllFullName OPTIONAL     // Module file full path
);

NTSTATUS NTAPI LdrLoadDllMemoryExA(
	OUT HMEMORYMODULE* BaseAddress,
	OUT PVOID* LdrEntry OPTIONAL,
	IN DWORD dwFlags,
	IN LPVOID BufferAddress,
	IN size_t Reserved,
	IN LPCSTR DllName OPTIONAL,
	IN LPCSTR DllFullName OPTIONAL
);

//Unload modules previously loaded from memory
NTSTATUS NTAPI LdrUnloadDllMemory(IN HMEMORYMODULE BaseAddress);

#ifdef _WIN64
#pragma comment(linker,"/export:LdrUnloadDllMemoryAndExitThread")
#pragma comment(linker,"/export:FreeLibraryMemoryAndExitThread=LdrUnloadDllMemoryAndExitThread")
#else
#pragma comment(linker,"/export:LdrUnloadDllMemoryAndExitThread=_NtUnloadDllMemoryAndExitThread@8")
#pragma comment(linker,"/export:FreeLibraryMemoryAndExitThread=_NtUnloadDllMemoryAndExitThread@8")
#endif
//FreeLibraryMemoryAndExitThread = GetProcAddress(GetModuleHandleW(nullptr), "FreeLibraryMemoryAndExitThread");
//FreeLibraryMemoryAndExitThread(hModule, 0);
extern "C" {
	__declspec(noreturn) VOID NTAPI LdrUnloadDllMemoryAndExitThread(IN HMEMORYMODULE BaseAddress, IN DWORD dwExitCode);
}
