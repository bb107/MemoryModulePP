#pragma once
#include <Windows.h>
typedef PVOID HMEMORYMODULE, HMEMORYRSRC;

//Deprecated API
#ifndef _DEPRECATED
/**
 * Load DLL from memory location with the given size.
 *
 * All dependencies are resolved using default LoadLibrary/GetProcAddress
 * calls through the Windows API.
 */
NOT_BUILD_WINDOWS_DEPRECATE
__drv_preferredFunction("NtLoadDllMemory*", "Deprecated. Use NtLoadDllMemory or NtLoadDllMemoryEx.")
HMEMORYMODULE MemoryLoadLibrary(const void*);

/**
 * Get address of exported method. Supports loading both by name and by
 * ordinal value.
 */
NOT_BUILD_WINDOWS_DEPRECATE
__drv_preferredFunction("GetProcAddress", "Deprecated. Use Win32API GetProcAddress.")
FARPROC MemoryGetProcAddress(HMEMORYMODULE, LPCSTR);

/**
 * Free previously loaded DLL.
 */
NOT_BUILD_WINDOWS_DEPRECATE
__drv_preferredFunction("NtUnloadDllMemory", "Deprecated. Use NtUnloadDllMemory.")
bool MemoryFreeLibrary(HMEMORYMODULE);

/**
 * Find the location of a resource with the specified type and name.
 */
NOT_BUILD_WINDOWS_DEPRECATE
__drv_preferredFunction("FindResource", "Deprecated. Use Win32API FindResource.")
HMEMORYRSRC MemoryFindResource(HMEMORYMODULE, LPCTSTR, LPCTSTR);

/**
 * Find the location of a resource with the specified type, name and language.
 */
NOT_BUILD_WINDOWS_DEPRECATE
__drv_preferredFunction("FindResourceEx", "Deprecated. Use Win32API FindResourceEx.")
HMEMORYRSRC MemoryFindResourceEx(HMEMORYMODULE, LPCTSTR, LPCTSTR, WORD);

/**
 * Get the size of the resource in bytes.
 */
NOT_BUILD_WINDOWS_DEPRECATE
__drv_preferredFunction("SizeofResource", "Deprecated. Use Win32API SizeofResource.")
DWORD MemorySizeofResource(HMEMORYMODULE, HMEMORYRSRC);

/**
 * Get a pointer to the contents of the resource.
 */
NOT_BUILD_WINDOWS_DEPRECATE
__drv_preferredFunction("LoadResource", "Deprecated. Use Win32API LoadResource.")
LPVOID MemoryLoadResource(HMEMORYMODULE, HMEMORYRSRC);

/**
 * Load a string resource.
 */
NOT_BUILD_WINDOWS_DEPRECATE
__drv_preferredFunction("LoadString*", "Deprecated. Use Win32API LoadStringA or LoadStringW.")
int MemoryLoadString(HMEMORYMODULE, UINT, LPTSTR, int);

/**
 * Load a string resource with a given language.
 */
NOT_BUILD_WINDOWS_DEPRECATE
__drv_preferredFunction("LoadString*", "Deprecated. Use Win32API LoadStringA or LoadStringW.")
int MemoryLoadStringEx(HMEMORYMODULE, UINT, LPTSTR, int, WORD);
#endif


#define MEMORY_FEATURE_SUPPORT_VERSION				0x00000001
#define MEMORY_FEATURE_MODULE_BASEADDRESS_INDEX		0x00000002  /* Windows8 and greater */
#define MEMORY_FEATURE_LDRP_HEAP					0x00000004
#define MEMORY_FEATURE_LDRP_HASH_TABLE				0x00000008
#define MEMORY_FEATURE_INVERTED_FUNCTION_TABLE		0x00000010
#define MEMORY_FEATURE_LDRP_HANDLE_TLS_DATA			0x00000020
#define MEMORY_FEATURE_ALL                          0x0000003f

//Get the implementation of the currently running operating system.
NTSTATUS NTAPI NtQuerySystemMemoryModuleFeatures(OUT PDWORD pFeatures);


//Load dll from the provided buffer.
NTSTATUS NTAPI NtLoadDllMemory(
	OUT HMEMORYMODULE* BaseAddress,     // Output module base address
	IN  LPVOID BufferAddress,           // Pointer to the dll file data buffer
	IN  size_t Reserved                 // Reserved parameter, must be 0
);


/*
    NtLoadDllMemoryEx dwFlags
*/

//If this flag is specified, all subsequent flags will be ignored.
//Also, will be incompatible with Win32 API.
#define LOAD_FLAGS_NOT_MAP_DLL						0x10000000

//If this flag is specified, this routine will not fail even if the call to LdrpTlsData fails.
#define LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS			0x20000000

//If this flag is specified, exception handling will not be supported.
#define LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION		0x00000001

//If this flag is specified, NtLoadDllMemory and NtUnloadDllMemory will not use reference counting.
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

NTSTATUS NTAPI NtLoadDllMemoryExW(
	OUT HMEMORYMODULE* BaseAddress,     // Output module base address
	OUT PVOID* LdrEntry OPTIONAL,       // Receive a pointer to the LDR node of the module
	IN DWORD dwFlags,                   // Flags
	IN LPVOID BufferAddress,            // Pointer to the dll file data buffer
	IN size_t Reserved,                 // Reserved parameter, must be 0
	IN LPCWSTR DllName OPTIONAL,        // Module file name
	IN LPCWSTR DllFullName OPTIONAL     // Module file full path
);

NTSTATUS NTAPI NtLoadDllMemoryExA(
	OUT HMEMORYMODULE* BaseAddress,
	OUT PVOID* LdrEntry OPTIONAL,
	IN DWORD dwFlags,
	IN LPVOID BufferAddress,
	IN size_t Reserved,
	IN LPCSTR DllName OPTIONAL,
	IN LPCSTR DllFullName OPTIONAL
);

//Unload modules previously loaded from memory
NTSTATUS NTAPI NtUnloadDllMemory(IN HMEMORYMODULE BaseAddress);

#ifdef _WIN64
#pragma comment(linker,"/export:NtUnloadDllMemoryAndExitThread")
#pragma comment(linker,"/export:FreeLibraryMemoryAndExitThread=NtUnloadDllMemoryAndExitThread")
#else
#pragma comment(linker,"/export:NtUnloadDllMemoryAndExitThread=_NtUnloadDllMemoryAndExitThread@8")
#pragma comment(linker,"/export:FreeLibraryMemoryAndExitThread=_NtUnloadDllMemoryAndExitThread@8")
#endif
//FreeLibraryMemoryAndExitThread = GetProcAddress(GetModuleHandleW(nullptr), "FreeLibraryMemoryAndExitThread");
//FreeLibraryMemoryAndExitThread(hModule, 0);
extern "C" {
    __declspec(noreturn) VOID NTAPI NtUnloadDllMemoryAndExitThread(IN HMEMORYMODULE BaseAddress, IN DWORD dwExitCode);
}

#define LoadLibraryMemory NtLoadDllMemory
#define FreeLibraryMemory NtUnloadDllMemory
#define FreeLibraryMemoryAndExitThread NtUnloadDllMemoryAndExitThread
#ifdef UNICODE
#define NtLoadDllMemoryEx NtLoadDllMemoryExW
#define LoadLibraryMemoryEx NtLoadDllMemoryExW
#else
#define NtLoadDllMemoryEx NtLoadDllMemoryExA
#define LoadLibraryMemoryEx NtLoadDllMemoryExA
#endif



