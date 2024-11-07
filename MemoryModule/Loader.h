#pragma once

#define MEMORY_FEATURE_SUPPORT_VERSION				0x00000001
#define MEMORY_FEATURE_MODULE_BASEADDRESS_INDEX		0x00000002  /* Windows8 and greater */
#define MEMORY_FEATURE_LDRP_HEAP					0x00000004
#define MEMORY_FEATURE_LDRP_HASH_TABLE				0x00000008
#define MEMORY_FEATURE_INVERTED_FUNCTION_TABLE		0x00000010
#define MEMORY_FEATURE_LDRP_HANDLE_TLS_DATA			0x00000020
#define MEMORY_FEATURE_LDRP_RELEASE_TLS_ENTRY		0x00000040
#define MEMORY_FEATURE_ALL                          0x0000007f


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

//Hook for dotnet dlls
#define LOAD_FLAGS_HOOK_DOT_NET						0x00000010

extern "C" {

	//Get the implementation of the currently running operating system.
	NTSTATUS NTAPI LdrQuerySystemMemoryModuleFeatures(_Out_ PDWORD pFeatures);

	NTSTATUS NTAPI LdrLoadDllMemoryExW(
		_Out_ HMEMORYMODULE* BaseAddress,		// Output module base address
		_Out_opt_ PVOID* LdrEntry,				// Receive a pointer to the LDR node of the module
		_In_ DWORD dwFlags,						// Flags
		_In_ LPVOID BufferAddress,				// Pointer to the dll file data buffer
		_In_ size_t Reserved,					// Reserved parameter, must be 0
		_In_opt_ LPCWSTR DllName,				// Module file name
		_In_opt_ LPCWSTR DllFullName			// Module file full path
	);

	//Unload modules previously loaded from memory
	NTSTATUS NTAPI LdrUnloadDllMemory(_In_ HMEMORYMODULE BaseAddress);

	__declspec(noreturn) VOID NTAPI LdrUnloadDllMemoryAndExitThread(
		_In_ HMEMORYMODULE BaseAddress,
		_In_ DWORD dwExitCode
	);
}
