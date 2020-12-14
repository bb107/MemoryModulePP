#pragma once

#ifndef __MEMORY_MODULE_HEADER
#define __MEMORY_MODULE_HEADER

#include <windows.h>

#pragma warning(disable:4996)
struct ExportNameEntry {
	LPCSTR name;
	WORD idx;
};
typedef struct {
	LPVOID address;
	LPVOID alignedAddress;
	SIZE_T size;
	DWORD characteristics;
	BOOL last;
} SECTIONFINALIZEDATA, * PSECTIONFINALIZEDATA;
typedef BOOL(WINAPI* DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
#ifdef _WIN64
typedef struct POINTER_LIST {
	struct POINTER_LIST* next;
	void* address;
} POINTER_LIST;
#endif
typedef HMODULE HMEMORYMODULE;
typedef void* HMEMORYRSRC;
typedef struct _MEMORYMODULE {
	/*
		---------------------------
		|xxxxxxxx    BaseAddress  |
		|...                      |
		|...                      |
		|...                      | --> IMAGE_DOS_HEADER
		|...                      | --> IMAGE_NT_HEADERS
		|...                      |
		|...                      |
		--------------------------
		struct MEMORYMODULE;
		... (align)
		codes
	*/
	ULONG64 Signature;
	__declspec(align(sizeof(size_t))) struct {
		DWORD SizeofHeaders;
		union {
			struct {
				//Status Flags
				BYTE initialized : 1;
				BYTE loadFromNtLoadDllMemory : 1;
				BYTE underUnload : 1;
				BYTE reservedStatusFlags : 5;

				BYTE cbFlagsReserved;

				//Load Flags
				WORD MappedDll : 1;
				WORD InsertInvertedFunctionTableEntry : 1;
				WORD TlsHandled : 1;
				WORD UseReferenceCount : 1;
				WORD reservedLoadFlags : 12;

			};
			DWORD dwFlags;
		};
	};

	LPBYTE codeBase;						//codeBase == ImageBase
	__declspec(align(sizeof(size_t))) struct {
		PVOID lpReserved;
	};

	HMODULE* hModulesList;					//Import module handles
	__declspec(align(sizeof(size_t))) struct {
		DWORD dwModulesCount;				//number of module handles
		DWORD dwReserved;
	};

	ExportNameEntry* nameExportsTable;
	__declspec(align(sizeof(size_t))) struct {
		DWORD pageSize;						//SYSTEM_INFO::dwPageSize
		DWORD headers_align;				//headers_align == OptionalHeaders.BaseOfCode;
	};

#ifdef _WIN64
	POINTER_LIST* blockedMemory;
	PVOID lpReserved2;
#endif
} MEMORYMODULE, * PMEMORYMODULE;


#define MEMORY_MODULE_SIGNATURE 0x00aabbcc11ffee00

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Load DLL from memory location with the given size.
     *
     * All dependencies are resolved using default LoadLibrary/GetProcAddress
     * calls through the Windows API.
     */
    HMEMORYMODULE MemoryLoadLibrary(const void*);

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

	bool WINAPI IsValidMemoryModuleHandle(HMEMORYMODULE hModule);

	PMEMORYMODULE WINAPI MapMemoryModuleHandle(HMEMORYMODULE hModule);

#ifdef __cplusplus
}
#endif

#endif  // __MEMORY_MODULE_HEADER
