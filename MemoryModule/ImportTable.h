#pragma once

typedef HMODULE(WINAPI* MM_IAT_RESOLVER_ENTRY)(LPCSTR lpModuleName);
typedef BOOL(WINAPI* MM_IAT_FREE_ENTRY)(HMODULE hModule);

typedef struct _MM_IAT_RESOLVER {

	LIST_ENTRY InMmpIatResolverList;

	MM_IAT_RESOLVER_ENTRY LoadLibraryProv;
	MM_IAT_FREE_ENTRY FreeLibraryProv;

	DWORD ReferenceCount;

}MM_IAT_RESOLVER, * PMM_IAT_RESOLVER;

VOID MemoryFreeImportTable(_In_ PMEMORYMODULE hMemoryModule);

NTSTATUS MemoryResolveImportTable(
	_In_ LPBYTE base,
	_In_ PIMAGE_NT_HEADERS lpNtHeaders,
	_In_ PMEMORYMODULE hMemoryModule
);

HANDLE WINAPI MmRegisterImportTableResolver(
	_In_ MM_IAT_RESOLVER_ENTRY LoadLibraryProv,
	_In_ MM_IAT_FREE_ENTRY FreeLibraryProv
);

_Success_(return)
BOOL WINAPI MmRemoveImportTableResolver(_In_ HANDLE hMmIatResolver);
