#include "stdafx.h"

typedef struct _MMP_IAT_HANDLE {

	HMODULE hModule;
	PMM_IAT_RESOLVER lpResolver;

}MMP_IAT_HANDLE, * PMMP_IAT_HANDLE;

HMODULE MmpLoadLibraryA(
	_In_ LPCSTR lpModuleName,
	_Out_ PMM_IAT_RESOLVER* lpModuleResolver) {

	HMODULE hModule = nullptr;
	PMM_IAT_RESOLVER resolver = nullptr;

	EnterCriticalSection(&MmpGlobalDataPtr->MmpIat->MmpIatResolverListLock);

	PLIST_ENTRY lpResolver = MmpGlobalDataPtr->MmpIat->MmpIatResolverList.Flink;
	while (lpResolver != &MmpGlobalDataPtr->MmpIat->MmpIatResolverList) {
		PMM_IAT_RESOLVER entry = CONTAINING_RECORD(lpResolver, MM_IAT_RESOLVER, MM_IAT_RESOLVER::InMmpIatResolverList);

		hModule = entry->LoadLibraryProv(lpModuleName);
		if (hModule) {
			resolver = entry;
			++entry->ReferenceCount;
			break;
		}

		lpResolver = lpResolver->Flink;
	}

	LeaveCriticalSection(&MmpGlobalDataPtr->MmpIat->MmpIatResolverListLock);

	*lpModuleResolver = resolver;
	return hModule;
}

VOID MemoryFreeImportTable(_In_ PMEMORYMODULE hMemoryModule) {

	EnterCriticalSection(&MmpGlobalDataPtr->MmpIat->MmpIatResolverListLock);

	PMMP_IAT_HANDLE list = (PMMP_IAT_HANDLE)hMemoryModule->hModulesList;
	for (DWORD i = 0; i < hMemoryModule->dwModulesCount; ++i) {
		auto entry = list[i];
		entry.lpResolver->FreeLibraryProv(entry.hModule);
		--entry.lpResolver->ReferenceCount;
	}

	LeaveCriticalSection(&MmpGlobalDataPtr->MmpIat->MmpIatResolverListLock);


	RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, hMemoryModule->hModulesList);
	hMemoryModule->hModulesList = nullptr;
	hMemoryModule->dwModulesCount = 0;
}

NTSTATUS MemoryResolveImportTable(
	_In_ LPBYTE base,
	_In_ PIMAGE_NT_HEADERS lpNtHeaders,
	_In_ PMEMORYMODULE hMemoryModule) {
	NTSTATUS status = STATUS_SUCCESS;
	PIMAGE_IMPORT_DESCRIPTOR importDesc = nullptr;
	DWORD count = 0;

	do {
		__try {
			PIMAGE_DATA_DIRECTORY dir = &lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
			PIMAGE_IMPORT_DESCRIPTOR iat = nullptr;

			if (dir && dir->Size) {
				iat = importDesc = PIMAGE_IMPORT_DESCRIPTOR(lpNtHeaders->OptionalHeader.ImageBase + dir->VirtualAddress);
			}

			if (iat) {
				while (iat->Name) {
					++count;
					++iat;
				}
			}

			if (importDesc && count) {
				PMMP_IAT_HANDLE handles = (PMMP_IAT_HANDLE)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(MMP_IAT_HANDLE) * count);
				hMemoryModule->hModulesList = handles;
				if (!hMemoryModule->hModulesList) {
					status = STATUS_NO_MEMORY;
					break;
				}

				for (DWORD i = 0; i < count; ++i, ++importDesc) {
					uintptr_t* thunkRef;
					FARPROC* funcRef;
					PMM_IAT_RESOLVER resolver;
					HMODULE handle = MmpLoadLibraryA((LPCSTR)(base + importDesc->Name), &resolver);

					if (!handle) {
						status = STATUS_DLL_NOT_FOUND;
						break;
					}

					handles[hMemoryModule->dwModulesCount].hModule = handle;
					handles[hMemoryModule->dwModulesCount++].lpResolver = resolver;
					thunkRef = (uintptr_t*)(base + (importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));
					funcRef = (FARPROC*)(base + importDesc->FirstThunk);
					while (*thunkRef) {
						*funcRef = GetProcAddress(
							handle,
							IMAGE_SNAP_BY_ORDINAL(*thunkRef) ? (LPCSTR)IMAGE_ORDINAL(*thunkRef) : (LPCSTR)PIMAGE_IMPORT_BY_NAME(base + (*thunkRef))->Name
						);
						if (!*funcRef) {
							status = STATUS_ENTRYPOINT_NOT_FOUND;
							break;
						}
						++thunkRef;
						++funcRef;
					}

					if (!NT_SUCCESS(status))break;
				}

			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
		}
	} while (false);

	if (!NT_SUCCESS(status)) {
		MemoryFreeImportTable(hMemoryModule);
	}

	return status;
}

HANDLE WINAPI MmRegisterImportTableResolver(
	_In_ MM_IAT_RESOLVER_ENTRY LoadLibraryProv,
	_In_ MM_IAT_FREE_ENTRY FreeLibraryProv) {

	HANDLE heap = RtlProcessHeap();
	PMM_IAT_RESOLVER resolver = (PMM_IAT_RESOLVER)RtlAllocateHeap(heap, 0, sizeof(MM_IAT_RESOLVER));

	if (resolver) {
		EnterCriticalSection(&MmpGlobalDataPtr->MmpIat->MmpIatResolverListLock);

		resolver->ReferenceCount = 1;
		resolver->LoadLibraryProv = LoadLibraryProv;
		resolver->FreeLibraryProv = FreeLibraryProv;
		InsertTailList(&MmpGlobalDataPtr->MmpIat->MmpIatResolverList, &resolver->InMmpIatResolverList);

		LeaveCriticalSection(&MmpGlobalDataPtr->MmpIat->MmpIatResolverListLock);
	}

	return resolver;
}

_Success_(return)
BOOL WINAPI MmRemoveImportTableResolver(_In_ HANDLE hMmIatResolver) {

	HANDLE heap = RtlProcessHeap();

	if (hMmIatResolver == &MmpGlobalDataPtr->MmpIat->MmpIatResolverHead) {
		return FALSE;
	}

	PMM_IAT_RESOLVER resolver = CONTAINING_RECORD(hMmIatResolver, MM_IAT_RESOLVER, MM_IAT_RESOLVER::InMmpIatResolverList);

	EnterCriticalSection(&MmpGlobalDataPtr->MmpIat->MmpIatResolverListLock);

	if (resolver->ReferenceCount > 1) {
		LeaveCriticalSection(&MmpGlobalDataPtr->MmpIat->MmpIatResolverListLock);
		return FALSE;
	}

	RemoveHeadList(&resolver->InMmpIatResolverList);
	LeaveCriticalSection(&MmpGlobalDataPtr->MmpIat->MmpIatResolverListLock);

	return RtlFreeHeap(heap, 0, hMmIatResolver);
}
