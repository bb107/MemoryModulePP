#include "stdafx.h"
#include <tchar.h>
#include <algorithm>

#if _MSC_VER
#pragma warning(disable:4055)
#pragma warning(error: 4244)
#pragma warning(error: 4267)
#pragma warning(disable:4996)
#define inline __inline
#endif

#ifdef _WIN64
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif

#define GET_HEADER_DICTIONARY(headers, idx)  &headers->OptionalHeader.DataDirectory[idx]

static PIMAGE_NT_HEADERS WINAPI GetImageNtHeaders(PMEMORYMODULE pModule) {
	if (pModule->Signature != MEMORY_MODULE_SIGNATURE)return nullptr;
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)((LPBYTE)pModule - pModule->SizeofHeaders);
	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)((LPBYTE)dos + dos->e_lfanew);
	if (headers->OptionalHeader.ImageBase != (ULONG64)pModule->codeBase)return nullptr;
	return headers;
}

PMEMORYMODULE WINAPI MapMemoryModuleHandle(HMEMORYMODULE hModule) {
	__try {
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
		if (!dos)return nullptr;
		PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + dos->e_lfanew);
		if (!nt)return nullptr;
		PMEMORYMODULE pModule = (PMEMORYMODULE)((LPBYTE)hModule + nt->OptionalHeader.SizeOfHeaders);
		if (!_ProbeForRead(pModule, sizeof(MEMORYMODULE)))return nullptr;
		if (pModule->Signature != MEMORY_MODULE_SIGNATURE || (size_t)pModule->codeBase != nt->OptionalHeader.ImageBase)return nullptr;
		return pModule;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return nullptr;
	}
}

bool WINAPI IsValidMemoryModuleHandle(HMEMORYMODULE hModule) {
	return MapMemoryModuleHandle(hModule) != nullptr;
}

static inline uintptr_t AlignValueDown(uintptr_t value, uintptr_t alignment) {
	return value & ~(alignment - 1);
}

static inline LPVOID AlignAddressDown(LPVOID address, uintptr_t alignment) {
	return (LPVOID)AlignValueDown((uintptr_t)address, alignment);
}

static inline size_t AlignValueUp(size_t value, size_t alignment) {
	return (value + alignment - 1) & ~(alignment - 1);
}

static inline void* OffsetPointer(void* data, ptrdiff_t offset) {
	return (void*)((uintptr_t)data + offset);
}

static inline void OutputLastError(const char* msg) {
#ifndef DEBUG_OUTPUT
	UNREFERENCED_PARAMETER(msg);
#else
	LPVOID tmp;
	char* tmpmsg;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&tmp, 0, nullptr);
	tmpmsg = (char*)LocalAlloc(LPTR, strlen(msg) + strlen(tmp) + 3);
	sprintf(tmpmsg, "%s: %s", msg, tmp);
	OutputDebugString(tmpmsg);
	LocalFree(tmpmsg);
	LocalFree(tmp);
#endif
}

#ifdef _WIN64
static void FreePointerList(POINTER_LIST* head) {
	POINTER_LIST* node = head;
	while (node) {
		POINTER_LIST* next;
		VirtualFree(node->address, 0, MEM_RELEASE);
		next = node->next;
		delete node;
		node = next;
	}
}
#endif

// Protection flags for memory pages (Executable, Readable, Writeable)
static int ProtectionFlags[2][2][2] = {
	{
		// not executable
		{PAGE_NOACCESS, PAGE_WRITECOPY},
		{PAGE_READONLY, PAGE_READWRITE},
	}, {
		// executable
		{PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
		{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
	},
};

static BOOL CopySections(const unsigned char* data, PMEMORYMODULE module) {
	LPVOID dest;
	PIMAGE_NT_HEADERS headers = GetImageNtHeaders(module);
	PIMAGE_SECTION_HEADER section = headers ? IMAGE_FIRST_SECTION(headers) : nullptr;
	size_t alloc_size = 0;
	bool cp = false;

	if (!headers) {
		SetLastError(ERROR_BAD_EXE_FORMAT);
		return FALSE;
	}
	for (int i = 0; i < headers->FileHeader.NumberOfSections; i++, section++) {
		alloc_size = headers->OptionalHeader.SectionAlignment;
		cp = false;
		if (section->SizeOfRawData) {
			__try {
				ProbeForRead(data + static_cast<size_t>(section->PointerToRawData), section->SizeOfRawData);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				SetLastError(ERROR_BAD_EXE_FORMAT);
				return FALSE;
			}
			alloc_size = section->SizeOfRawData;
			cp = true;
		}
		if (alloc_size) {
			if (!(dest = VirtualAlloc((LPSTR)headers->OptionalHeader.ImageBase + section->VirtualAddress, alloc_size, MEM_COMMIT, PAGE_READWRITE))) {
				SetLastError(ERROR_OUTOFMEMORY);
				return FALSE;
			}
			section->Misc.PhysicalAddress = (DWORD)((uintptr_t)dest & 0xffffffff);
			RtlZeroMemory(dest, alloc_size);
			if (cp) {
				//section->VirtualAddress += module->headers_align;
				RtlCopyMemory(dest, data + section->PointerToRawData, section->SizeOfRawData);
			}
		}
	}
	return TRUE;
}

static SIZE_T GetRealSectionSize(PMEMORYMODULE module, PIMAGE_SECTION_HEADER section) {
	DWORD size = section->SizeOfRawData;
	PIMAGE_NT_HEADERS headers = GetImageNtHeaders(module);
	if (size == 0) {
		if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
			size = headers->OptionalHeader.SizeOfInitializedData;
		}
		else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
			size = headers->OptionalHeader.SizeOfUninitializedData;
		}
	}
	return (SIZE_T)size;
}

static BOOL FinalizeSection(PMEMORYMODULE module, PSECTIONFINALIZEDATA sectionData) {
	DWORD protect, oldProtect;
	BOOL executable;
	BOOL readable;
	BOOL writeable;
	PIMAGE_NT_HEADERS headers = GetImageNtHeaders(module);

	if (!sectionData->size) return TRUE;
	if (sectionData->characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
		// section is not needed any more and can safely be freed
		if (sectionData->address == sectionData->alignedAddress &&
			(sectionData->last || headers->OptionalHeader.SectionAlignment == module->pageSize ||
				(sectionData->size % module->pageSize) == 0)
			)
#pragma warning(disable:6250)
			VirtualFree(sectionData->address, sectionData->size, MEM_DECOMMIT);
#pragma warning(default:6250)
		return TRUE;
	}

	// determine protection flags based on characteristics
	executable = (sectionData->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
	readable = (sectionData->characteristics & IMAGE_SCN_MEM_READ) != 0;
	writeable = (sectionData->characteristics & IMAGE_SCN_MEM_WRITE) != 0;
	protect = ProtectionFlags[executable][readable][writeable];
	if (sectionData->characteristics & IMAGE_SCN_MEM_NOT_CACHED) protect |= PAGE_NOCACHE;

	// change memory access flags
	return VirtualProtect(sectionData->address, sectionData->size, protect, &oldProtect);
}

static BOOL FinalizeSections(PMEMORYMODULE module) {
	PIMAGE_NT_HEADERS headers = GetImageNtHeaders(module);
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(headers);
#ifdef _WIN64
	uintptr_t imageOffset = ((uintptr_t)headers->OptionalHeader.ImageBase & 0xffffffff00000000);
#else
	static const uintptr_t imageOffset = 0;
#endif
	SECTIONFINALIZEDATA sectionData;
	sectionData.address = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
	sectionData.alignedAddress = AlignAddressDown(sectionData.address, module->pageSize);
	sectionData.size = GetRealSectionSize(module, section);
	sectionData.characteristics = section->Characteristics;
	sectionData.last = FALSE;
	section++;

	for (int i = 1; i < headers->FileHeader.NumberOfSections; i++, section++) {
		LPVOID sectionAddress = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
		LPVOID alignedAddress = AlignAddressDown(sectionAddress, module->pageSize);
		SIZE_T sectionSize = GetRealSectionSize(module, section);
		if (sectionData.alignedAddress == alignedAddress || (uintptr_t)sectionData.address + sectionData.size > (uintptr_t) alignedAddress) {
			if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) {
				sectionData.characteristics = (sectionData.characteristics | section->Characteristics) & ~IMAGE_SCN_MEM_DISCARDABLE;
			}
			else {
				sectionData.characteristics |= section->Characteristics;
			}
			sectionData.size = (((uintptr_t)sectionAddress) + ((uintptr_t)sectionSize)) - (uintptr_t)sectionData.address;
			continue;
		}
		if (!FinalizeSection(module, &sectionData)) return FALSE;
		sectionData.address = sectionAddress;
		sectionData.alignedAddress = alignedAddress;
		sectionData.size = sectionSize;
		sectionData.characteristics = section->Characteristics;
	}
	sectionData.last = TRUE;
	return FinalizeSection(module, &sectionData);
}

static BOOL ExecuteTLS(PMEMORYMODULE module) {
	unsigned char* codeBase = module->codeBase;
	PIMAGE_TLS_DIRECTORY tls;
	PIMAGE_TLS_CALLBACK* callback;
	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(codeBase);
	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(headers, IMAGE_DIRECTORY_ENTRY_TLS);
	if (directory->VirtualAddress == 0) return TRUE;

	tls = (PIMAGE_TLS_DIRECTORY)(codeBase + directory->VirtualAddress);
	callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
	if (callback) {
		while (*callback) {
			(*callback)((LPVOID)codeBase, DLL_PROCESS_ATTACH, nullptr);
			callback++;
		}
	}
	return TRUE;
}

typedef struct _REBASE_INFO {
	USHORT Offset : 12;
	USHORT Type : 4;
}REBASE_INFO, * PREBASE_INFO;
typedef struct _IMAGE_BASE_RELOCATION_HEADER {
	DWORD VirtualAddress;
	DWORD SizeOfBlock;
	REBASE_INFO TypeOffset[ANYSIZE_ARRAY];

	DWORD TypeOffsetCount()const {
		return (this->SizeOfBlock - 8) / sizeof(_REBASE_INFO);
	}
}IMAGE_BASE_RELOCATION_HEADER, * PIMAGE_BASE_RELOCATION_HEADER;
static BOOL PerformBaseRelocation(PMEMORYMODULE module, ptrdiff_t delta) {
	unsigned char* codeBase = module->codeBase;
	auto directory = GET_HEADER_DICTIONARY(GetImageNtHeaders(module), IMAGE_DIRECTORY_ENTRY_BASERELOC);
	auto relocation = (PIMAGE_BASE_RELOCATION_HEADER)(codeBase + directory->VirtualAddress);
	if (!directory->Size) return (delta == 0);
	while (relocation->VirtualAddress > 0) {
		auto relInfo = (_REBASE_INFO*)&relocation->TypeOffset;
		for (DWORD i = 0; i < relocation->TypeOffsetCount(); ++i, ++relInfo) {
			switch (relInfo->Type) {
			case IMAGE_REL_BASED_HIGHLOW: *(DWORD*)(codeBase + relocation->VirtualAddress + relInfo->Offset) += (DWORD)delta; break;
#ifdef _WIN64
			case IMAGE_REL_BASED_DIR64: *(ULONGLONG*)(codeBase + relocation->VirtualAddress + relInfo->Offset) += (ULONGLONG)delta; break;
#endif
			case IMAGE_REL_BASED_ABSOLUTE:
			default: break;
			}
		}
		// advance to next relocation block
		//relocation->VirtualAddress += module->headers_align;
		relocation = decltype(relocation)(OffsetPointer(relocation, relocation->SizeOfBlock));
	}
	return TRUE;
}

static BOOL GetImportAddressTableEntryCountAndVerify(PMEMORYMODULE module, LPDWORD Count, PIMAGE_IMPORT_DESCRIPTOR* IAT) {
	__try {
		PIMAGE_NT_HEADERS headers = GetImageNtHeaders(module);
		PIMAGE_DATA_DIRECTORY dir = GET_HEADER_DICTIONARY(headers, IMAGE_DIRECTORY_ENTRY_IMPORT);
		PIMAGE_IMPORT_DESCRIPTOR iat = *IAT = (dir && dir->Size) ? decltype(iat)(headers->OptionalHeader.ImageBase + dir->VirtualAddress) : nullptr;
		*Count = 0;
		if (!iat)return TRUE;
		ProbeForRead(iat, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		while (iat->Name) {
			++*Count;
			++iat;
			ProbeForRead(iat, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		}
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		SetLastError(RtlNtStatusToDosError(GetExceptionCode()));
		return FALSE;
	}
}
static void FreeLoadedModule(PMEMORYMODULE module) {
	for (DWORD i = 0; i < module->dwModulesCount; ++i) FreeLibrary(module->hModulesList[i]);
	delete[]module->hModulesList;
	module->hModulesList = nullptr;
	module->dwModulesCount = 0;
	return;
}
static BOOL BuildImportTable(PMEMORYMODULE module) {
	unsigned char* codeBase = module->codeBase;
	PIMAGE_IMPORT_DESCRIPTOR importDesc;
	DWORD count;
	if (!GetImportAddressTableEntryCountAndVerify(module, &count, &importDesc)) {
		SetLastError(ERROR_BAD_EXE_FORMAT);
		return FALSE;
	}
	if (!importDesc || !count)return TRUE;
	if (!(module->hModulesList = new HMODULE[count])) {
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}
	RtlZeroMemory(module->hModulesList, sizeof(HMODULE) * count);
	__try {
		for (DWORD i = 0; i < count; ++i, ++importDesc) {
			uintptr_t* thunkRef;
			FARPROC* funcRef;
			HMODULE handle = LoadLibraryA((LPCSTR)(codeBase + importDesc->Name));
			if (!handle) {
				FreeLoadedModule(module);
				SetLastError(ERROR_MOD_NOT_FOUND);
				return FALSE;
			}
			module->hModulesList[module->dwModulesCount++] = handle;
			thunkRef = (uintptr_t*)(codeBase + (importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));
			funcRef = (FARPROC*)(codeBase + importDesc->FirstThunk);
			while (*thunkRef) {
				*funcRef = GetProcAddress(
					handle,
					IMAGE_SNAP_BY_ORDINAL(*thunkRef) ? (LPCSTR)IMAGE_ORDINAL(*thunkRef) : (LPCSTR)PIMAGE_IMPORT_BY_NAME(codeBase + (*thunkRef))->Name
				);
				if (!*funcRef) {
					FreeLoadedModule(module);
					SetLastError(ERROR_PROC_NOT_FOUND);
					return FALSE;
				}
				++thunkRef;
				++funcRef;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		SetLastError(RtlNtStatusToDosError(GetExceptionCode()));
		return FALSE;
	}
	return TRUE;
}

HMEMORYMODULE MemoryLoadLibrary(const void* data) {
	PMEMORYMODULE hMemoryModule = nullptr;
	PIMAGE_DOS_HEADER dos_header, new_dos_header;
	PIMAGE_NT_HEADERS old_header, new_header;
	unsigned char* base;
	ptrdiff_t locationDelta;
	static SYSTEM_INFO sysInfo{};
	PIMAGE_SECTION_HEADER section;
	size_t optionalSectionSize;
	size_t lastSectionEnd = 0;
	size_t alignedImageSize;
	DWORD headers_align;
#ifdef _WIN64
	POINTER_LIST* blockedMemory = nullptr;
#endif

	__try {
		ProbeForRead(data, sizeof(IMAGE_DOS_HEADER));
		dos_header = (PIMAGE_DOS_HEADER)data;
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
			SetLastError(ERROR_BAD_EXE_FORMAT);
			return nullptr;
		}
		ProbeForRead(data, dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS));
		old_header = (PIMAGE_NT_HEADERS)((size_t)data + dos_header->e_lfanew);
		if (old_header->Signature != IMAGE_NT_SIGNATURE ||
			!ProbeForRead(data, old_header->OptionalHeader.SizeOfHeaders) ||
			old_header->FileHeader.Machine != HOST_MACHINE ||
			old_header->OptionalHeader.SectionAlignment & 1) {
			SetLastError(ERROR_BAD_EXE_FORMAT);
			return nullptr;
		}
		//only dll image support
		if (!(old_header->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
			SetLastError(ERROR_NOT_SUPPORTED);
			return nullptr;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		SetLastError(ERROR_INVALID_DATA);
		return nullptr;
	}
	
	section = IMAGE_FIRST_SECTION(old_header);
	optionalSectionSize = old_header->OptionalHeader.SectionAlignment;
	for (DWORD i = 0; i < old_header->FileHeader.NumberOfSections; i++, section++) {
		size_t endOfSection;
		if (section->SizeOfRawData == 0) {
			// Section without data in the DLL
			endOfSection = section->VirtualAddress + optionalSectionSize;
		}
		else {
			endOfSection = static_cast<size_t>(section->VirtualAddress) + section->SizeOfRawData;
		}

		if (endOfSection > lastSectionEnd) {
			lastSectionEnd = endOfSection;
		}
	}

	if (!sysInfo.dwPageSize)GetNativeSystemInfo(&sysInfo);
	alignedImageSize = AlignValueUp(old_header->OptionalHeader.SizeOfImage, sysInfo.dwPageSize);
	if (alignedImageSize != AlignValueUp(lastSectionEnd, sysInfo.dwPageSize)) {
		SetLastError(ERROR_BAD_EXE_FORMAT);
		return nullptr;
	}
	alignedImageSize += headers_align = (DWORD)AlignValueUp(sizeof(MEMORYMODULE) + old_header->OptionalHeader.SizeOfHeaders, sysInfo.dwPageSize);

	// reserve memory for image of library
	// XXX: is it correct to commit the complete memory region at once?
	//      calling DllEntry raises an exception if we don't...
	if (!(base = (LPBYTE)VirtualAlloc((LPVOID)(old_header->OptionalHeader.ImageBase), alignedImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
		if (!(old_header->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) {
			SetLastError(ERROR_BAD_EXE_FORMAT);
			return nullptr;
		}
		if (!(base = (LPBYTE)VirtualAlloc(nullptr, alignedImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
			SetLastError(ERROR_OUTOFMEMORY);
			return nullptr;
		}
	}

#ifdef _WIN64
	// Memory block may not span 4 GB boundaries.
	while ((((uintptr_t)base) >> 32) < (((uintptr_t)(base + alignedImageSize)) >> 32)) {
		POINTER_LIST* node = new POINTER_LIST;
		if (!node) {
			VirtualFree(base, 0, MEM_RELEASE);
			FreePointerList(blockedMemory);
			SetLastError(ERROR_OUTOFMEMORY);
			return nullptr;
		}

		node->next = blockedMemory;
		node->address = base;
		blockedMemory = node;

		if (!(base = (LPBYTE)VirtualAlloc(nullptr, alignedImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
			FreePointerList(blockedMemory);
			SetLastError(ERROR_OUTOFMEMORY);
			return nullptr;
		}
	}
#endif

	new_dos_header = (PIMAGE_DOS_HEADER)base;
	new_header = (PIMAGE_NT_HEADERS)(base + dos_header->e_lfanew);
	hMemoryModule = (PMEMORYMODULE)(base + old_header->OptionalHeader.SizeOfHeaders);
	RtlZeroMemory(hMemoryModule, sizeof(MEMORYMODULE));
	hMemoryModule->codeBase = base;
	hMemoryModule->pageSize = sysInfo.dwPageSize;
	hMemoryModule->Signature = MEMORY_MODULE_SIGNATURE;
	hMemoryModule->SizeofHeaders = old_header->OptionalHeader.SizeOfHeaders;
	hMemoryModule->headers_align = headers_align;
#ifdef _WIN64
	hMemoryModule->blockedMemory = blockedMemory;
#endif

	// copy PE header to code
	memcpy(new_dos_header, dos_header, old_header->OptionalHeader.SizeOfHeaders);
	new_header->OptionalHeader.SizeOfImage = (DWORD)(alignedImageSize);
	new_header->OptionalHeader.ImageBase = (size_t)base;
	new_header->OptionalHeader.BaseOfCode = headers_align;

	// copy sections from DLL file block to new memory location
	if (!CopySections((LPBYTE)data, hMemoryModule)) goto error;

	// adjust base address of imported data
	locationDelta = (ptrdiff_t)(hMemoryModule->codeBase - old_header->OptionalHeader.ImageBase);
	if (locationDelta && !PerformBaseRelocation(hMemoryModule, locationDelta))goto error;

	// load required dlls and adjust function table of imports
	if (!BuildImportTable(hMemoryModule)) goto error;

	// mark memory pages depending on section headers and release
	// sections that are marked as "discardable"
	if (!FinalizeSections(hMemoryModule)) goto error;

	// TLS callbacks are executed BEFORE the main loading
	if (!ExecuteTLS(hMemoryModule)) goto error;

	// get entry point of loaded library
	if (new_header->OptionalHeader.AddressOfEntryPoint) {
		__try {
			// notify library about attaching to process
			if (!((DllEntryProc)(base + new_header->OptionalHeader.AddressOfEntryPoint))((HINSTANCE)base, DLL_PROCESS_ATTACH, 0)) {
				SetLastError(ERROR_DLL_INIT_FAILED);
				goto error;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			SetLastError(RtlNtStatusToDosError(GetExceptionCode()));
			goto error;
		}
		hMemoryModule->initialized = TRUE;
	}
	
	return (HMEMORYMODULE)base;
error:
	// cleanup
	MemoryFreeLibrary((HMEMORYMODULE)base);
	return nullptr;
}

bool MemoryFreeLibrary(HMEMORYMODULE mod) {
	PMEMORYMODULE module = MapMemoryModuleHandle(mod);
	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(mod);

	if (!module) return false;
	if (module->loadFromNtLoadDllMemory && !module->underUnload)return false;
	if (module->initialized) {
		DllEntryProc DllEntry = (DllEntryProc)(LPVOID)(module->codeBase + headers->OptionalHeader.AddressOfEntryPoint);
		(*DllEntry)((HINSTANCE)module->codeBase, DLL_PROCESS_DETACH, 0);
	}
	if (module->nameExportsTable)delete[] module->nameExportsTable;
	if (module->hModulesList) {
		for (DWORD i = 0; i < module->dwModulesCount; ++i) {
			if (module->hModulesList[i]) {
				FreeLibrary(module->hModulesList[i]);
			}
		}
		delete[] module->hModulesList;
	}
#ifdef _WIN64
	FreePointerList(module->blockedMemory);
#endif
	if (module->codeBase) VirtualFree(mod, 0, MEM_RELEASE);
	return true;
}



/*
	Deprecated API
*/
static int _compare(const void* a, const void* b) {
	const struct ExportNameEntry* p1 = (const struct ExportNameEntry*) a;
	const struct ExportNameEntry* p2 = (const struct ExportNameEntry*) b;
	return strcmp(p1->name, p2->name);
}
static int _find(const void* a, const void* b) {
	LPCSTR* name = (LPCSTR*)a;
	const struct ExportNameEntry* p = (const struct ExportNameEntry*) b;
	return strcmp(*name, p->name);
}
FARPROC MemoryGetProcAddress(HMEMORYMODULE mod, LPCSTR name) {
	PMEMORYMODULE module = MapMemoryModuleHandle(mod);
	unsigned char* codeBase = module->codeBase;
	DWORD idx = 0;
	PIMAGE_EXPORT_DIRECTORY exports;
	PIMAGE_NT_HEADERS headers = GetImageNtHeaders(module);
	PIMAGE_DATA_DIRECTORY directory = headers ? GET_HEADER_DICTIONARY(headers, IMAGE_DIRECTORY_ENTRY_EXPORT) : nullptr;
	if (!headers) {
		SetLastError(ERROR_INVALID_HANDLE);
		return nullptr;
	}
	if (directory->Size == 0) {
		// no export table found
		SetLastError(ERROR_PROC_NOT_FOUND);
		return nullptr;
	}

	exports = (PIMAGE_EXPORT_DIRECTORY)(codeBase + directory->VirtualAddress);
	if (exports->NumberOfNames == 0 || exports->NumberOfFunctions == 0) {
		// DLL doesn't export anything
		SetLastError(ERROR_PROC_NOT_FOUND);
		return nullptr;
	}

	if (HIWORD(name) == 0) {
		// load function by ordinal value
		if (LOWORD(name) < exports->Base) {
			SetLastError(ERROR_PROC_NOT_FOUND);
			return nullptr;
		}

		idx = LOWORD(name) - exports->Base;
	}
	else if (!exports->NumberOfNames) {
		SetLastError(ERROR_PROC_NOT_FOUND);
		return nullptr;
	}
	else {
		const struct ExportNameEntry* found;

		// Lazily build name table and sort it by names
		if (!module->nameExportsTable) {
			DWORD i;
			DWORD* nameRef = (DWORD*)(codeBase + exports->AddressOfNames);
			WORD* ordinal = (WORD*)(codeBase + exports->AddressOfNameOrdinals);
			ExportNameEntry* entry = new ExportNameEntry[exports->NumberOfNames];
			module->nameExportsTable = entry;
			if (!entry) {
				SetLastError(ERROR_OUTOFMEMORY);
				return nullptr;
			}
			for (i = 0; i < exports->NumberOfNames; i++, nameRef++, ordinal++, entry++) {
				entry->name = (const char*)(codeBase + (*nameRef));
				entry->idx = *ordinal;
			}
			qsort(module->nameExportsTable,
				exports->NumberOfNames,
				sizeof(struct ExportNameEntry), _compare);
		}

		// search function name in list of exported names with binary search
		found = (const struct ExportNameEntry*) bsearch(&name,
			module->nameExportsTable,
			exports->NumberOfNames,
			sizeof(struct ExportNameEntry), _find);
		if (!found) {
			// exported symbol not found
			SetLastError(ERROR_PROC_NOT_FOUND);
			return nullptr;
		}

		idx = found->idx;
	}

	if (idx > exports->NumberOfFunctions) {
		// name <-> ordinal number don't match
		SetLastError(ERROR_PROC_NOT_FOUND);
		return nullptr;
	}

	// AddressOfFunctions contains the RVAs to the "real" functions
	return (FARPROC)(LPVOID)(codeBase + (*(DWORD*)(codeBase + exports->AddressOfFunctions + (static_cast<size_t>(idx) * 4))));
}
#define DEFAULT_LANGUAGE        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL)
HMEMORYRSRC MemoryFindResource(HMEMORYMODULE module, LPCTSTR name, LPCTSTR type) {
	return MemoryFindResourceEx(module, name, type, DEFAULT_LANGUAGE);
}
static PIMAGE_RESOURCE_DIRECTORY_ENTRY _MemorySearchResourceEntry(void* root, PIMAGE_RESOURCE_DIRECTORY resources, LPCTSTR key) {
	PIMAGE_RESOURCE_DIRECTORY_ENTRY entries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resources + 1);
	PIMAGE_RESOURCE_DIRECTORY_ENTRY result = nullptr;
	DWORD start;
	DWORD end;
	DWORD middle;

	if (!IS_INTRESOURCE(key) && key[0] == TEXT('#')) {
		// special case: resource id given as string
		TCHAR* endpos = nullptr;
		long int tmpkey = (WORD)_tcstol((TCHAR*)&key[1], &endpos, 10);
		if (tmpkey <= 0xffff && lstrlen(endpos) == 0) {
			key = MAKEINTRESOURCE(tmpkey);
		}
	}

	// entries are stored as ordered list of named entries,
	// followed by an ordered list of id entries - we can do
	// a binary search to find faster...
	if (IS_INTRESOURCE(key)) {
		WORD check = (WORD)(uintptr_t)key;
		start = resources->NumberOfNamedEntries;
		end = start + resources->NumberOfIdEntries;

		while (end > start) {
			WORD entryName;
			middle = (start + end) >> 1;
			entryName = (WORD)entries[middle].Name;
			if (check < entryName) {
				end = (end != middle ? middle : middle - 1);
			}
			else if (check > entryName) {
				start = (start != middle ? middle : middle + 1);
			}
			else {
				result = &entries[middle];
				break;
			}
		}
	}
	else {
		LPCWSTR searchKey;
		size_t searchKeyLen = _tcslen(key);

#if defined(UNICODE)
		searchKey = key;
#else
		// Resource names are always stored using 16bit characters, need to
		// convert string we search for.
#define MAX_LOCAL_KEY_LENGTH 2048
		// In most cases resource names are short, so optimize for that by
		// using a pre-allocated array.
		wchar_t _searchKeySpace[MAX_LOCAL_KEY_LENGTH + 1];
		LPWSTR _searchKey = nullptr;
		if (searchKeyLen > MAX_LOCAL_KEY_LENGTH) {
			if (!(_searchKey = new wchar_t[searchKeyLen + 1])) {
				SetLastError(ERROR_OUTOFMEMORY);
				return nullptr;
			}
		}
		else {
			_searchKey = &_searchKeySpace[0];
		}

		mbstowcs(_searchKey, key, searchKeyLen);
		_searchKey[searchKeyLen] = 0;
		searchKey = _searchKey;
#endif
		start = 0;
		end = resources->NumberOfNamedEntries;
		while (end > start) {
			int cmp;
			PIMAGE_RESOURCE_DIR_STRING_U resourceString;
			middle = (start + end) >> 1;
			resourceString = (PIMAGE_RESOURCE_DIR_STRING_U)OffsetPointer(root, entries[middle].Name & 0x7FFFFFFF);
			cmp = _wcsnicmp(searchKey, resourceString->NameString, resourceString->Length);
			if (cmp == 0) {
				// Handle partial match
				if (searchKeyLen > resourceString->Length) {
					cmp = 1;
				}
				else if (searchKeyLen < resourceString->Length) {
					cmp = -1;
				}
			}
			if (cmp < 0) {
				end = (middle != end ? middle : middle - 1);
			}
			else if (cmp > 0) {
				start = (middle != start ? middle : middle + 1);
			}
			else {
				result = &entries[middle];
				break;
			}
		}
#if !defined(UNICODE)
		if (searchKeyLen > MAX_LOCAL_KEY_LENGTH) {
			delete[] _searchKey;
		}
#undef MAX_LOCAL_KEY_LENGTH
#endif
	}

	return result;
}
HMEMORYRSRC MemoryFindResourceEx(HMEMORYMODULE module, LPCTSTR name, LPCTSTR type, WORD language) {
	PMEMORYMODULE mod = MapMemoryModuleHandle(module);
	unsigned char* codeBase = mod->codeBase;
	PIMAGE_NT_HEADERS headers = GetImageNtHeaders(mod);
	PIMAGE_DATA_DIRECTORY directory = headers ? GET_HEADER_DICTIONARY(headers, IMAGE_DIRECTORY_ENTRY_RESOURCE) : nullptr;
	PIMAGE_RESOURCE_DIRECTORY rootResources;
	PIMAGE_RESOURCE_DIRECTORY nameResources;
	PIMAGE_RESOURCE_DIRECTORY typeResources;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY foundType;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY foundName;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY foundLanguage;
	if (!headers) {
		SetLastError(ERROR_INVALID_HANDLE);
		return nullptr;
	}
	if (directory->Size == 0) {
		// no resource table found
		SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
		return nullptr;
	}

	if (language == DEFAULT_LANGUAGE) {
		// use language from current thread
		language = LANGIDFROMLCID(GetThreadLocale());
	}

	// resources are stored as three-level tree
	// - first node is the type
	// - second node is the name
	// - third node is the language
	rootResources = (PIMAGE_RESOURCE_DIRECTORY)(codeBase + directory->VirtualAddress);
	foundType = _MemorySearchResourceEntry(rootResources, rootResources, type);
	if (foundType == nullptr) {
		SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND);
		return nullptr;
	}

	typeResources = (PIMAGE_RESOURCE_DIRECTORY)(codeBase + directory->VirtualAddress + (foundType->OffsetToData & 0x7fffffff));
	foundName = _MemorySearchResourceEntry(rootResources, typeResources, name);
	if (foundName == nullptr) {
		SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND);
		return nullptr;
	}

	nameResources = (PIMAGE_RESOURCE_DIRECTORY)(codeBase + directory->VirtualAddress + (foundName->OffsetToData & 0x7fffffff));
	foundLanguage = _MemorySearchResourceEntry(rootResources, nameResources, (LPCTSTR)(uintptr_t)language);
	if (foundLanguage == nullptr) {
		// requested language not found, use first available
		if (nameResources->NumberOfIdEntries == 0) {
			SetLastError(ERROR_RESOURCE_LANG_NOT_FOUND);
			return nullptr;
		}

		foundLanguage = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(nameResources + 1);
	}

	return (codeBase + directory->VirtualAddress + (foundLanguage->OffsetToData & 0x7fffffff));
}
DWORD MemorySizeofResource(HMEMORYMODULE module, HMEMORYRSRC resource) {
	PIMAGE_RESOURCE_DATA_ENTRY entry;
	UNREFERENCED_PARAMETER(module);
	entry = (PIMAGE_RESOURCE_DATA_ENTRY)resource;
	if (entry == nullptr) {
		return 0;
	}

	return entry->Size;
}
LPVOID MemoryLoadResource(HMEMORYMODULE module, HMEMORYRSRC resource) {
	unsigned char* codeBase = MapMemoryModuleHandle(module)->codeBase;
	PIMAGE_RESOURCE_DATA_ENTRY entry = (PIMAGE_RESOURCE_DATA_ENTRY)resource;
	if (entry == nullptr) {
		return nullptr;
	}

	return codeBase + entry->OffsetToData;
}
int MemoryLoadString(HMEMORYMODULE module, UINT id, LPTSTR buffer, int maxsize) {
	return MemoryLoadStringEx(module, id, buffer, maxsize, DEFAULT_LANGUAGE);
}
int MemoryLoadStringEx(HMEMORYMODULE module, UINT id, LPTSTR buffer, int maxsize, WORD language) {
	HMEMORYRSRC resource;
	PIMAGE_RESOURCE_DIR_STRING_U data;
	DWORD size;
	if (maxsize == 0) {
		return 0;
	}

	resource = MemoryFindResourceEx(module, MAKEINTRESOURCEW((static_cast<size_t>(id) >> 4) + 1), RT_STRING, language);
	if (resource == nullptr) {
		buffer[0] = 0;
		return 0;
	}

	data = (PIMAGE_RESOURCE_DIR_STRING_U)MemoryLoadResource(module, resource);
	id = id & 0x0f;
	while (id--) {
		data = (PIMAGE_RESOURCE_DIR_STRING_U)OffsetPointer(data, (static_cast<size_t>(data->Length) + 1) * sizeof(WCHAR));
	}
	if (data->Length == 0) {
		SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND);
		buffer[0] = 0;
		return 0;
	}

	size = data->Length;
	if (size >= (DWORD)maxsize) {
		size = maxsize;
	}
	else {
		buffer[size] = 0;
	}
#if defined(UNICODE)
	wcsncpy(buffer, data->NameString, size);
#else
	wcstombs(buffer, data->NameString, size);
#endif
	return size;
}
