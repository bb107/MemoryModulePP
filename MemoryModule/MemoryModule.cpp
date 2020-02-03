#include <windows.h>
#include <winnt.h>
#include <stddef.h>
#include <tchar.h>
#include "rtltype.h"
#include "ntstatus.h"
#include <algorithm>
#ifdef DEBUG_OUTPUT
#include <stdio.h>
#endif

#if _MSC_VER
#pragma warning(disable:4055)
#pragma warning(error: 4244)
#pragma warning(error: 4267)
#pragma warning(disable:4996)
#define inline __inline
#endif

#ifndef IMAGE_SIZEOF_BASE_RELOCATION
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif

#ifdef _WIN64
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif

#include "MemoryModule.h"
#define GET_HEADER_DICTIONARY(headers, idx)  &headers->OptionalHeader.DataDirectory[idx]

static PIMAGE_NT_HEADERS WINAPI GetImageNtHeaders(PMEMORYMODULE pModule) {
	if (pModule->Signature != MEMORY_MODULE_SIGNATURE)return nullptr;
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)((LPBYTE)pModule - pModule->SizeofHeaders);
	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)((LPBYTE)dos + dos->e_lfanew);
	if (headers->OptionalHeader.ImageBase /*+ pModule->headers_align*/ != (ULONG64)pModule->codeBase)return nullptr;
	return headers;
}

PMEMORYMODULE WINAPI MapMemoryModuleHandle(HMEMORYMODULE hModule) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
	if (!dos)return nullptr;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + dos->e_lfanew);
	if (!nt)return nullptr;
	PMEMORYMODULE pModule = (PMEMORYMODULE)((LPBYTE)hModule + nt->OptionalHeader.SizeOfHeaders);
	if (pModule->Signature != MEMORY_MODULE_SIGNATURE || (size_t)pModule->codeBase != nt->OptionalHeader.ImageBase)return nullptr;
	return pModule;
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
static SIZE_T GetRealSectionSize(PMEMORYMODULE module, PIMAGE_SECTION_HEADER section);
static VOID FinalSectionsProtect(PMEMORYMODULE module) {
	PIMAGE_NT_HEADERS headers = GetImageNtHeaders(module);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	DWORD protect, oldProtect;
	bool executable, readable, writeable;
#ifdef _WIN64
	uintptr_t imageOffset = ((uintptr_t)headers->OptionalHeader.ImageBase & 0xffffffff00000000);
#else
	static const uintptr_t imageOffset = 0;
#endif
	for (WORD i = 0; i < headers->FileHeader.NumberOfSections; ++i, ++sections) {
		executable = (sections->Characteristics & IMAGE_SCN_MEM_EXECUTE);
		readable = (sections->Characteristics & IMAGE_SCN_MEM_READ);
		writeable = (sections->Characteristics & IMAGE_SCN_MEM_WRITE);
		protect = ProtectionFlags[executable][readable][writeable];
		if (sections->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) protect |= PAGE_NOCACHE;
		VirtualProtect((LPVOID)((uintptr_t)sections->Misc.PhysicalAddress | imageOffset),
			GetRealSectionSize(module, sections), protect, &oldProtect);
	}
	return;
}

static BOOL CheckSize(size_t size, size_t expected) {
	if (size < expected) {
		SetLastError(ERROR_INVALID_DATA);
		return FALSE;
	}

	return TRUE;
}

static BOOL CopySections(const unsigned char* data, size_t size, PMEMORYMODULE module) {
	LPBYTE codeBase = module->codeBase;
	LPVOID dest;
	PIMAGE_NT_HEADERS headers = GetImageNtHeaders(module);
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(headers);
	size_t alloc_size = 0;
	bool cp = false;
	for (int i = 0; i < headers->FileHeader.NumberOfSections; i++, section++) {
		alloc_size = headers->OptionalHeader.SectionAlignment;
		cp = false;
		if (section->SizeOfRawData) {
			if (!CheckSize(size, static_cast<size_t>(section->PointerToRawData) + section->SizeOfRawData)) return FALSE;
			alloc_size = section->SizeOfRawData;
			cp = true;
		}
		if (alloc_size) {
			if (!(dest = VirtualAlloc(codeBase + section->VirtualAddress, alloc_size, MEM_COMMIT, PAGE_READWRITE))) {
				//section = IMAGE_FIRST_SECTION(headers);
				//for (int j = 0; j < i; ++j, ++section)VirtualFree(codeBase + section->VirtualAddress, 0, MEM_RELEASE);
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
	if (!sectionData->size) return TRUE;
	if (sectionData->characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
		// section is not needed any more and can safely be freed
		if (sectionData->address == sectionData->alignedAddress &&
			(sectionData->last || GetImageNtHeaders(module)->OptionalHeader.SectionAlignment == module->pageSize || !(sectionData->size % module->pageSize))) {
#pragma warning (disable:6250)
			VirtualFree(sectionData->address, sectionData->size, MEM_DECOMMIT);
#pragma warning (default:6250)
		}
		return TRUE;
	}
	return TRUE;
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

	// loop through all sections and change access flags
	for (int i = 1; i < headers->FileHeader.NumberOfSections; i++, section++) {
		LPVOID sectionAddress = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
		LPVOID alignedAddress = AlignAddressDown(sectionAddress, module->pageSize);
		SIZE_T sectionSize = GetRealSectionSize(module, section);
		if (sectionData.alignedAddress == alignedAddress || (uintptr_t)sectionData.address + sectionData.size > (uintptr_t) alignedAddress) {
			if (!(section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) || !(sectionData.characteristics & IMAGE_SCN_MEM_DISCARDABLE))
				sectionData.characteristics = (sectionData.characteristics | section->Characteristics) & ~IMAGE_SCN_MEM_DISCARDABLE;
			else
				sectionData.characteristics |= section->Characteristics;
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
	PIMAGE_NT_HEADERS headers = GetImageNtHeaders(module);
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

static BOOL BuildImportTable(PMEMORYMODULE module) {
	unsigned char* codeBase = module->codeBase;
	PIMAGE_IMPORT_DESCRIPTOR importDesc;
	BOOL result = TRUE;
	PIMAGE_NT_HEADERS headers = GetImageNtHeaders(module);
	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(headers, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (directory->Size == 0) {
		return TRUE;
	}

	importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(codeBase + directory->VirtualAddress);
	for (; !IsBadReadPtr(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && importDesc->Name; importDesc++) {
		uintptr_t* thunkRef;
		FARPROC* funcRef;
		HMODULE* tmp;
		HMODULE handle = LoadLibraryA((LPCSTR)(codeBase + importDesc->Name));
		if (!handle) {
			SetLastError(ERROR_MOD_NOT_FOUND);
			result = FALSE;
			break;
		}

		if (!(tmp = (HMODULE*)realloc(module->hModulesList, (static_cast<size_t>(module->dwModulesCount) + 1)* (sizeof(HMODULE))))) {
			FreeLibrary(handle);
			SetLastError(ERROR_OUTOFMEMORY);
			result = FALSE;
			break;
		}
		module->hModulesList = tmp;

		module->hModulesList[module->dwModulesCount++] = handle;
		if (importDesc->OriginalFirstThunk) {
			thunkRef = (uintptr_t*)(codeBase + importDesc->OriginalFirstThunk);
			funcRef = (FARPROC*)(codeBase + importDesc->FirstThunk);
		}
		else {
			// no hint table
			thunkRef = (uintptr_t*)(codeBase + importDesc->FirstThunk);
			funcRef = (FARPROC*)(codeBase + importDesc->FirstThunk);
		}
		for (; *thunkRef; thunkRef++, funcRef++) {
			if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
				*funcRef = GetProcAddress(handle, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
			}
			else {
				PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(codeBase + (*thunkRef));
				*funcRef = GetProcAddress(handle, (LPCSTR)&thunkData->Name);
			}
			if (*funcRef == 0) {
				result = FALSE;
				break;
			}
		}

		if (!result) {
			FreeLibrary(handle);
			SetLastError(ERROR_PROC_NOT_FOUND);
			break;
		}
	}

	return result;
}

HMEMORYMODULE MemoryLoadLibrary(const void* data, size_t size) {
	PMEMORYMODULE hMemoryModule = nullptr;
	PIMAGE_DOS_HEADER dos_header, new_dos_header;
	PIMAGE_NT_HEADERS old_header, new_header;
	unsigned char* code;
	ptrdiff_t locationDelta;
	SYSTEM_INFO sysInfo;
	PIMAGE_SECTION_HEADER section;
	DWORD i;
	size_t optionalSectionSize;
	size_t lastSectionEnd = 0;
	size_t alignedImageSize;
	DWORD headers_align;
#ifdef _WIN64
	POINTER_LIST* blockedMemory = nullptr;
#endif

	if (!CheckSize(size, sizeof(IMAGE_DOS_HEADER))) return nullptr;
	dos_header = (PIMAGE_DOS_HEADER)data;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		SetLastError(ERROR_BAD_EXE_FORMAT);
		return nullptr;
	}

	if (!CheckSize(size, dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS))) return nullptr;
	old_header = (PIMAGE_NT_HEADERS) & ((const unsigned char*)(data))[dos_header->e_lfanew];
	if (old_header->Signature != IMAGE_NT_SIGNATURE) {
		SetLastError(ERROR_BAD_EXE_FORMAT);
		return nullptr;
	}

	if (old_header->FileHeader.Machine != HOST_MACHINE) {
		SetLastError(ERROR_BAD_EXE_FORMAT);
		return nullptr;
	}

	if (old_header->OptionalHeader.SectionAlignment & 1) {
		// Only support section alignments that are a multiple of 2
		SetLastError(ERROR_BAD_EXE_FORMAT);
		return nullptr;
	}

	//only dll image support
	if (!(old_header->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
		SetLastError(ERROR_NOT_SUPPORTED);
		return nullptr;
	}

	section = IMAGE_FIRST_SECTION(old_header);
	optionalSectionSize = old_header->OptionalHeader.SectionAlignment;
	for (i = 0; i < old_header->FileHeader.NumberOfSections; i++, section++) {
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

	GetNativeSystemInfo(&sysInfo);
	alignedImageSize = AlignValueUp(old_header->OptionalHeader.SizeOfImage, sysInfo.dwPageSize);
	if (alignedImageSize != AlignValueUp(lastSectionEnd, sysInfo.dwPageSize)) {
		SetLastError(ERROR_BAD_EXE_FORMAT);
		return nullptr;
	}
	alignedImageSize += headers_align = (DWORD)AlignValueUp(sizeof(HMEMORYMODULE) + old_header->OptionalHeader.SizeOfHeaders, sysInfo.dwPageSize);

	// reserve memory for image of library
	// XXX: is it correct to commit the complete memory region at once?
	//      calling DllEntry raises an exception if we don't...
	if (!(code = (LPBYTE)VirtualAlloc((LPVOID)(old_header->OptionalHeader.ImageBase), alignedImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
		if (!(old_header->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) {
			SetLastError(ERROR_BAD_EXE_FORMAT);
			return nullptr;
		}
		if (!(code = (LPBYTE)VirtualAlloc(nullptr, alignedImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
			SetLastError(ERROR_OUTOFMEMORY);
			return nullptr;
		}
	}

#ifdef _WIN64
	// Memory block may not span 4 GB boundaries.
	while ((((uintptr_t)code) >> 32) < (((uintptr_t)(code + alignedImageSize)) >> 32)) {
		POINTER_LIST* node = new POINTER_LIST;
		if (!node) {
			VirtualFree(code, 0, MEM_RELEASE);
			FreePointerList(blockedMemory);
			SetLastError(ERROR_OUTOFMEMORY);
			return nullptr;
		}

		node->next = blockedMemory;
		node->address = code;
		blockedMemory = node;

		if (!(code = (LPBYTE)VirtualAlloc(nullptr, alignedImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
			FreePointerList(blockedMemory);
			SetLastError(ERROR_OUTOFMEMORY);
			return nullptr;
		}
	}
#endif

	new_dos_header = (PIMAGE_DOS_HEADER)code;
	new_header = (PIMAGE_NT_HEADERS)(code + dos_header->e_lfanew);
	hMemoryModule = (PMEMORYMODULE)(code + old_header->OptionalHeader.SizeOfHeaders);
	RtlZeroMemory(hMemoryModule, sizeof(MEMORYMODULE));
	hMemoryModule->codeBase = code;
	hMemoryModule->pageSize = sysInfo.dwPageSize;
	hMemoryModule->Signature = MEMORY_MODULE_SIGNATURE;
	hMemoryModule->SizeofHeaders = old_header->OptionalHeader.SizeOfHeaders;
	hMemoryModule->headers_align = headers_align;
#ifdef _WIN64
	hMemoryModule->blockedMemory = blockedMemory;
#endif

	if (!CheckSize(size, old_header->OptionalHeader.SizeOfHeaders)) {
		goto error;
	}

	// copy PE header to code
	memcpy(new_dos_header, dos_header, old_header->OptionalHeader.SizeOfHeaders);
	new_header->OptionalHeader.SizeOfImage = (DWORD)(alignedImageSize);
	new_header->OptionalHeader.ImageBase = (size_t)code;
	new_header->OptionalHeader.BaseOfCode = headers_align;

	// copy sections from DLL file block to new memory location
	if (!CopySections((LPBYTE)data, size, hMemoryModule)) goto error;

	// adjust base address of imported data
	locationDelta = (ptrdiff_t)(hMemoryModule->codeBase - old_header->OptionalHeader.ImageBase);
	if (locationDelta && !PerformBaseRelocation(hMemoryModule, locationDelta))goto error;

	// load required dlls and adjust function table of imports
	if (!BuildImportTable(hMemoryModule)) goto error;

	// mark memory pages depending on section headers and release
	// sections that are marked as "discardable"
	if (!FinalizeSections(hMemoryModule)) goto error;
	FinalSectionsProtect(hMemoryModule);

	// TLS callbacks are executed BEFORE the main loading
	if (!ExecuteTLS(hMemoryModule)) goto error;

	// get entry point of loaded library
	if (new_header->OptionalHeader.AddressOfEntryPoint) {
		__try {
			// notify library about attaching to process
			if (!((DllEntryProc)(code + new_header->OptionalHeader.AddressOfEntryPoint))((HINSTANCE)code, DLL_PROCESS_ATTACH, 0)) {
				SetLastError(ERROR_DLL_INIT_FAILED);
				goto error;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			SetLastError(ERROR_ACCESS_DENIED);
			goto error;
		}
		hMemoryModule->initialized = TRUE;
	}
	
	return code;
error:
	// cleanup
	MemoryFreeLibrary(hMemoryModule);
	return nullptr;
}

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
	unsigned char* codeBase = module->codeBase - module->headers_align;
	DWORD idx = 0;
	PIMAGE_EXPORT_DIRECTORY exports;
	PIMAGE_NT_HEADERS headers = GetImageNtHeaders(module);
	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(headers, IMAGE_DIRECTORY_ENTRY_EXPORT);
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

bool MemoryFreeLibrary(HMEMORYMODULE mod) {
	PMEMORYMODULE module = MapMemoryModuleHandle(mod);
	PIMAGE_NT_HEADERS headers = module ? GetImageNtHeaders(module) : nullptr;

	if (!module || module->Signature != MEMORY_MODULE_SIGNATURE || !headers) return false;
	if (module->initialized) {
		DllEntryProc DllEntry = (DllEntryProc)(LPVOID)(module->codeBase + headers->OptionalHeader.AddressOfEntryPoint);
		(*DllEntry)((HINSTANCE)module->codeBase, DLL_PROCESS_DETACH, 0);
	}
	if (module->nameExportsTable)delete[] module->nameExportsTable;
	if (module->hModulesList != nullptr) {
		int i;
		for (i = 0; i < module->dwModulesCount; i++) {
			if (module->hModulesList[i]) {
				FreeLibrary(module->hModulesList[i]);
			}
		}
		free(module->hModulesList);
	}
#ifdef _WIN64
	FreePointerList(module->blockedMemory);
#endif
	if (module->codeBase != nullptr) VirtualFree(mod, 0, MEM_RELEASE);
	return true;
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
	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(GetImageNtHeaders(mod), IMAGE_DIRECTORY_ENTRY_RESOURCE);
	PIMAGE_RESOURCE_DIRECTORY rootResources;
	PIMAGE_RESOURCE_DIRECTORY nameResources;
	PIMAGE_RESOURCE_DIRECTORY typeResources;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY foundType;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY foundName;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY foundLanguage;
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
