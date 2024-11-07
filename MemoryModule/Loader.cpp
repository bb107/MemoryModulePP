#include "stdafx.h"
#include <cmath>

#ifdef _USRDLL
#if (defined(_WIN64) || defined(_M_ARM))
#pragma comment(linker,"/export:LdrUnloadDllMemoryAndExitThread")
#pragma comment(linker,"/export:FreeLibraryMemoryAndExitThread=LdrUnloadDllMemoryAndExitThread")
#else
#pragma comment(linker,"/export:LdrUnloadDllMemoryAndExitThread=_LdrUnloadDllMemoryAndExitThread@8")
#pragma comment(linker,"/export:FreeLibraryMemoryAndExitThread=_LdrUnloadDllMemoryAndExitThread@8")
#endif
#endif

NTSTATUS NTAPI LdrMapDllMemory(
	_In_ HMEMORYMODULE ViewBase,
	_In_ DWORD dwFlags,
	_In_opt_ PCWSTR DllName,
	_In_opt_ PCWSTR lpFullDllName,
	_Out_opt_ PLDR_DATA_TABLE_ENTRY* DataTableEntry) {

	UNICODE_STRING FullDllName, BaseDllName;
	PIMAGE_NT_HEADERS NtHeaders;
	PLDR_DATA_TABLE_ENTRY LdrEntry;
	HANDLE heap = NtCurrentPeb()->ProcessHeap;

	if (!(NtHeaders = RtlImageNtHeader(ViewBase))) return STATUS_INVALID_IMAGE_FORMAT;

	if (!(LdrEntry = RtlAllocateDataTableEntry(ViewBase))) return STATUS_NO_MEMORY;

	if (!NT_SUCCESS(RtlResolveDllNameUnicodeString(DllName, lpFullDllName, &BaseDllName, &FullDllName))) {
		RtlFreeHeap(heap, 0, LdrEntry);
		return STATUS_NO_MEMORY;
	}

	if (!RtlInitializeLdrDataTableEntry(LdrEntry, dwFlags, ViewBase, BaseDllName, FullDllName)) {
		RtlFreeHeap(heap, 0, LdrEntry);
		RtlFreeHeap(heap, 0, BaseDllName.Buffer);
		RtlFreeHeap(heap, 0, FullDllName.Buffer);
		return STATUS_UNSUCCESSFUL;
	}

	RtlInsertMemoryTableEntry(LdrEntry);
	if (DataTableEntry)*DataTableEntry = LdrEntry;
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI LdrLoadDllMemoryExW(
	_Out_ HMEMORYMODULE* BaseAddress,
	_Out_opt_ PVOID* LdrEntry,
	_In_ DWORD dwFlags,
	_In_ LPVOID BufferAddress,
	_In_ size_t BufferSize,
	_In_opt_ LPCWSTR DllName,
	_In_opt_ LPCWSTR DllFullName) {
	PMEMORYMODULE module = nullptr;
	NTSTATUS status = STATUS_SUCCESS;
	PLDR_DATA_TABLE_ENTRY ModuleEntry = nullptr;
	PIMAGE_NT_HEADERS headers = nullptr;

	if (BufferSize)return STATUS_INVALID_PARAMETER_5;
	__try {
		*BaseAddress = nullptr;
		if (LdrEntry)*LdrEntry = nullptr;

		if (!RtlIsValidImageBuffer(BufferAddress, &BufferSize) && !(dwFlags & LOAD_FLAGS_PASS_IMAGE_CHECK)) {
			status = STATUS_INVALID_IMAGE_FORMAT;
		}

		if (MmpGlobalDataPtr == nullptr) {
			status = STATUS_INVALID_PARAMETER;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}
	if (!NT_SUCCESS(status))return status;

	if (dwFlags & LOAD_FLAGS_NOT_MAP_DLL) {
		dwFlags &= LOAD_FLAGS_NOT_MAP_DLL;
		DllName = DllFullName = nullptr;
	}
	if (dwFlags & LOAD_FLAGS_USE_DLL_NAME && (!DllName || !DllFullName))return STATUS_INVALID_PARAMETER_3;

	if (DllName) {
		int length = (int)wcslen(DllName);
		PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList, ListEntry = ListHead->Flink;
		PIMAGE_NT_HEADERS h1 = RtlImageNtHeader(BufferAddress), h2 = nullptr;
		if (!h1)return STATUS_INVALID_IMAGE_FORMAT;
		
		while (ListEntry != ListHead) {
			PLDR_DATA_TABLE_ENTRY CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			ListEntry = ListEntry->Flink;

			/* Check if it's being unloaded */
			if (!CurEntry->InMemoryOrderLinks.Flink) continue;

			auto dist = (CurEntry->BaseDllName.Length / sizeof(wchar_t)) - length;
			bool equal = false;
			if (dist == 0 || dist == 4) {
				equal = !_wcsnicmp(DllName, CurEntry->BaseDllName.Buffer, length);
			}
			else {
				continue;
			}
			
			/* Check if name matches */
			if (equal) {

				/* Let's compare their headers */
				if (!(h2 = RtlImageNtHeader(CurEntry->DllBase)))continue;
				if (!(module = MapMemoryModuleHandle((HMEMORYMODULE)CurEntry->DllBase)))continue;
				if ((h1->OptionalHeader.SizeOfCode == h2->OptionalHeader.SizeOfCode) &&
					(h1->OptionalHeader.SizeOfHeaders == h2->OptionalHeader.SizeOfHeaders)) {
				
					/* This is our entry!, update load count and return success */
					if (!module->UseReferenceCount || dwFlags & LOAD_FLAGS_NOT_USE_REFERENCE_COUNT)return STATUS_INVALID_PARAMETER_3;
					
					RtlUpdateReferenceCount(module, FLAG_REFERENCE);
					*BaseAddress = (HMEMORYMODULE)CurEntry->DllBase;
					if (LdrEntry)*LdrEntry = CurEntry;
					return STATUS_SUCCESS;
				}
			}
		}
	}

	status = MemoryLoadLibrary(BaseAddress, BufferAddress, (DWORD)BufferSize);
	if (!NT_SUCCESS(status) || status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH)return status;

	if (!(module = MapMemoryModuleHandle(*BaseAddress))) {
		__fastfail(FAST_FAIL_FATAL_APP_EXIT);
		DebugBreak();
		ExitProcess(STATUS_INVALID_ADDRESS);
		TerminateProcess(NtCurrentProcess(), STATUS_INVALID_ADDRESS);
	}
	module->loadFromLdrLoadDllMemory = true;

	headers = RtlImageNtHeader(*BaseAddress);
	if (headers->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)dwFlags |= LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION;

	if (dwFlags & LOAD_FLAGS_NOT_MAP_DLL) {

		do {
			status = MemoryResolveImportTable(LPBYTE(*BaseAddress), headers, module);
			if (!NT_SUCCESS(status))break;

			status = MemorySetSectionProtection(LPBYTE(*BaseAddress), headers);
			if (!NT_SUCCESS(status))break;

			if (!LdrpExecuteTLS(module) || !LdrpCallInitializers(module, DLL_PROCESS_ATTACH)) {
				status = STATUS_DLL_INIT_FAILED;
				break;
			}

		} while (false);

		if (!NT_SUCCESS(status)) {
			MemoryFreeLibrary(*BaseAddress);
		}

		return status;
	}

	do {

		status = LdrMapDllMemory(*BaseAddress, dwFlags, DllName, DllFullName, &ModuleEntry);
		if (!NT_SUCCESS(status))break;

		module->MappedDll = true;
		module->LdrEntry = ModuleEntry;

		status = MemoryResolveImportTable(LPBYTE(*BaseAddress), headers, module);
		if (!NT_SUCCESS(status))break;

		status = MemorySetSectionProtection(LPBYTE(*BaseAddress), headers);
		if (!NT_SUCCESS(status))break;

		if (!(dwFlags & LOAD_FLAGS_NOT_USE_REFERENCE_COUNT))module->UseReferenceCount = true;

		if (!(dwFlags & LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION)) {
			status = RtlInsertInvertedFunctionTable((PVOID)module->codeBase, headers->OptionalHeader.SizeOfImage);
			if (!NT_SUCCESS(status)) break;

			module->InsertInvertedFunctionTableEntry = true;
		}

		if (!(dwFlags & LOAD_FLAGS_NOT_HANDLE_TLS)) {
			status = MmpGlobalDataPtr->MmpFunctions->_MmpHandleTlsData(ModuleEntry);
			if (!NT_SUCCESS(status)) {
				if (dwFlags & LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS) status = 0x7fffffff;
				if (!NT_SUCCESS(status))break;
			}
			else {
				module->TlsHandled = true;
			}
		}

		if (dwFlags & LOAD_FLAGS_HOOK_DOT_NET) {
			MmpPreInitializeHooksForDotNet();
		}

		if (!LdrpExecuteTLS(module) || !LdrpCallInitializers(module, DLL_PROCESS_ATTACH)) {
			status = STATUS_DLL_INIT_FAILED;
			break;
		}

		if (dwFlags & LOAD_FLAGS_HOOK_DOT_NET) {
			MmpInitializeHooksForDotNet();
		}

	} while (false);

	if (NT_SUCCESS(status)) {
		if (LdrEntry)*LdrEntry = ModuleEntry;
	}
	else {
		LdrUnloadDllMemory(*BaseAddress);
		*BaseAddress = nullptr;
	}

	return status;
}

NTSTATUS NTAPI LdrUnloadDllMemory(_In_ HMEMORYMODULE BaseAddress) {
	PLDR_DATA_TABLE_ENTRY CurEntry;
	ULONG count = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PMEMORYMODULE module = MapMemoryModuleHandle(BaseAddress);
	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(BaseAddress);

	do {

		//Not a memory module loaded via LdrLoadDllMemory
		if (!module || !module->loadFromLdrLoadDllMemory) {
			status = STATUS_INVALID_HANDLE;
			break;
		}

		if (MmpGlobalDataPtr == nullptr) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		//Mapping dll failed
		if (!module->MappedDll) {
			module->underUnload = true;
			status = (MemoryFreeLibrary(BaseAddress) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL);
			break;
		}

		CurEntry = (PLDR_DATA_TABLE_ENTRY)module->LdrEntry;

		if (headers->OptionalHeader.SizeOfImage != CurEntry->SizeOfImage) __fastfail(FAST_FAIL_FATAL_APP_EXIT);

		if (module->UseReferenceCount) {
			status = RtlGetReferenceCount(module, &count);
			if (!NT_SUCCESS(status)) break;
		}

		if (count & ~1) {
			status = RtlUpdateReferenceCount(module, FLAG_DEREFERENCE);
			break;
		}

		module->underUnload = true;
		if (module->initialized) {
			PLDR_INIT_ROUTINE((LPVOID)(module->codeBase + headers->OptionalHeader.AddressOfEntryPoint))(
				(HINSTANCE)module->codeBase,
				DLL_PROCESS_DETACH,
				0
				);
		}

		if (module->MappedDll) {
			if (module->InsertInvertedFunctionTableEntry) {
				status = RtlRemoveInvertedFunctionTable(BaseAddress);
				if (!NT_SUCCESS(status)) __fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
			}

			if (module->TlsHandled) {
				status = MmpGlobalDataPtr->MmpFunctions->_MmpReleaseTlsEntry(CurEntry);
				if (!NT_SUCCESS(status)) __fastfail(FAST_FAIL_FATAL_APP_EXIT);
			}

			if (!RtlFreeLdrDataTableEntry(CurEntry)) __fastfail(FAST_FAIL_FATAL_APP_EXIT);
		}

		if (!MemoryFreeLibrary(BaseAddress)) __fastfail(FAST_FAIL_FATAL_APP_EXIT);

	} while (false);

	return status;
}

DECLSPEC_NORETURN
VOID NTAPI LdrUnloadDllMemoryAndExitThread(_In_ HMEMORYMODULE BaseAddress, _In_ DWORD dwExitCode) {
	LdrUnloadDllMemory(BaseAddress);
	RtlExitUserThread(dwExitCode);
}

NTSTATUS NTAPI LdrQuerySystemMemoryModuleFeatures(_Out_ PDWORD pFeatures) {
	NTSTATUS status = STATUS_SUCCESS;
	__try {
		*pFeatures = MmpGlobalDataPtr->MmpFeatures;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}
	return status;
}
