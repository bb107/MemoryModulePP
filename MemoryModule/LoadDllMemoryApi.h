#pragma once
#include <Windows.h>

typedef HMODULE HMEMORYMODULE;
#include "Loader.h"
#include "Initialize.h"

#define MemoryModuleToModule(_hMemoryModule_) (_hMemoryModule_)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

extern "C" {

	HMEMORYMODULE WINAPI LoadLibraryMemory(_In_ PVOID BufferAddress);

	HMEMORYMODULE WINAPI LoadLibraryMemoryExA(
		_In_ PVOID BufferAddress,
		_In_ size_t Reserved,
		_In_opt_ LPCSTR DllBaseName,
		_In_opt_ LPCSTR DllFullName,
		_In_ DWORD Flags
	);

	HMEMORYMODULE WINAPI LoadLibraryMemoryExW(
		_In_ PVOID BufferAddress,
		_In_ size_t Reserved,
		_In_opt_ LPCWSTR DllBaseName,
		_In_opt_ LPCWSTR DllFullName,
		_In_ DWORD Flags
	);

	BOOL WINAPI FreeLibraryMemory(_In_ HMEMORYMODULE hMemoryModule);

}

#define NtLoadDllMemory						LdrLoadDllMemory
#define NtLoadDllMemoryExA					LdrLoadDllMemoryExA
#define NtLoadDllMemoryExW					LdrLoadDllMemoryExW
#define NtUnloadDllMemory					LdrUnloadDllMemory
#define NtUnloadDllMemoryAndExitThread		LdrUnloadDllMemoryAndExitThread
#define FreeLibraryMemoryAndExitThread		LdrUnloadDllMemoryAndExitThread
#define NtQuerySystemMemoryModuleFeatures	LdrQuerySystemMemoryModuleFeatures

#ifdef UNICODE
#define LdrLoadDllMemoryEx LdrLoadDllMemoryExW
#define LoadLibraryMemoryEx LoadLibraryMemoryExW
#else
#define LdrLoadDllMemoryEx LdrLoadDllMemoryExA
#define LoadLibraryMemoryEx LoadLibraryMemoryExA
#endif
#define NtLoadDllMemoryEx LdrLoadDllMemoryEx



