#pragma once
#include <Windows.h>

typedef HMODULE HMEMORYMODULE;
#include "NativeFunctionsInternal.h"

#define MemoryModuleToModule(_hMemoryModule_) (_hMemoryModule_)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

HMEMORYMODULE WINAPI LoadLibraryMemory(PVOID BufferAddress);

HMEMORYMODULE WINAPI LoadLibraryMemoryExA(PVOID BufferAddress, size_t Reserved, LPCSTR DllBaseName, LPCSTR DllFullName, DWORD Flags);

HMEMORYMODULE WINAPI LoadLibraryMemoryExW(PVOID BufferAddress, size_t Reserved, LPCWSTR DllBaseName, LPCWSTR DllFullName, DWORD Flags);

BOOL WINAPI FreeLibraryMemory(HMEMORYMODULE hMemoryModule);

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



