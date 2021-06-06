#include "stdafx.h"

HMEMORYMODULE WINAPI LoadLibraryMemory(PVOID BufferAddress) {
	HMEMORYMODULE hMemoryModule = nullptr;
	NTSTATUS status = LdrLoadDllMemory(&hMemoryModule, BufferAddress, 0);
	if (!NT_SUCCESS(status)) {
		SetLastError(RtlNtStatusToDosError(status));
	}
	return hMemoryModule;
}

HMEMORYMODULE WINAPI LoadLibraryMemoryExA(PVOID BufferAddress, size_t Reserved, LPCSTR DllBaseName, LPCSTR DllFullName, DWORD Flags) {
	HMEMORYMODULE hMemoryModule = nullptr;
	NTSTATUS status = LdrLoadDllMemoryExA(&hMemoryModule, nullptr, Flags, BufferAddress, Reserved, DllBaseName, DllFullName);
	if (!NT_SUCCESS(status)) {
		SetLastError(RtlNtStatusToDosError(status));
	}
	return hMemoryModule;
}

HMEMORYMODULE WINAPI LoadLibraryMemoryExW(PVOID BufferAddress, size_t Reserved, LPCWSTR DllBaseName, LPCWSTR DllFullName, DWORD Flags) {
	HMEMORYMODULE hMemoryModule = nullptr;
	NTSTATUS status = LdrLoadDllMemoryExW(&hMemoryModule, nullptr, Flags, BufferAddress, Reserved, DllBaseName, DllFullName);
	if (!NT_SUCCESS(status)) {
		SetLastError(RtlNtStatusToDosError(status));
	}
	return hMemoryModule;
}

BOOL WINAPI FreeLibraryMemory(HMEMORYMODULE hMemoryModule) {
	NTSTATUS status = LdrUnloadDllMemory(hMemoryModule);
	if (!NT_SUCCESS(status)) {
		SetLastError(RtlNtStatusToDosError(status));
		return FALSE;
	}
	return TRUE;
}
