#include "stdafx.h"

HMEMORYMODULE WINAPI LoadLibraryMemory(_In_ PVOID BufferAddress) {
	HMEMORYMODULE hMemoryModule = nullptr;
	NTSTATUS status = LdrLoadDllMemory(&hMemoryModule, BufferAddress, 0);
	if (!NT_SUCCESS(status) || status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {
		SetLastError(RtlNtStatusToDosError(status));
	}
	return hMemoryModule;
}

HMEMORYMODULE WINAPI LoadLibraryMemoryExA(
	_In_ PVOID BufferAddress,
	_In_ size_t Reserved,
	_In_opt_ LPCSTR DllBaseName,
	_In_opt_ LPCSTR DllFullName,
	_In_ DWORD Flags) {
	HMEMORYMODULE hMemoryModule = nullptr;
	NTSTATUS status = LdrLoadDllMemoryExA(&hMemoryModule, nullptr, Flags, BufferAddress, Reserved, DllBaseName, DllFullName);
	if (!NT_SUCCESS(status) || status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {
		SetLastError(RtlNtStatusToDosError(status));
	}
	return hMemoryModule;
}

HMEMORYMODULE WINAPI LoadLibraryMemoryExW(
	_In_ PVOID BufferAddress,
	_In_ size_t Reserved,
	_In_opt_ LPCWSTR DllBaseName,
	_In_opt_ LPCWSTR DllFullName,
	_In_ DWORD Flags) {
	HMEMORYMODULE hMemoryModule = nullptr;
	NTSTATUS status = LdrLoadDllMemoryExW(&hMemoryModule, nullptr, Flags, BufferAddress, Reserved, DllBaseName, DllFullName);
	if (!NT_SUCCESS(status) || status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {
		SetLastError(RtlNtStatusToDosError(status));
	}
	return hMemoryModule;
}

BOOL WINAPI FreeLibraryMemory(_In_ HMEMORYMODULE hMemoryModule) {
	NTSTATUS status = LdrUnloadDllMemory(hMemoryModule);
	if (!NT_SUCCESS(status)) {
		SetLastError(RtlNtStatusToDosError(status));
		return FALSE;
	}
	return TRUE;
}
