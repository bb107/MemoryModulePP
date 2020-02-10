#include "Native.h"
#pragma warning(disable:6387)
#pragma warning(disable:26812)
#pragma comment(lib,"Secur32.lib")

FARPROC NTAPI RtlGetNtProcAddress(LPCSTR func_name) {
	return GetProcAddress(GetModuleHandleA("ntdll.dll"), func_name);
}

NTSTATUS NTAPI NtOpenProcessToken(IN HANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, OUT PHANDLE TokenHandle) {
	typedef NTSTATUS(NTAPI *NtOpenProcessToken_t)(IN HANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, OUT PHANDLE TokenHandle);
	return (((NtOpenProcessToken_t)RtlGetNtProcAddress("NtOpenProcessToken"))(ProcessHandle, DesiredAccess, TokenHandle));
}

NTSTATUS NTAPI NtDuplicateToken(IN HANDLE ExistingToken, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, IN TOKEN_TYPE TokenType, OUT PHANDLE NewToken) {
	typedef NTSTATUS(NTAPI *NtDuplicateToken_t)(IN HANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES OPTIONAL, IN SECURITY_IMPERSONATION_LEVEL, IN TOKEN_TYPE, OUT PHANDLE);
	return (((NtDuplicateToken_t)RtlGetNtProcAddress("NtDuplicateToken"))(ExistingToken, DesiredAccess, ObjectAttributes, ImpersonationLevel, TokenType, NewToken));
}

NTSTATUS NTAPI NtAdjustPrivilegesToken(IN HANDLE TokenHandle, IN BOOLEAN DisableAllPrivileges, IN PTOKEN_PRIVILEGES TokenPrivileges,
	IN ULONG PreviousPrivilegesLength, OUT PTOKEN_PRIVILEGES PreviousPrivileges OPTIONAL, OUT PULONG RequiredLength OPTIONAL) {
	typedef NTSTATUS(NTAPI *NtAdjustPrivilegesToken_t)(IN HANDLE, IN BOOLEAN, IN PTOKEN_PRIVILEGES, IN ULONG, OUT PTOKEN_PRIVILEGES OPTIONAL, OUT PULONG OPTIONAL);
	return (((NtAdjustPrivilegesToken_t)RtlGetNtProcAddress("NtAdjustPrivilegesToken"))
		(TokenHandle, DisableAllPrivileges, TokenPrivileges, PreviousPrivilegesLength, PreviousPrivileges, RequiredLength));
}

NTSTATUS NTAPI NtAllocateLocallyUniqueId(OUT PLUID LocallyUniqueId) {
	typedef NTSTATUS(NTAPI *NtAllocateLocallyUniqueId_t)(OUT PLUID LocallyUniqueId);
	return (((NtAllocateLocallyUniqueId_t)RtlGetNtProcAddress("NtAllocateLocallyUniqueId"))(LocallyUniqueId));
}

NTSTATUS NTAPI NtQueryObject(
	IN HANDLE               ObjectHandle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	OUT PVOID               ObjectInformation,
	IN ULONG                Length,
	OUT PULONG              ResultLength) {
	typedef NtQueryInformation_t NtQueryObject_t;
	return (((NtQueryObject_t)RtlGetNtProcAddress("NtQueryObject")))(ObjectHandle, ObjectInformationClass, ObjectInformation, Length, ResultLength);
}

NTSTATUS NTAPI NtSetInformationObject(
	IN HANDLE               ObjectHandle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	IN PVOID               ObjectInformation,
	IN ULONG                Length) {
	return (((NTSTATUS(__stdcall*)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG))RtlGetNtProcAddress("NtSetInformationObject")))
		(ObjectHandle, ObjectInformationClass, ObjectInformation, Length);
}

NTSTATUS NTAPI NtOpenThreadToken(
	IN HANDLE               ThreadHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN BOOLEAN              OpenAsSelf,
	OUT PHANDLE             TokenHandle) {
	typedef NTSTATUS (NTAPI *NtOpenThreadToken_t)(
		IN HANDLE               ThreadHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN BOOLEAN              OpenAsSelf,
		OUT PHANDLE             TokenHandle);
	return (((NtOpenThreadToken_t)RtlGetNtProcAddress("NtOpenThreadToken")))(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);
}

BOOL RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress) {
	return ((BOOL(__stdcall*)(PVOID, ULONG, PVOID))RtlGetNtProcAddress("RtlFreeHeap"))(HeapHandle, Flags, BaseAddress);
}

PVOID RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size) {
	return ((PVOID(__stdcall*)(PVOID, ULONG, SIZE_T))RtlGetNtProcAddress("RtlAllocateHeap"))(HeapHandle, Flags, Size);
}

PVOID RtlCreateHeap(ULONG Flags, PVOID HeapBase, SIZE_T ReserveSize, SIZE_T CommitSize, PVOID Lock, PRTL_HEAP_PARAMETERS Parameters) {
	return ((PVOID(__stdcall*)(ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PRTL_HEAP_PARAMETERS))RtlGetNtProcAddress("RtlCreateHeap"))(
		Flags, HeapBase, ReserveSize, CommitSize, Lock, Parameters);
}

PVOID BsRtlCreateHeap(ULONG Flags, SIZE_T ReserveSize, SIZE_T CommitSize) {
	return RtlCreateHeap(Flags | HEAP_GROWABLE, NULL, ReserveSize, CommitSize, NULL, NULL);
}

PVOID RtlDestroyHeap(PVOID HeapHandle) {
	return ((PVOID(__stdcall*)(PVOID))RtlGetNtProcAddress("RtlDestroyHeap"))(HeapHandle);
}

FARPROC WINAPI GetNtProcAddress(LPCSTR func_name) {
	return GetProcAddress(GetModuleHandleA("ntdll.dll"), func_name);
}

LPCSTR f_NtCreateToken = "NtCreateToken";
LPCSTR f_NtDuplicateObject = "NtDuplicateObject";
LPCSTR f_RtlNtStatusToDosError = "RtlNtStatusToDosError";
LPCSTR f_NtDuplicateToken = "NtDuplicateToken";

NTSTATUS NTAPI NtCreateToken(
	PHANDLE             TokenHandle,
	ACCESS_MASK          DesiredAccess,
	POBJECT_ATTRIBUTES   ObjectAttributes,
	TOKEN_TYPE           TokenType,
	PLUID                AuthenticationId,
	PLARGE_INTEGER       ExpirationTime,
	PTOKEN_USER          TokenUser,
	PTOKEN_GROUPS        TokenGroups,
	PTOKEN_PRIVILEGES    TokenPrivileges,
	PTOKEN_OWNER         TokenOwner,
	PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
	PTOKEN_DEFAULT_DACL  TokenDefaultDacl,
	PTOKEN_SOURCE        TokenSource) {
	return reinterpret_cast<NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, LPVOID, TOKEN_TYPE, PLUID,
		PLARGE_INTEGER, PTOKEN_USER, PTOKEN_GROUPS, PTOKEN_PRIVILEGES,
		PTOKEN_OWNER, PTOKEN_PRIMARY_GROUP, PTOKEN_DEFAULT_DACL, PTOKEN_SOURCE)>(GetNtProcAddress(f_NtCreateToken))(
			TokenHandle, DesiredAccess, ObjectAttributes, TokenType, AuthenticationId,
			ExpirationTime, TokenUser, TokenGroups, TokenPrivileges, TokenOwner,
			TokenPrimaryGroup, TokenDefaultDacl, TokenSource);
}

NTSTATUS NTAPI NtDuplicateObject(
	IN HANDLE               SourceProcessHandle,
	IN HANDLE               SourceHandle,
	IN HANDLE               TargetProcessHandle,
	OUT PHANDLE             TargetHandle,
	IN ACCESS_MASK          DesiredAccess OPTIONAL,
	IN BOOLEAN              InheritHandle,
	IN ULONG                Options) {
	return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, BOOLEAN, LONG)>(GetNtProcAddress(f_NtDuplicateObject))
		(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, InheritHandle, Options);
}

DWORD NTAPI RtlNtStatusToDosError(NTSTATUS status) {
	return reinterpret_cast<DWORD(NTAPI*)(NTSTATUS)>(GetNtProcAddress(f_RtlNtStatusToDosError))(status);
}

NTSTATUS NTAPI NtDuplicateToken(
	HANDLE ExistingTokenHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	BOOLEAN EffectiveOnly,
	TOKEN_TYPE TokenType,
	PHANDLE NewTokenHandle) {
	return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, TOKEN_TYPE, PHANDLE)>
		(GetNtProcAddress(f_NtDuplicateToken))(ExistingTokenHandle, DesiredAccess, ObjectAttributes, EffectiveOnly, TokenType, NewTokenHandle);
}

NTSTATUS NtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS _class, OUT PVOID buffer, IN ULONG buffer_size, OUT PULONG out_len) {
	return reinterpret_cast<NtQuerySystemInformation_t>(GetNtProcAddress("NtQuerySystemInformation"))(_class, buffer, buffer_size, out_len);
}

NTSTATUS WINAPI NtQueryInformationProcess(IN HANDLE hProcess, IN LONG _class, OUT PVOID buffer, IN ULONG buffer_size, OUT PULONG out_len) {
	return reinterpret_cast<NtQueryInformation_t>(GetNtProcAddress("NtQueryInformationProcess"))(hProcess, _class, buffer, buffer_size, out_len);
}

NTSTATUS WINAPI NtQueryInformationThread(IN HANDLE hThread, IN LONG _class, OUT PVOID buffer, IN ULONG buffer_size, OUT PULONG out_len) {
	return reinterpret_cast<NtQueryInformation_t>(GetNtProcAddress("NtQueryInformationThread"))(hThread, _class, buffer, buffer_size, out_len);
}

LPCSTR module = "kernel32.dll";
LPCSTR f_CreateProcessInternalW = "CreateProcessInternalW";
BOOL WINAPI CreateProcessInternalW(
	_In_opt_ HANDLE hUserToken,
	_In_opt_ LPCWSTR lpApplicationName,
	_Inout_opt_ LPWSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCWSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOW lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation,
	_Outptr_opt_ PHANDLE hRestrictedUserToken
) {
	return reinterpret_cast<BOOL(WINAPI*)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
		LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE)>
		(GetProcAddress(GetModuleHandleA(module), f_CreateProcessInternalW))(hUserToken, lpApplicationName,
			lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
			lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hRestrictedUserToken);
}

LPCSTR f_CreateProcessInternalA = "CreateProcessInternalA";
BOOL WINAPI CreateProcessInternalA(
	_In_opt_ HANDLE hUserToken,
	_In_opt_ LPCSTR lpApplicationName,
	_Inout_opt_ LPSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOA lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation,
	_Outptr_opt_ PHANDLE hRestrictedUserToken
) {
	return reinterpret_cast<BOOL(WINAPI*)(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
		LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION, PHANDLE)>
		(GetProcAddress(GetModuleHandleA(module), f_CreateProcessInternalA))(hUserToken, lpApplicationName,
			lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
			lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hRestrictedUserToken);
}

VOID NTAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
	return reinterpret_cast<VOID(NTAPI*)(PUNICODE_STRING, PCWSTR)>
		(RtlGetNtProcAddress("RtlInitUnicodeString"))(DestinationString, SourceString);
}

BOOL NTAPI RtlCreateUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
	return reinterpret_cast<BOOL(NTAPI*)(PUNICODE_STRING, PCWSTR)>
		(RtlGetNtProcAddress("RtlCreateUnicodeString"))(DestinationString, SourceString);
}

VOID NTAPI RtlFreeUnicodeString(PUNICODE_STRING UnicodeString) {
	return reinterpret_cast<VOID(NTAPI*)(PUNICODE_STRING)>
		(RtlGetNtProcAddress("RtlFreeUnicodeString"))(UnicodeString);
}

NTSTATUS NTAPI NtClose(IN HANDLE Handle) {
	return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE)>(RtlGetNtProcAddress("NtClose"))(Handle);
}

NTSTATUS NTAPI RtlCreateUserThread(
	IN HANDLE               ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN              CreateSuspended,
	IN ULONG                StackZeroBits,
	IN SIZE_T               StackReserved,
	IN SIZE_T               StackCommit,
	IN PVOID                StartAddress,
	IN PVOID                StartParameter OPTIONAL,
	OUT PHANDLE             ThreadHandle,
	OUT CLIENT_ID*          ClientID) {
	return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, CLIENT_ID*)>
		(RtlGetNtProcAddress("RtlCreateUserThread"))(
			ProcessHandle, SecurityDescriptor, CreateSuspended, StackZeroBits,
			StackReserved, StackCommit, StartAddress, StartParameter, ThreadHandle, ClientID);
}

NTSTATUS NTAPI NtAllocateVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN ULONG                ZeroBits,
	IN OUT PULONG           RegionSize,
	IN ULONG                AllocationType,
	IN ULONG                Protect) {
	return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PVOID, ULONG, PULONG, ULONG, ULONG)>(RtlGetNtProcAddress("NtAllocateVirtualMemory"))
		(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}
NTSTATUS NTAPI NtFreeVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                *BaseAddress,
	IN OUT PULONG           RegionSize,
	IN ULONG                FreeType) {
	return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PVOID, PULONG, ULONG)>(RtlGetNtProcAddress("NtFreeVirtualMemory"))
		(ProcessHandle, BaseAddress, RegionSize, FreeType);
}
NTSTATUS NTAPI NtReadVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	OUT PVOID               Buffer,
	IN ULONG                NumberOfBytesToRead,
	OUT PULONG              NumberOfBytesReaded OPTIONAL) {
	return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, ULONG, PULONG)>(RtlGetNtProcAddress("NtReadVirtualMemory"))
		(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
}
NTSTATUS NTAPI NtWriteVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL) {
	return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, ULONG, PULONG)>(RtlGetNtProcAddress("NtWriteVirtualMemory"))
		(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}
NTSTATUS NTAPI NtProtectVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN OUT PSIZE_T           NumberOfBytesToProtect,
	IN SIZE_T                NewAccessProtection,
	OUT PSIZE_T              OldAccessProtection) {
	return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PVOID, PSIZE_T, SIZE_T, PSIZE_T)>(RtlGetNtProcAddress("NtProtectVirtualMemory"))
		(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}
NTSTATUS NTAPI NtLockVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                *BaseAddress,
	IN OUT PULONG           NumberOfBytesToLock,
	IN ULONG                LockOption) {
	return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PVOID, PULONG, ULONG)>(RtlGetNtProcAddress("NtLockVirtualMemory"))
		(ProcessHandle, BaseAddress, NumberOfBytesToLock, LockOption);
}
NTSTATUS NTAPI NtUnlockVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                *BaseAddress,
	IN OUT PULONG           NumberOfBytesToUnlock,
	IN ULONG                LockType) {
	return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PVOID, PULONG, ULONG)>(RtlGetNtProcAddress("NtUnlockVirtualMemory"))
		(ProcessHandle, BaseAddress, NumberOfBytesToUnlock, LockType);
}
NTSTATUS NTAPI NtQueryVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID               Buffer,
	IN SIZE_T                Length,
	OUT PSIZE_T              ResultLength OPTIONAL) {
	return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T)>(RtlGetNtProcAddress("NtQueryVirtualMemory"))
		(ProcessHandle, BaseAddress, MemoryInformationClass, Buffer, Length, ResultLength);
}

PVOID NTAPI RtlImageDirectoryEntryToData(PVOID BaseAddress, BOOLEAN MappedAsImage, USHORT Directory, PULONG Size) {
	return ((decltype(&RtlImageDirectoryEntryToData))(RtlGetNtProcAddress("RtlImageDirectoryEntryToData")))(BaseAddress, MappedAsImage, Directory, Size);
}

VOID NTAPI RtlInitAnsiString(PANSI_STRING DestinationString, LPCSTR SourceString) {
	return ((decltype(&RtlInitAnsiString))RtlGetNtProcAddress("RtlInitAnsiString"))(DestinationString, SourceString);
}

NTSTATUS NTAPI RtlAnsiStringToUnicodeString(PUNICODE_STRING DestinationString, PANSI_STRING SourceString, BOOLEAN AllocateDestinationString) {
	return ((decltype(&RtlAnsiStringToUnicodeString))RtlGetNtProcAddress("RtlAnsiStringToUnicodeString"))(DestinationString, SourceString, AllocateDestinationString);
}

PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(LPVOID BaseAddress) {
#pragma warning(disable:6387)
	return (decltype(&RtlImageNtHeader)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlImageNtHeader")))(BaseAddress);
}

PPEB NTAPI NtCurrentPeb() {
	return NtCurrentTeb()->ProcessEnvironmentBlock;
}

WCHAR NTAPI RtlUpcaseUnicodeChar(IN WCHAR Source) {
	USHORT Offset;
	if (Source < 'a') return Source;
	if (Source <= 'z') return (Source - ('a' - 'A'));
	Offset = 0;
	return Source + (SHORT)Offset;
}

NTSTATUS NTAPI RtlHashUnicodeString(IN PCUNICODE_STRING String, IN BOOLEAN CaseInSensitive, IN ULONG HashAlgorithm, OUT PULONG HashValue) {
	return (decltype(&RtlHashUnicodeString)(RtlGetNtProcAddress("RtlHashUnicodeString")))(String, CaseInSensitive, HashAlgorithm, HashValue);
}

VOID NTAPI RtlGetNtVersionNumbers(OUT DWORD* MajorVersion, OUT DWORD* MinorVersion, OUT DWORD* BuildNumber) {
	static DWORD Versions[3]{ 0 };
	static auto _RtlGetNtVersionNumbers = (decltype(&RtlGetNtVersionNumbers))(RtlGetNtProcAddress("RtlGetNtVersionNumbers"));

	if (Versions[0] || !_RtlGetNtVersionNumbers) goto ret;
	_RtlGetNtVersionNumbers(Versions, Versions + 1, Versions + 2);
	if (Versions[2] & 0xf0000000)Versions[2] &= 0xffff;

ret:
	if (MajorVersion)*MajorVersion = Versions[0];
	if (MinorVersion)*MinorVersion = Versions[1];
	if (BuildNumber)*BuildNumber = Versions[2];
	return;
}

NTSTATUS NTAPI NtQuerySystemTime(PLARGE_INTEGER SystemTime) {
	return (decltype(&NtQuerySystemTime)(RtlGetNtProcAddress("NtQuerySystemTime")))(SystemTime);
}

PVOID NTAPI RtlEncodeSystemPointer(PVOID Pointer) {
	return decltype(&RtlEncodeSystemPointer)(RtlGetNtProcAddress("RtlEncodeSystemPointer"))(Pointer);
}
PVOID NTAPI RtlDecodeSystemPointer(PVOID Pointer) {
	return decltype(&RtlDecodeSystemPointer)(RtlGetNtProcAddress("RtlDecodeSystemPointer"))(Pointer);
}
