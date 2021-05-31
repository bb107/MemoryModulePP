#include "stdafx.h"

static NTSTATUS NTAPI LdrpHandleTlsDataXp(PLDR_DATA_TABLE_ENTRY LdrEntry) {
	return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI RtlFindLdrpHandleTlsData(PVOID* _LdrpHandleTlsData, bool* stdcall) {
	static PVOID _LdrpHandleTlsData_ = (PVOID)~0;
	NTSTATUS status = STATUS_SUCCESS;

	__try {
		if (_LdrpHandleTlsData_ != (PVOID)~0) {
			*_LdrpHandleTlsData = _LdrpHandleTlsData_;
			if (_LdrpHandleTlsData_ == nullptr)status = STATUS_NOT_SUPPORTED;
		}
		else {
			*_LdrpHandleTlsData = _LdrpHandleTlsData_ = nullptr;
			if (stdcall) {
				*stdcall = false;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}
	if (!NT_SUCCESS(status))return status;

	DWORD Versions[3]{};
	LPCVOID Feature = nullptr;
	BYTE Size = 0;
	WORD OffsetOfFunctionBegin = 0;
	RtlGetNtVersionNumbers(Versions, Versions + 1, Versions + 2);
	switch (Versions[0]) {
	case 10: {
		if (Versions[1])return STATUS_NOT_SUPPORTED;

		//RS3
		if (Versions[2] >= 16299) {
			Size = 7;
			//19H2
			if (Versions[2] >= 18363)Feature = "\x74\x33\x44\x8D\x43\x09";
			//RS5
			else if (Versions[2] >= 17763) Feature = "\x8b\xc1\x8d\x4d\xbc\x51";
			//RS4
			else if (Versions[2] >= 17134) Feature = "\x33\xf6\x85\xc0\x79\x03";
			//RS3
			else Feature = "\x8b\xc1\x8d\x4d\xac\x51";
#ifdef _WIN64
			//RS6(19H1)
			if (Versions[2] >= 18362) OffsetOfFunctionBegin = 0x46;
			//RS4
			else if (Versions[2] >= 17134) OffsetOfFunctionBegin = 0x44;
			//RS3
			else OffsetOfFunctionBegin = 0x43;
#else
			//19H2
			if (Versions[2] == 18363) {
				Feature = "\x74\x25\x8b\xc1\x8d\x4d\xbc";
				OffsetOfFunctionBegin = 0x16;
			}
			//RS6(19H1)
			else if (Versions[2] == 18362) OffsetOfFunctionBegin = 0x2E;
			//RS5
			else if (Versions[2] >= 17763) OffsetOfFunctionBegin = 0x2C;
			//RS3,4
			else OffsetOfFunctionBegin = 0x18;
#endif
			break;
		}
		//RS2
		else if (Versions[2] >= 15063) {
			Size = 7;
#ifdef _WIN64
			OffsetOfFunctionBegin = 0x43;
			Feature = "\x74\x33\x44\x8d\x43\x09";
#else
			OffsetOfFunctionBegin = 0x18;
			Feature = "\x8b\xc1\x8d\x4d\xbc\x51";
#endif
			break;
		}

		// NO BREAK
	}
	case 6: {
		switch (Versions[1]) {
			//8.1
		case 3: {
#ifdef _WIN64
			Size = 10;
			OffsetOfFunctionBegin = 0x43;
			Feature = "\x44\x8d\x43\x09\x4c\x8d\x4c\x24\x38";
#else
			Size = 8;
			OffsetOfFunctionBegin = 0x1B;
			Feature = "\x50\x6a\x09\x6a\x01\x8b\xc1";
#endif
			break;
		}
			  //8
		case 2: {
#ifdef _WIN64
			Size = 9;
			OffsetOfFunctionBegin = 0x49;
			Feature = "\x48\x8b\x79\x30\x45\x8d\x66\x01";
#else
			Size = 7;
			OffsetOfFunctionBegin = 0xC;
			Feature = "\x8b\x45\x08\x89\x45\xa0";
#endif
			break;
		}
			  //7
		case 1: {
#ifdef _WIN64
			Size = 12;
			OffsetOfFunctionBegin = 0x27;
			Feature = "\x41\xb8\x09\x00\x00\x00\x48\x8d\x44\x24\x38";
#else
			Size = 9;
			OffsetOfFunctionBegin = 0x14;
			Feature = "\x74\x20\x8d\x45\xd4\x50\x6a\x09";
#endif
			break;
		}
		default:return STATUS_NOT_SUPPORTED;
		}
		break;
	}

	default: {
		*_LdrpHandleTlsData = LdrpHandleTlsDataXp;
		*stdcall = true;
		return status;
	}
	}

	SEARCH_CONTEXT SearchContext{ SearchContext.MemoryBuffer = const_cast<PVOID>(Feature),SearchContext.BufferLength = Size - 1 };
	if (NT_SUCCESS(RtlFindMemoryBlockFromModuleSection(HMODULE(RtlFindNtdllLdrEntry()->DllBase), ".text", &SearchContext)))
		SearchContext.OutBufferPtr -= OffsetOfFunctionBegin;
	if (!(*_LdrpHandleTlsData = _LdrpHandleTlsData_ = SearchContext.MemoryBlockInSection))return STATUS_NOT_SUPPORTED;
	if (stdcall) *stdcall = !RtlIsWindowsVersionOrGreater(6, 3, 0);
	return status;
}

NTSTATUS NTAPI RtlFindLdrpReleaseTlsEntry(PVOID* _LdrpReleaseTlsEntry, bool* stdcall) {
	static PVOID _LdrpReleaseTlsEntry_ = (PVOID)~0;
	NTSTATUS status = STATUS_SUCCESS;

	__try {
		if (_LdrpReleaseTlsEntry_ != (PVOID)~0) {
			*_LdrpReleaseTlsEntry = _LdrpReleaseTlsEntry_;
			if (!_LdrpReleaseTlsEntry_)status = STATUS_NOT_SUPPORTED;
		}
		else {
			*_LdrpReleaseTlsEntry = _LdrpReleaseTlsEntry_ = nullptr;
			if (stdcall) {
				*stdcall = false;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}
	if (!NT_SUCCESS(status))return status;

	DWORD Versions[3]{};
	LPCVOID Feature = nullptr;
	BYTE Size = 0;
	WORD OffsetOfFunctionBegin = 0;
	RtlGetNtVersionNumbers(Versions, Versions + 1, Versions + 2);
	switch (Versions[0]) {
	case 10: {
		if (Versions[1]) {
			status = STATUS_NOT_SUPPORTED;
			break;
		}
		if (Versions[2] >= 18362) {
			Size = 0x10;
			OffsetOfFunctionBegin = 0x2F;
			Feature = "\x74\x26\x48\x8B\x00\x48\x39\x58\x08\x75\x5D\x48\x8B\x4B\x08";
			break;
		}
	}
	default:
		status = STATUS_NOT_SUPPORTED;
	}

	if (!NT_SUCCESS(status)) {
		return status;
	}

	SEARCH_CONTEXT SearchContext{ SearchContext.MemoryBuffer = const_cast<PVOID>(Feature),SearchContext.BufferLength = Size - 1 };
	if (NT_SUCCESS(RtlFindMemoryBlockFromModuleSection(HMODULE(RtlFindNtdllLdrEntry()->DllBase), ".text", &SearchContext)))
		SearchContext.OutBufferPtr -= OffsetOfFunctionBegin;
	if (!(*_LdrpReleaseTlsEntry = _LdrpReleaseTlsEntry_ = SearchContext.MemoryBlockInSection))return STATUS_NOT_SUPPORTED;
	if (stdcall)*stdcall = !RtlIsWindowsVersionOrGreater(6, 3, 0);
	return status;
}

static NTSTATUS NTAPI RtlInvokeTlsHandler(IN PLDR_DATA_TABLE_ENTRY LdrEntry, IN BOOLEAN Release) {
	struct _FUNCTION_SET {
		bool stdcall;

		union {
			struct {
				NTSTATUS(__stdcall* LdrpHandleTlsData)(PLDR_DATA_TABLE_ENTRY LdrEntry);
				NTSTATUS(__stdcall* LdrpReleaseTlsEntry)(PLDR_DATA_TABLE_ENTRY LdrEntry, DWORD);
			}Default;

			struct {
				NTSTATUS(__thiscall* LdrpHandleTlsData)(PLDR_DATA_TABLE_ENTRY LdrEntry);
				NTSTATUS(__thiscall* LdrpReleaseTlsEntry)(PLDR_DATA_TABLE_ENTRY LdrEntry, DWORD);
			}WinBlue;
		};

		_FUNCTION_SET() {
			if (!NT_SUCCESS(RtlFindLdrpHandleTlsData((PVOID*)(&this->Default.LdrpHandleTlsData), &this->stdcall)) ||
				!NT_SUCCESS(RtlFindLdrpReleaseTlsEntry((PVOID*)(&this->Default.LdrpReleaseTlsEntry), nullptr))) {
				this->Default = {};
				OutputDebugString(L"Can`t find both LdrpHandleTlsData and LdrpReleaseTlsEntry.\n");
			}
		}

		NTSTATUS operator()(PLDR_DATA_TABLE_ENTRY LdrEntry) {
			if (!Default.LdrpHandleTlsData) {
				return STATUS_NOT_SUPPORTED;
			}
			return stdcall ? Default.LdrpHandleTlsData(LdrEntry) : WinBlue.LdrpHandleTlsData(LdrEntry);
		}

		NTSTATUS operator()(PLDR_DATA_TABLE_ENTRY LdrEntry, DWORD dwFlags) {
			if (!Default.LdrpReleaseTlsEntry) {
				return STATUS_NOT_SUPPORTED;
			}
			return stdcall ? Default.LdrpReleaseTlsEntry(LdrEntry,dwFlags) : WinBlue.LdrpReleaseTlsEntry(LdrEntry, dwFlags);
		}

	}static InvokeHandler;

	return Release ? InvokeHandler(LdrEntry, 0) : InvokeHandler(LdrEntry);
}

NTSTATUS NTAPI LdrpHandleTlsData(IN PLDR_DATA_TABLE_ENTRY LdrEntry) {
	return RtlInvokeTlsHandler(LdrEntry, FALSE);
}

NTSTATUS NTAPI LdrpReleaseTlsEntry(IN PLDR_DATA_TABLE_ENTRY LdrEntry) {
	return RtlInvokeTlsHandler(LdrEntry, TRUE);
}
