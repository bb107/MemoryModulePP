#pragma once

//BaseAddressIndex.cpp
typedef struct _MMP_BASE_ADDRESS_INDEX_DATA {
	PRTL_RB_TREE LdrpModuleBaseAddressIndex;
	PLDR_DATA_TABLE_ENTRY NtdllLdrEntry;

	PVOID _RtlRbInsertNodeEx;
	PVOID _RtlRbRemoveNode;
}MMP_BASE_ADDRESS_INDEX_DATA, * PMMP_BASE_ADDRESS_INDEX_DATA;

//InvertedFunctionTable.cpp
typedef struct _MMP_INVERTED_FUNCTION_TABLE_DATA {
	PVOID LdrpInvertedFunctionTable;
}MMP_INVERTED_FUNCTION_TABLE_DATA, * PMMP_INVERTED_FUNCTION_TABLE_DATA;

//LdrEntry.cpp
typedef struct _MMP_LDR_ENTRY_DATA {
	PLIST_ENTRY LdrpHashTable;
}MMP_LDR_ENTRY_DATA, * PMMP_LDR_ENTRY_DATA;

//MmpTls.cpp
typedef struct _MMP_TLS_DATA {
	LIST_ENTRY MmpTlsList;
	RTL_BITMAP MmpTlsBitmap;
	SRWLOCK MmpTlsListLock;
	CRITICAL_SECTION MmpTlspLock;
	LIST_ENTRY MmpThreadLocalStoragePointer;
	DWORD MmpActiveThreadCount;

	struct {
		PVOID HookReserved1;
		PVOID HookReserved2;
		decltype(&NtSetInformationProcess) OriginNtSetInformationProcess;
		decltype(&LdrShutdownThread) OriginLdrShutdownThread;
		decltype(&RtlUserThreadStart) OriginRtlUserThreadStart;
	}Hooks;
}MMP_TLS_DATA, * PMMP_TLS_DATA;

//MmpDotNet.cpp
typedef struct _MMP_DOT_NET_DATA {
	FILETIME AssemblyTimes;

	CRITICAL_SECTION MmpFakeHandleListLock;
	LIST_ENTRY MmpFakeHandleListHead;

	BOOLEAN PreHooked;
	BOOLEAN Initialized;

	struct {
		decltype(&CreateFileW) OriginCreateFileW;
		decltype(&GetFileInformationByHandle) OriginGetFileInformationByHandle;
		decltype(&GetFileAttributesExW) OriginGetFileAttributesExW;
		decltype(&GetFileSize) OriginGetFileSize;
		decltype(&GetFileSizeEx) OriginGetFileSizeEx;
		decltype(&CreateFileMappingW) OriginCreateFileMappingW;
		decltype(&MapViewOfFileEx) OriginMapViewOfFileEx;
		decltype(&MapViewOfFile) OriginMapViewOfFile;
		decltype(&UnmapViewOfFile)OriginUnmapViewOfFile;
		decltype(&CloseHandle)OriginCloseHandle;
		GetFileVersion_T OriginGetFileVersion1;
		GetFileVersion_T OriginGetFileVersion2;
	}Hooks;
}MMP_DOT_NET_DATA, * PMMP_DOT_NET_DATA;

typedef struct _MMP_FUNCTIONS {
	decltype(&LdrLoadDllMemoryExW) _LdrLoadDllMemoryExW;
	decltype(&LdrUnloadDllMemory) _LdrUnloadDllMemory;
	decltype(&LdrUnloadDllMemoryAndExitThread) _LdrUnloadDllMemoryAndExitThread;

	decltype(&MmpHandleTlsData) _MmpHandleTlsData;
	decltype(&MmpReleaseTlsEntry) _MmpReleaseTlsEntry;
}MMP_FUNCTIONS, * PMMP_FUNCTIONS;

//ImportTable.cpp
typedef struct _MMP_IAT_DATA {

	LIST_ENTRY MmpIatResolverList;
	CRITICAL_SECTION MmpIatResolverListLock;
	MM_IAT_RESOLVER MmpIatResolverHead;

}MMP_IAT_DATA, * PMMP_IAT_DATA;

typedef enum class _WINDOWS_VERSION :BYTE {
	null,
	xp,
	vista,
	win7,
	win8,
	winBlue,
	win10,
	win10_1,
	win10_2,
	win11,
	invalid
}WINDOWS_VERSION;

#define MEMORY_MODULE_MAKE_PREVIEW(MinorVersion) (0x8000|(MinorVersion))
#define MEMORY_MODULE_IS_PREVIEW(MinorVersion) (!!(0x8000&(MinorVersion)))
#define MEMORY_MODULE_GET_MINOR_VERSION(MinorVersion) (~0x8000&(MinorVersion))

#define MEMORY_MODULE_MAJOR_VERSION 2
#define MEMORY_MODULE_MINOR_VERSION MEMORY_MODULE_MAKE_PREVIEW(2)

typedef struct _MMP_GLOBAL_DATA {

	WORD MajorVersion;
	WORD MinorVersion;

	DWORD MmpFeatures;

	struct {
		DWORD MajorVersion;
		DWORD MinorVersion;
		DWORD BuildNumber;
	}NtVersions;

	WINDOWS_VERSION WindowsVersion;

	WORD LdrDataTableEntrySize;

	SYSTEM_INFO SystemInfo;

	PMMP_BASE_ADDRESS_INDEX_DATA MmpBaseAddressIndex;

	PMMP_INVERTED_FUNCTION_TABLE_DATA MmpInvertedFunctionTable;

	PMMP_LDR_ENTRY_DATA MmpLdrEntry;

	PMMP_TLS_DATA MmpTls;

	PMMP_DOT_NET_DATA MmpDotNet;

	PVOID BaseAddress;

	PMMP_FUNCTIONS MmpFunctions;

	PMMP_IAT_DATA MmpIat;

	DWORD ReferenceCount;

}MMP_GLOBAL_DATA, * PMMP_GLOBAL_DATA;

#define MMP_GLOBAL_DATA_SIZE (\
	sizeof(MMP_GLOBAL_DATA) + \
	sizeof(MMP_BASE_ADDRESS_INDEX_DATA) + \
	sizeof(MMP_INVERTED_FUNCTION_TABLE_DATA) + \
	sizeof(MMP_LDR_ENTRY_DATA) + \
	sizeof(MMP_TLS_DATA) + \
	sizeof(MMP_DOT_NET_DATA) + \
	sizeof(MMP_FUNCTIONS) + \
	sizeof(PMMP_IAT_DATA)\
)

extern PMMP_GLOBAL_DATA MmpGlobalDataPtr;
