#pragma once

//BaseAddressIndex.cpp
typedef struct _MMP_BASE_ADDRESS_INDEX_DATA {
	PRTL_RB_TREE LdrpModuleBaseAddressIndex;
	PLDR_DATA_TABLE_ENTRY NtdllLdrEntry;
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
}MMP_TLS_DATA, * PMMP_TLS_DATA;

//MmpDotNet.cpp
typedef struct _MMP_DOT_NET_DATA {
	FILETIME AssemblyTimes;

	CRITICAL_SECTION MmpFakeHandleListLock;
	LIST_ENTRY MmpFakeHandleListHead;

	BOOLEAN PreHooked;
	BOOLEAN Initialized;
}MMP_DOT_NET_DATA, * PMMP_DOT_NET_DATA;

typedef struct _MMP_GLOBAL_DATA {

	WORD MajorVersion;
	WORD MinorVersion;

	DWORD MmpFeatures;

	SYSTEM_INFO SystemInfo;

	MMP_BASE_ADDRESS_INDEX_DATA MmpBaseAddressIndex;

	MMP_INVERTED_FUNCTION_TABLE_DATA MmpInvertedFunctionTable;

	MMP_LDR_ENTRY_DATA MmpLdrEntry;

	MMP_TLS_DATA MmpTls;

	MMP_DOT_NET_DATA MmpDotNet;

}MMP_GLOBAL_DATA, * PMMP_GLOBAL_DATA;

extern PMMP_GLOBAL_DATA MmpGlobalDataPtr;
