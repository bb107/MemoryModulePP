#pragma once

typedef struct _MMP_GLOBAL_DATA {

	WORD MajorVersion;
	WORD MinorVersion;

	DWORD MmpFeatures;

	//BaseAddressIndex.cpp
	PRTL_RB_TREE LdrpModuleBaseAddressIndex;

	//InvertedFunctionTable.cpp
	PVOID LdrpInvertedFunctionTable;

	//LdrEntry.cpp
	PLDR_DATA_TABLE_ENTRY LdrpNtdllBase;
	PLIST_ENTRY LdrpHashTable;

	//MmpTls.cpp
	LIST_ENTRY MmpTlsList;
	RTL_BITMAP MmpTlsBitmap;
	SRWLOCK MmpTlsListLock;
	CRITICAL_SECTION MmpTlspLock;
	LIST_ENTRY MmpThreadLocalStoragePointer;
	DWORD MmpActiveThreadCount;
}MMP_GLOBAL_DATA, * PMMP_GLOBAL_DATA;

extern PMMP_GLOBAL_DATA MmpGlobalDataPtr;