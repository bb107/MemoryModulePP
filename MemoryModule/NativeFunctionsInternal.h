#pragma once
#include <Windows.h>
#include "rtltype.h"
#include "ntstatus.h"
#include "MemoryModule.h"

//
// Loader Data Table Entry Flags
//
#define LDRP_STATIC_LINK                        0x00000002
#define LDRP_IMAGE_DLL                          0x00000004
#define LDRP_SHIMENG_SUPPRESSED_ENTRY           0x00000008
#define LDRP_IMAGE_INTEGRITY_FORCED             0x00000020
#define LDRP_LOAD_IN_PROGRESS                   0x00001000
#define LDRP_UNLOAD_IN_PROGRESS                 0x00002000
#define LDRP_ENTRY_PROCESSED                    0x00004000
#define LDRP_ENTRY_INSERTED                     0x00008000
#define LDRP_CURRENT_LOAD                       0x00010000
#define LDRP_FAILED_BUILTIN_LOAD                0x00020000
#define LDRP_DONT_CALL_FOR_THREADS              0x00040000
#define LDRP_PROCESS_ATTACH_CALLED              0x00080000
#define LDRP_DEBUG_SYMBOLS_LOADED               0x00100000
#define LDRP_IMAGE_NOT_AT_BASE                  0x00200000
#define LDRP_COR_IMAGE                          0x00400000
#define LDR_COR_OWNS_UNMAP                      0x00800000
#define LDRP_SYSTEM_MAPPED                      0x01000000
#define LDRP_IMAGE_VERIFYING                    0x02000000
#define LDRP_DRIVER_DEPENDENT_DLL               0x04000000
#define LDRP_ENTRY_NATIVE                       0x08000000
#define LDRP_REDIRECTED                         0x10000000
#define LDRP_NON_PAGED_DEBUG_INFO               0x20000000
#define LDRP_MM_LOADED                          0x40000000
#define LDRP_COMPAT_DATABASE_PROCESSED          0x80000000

#define LDR_GET_HASH_ENTRY(x)		(RtlUpcaseUnicodeChar((x)) & (LDR_HASH_TABLE_ENTRIES - 1))
#define LDR_HASH_TABLE_ENTRIES		32
#define InsertTailList(ListHead,Entry) {\
	 PLIST_ENTRY _EX_Blink;\
	 PLIST_ENTRY _EX_ListHead;\
	 _EX_ListHead = (ListHead);\
	 _EX_Blink = _EX_ListHead->Blink;\
	 (Entry)->Flink = _EX_ListHead;\
	 (Entry)->Blink = _EX_Blink;\
	 _EX_Blink->Flink = (Entry);\
	 _EX_ListHead->Blink = (Entry);\
}

//0x18 bytes (sizeof)
typedef struct _RTL_BALANCED_NODE {
	union {
		_RTL_BALANCED_NODE* Children[2];					                //0x0
		struct {
			_RTL_BALANCED_NODE* Left;						                //0x0
			_RTL_BALANCED_NODE* Right;				                        //0x8
		};
	};
	union {
		struct {
			UCHAR Red : 1;                                                  //0x10
			UCHAR Balance : 2;                                              //0x10
		};
		size_t ParentValue;                                                 //0x10
	};
}RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

enum _LDR_DLL_LOAD_REASON {
	LoadReasonStaticDependency = 0,
	LoadReasonStaticForwarderDependency = 1,
	LoadReasonDynamicForwarderDependency = 2,
	LoadReasonDelayloadDependency = 3,
	LoadReasonDynamicLoad = 4,
	LoadReasonAsImageLoad = 5,
	LoadReasonAsDataLoad = 6,
	LoadReasonUnknown = -1
};

//0x10 bytes (sizeof)
struct _LDR_SERVICE_TAG_RECORD {
	_LDR_SERVICE_TAG_RECORD* Next;									        //0x0
	ULONG ServiceTag;                                                       //0x8
};
//0x8 bytes (sizeof)
struct _LDRP_CSLIST {
	_SINGLE_LIST_ENTRY* Tail;                                        //0x0
};
//0x4 bytes (sizeof)
enum _LDR_DDAG_STATE {
	LdrModulesMerged = -5,
	LdrModulesInitError = -4,
	LdrModulesSnapError = -3,
	LdrModulesUnloaded = -2,
	LdrModulesUnloading = -1,
	LdrModulesPlaceHolder = 0,
	LdrModulesMapping = 1,
	LdrModulesMapped = 2,
	LdrModulesWaitingForDependencies = 3,
	LdrModulesSnapping = 4,
	LdrModulesSnapped = 5,
	LdrModulesCondensed = 6,
	LdrModulesReadyToInit = 7,
	LdrModulesInitializing = 8,
	LdrModulesReadyToRun = 9
};
//0x50 bytes (sizeof)
struct _LDR_DDAG_NODE {
	_LIST_ENTRY Modules;												    //0x0
	_LDR_SERVICE_TAG_RECORD* ServiceTagList;							    //0x10
	ULONG LoadCount;                                                        //0x18
	ULONG LoadWhileUnloadingCount;                                          //0x1c
	ULONG LowestLink;                                                       //0x20
	_LDRP_CSLIST Dependencies;												//0x28
	_LDRP_CSLIST IncomingDependencies;										//0x30
	_LDR_DDAG_STATE State;													//0x38
	_SINGLE_LIST_ENTRY CondenseLink;										//0x40
	ULONG PreorderNumber;                                                   //0x48
};

//5.1.2600  Windows XP SP3
//5.2.3790  Windows XP | 2003 SP2
typedef struct _LDR_DATA_TABLE_ENTRY_XP {
	_LIST_ENTRY InLoadOrderLinks;											//0x0
	_LIST_ENTRY InMemoryOrderLinks;											//0x10
	_LIST_ENTRY InInitializationOrderLinks;									//0x20
	VOID* DllBase;                                                          //0x30
	VOID* EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	_UNICODE_STRING FullDllName;											//0x48
	_UNICODE_STRING BaseDllName;											//0x58
	ULONG Flags;                                                            //0x68
	USHORT LoadCount;                                                       //0x6c
	USHORT TlsIndex;                                                        //0x6e
	union {
		_LIST_ENTRY HashLinks;												//0x70
		struct {
			VOID* SectionPointer;                                           //0x70
			ULONG CheckSum;                                                 //0x78
		};
	};
	union {
		ULONG TimeDateStamp;                                                //0x80
		VOID* LoadedImports;                                                //0x80
	};
	_ACTIVATION_CONTEXT* EntryPointActivationContext;						//0x88
	VOID* PatchInformation;                                                 //0x90
}LDR_DATA_TABLE_ENTRY_XP, * PLDR_DATA_TABLE_ENTRY_XP;

//6.0.6000  Vista | 2008 RTM
//6.0.6001  Vista | 2008 SP1
//6.0.6002  Vista | 2008 SP2
typedef struct _LDR_DATA_TABLE_ENTRY_VISTA :public _LDR_DATA_TABLE_ENTRY_XP {
	_LIST_ENTRY ForwarderLinks;                                      //0x98
	_LIST_ENTRY ServiceTagLinks;                                     //0xa8
	_LIST_ENTRY StaticLinks;                                         //0xb8
}LDR_DATA_TABLE_ENTRY_VISTA, * PLDR_DATA_TABLE_ENTRY_VISTA;

//6.1.7600  Windows 7 | 2008R2 SP1
//6.1.7601  Windows 7 | 2008R2 RTM
typedef struct _LDR_DATA_TABLE_ENTRY_WIN7 :public _LDR_DATA_TABLE_ENTRY_VISTA {
	VOID* ContextInformation;                                               //0xc8
	ULONGLONG OriginalBase;                                                 //0xd0
	_LARGE_INTEGER LoadTime;                                                //0xd8
}LDR_DATA_TABLE_ENTRY_WIN7, * PLDR_DATA_TABLE_ENTRY_WIN7;

//6.2.9200	Windows 8 | 2012 RTM
typedef struct _LDR_DATA_TABLE_ENTRY_WIN8 {
	_LIST_ENTRY InLoadOrderLinks;											  //0x0
	_LIST_ENTRY InMemoryOrderLinks;											  //0x10
	union {
		_LIST_ENTRY InInitializationOrderLinks;								  //0x20
		_LIST_ENTRY InProgressLinks;										  //0x20
	};
	VOID* DllBase;                                                            //0x30
	VOID* EntryPoint;                                                         //0x38
	ULONG SizeOfImage;                                                        //0x40
	_UNICODE_STRING FullDllName;											  //0x48
	_UNICODE_STRING BaseDllName;											  //0x58
	union {
		UCHAR FlagGroup[4];                                                   //0x68
		ULONG Flags;                                                          //0x68
		struct {
			ULONG PackagedBinary : 1;                                         //0x68
			ULONG MarkedForRemoval : 1;                                       //0x68
			ULONG ImageDll : 1;                                               //0x68
			ULONG LoadNotificationsSent : 1;                                  //0x68
			ULONG TelemetryEntryProcessed : 1;                                //0x68
			ULONG ProcessStaticImport : 1;                                    //0x68
			ULONG InLegacyLists : 1;                                          //0x68
			ULONG InIndexes : 1;                                              //0x68
			ULONG ShimDll : 1;                                                //0x68
			ULONG InExceptionTable : 1;                                       //0x68
			ULONG ReservedFlags1 : 2;                                         //0x68
			ULONG LoadInProgress : 1;                                         //0x68
			ULONG ReservedFlags2 : 1;                                         //0x68
			ULONG EntryProcessed : 1;                                         //0x68
			ULONG ReservedFlags3 : 3;                                         //0x68
			ULONG DontCallForThreads : 1;                                     //0x68
			ULONG ProcessAttachCalled : 1;                                    //0x68
			ULONG ProcessAttachFailed : 1;                                    //0x68
			ULONG CorDeferredValidate : 1;                                    //0x68
			ULONG CorImage : 1;                                               //0x68
			ULONG DontRelocate : 1;                                           //0x68
			ULONG CorILOnly : 1;                                              //0x68
			ULONG ReservedFlags5 : 3;                                         //0x68
			ULONG Redirected : 1;                                             //0x68
			ULONG ReservedFlags6 : 2;                                         //0x68
			ULONG CompatDatabaseProcessed : 1;                                //0x68
		};
	};
	USHORT ObsoleteLoadCount;                                                 //0x6c
	USHORT TlsIndex;                                                          //0x6e
	_LIST_ENTRY HashLinks;                                                    //0x70
	ULONG TimeDateStamp;                                                      //0x80
	_ACTIVATION_CONTEXT* EntryPointActivationContext;                         //0x88
	VOID* PatchInformation;                                                   //0x90
	_LDR_DDAG_NODE* DdagNode;                                                 //0x98
	_LIST_ENTRY NodeModuleLink;                                               //0xa0
	VOID* SnapContext;						                                  //0xb0
	VOID* ParentDllBase;                                                      //0xb8
	VOID* SwitchBackContext;                                                  //0xc0
	_RTL_BALANCED_NODE BaseAddressIndexNode;                                  //0xc8
	_RTL_BALANCED_NODE MappingInfoIndexNode;                                  //0xe0
	ULONGLONG OriginalBase;                                                   //0xf8
	_LARGE_INTEGER LoadTime;                                                  //0x100
	ULONG BaseNameHashValue;                                                  //0x108
	_LDR_DLL_LOAD_REASON LoadReason;                                          //0x10c
}LDR_DATA_TABLE_ENTRY_WIN8, * PLDR_DATA_TABLE_ENTRY_WIN8;

//6.3.9600	Windows 8.1 | 2012R2 RTM | 2012R2 Update 1
typedef struct _LDR_DATA_TABLE_ENTRY_WIN8_1 :public _LDR_DATA_TABLE_ENTRY_WIN8 {
	ULONG ImplicitPathOptions;
}LDR_DATA_TABLE_ENTRY_WIN8_1, * PLDR_DATA_TABLE_ENTRY_WIN8_1;

//10.0.10240	Windows 10 | 2016 1507 Threshold 1
//10.0.10586	Windows 10 | 2016 1511 Threshold 2
typedef struct _LDR_DATA_TABLE_ENTRY_WIN10 {
	_LIST_ENTRY InLoadOrderLinks;											  //0x0
	_LIST_ENTRY InMemoryOrderLinks;											  //0x10
	_LIST_ENTRY InInitializationOrderLinks;									  //0x20
	VOID* DllBase;                                                            //0x30
	VOID* EntryPoint;                                                         //0x38
	ULONG SizeOfImage;                                                        //0x40
	_UNICODE_STRING FullDllName;											  //0x48
	_UNICODE_STRING BaseDllName;											  //0x58
	union {
		UCHAR FlagGroup[4];                                                   //0x68
		ULONG Flags;                                                          //0x68
		struct {
			ULONG PackagedBinary : 1;                                         //0x68
			ULONG MarkedForRemoval : 1;                                       //0x68
			ULONG ImageDll : 1;                                               //0x68
			ULONG LoadNotificationsSent : 1;                                  //0x68
			ULONG TelemetryEntryProcessed : 1;                                //0x68
			ULONG ProcessStaticImport : 1;                                    //0x68
			ULONG InLegacyLists : 1;                                          //0x68
			ULONG InIndexes : 1;                                              //0x68
			ULONG ShimDll : 1;                                                //0x68
			ULONG InExceptionTable : 1;                                       //0x68
			ULONG ReservedFlags1 : 2;                                         //0x68
			ULONG LoadInProgress : 1;                                         //0x68
			ULONG LoadConfigProcessed : 1;                                    //0x68
			ULONG EntryProcessed : 1;                                         //0x68
			ULONG ProtectDelayLoad : 1;                                       //0x68
			ULONG ReservedFlags3 : 2;                                         //0x68
			ULONG DontCallForThreads : 1;                                     //0x68
			ULONG ProcessAttachCalled : 1;                                    //0x68
			ULONG ProcessAttachFailed : 1;                                    //0x68
			ULONG CorDeferredValidate : 1;                                    //0x68
			ULONG CorImage : 1;                                               //0x68
			ULONG DontRelocate : 1;                                           //0x68
			ULONG CorILOnly : 1;                                              //0x68
			ULONG ReservedFlags5 : 3;                                         //0x68
			ULONG Redirected : 1;                                             //0x68
			ULONG ReservedFlags6 : 2;                                         //0x68
			ULONG CompatDatabaseProcessed : 1;                                //0x68
		};
	};
	USHORT ObsoleteLoadCount;												  //0x6c
	USHORT TlsIndex;														  //0x6e
	_LIST_ENTRY HashLinks;												      //0x70
	ULONG TimeDateStamp;                                                      //0x80
	_ACTIVATION_CONTEXT* EntryPointActivationContext;				          //0x88
	VOID* Lock;                                                               //0x90
	_LDR_DDAG_NODE* DdagNode;											      //0x98
	_LIST_ENTRY NodeModuleLink;										          //0xa0
	VOID* LoadContext;														  //0xb0
	VOID* ParentDllBase;                                                      //0xb8
	VOID* SwitchBackContext;                                                  //0xc0
	_RTL_BALANCED_NODE BaseAddressIndexNode;								  //0xc8
	_RTL_BALANCED_NODE MappingInfoIndexNode;								  //0xe0
	ULONGLONG OriginalBase;                                                   //0xf8
	_LARGE_INTEGER LoadTime;												  //0x100
	ULONG BaseNameHashValue;                                                  //0x108
	_LDR_DLL_LOAD_REASON LoadReason;										  //0x10c
	ULONG ImplicitPathOptions;                                                //0x110
	ULONG ReferenceCount;                                                     //0x114
}LDR_DATA_TABLE_ENTRY_WIN10, * PLDR_DATA_TABLE_ENTRY_WIN10;

//10.0.14393	Windows 10 | 2016 1607 Redstone 1 (Anniversary Update)
typedef struct _LDR_DATA_TABLE_ENTRY_WIN10_1 :public _LDR_DATA_TABLE_ENTRY_WIN10 {
	ULONG DependentLoadFlags;                                               //0x118
}LDR_DATA_TABLE_ENTRY_WIN10_1,*PLDR_DATA_TABLE_ENTRY_WIN10_1;

//10.0.15063	Windows 10 | 2016 1703 Redstone 2 (Creators Update)
//10.0.16299	Windows 10 | 2016 1709 Redstone 3 (Fall Creators Update)
//10.0.17134	Windows 10 | 2016 1803 Redstone 4 (Spring Creators Update)
//10.0.17763	Windows 10 | 2016 1809 Redstone 5 (October Update)
//10.0.18362	Windows 10 | 2016 1903 19H1 (May 2019 Update) | 2016 1909 19H2 (November 2019 Update)
typedef struct _LDR_DATA_TABLE_ENTRY_WIN10_2  {
	_LIST_ENTRY InLoadOrderLinks;											//0x0
	_LIST_ENTRY InMemoryOrderLinks;											//0x10
	_LIST_ENTRY InInitializationOrderLinks;									//0x20
	VOID* DllBase;                                                          //0x30
	VOID* EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	_UNICODE_STRING FullDllName;											//0x48
	_UNICODE_STRING BaseDllName;											//0x58
	union {
		UCHAR FlagGroup[4];                                                 //0x68
		ULONG Flags;                                                        //0x68
		struct {
			ULONG PackagedBinary : 1;                                         //0x68
			ULONG MarkedForRemoval : 1;                                       //0x68
			ULONG ImageDll : 1;                                               //0x68
			ULONG LoadNotificationsSent : 1;                                  //0x68
			ULONG TelemetryEntryProcessed : 1;                                //0x68
			ULONG ProcessStaticImport : 1;                                    //0x68
			ULONG InLegacyLists : 1;                                          //0x68
			ULONG InIndexes : 1;                                              //0x68
			ULONG ShimDll : 1;                                                //0x68
			ULONG InExceptionTable : 1;                                       //0x68
			ULONG ReservedFlags1 : 2;                                         //0x68
			ULONG LoadInProgress : 1;                                         //0x68
			ULONG LoadConfigProcessed : 1;                                    //0x68
			ULONG EntryProcessed : 1;                                         //0x68
			ULONG ProtectDelayLoad : 1;                                       //0x68
			ULONG ReservedFlags3 : 2;                                         //0x68
			ULONG DontCallForThreads : 1;                                     //0x68
			ULONG ProcessAttachCalled : 1;                                    //0x68
			ULONG ProcessAttachFailed : 1;                                    //0x68
			ULONG CorDeferredValidate : 1;                                    //0x68
			ULONG CorImage : 1;                                               //0x68
			ULONG DontRelocate : 1;                                           //0x68
			ULONG CorILOnly : 1;                                              //0x68
			ULONG ReservedFlags5 : 3;                                         //0x68
			ULONG Redirected : 1;                                             //0x68
			ULONG ReservedFlags6 : 2;                                         //0x68
			ULONG CompatDatabaseProcessed : 1;                                //0x68
		};
	};
	USHORT ObsoleteLoadCount;                                               //0x6c
	USHORT TlsIndex;                                                        //0x6e
	_LIST_ENTRY HashLinks;												    //0x70
	ULONG TimeDateStamp;                                                    //0x80
	_ACTIVATION_CONTEXT* EntryPointActivationContext;			            //0x88
	VOID* Lock;                                                             //0x90
	_LDR_DDAG_NODE* DdagNode;											    //0x98
	_LIST_ENTRY NodeModuleLink;				                                //0xa0
	VOID* LoadContext;						                                //0xb0
	VOID* ParentDllBase;                                                    //0xb8
	VOID* SwitchBackContext;                                                //0xc0
	_RTL_BALANCED_NODE BaseAddressIndexNode;								//0xc8
	_RTL_BALANCED_NODE MappingInfoIndexNode;								//0xe0
	ULONGLONG OriginalBase;                                                 //0xf8
	_LARGE_INTEGER LoadTime;												//0x100
	ULONG BaseNameHashValue;                                                //0x108
	_LDR_DLL_LOAD_REASON LoadReason;										//0x10c
	ULONG ImplicitPathOptions;                                              //0x110
	ULONG ReferenceCount;                                                   //0x114
	ULONG DependentLoadFlags;                                               //0x118
	UCHAR SigningLevel;                                                     //0x11c
}LDR_DATA_TABLE_ENTRY_WIN10_2, * PLDR_DATA_TABLE_ENTRY_WIN10_2;

typedef enum _WINDOWS_VERSION {
	null,
	xp,
	vista,
	win7,
	win8,
	win8_1,
	win10,
	win10_1,
	win10_2,
	invalid
}WINDOWS_VERSION;

NTSTATUS NTAPI NtLoadDllMemory(
	OUT HMEMORYMODULE* BaseAddress,
	IN  LPVOID BufferAddress,
	IN  size_t BufferSize
);


/*
	NtLoadDllMemoryEx dwFlags
*/

//If this flag is specified, all subsequent flags will be ignored.
//Also, will be incompatible with Win32 API.
#define LOAD_FLAGS_NOT_MAP_DLL						0x10000000

//If this flag is specified, exception handling will not be supported.
#define LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION		0x00000001

//If this flag is specified, NtLoadDllMemory and NtUnloadDllMemory will not use reference counting.
//If you try to load the same module, it will fail. When you unload the module,
//	it will be unloaded without checking the reference count.
#define LOAD_FLAGS_NOT_USE_REFERENCE_COUNT			0x00000002

//If this flag is specified, DllName and DllFullName cannot be nullptr,
//	they can be arbitrary strings without having to be correct file names and paths.
//Otherwise, DllName and DllFullName will use random names if they are nullptr.
//For compatibility with GetModuleHandle, DllName and DllFullName should be guaranteed to always end in ".dll"
#define LOAD_FLAGS_USE_DLL_NAME						0x00000004

//Dont call LdrpHandleTlsData routine if this flag is specified.
#define LOAD_FLAGS_NOT_HANDLE_TLS					0x00000008


NTSTATUS NTAPI NtLoadDllMemoryExW(
	OUT HMEMORYMODULE* BaseAddress,
	OUT PVOID* LdrEntry OPTIONAL,
	IN DWORD dwFlags,
	IN LPVOID BufferAddress,
	IN size_t BufferSize,
	IN LPCWSTR DllName OPTIONAL,
	IN LPCWSTR DllFullName OPTIONAL
);

NTSTATUS NTAPI NtUnloadDllMemory(IN HMEMORYMODULE BaseAddress);

typedef struct _RTL_RB_TREE {
	PRTL_BALANCED_NODE Root;
	PRTL_BALANCED_NODE Min;
} RTL_RB_TREE, * PRTL_RB_TREE;
// RtlRbInsertNodeEx
VOID NTAPI RtlRbInsertNodeEx(IN PRTL_RB_TREE Tree, IN PRTL_BALANCED_NODE Parent, IN BOOLEAN Right, OUT PRTL_BALANCED_NODE Node);
// RtlRbRemoveNode
VOID NTAPI RtlRbRemoveNode(IN PRTL_RB_TREE Tree, IN PRTL_BALANCED_NODE Node);

typedef struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY_64 {
	PIMAGE_RUNTIME_FUNCTION_ENTRY ExceptionDirectory;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG ExceptionDirectorySize;
} RTL_INVERTED_FUNCTION_TABLE_ENTRY_64, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY_64;
typedef struct _RTL_INVERTED_FUNCTION_TABLE_64 {
	ULONG Count;
	ULONG MaxCount;
	ULONG Epoch;
	ULONG Overflow;
	RTL_INVERTED_FUNCTION_TABLE_ENTRY_64 Entries[0x200];
} RTL_INVERTED_FUNCTION_TABLE_64, * PRTL_INVERTED_FUNCTION_TABLE_64;

typedef struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32 {
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG SEHandlerCount;
	PVOID NextEntrySEHandlerTableEncoded;
} RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32;
typedef struct _RTL_INVERTED_FUNCTION_TABLE_WIN7_32 {
	ULONG Count;
	ULONG MaxCount;
	ULONG Overflow;
	ULONG NextEntrySEHandlerTableEncoded;
	RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32 Entries[0x200];
} RTL_INVERTED_FUNCTION_TABLE_WIN7_32, * PRTL_INVERTED_FUNCTION_TABLE_WIN7_32;

#ifdef _WIN64
typedef _RTL_INVERTED_FUNCTION_TABLE_ENTRY_64 _RTL_INVERTED_FUNCTION_TABLE_ENTRY, RTL_INVERTED_FUNCTION_TABLE_ENTRY, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY;
typedef RTL_INVERTED_FUNCTION_TABLE_64 _RTL_INVERTED_FUNCTION_TABLE, RTL_INVERTED_FUNCTION_TABLE, * PRTL_INVERTED_FUNCTION_TABLE;
#else
typedef RTL_INVERTED_FUNCTION_TABLE_WIN7_32 _RTL_INVERTED_FUNCTION_TABLE, RTL_INVERTED_FUNCTION_TABLE, * PRTL_INVERTED_FUNCTION_TABLE;
typedef _RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32 _RTL_INVERTED_FUNCTION_TABLE_ENTRY, RTL_INVERTED_FUNCTION_TABLE_ENTRY, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY;
#endif

NTSTATUS NTAPI RtlInsertInvertedFunctionTable(IN PVOID BaseAddress, IN size_t ImageSize);
NTSTATUS NTAPI RtlRemoveInvertedFunctionTable(IN PVOID ImageBase);
NTSTATUS NTAPI LdrpHandleTlsData(IN PLDR_DATA_TABLE_ENTRY LdrEntry);
int NTAPI RtlCaptureImageExceptionValues(PVOID BaseAddress, PDWORD SEHandlerTable, PDWORD SEHandlerCount);
