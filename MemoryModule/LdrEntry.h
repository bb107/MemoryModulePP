#pragma once

#define FLAG_REFERENCE		0
#define FLAG_DEREFERENCE	1

PLDR_DATA_TABLE_ENTRY NTAPI RtlAllocateDataTableEntry(_In_ PVOID BaseAddress);

BOOL NTAPI RtlInitializeLdrDataTableEntry(
	_Out_ PLDR_DATA_TABLE_ENTRY LdrEntry,
	_In_ DWORD dwFlags,
	_In_ PVOID BaseAddress,
	_In_ UNICODE_STRING& DllBaseName,
	_In_ UNICODE_STRING& DllFullName
);

BOOL NTAPI RtlFreeLdrDataTableEntry(_In_ PLDR_DATA_TABLE_ENTRY LdrEntry);

NTSTATUS NTAPI RtlUpdateReferenceCount(
	_Inout_ PMEMORYMODULE pModule,
	_In_ DWORD Flags
);

NTSTATUS NTAPI RtlGetReferenceCount(
	_In_ PMEMORYMODULE pModule,
	_Out_ PULONG Count
);

VOID NTAPI RtlInsertMemoryTableEntry(_In_ PLDR_DATA_TABLE_ENTRY LdrEntry);

PLDR_DATA_TABLE_ENTRY NTAPI RtlFindLdrTableEntryByHandle(_In_ PVOID BaseAddress);

PLDR_DATA_TABLE_ENTRY NTAPI RtlFindLdrTableEntryByBaseName(_In_z_ PCWSTR BaseName);

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

struct _LDR_DDAG_NODE_WIN8 {
	_LIST_ENTRY Modules;							                        //0x0
	_LDR_SERVICE_TAG_RECORD* ServiceTagList;				                //0x10
	ULONG LoadCount;                                                        //0x18
	ULONG ReferenceCount;                                                   //0x1c
	ULONG DependencyCount;                                                  //0x20
	_LDRP_CSLIST::_LDRP_CSLIST_DEPENDENT* Dependencies;						//0x28
	_LDRP_CSLIST::_LDRP_CSLIST_INCOMMING* IncomingDependencies;				//0x30
	_LDR_DDAG_STATE State;                                                  //0x38
	_SINGLE_LIST_ENTRY CondenseLink;									    //0x40
	ULONG PreorderNumber;                                                   //0x48
	ULONG LowestLink;                                                       //0x4c
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
	_LDR_DDAG_NODE_WIN8* DdagNode;                                            //0x98
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
typedef struct _LDR_DATA_TABLE_ENTRY_WINBLUE :public _LDR_DATA_TABLE_ENTRY_WIN8 {
	ULONG ImplicitPathOptions;
}LDR_DATA_TABLE_ENTRY_WINBLUE, * PLDR_DATA_TABLE_ENTRY_WINBLUE;

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
}LDR_DATA_TABLE_ENTRY_WIN10_1, * PLDR_DATA_TABLE_ENTRY_WIN10_1;

//10.0.15063	Windows 10 | 2016 1703 Redstone 2 (Creators Update)
//10.0.16299	Windows 10 | 2016 1709 Redstone 3 (Fall Creators Update)
//10.0.17134	Windows 10 | 2016 1803 Redstone 4 (Spring Creators Update)
//10.0.17763	Windows 10 | 2016 1809 Redstone 5 (October Update)
//10.0.18362	Windows 10 | 2016 1903 19H1 (May 2019 Update) | 2016 1909 19H2 (November 2019 Update)
//10.0.19041	Windows 10 | 2016 2004 20H1 (May 2020 Update)
//10.0.19042	Windows 10 | 2016 2009 20H2 (October 2020 Update)
typedef struct _LDR_DATA_TABLE_ENTRY_WIN10_2 :LDR_DATA_TABLE_ENTRY_WIN10 {
	ULONG DependentLoadFlags;                                               //0x118
	UCHAR SigningLevel;                                                     //0x11c
}LDR_DATA_TABLE_ENTRY_WIN10_2, * PLDR_DATA_TABLE_ENTRY_WIN10_2;

//10.0.22000	Windows 11 Insider Preview (Jun 2021)
//10.0.22000	Windows 11 21H2 (RTM)
//10.0.22621	Windows 11 22H2 (2022 Update)
typedef struct _LDR_DATA_TABLE_ENTRY_WIN11 :LDR_DATA_TABLE_ENTRY_WIN10_2 {
	ULONG CheckSum;                                                         //0x120
	VOID* ActivePatchImageBase;                                             //0x128
	LDR_HOT_PATCH_STATE HotPatchState;                                      //0x130
}LDR_DATA_TABLE_ENTRY_WIN11, * PLDR_DATA_TABLE_ENTRY_WIN11;

ULONG NTAPI LdrHashEntry(_In_ UNICODE_STRING& DllBaseName, _In_ BOOL ToIndex = TRUE);
