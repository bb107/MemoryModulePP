#pragma once
#include <Windows.h>

//typedef unsigned long NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

FARPROC NTAPI RtlGetNtProcAddress(LPCSTR func_name);

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
	PVOID Object;
	HANDLE UniqueProcessId;
	HANDLE HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;
typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

enum KWAIT_REASON {
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	Spare2,
	Spare3,
	Spare4,
	Spare5,
	Spare6,
	WrKernel,
	MaximumWaitReason
};
enum THREAD_STATE {
	StateInitialised,
	StateReady,
	StateRunning,
	StateStandby,
	StateTerminated,
	StateWait,
	StateTransition,
	StateUnknown
};

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING, LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
typedef struct _ANSI_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PSTR   Buffer;
} ANSI_STRING;
typedef ANSI_STRING* PANSI_STRING;
typedef struct _STRING {
	WORD Length;
	WORD MaximumLength;
	CHAR * Buffer;
} STRING, *PSTRING;
struct CLIENT_ID {
	HANDLE UniqueProcess;//Process ID
	HANDLE UniqueThread;//Thread ID
};
typedef struct _SYSTEM_THREAD {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientID;//process/thread ids
	LONG Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	THREAD_STATE ThreadState;
	KWAIT_REASON WaitReason;
}SYSTEM_THREAD, *PSYSTEM_THREAD;
typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS	ExitStatus;
	PVOID		TebBaseAddress;
	CLIENT_ID	ClientId;
	KAFFINITY	AffinityMask;
	ULONG		Priority;
	ULONG		BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;
struct VM_COUNTERS {
	ULONG_PTR PeakVirtualSize;
	ULONG_PTR VirtualSize;
	ULONG PageFaultCount;
	ULONG_PTR PeakWorkingSetSize;
	ULONG_PTR WorkingSetSize;
	ULONG_PTR QuotaPeakPagedPoolUsage;
	ULONG_PTR QuotaPagedPoolUsage;
	ULONG_PTR QuotaPeakNonPagedPoolUsage;
	ULONG_PTR QuotaNonPagedPoolUsage;
	ULONG_PTR PagefileUsage;
	ULONG_PTR PeakPagefileUsage;
};
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0x0000,
	SystemProcessorInformation = 0x0001,
	SystemPerformanceInformation = 0x0002,
	SystemTimeOfDayInformation = 0x0003,
	SystemPathInformation = 0x0004,
	SystemProcessInformation = 0x0005,
	SystemCallCountInformation = 0x0006,
	SystemDeviceInformation = 0x0007,
	SystemProcessorPerformanceInformation = 0x0008,
	SystemFlagsInformation = 0x0009,
	SystemCallTimeInformation = 0x000A,
	SystemModuleInformation = 0x000B,
	SystemLocksInformation = 0x000C,
	SystemStackTraceInformation = 0x000D,
	SystemPagedPoolInformation = 0x000E,
	SystemNonPagedPoolInformation = 0x000F,
	SystemHandleInformation = 0x0010,
	SystemObjectInformation = 0x0011,
	SystemPageFileInformation = 0x0012,
	SystemVdmInstemulInformation = 0x0013,
	SystemVdmBopInformation = 0x0014,
	SystemFileCacheInformation = 0x0015,
	SystemPoolTagInformation = 0x0016,
	SystemInterruptInformation = 0x0017,
	SystemDpcBehaviorInformation = 0x0018,
	SystemFullMemoryInformation = 0x0019,
	SystemLoadGdiDriverInformation = 0x001A,
	SystemUnloadGdiDriverInformation = 0x001B,
	SystemTimeAdjustmentInformation = 0x001C,
	SystemSummaryMemoryInformation = 0x001D,
	SystemMirrorMemoryInformation = 0x001E,
	SystemPerformanceTraceInformation = 0x001F,
	SystemCrashDumpInformation = 0x0020,
	SystemExceptionInformation = 0x0021,
	SystemCrashDumpStateInformation = 0x0022,
	SystemKernelDebuggerInformation = 0x0023,
	SystemContextSwitchInformation = 0x0024,
	SystemRegistryQuotaInformation = 0x0025,
	SystemExtendServiceTableInformation = 0x0026,
	SystemPrioritySeperation = 0x0027,
	SystemVerifierAddDriverInformation = 0x0028,
	SystemVerifierRemoveDriverInformation = 0x0029,
	SystemProcessorIdleInformation = 0x002A,
	SystemLegacyDriverInformation = 0x002B,
	SystemCurrentTimeZoneInformation = 0x002C,
	SystemLookasideInformation = 0x002D,
	SystemTimeSlipNotification = 0x002E,
	SystemSessionCreate = 0x002F,
	SystemSessionDetach = 0x0030,
	SystemSessionInformation = 0x0031,
	SystemRangeStartInformation = 0x0032,
	SystemVerifierInformation = 0x0033,
	SystemVerifierThunkExtend = 0x0034,
	SystemSessionProcessInformation = 0x0035,
	SystemLoadGdiDriverInSystemSpace = 0x0036,
	SystemNumaProcessorMap = 0x0037,
	SystemPrefetcherInformation = 0x0038,
	SystemExtendedProcessInformation = 0x0039,
	SystemRecommendedSharedDataAlignment = 0x003A,
	SystemComPlusPackage = 0x003B,
	SystemNumaAvailableMemory = 0x003C,
	SystemProcessorPowerInformation = 0x003D,
	SystemEmulationBasicInformation = 0x003E,
	SystemEmulationProcessorInformation = 0x003F,
	SystemExtendedHandleInformation = 0x0040,
	SystemLostDelayedWriteInformation = 0x0041,
	SystemBigPoolInformation = 0x0042,
	SystemSessionPoolTagInformation = 0x0043,
	SystemSessionMappedViewInformation = 0x0044,
	SystemHotpatchInformation = 0x0045,
	SystemObjectSecurityMode = 0x0046,
	SystemWatchdogTimerHandler = 0x0047,
	SystemWatchdogTimerInformation = 0x0048,
	SystemLogicalProcessorInformation = 0x0049,
	SystemWow64SharedInformationObsolete = 0x004A,
	SystemRegisterFirmwareTableInformationHandler = 0x004B,
	SystemFirmwareTableInformation = 0x004C,
	SystemModuleInformationEx = 0x004D,
	SystemVerifierTriageInformation = 0x004E,
	SystemSuperfetchInformation = 0x004F,
	SystemMemoryListInformation = 0x0050,
	SystemFileCacheInformationEx = 0x0051,
	SystemThreadPriorityClientIdInformation = 0x0052,
	SystemProcessorIdleCycleTimeInformation = 0x0053,
	SystemVerifierCancellationInformation = 0x0054,
	SystemProcessorPowerInformationEx = 0x0055,
	SystemRefTraceInformation = 0x0056,
	SystemSpecialPoolInformation = 0x0057,
	SystemProcessIdInformation = 0x0058,
	SystemErrorPortInformation = 0x0059,
	SystemBootEnvironmentInformation = 0x005A,
	SystemHypervisorInformation = 0x005B,
	SystemVerifierInformationEx = 0x005C,
	SystemTimeZoneInformation = 0x005D,
	SystemImageFileExecutionOptionsInformation = 0x005E,
	SystemCoverageInformation = 0x005F,
	SystemPrefetchPatchInformation = 0x0060,
	SystemVerifierFaultsInformation = 0x0061,
	SystemSystemPartitionInformation = 0x0062,
	SystemSystemDiskInformation = 0x0063,
	SystemProcessorPerformanceDistribution = 0x0064,
	SystemNumaProximityNodeInformation = 0x0065,
	SystemDynamicTimeZoneInformation = 0x0066,
	SystemCodeIntegrityInformation = 0x0067,
	SystemProcessorMicrocodeUpdateInformation = 0x0068,
	SystemProcessorBrandString = 0x0069,
	SystemVirtualAddressInformation = 0x006A,
	SystemLogicalProcessorAndGroupInformation = 0x006B,
	SystemProcessorCycleTimeInformation = 0x006C,
	SystemStoreInformation = 0x006D,
	SystemRegistryAppendString = 0x006E,
	SystemAitSamplingValue = 0x006F,
	SystemVhdBootInformation = 0x0070,
	SystemCpuQuotaInformation = 0x0071,
	SystemNativeBasicInformation = 0x0072,
	SystemErrorPortTimeouts = 0x0073,
	SystemLowPriorityIoInformation = 0x0074,
	SystemBootEntropyInformation = 0x0075,
	SystemVerifierCountersInformation = 0x0076,
	SystemPagedPoolInformationEx = 0x0077,
	SystemSystemPtesInformationEx = 0x0078,
	SystemNodeDistanceInformation = 0x0079,
	SystemAcpiAuditInformation = 0x007A,
	SystemBasicPerformanceInformation = 0x007B,
	SystemQueryPerformanceCounterInformation = 0x007C,
	SystemSessionBigPoolInformation = 0x007D,
	SystemBootGraphicsInformation = 0x007E,
	SystemScrubPhysicalMemoryInformation = 0x007F,
	SystemBadPageInformation = 0x0080,
	SystemProcessorProfileControlArea = 0x0081,
	SystemCombinePhysicalMemoryInformation = 0x0082,
	SystemEntropyInterruptTimingInformation = 0x0083,
	SystemConsoleInformation = 0x0084,
	SystemPlatformBinaryInformation = 0x0085,
	SystemThrottleNotificationInformation = 0x0086,
	SystemHypervisorProcessorCountInformation = 0x0087,
	SystemDeviceDataInformation = 0x0088,
	SystemDeviceDataEnumerationInformation = 0x0089,
	SystemMemoryTopologyInformation = 0x008A,
	SystemMemoryChannelInformation = 0x008B,
	SystemBootLogoInformation = 0x008C,
	SystemProcessorPerformanceInformationEx = 0x008D,
	SystemSpare0 = 0x008E,
	SystemSecureBootPolicyInformation = 0x008F,
	SystemPageFileInformationEx = 0x0090,
	SystemSecureBootInformation = 0x0091,
	SystemEntropyInterruptTimingRawInformation = 0x0092,
	SystemPortableWorkspaceEfiLauncherInformation = 0x0093,
	SystemFullProcessInformation = 0x0094,
	MaxSystemInfoClass = 0x0095
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;
typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
	ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
	ProcessIoCounters, // q: IO_COUNTERS
	ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
	ProcessTimes, // q: KERNEL_USER_TIMES
	ProcessBasePriority, // s: KPRIORITY
	ProcessRaisePriority, // s: ULONG
	ProcessDebugPort, // q: HANDLE
	ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT
	ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
	ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
	ProcessLdtSize, // s: PROCESS_LDT_SIZE
	ProcessDefaultHardErrorMode, // qs: ULONG
	ProcessIoPortHandlers, // (kernel-mode only)
	ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
	ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
	ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
	ProcessWx86Information,
	ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
	ProcessAffinityMask, // s: KAFFINITY
	ProcessPriorityBoost, // qs: ULONG
	ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
	ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
	ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
	ProcessWow64Information, // q: ULONG_PTR
	ProcessImageFileName, // q: UNICODE_STRING
	ProcessLUIDDeviceMapsEnabled, // q: ULONG
	ProcessBreakOnTermination, // qs: ULONG
	ProcessDebugObjectHandle, // q: HANDLE // 30
	ProcessDebugFlags, // qs: ULONG
	ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
	ProcessIoPriority, // qs: IO_PRIORITY_HINT
	ProcessExecuteFlags, // qs: ULONG
	ProcessResourceManagement, // ProcessTlsInformation // PROCESS_TLS_INFORMATION
	ProcessCookie, // q: ULONG
	ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
	ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
	ProcessPagePriority, // q: PAGE_PRIORITY_INFORMATION
	ProcessInstrumentationCallback, // qs: PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
	ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
	ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
	ProcessImageFileNameWin32, // q: UNICODE_STRING
	ProcessImageFileMapping, // q: HANDLE (input)
	ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
	ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
	ProcessGroupInformation, // q: USHORT[]
	ProcessTokenVirtualizationEnabled, // s: ULONG
	ProcessConsoleHostProcess, // q: ULONG_PTR // ProcessOwnerInformation
	ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
	ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
	ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
	ProcessDynamicFunctionTableInformation,
	ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
	ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
	ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
	ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
	ProcessHandleTable, // since WINBLUE
	ProcessCheckStackExtentsMode,
	ProcessCommandLineInformation, // q: UNICODE_STRING // 60
	ProcessProtectionInformation, // q: PS_PROTECTION
	ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
	ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
	ProcessTelemetryIdInformation, // PROCESS_TELEMETRY_ID_INFORMATION
	ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
	ProcessDefaultCpuSetsInformation,
	ProcessAllowedCpuSetsInformation,
	ProcessSubsystemProcess,
	ProcessJobMemoryInformation, // PROCESS_JOB_MEMORY_INFO
	ProcessInPrivate, // since THRESHOLD2 // 70
	ProcessRaiseUMExceptionOnInvalidHandleClose,
	ProcessIumChallengeResponse,
	ProcessChildProcessInformation, // PROCESS_CHILD_PROCESS_INFORMATION
	ProcessHighGraphicsPriorityInformation,
	ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
	ProcessEnergyValues, // PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
	ProcessActivityThrottleState, // PROCESS_ACTIVITY_THROTTLE_STATE
	ProcessActivityThrottlePolicy, // PROCESS_ACTIVITY_THROTTLE_POLICY
	ProcessWin32kSyscallFilterInformation,
	ProcessDisableSystemAllowedCpuSets, // 80
	ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
	ProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
	ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
	ProcessCaptureTrustletLiveDump,
	ProcessTelemetryCoverage,
	ProcessEnclaveInformation,
	ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
	ProcessUptimeInformation, // PROCESS_UPTIME_INFORMATION
	ProcessImageSection,
	ProcessDebugAuthInformation, // since REDSTONE4 // 90
	ProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
	ProcessSequenceNumber, // q: ULONGLONG
	ProcessLoaderDetour, // since REDSTONE5
	ProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
	ProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
	ProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
	ProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
	MaxProcessInfoClass
} PROCESSINFOCLASS;
typedef struct _SYSTEM_PROCESS {
	ULONG NextEntryOffset;//relative offset
	ULONG ThreadCount;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	LONG BasePriority;
	HANDLE UniqueProcessId;
	PVOID InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	VM_COUNTERS VmCounters;
	ULONG_PTR PrivatePageCount;
	IO_COUNTERS IoCounters;//defined in winnt.h
}SYSTEM_PROCESS, *PSYSTEM_PROCESS;
typedef LONG KPRIORITY;
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
	ULONG HardFaultCount; // since WIN7
	ULONG NumberOfThreadsHighWatermark; // since WIN7
	ULONGLONG CycleTime; // since WIN7
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	LPVOID PebBaseAddress;
	ULONG_PTR AffinityMask;
	ULONG BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;
typedef NTSTATUS(WINAPI *NtQuerySystemInformation_t)(IN SYSTEM_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG);
typedef NTSTATUS(WINAPI *NtQueryInformation_t)(IN HANDLE, IN LONG, OUT PVOID, IN ULONG, OUT PULONG);
typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation, // MEMORY_BASIC_INFORMATION
	MemoryWorkingSetInformation, // MEMORY_WORKING_SET_INFORMATION
	MemoryMappedFilenameInformation, // UNICODE_STRING
	MemoryRegionInformation, // MEMORY_REGION_INFORMATION
	MemoryWorkingSetExInformation, // MEMORY_WORKING_SET_EX_INFORMATION
	MemorySharedCommitInformation, // MEMORY_SHARED_COMMIT_INFORMATION
	MemoryImageInformation, // MEMORY_IMAGE_INFORMATION
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation, // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
	MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS;

#define GDI_BATCH_BUFFER_SIZE 0x136
typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	HMODULE                 BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	_ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
typedef struct _GDI_TEB_BATCH {
	ULONG Offset;
	HANDLE HDC;
	ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;
typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
typedef struct _CURDIR {
	UNICODE_STRING DosPath;
	PVOID Handle;
} CURDIR, *PCURDIR;
typedef struct _RTL_DRIVE_LETTER_CURDIR {
	WORD Flags;
	WORD Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;
typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	PVOID StandardInput;
	PVOID StandardOutput;
	PVOID StandardError;
	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
	ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
typedef PVOID PACTIVATION_CONTEXT;
typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
	struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
	PACTIVATION_CONTEXT ActivationContext;
	ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;
typedef struct _RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED {
	SIZE_T Size;
	ULONG Format;
	RTL_ACTIVATION_CONTEXT_STACK_FRAME Frame;
	PVOID Extra1;
	PVOID Extra2;
	PVOID Extra3;
	PVOID Extra4;
} RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED, * PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED;
typedef RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME;
typedef PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME;
typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID TransferAddress;
	ULONG ZeroBits;
	ULONG MaximumStackSize;
	ULONG CommittedStackSize;
	ULONG SubSystemType;
	union 	{
		struct {
			WORD SubSystemMinorVersion;
			WORD SubSystemMajorVersion;
		};
		ULONG SubSystemVersion;
	};
	ULONG GpValue;
	WORD ImageCharacteristics;
	WORD DllCharacteristics;
	WORD Machine;
	UCHAR ImageContainsCode;
	UCHAR ImageFlags;
	ULONG ComPlusNativeReady : 1;
	ULONG ComPlusILOnly : 1;
	ULONG ImageDynamicallyRelocated : 1;
	ULONG Reserved : 5;
	ULONG LoaderFlags;
	ULONG ImageFileSize;
	ULONG CheckSum;
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;
typedef struct _MEMORY_IMAGE_INFORMATION {
	PVOID ImageBase;
	SIZE_T SizeOfImage;
	union {
		ULONG ImageFlags;
		struct {
			ULONG ImagePartialMap : 1;
			ULONG ImageNotExecutable : 1;
			ULONG ImageSigningLevel : 4; // REDSTONE3
			ULONG Reserved : 26;
		};
	};
} MEMORY_IMAGE_INFORMATION, * PMEMORY_IMAGE_INFORMATION;

#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60
#ifndef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif
typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];
typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union {
		BOOLEAN BitField;
		struct {
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN SpareBits : 1;
		};
	};
	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	union {
		ULONG CrossProcessFlags;
		struct {
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ReservedBits0 : 27;
		};
	};
	union {
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved[1];
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID HotpatchInformation;
	PVOID *ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	LARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID *ProcessHeaps;

	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;

	PRTL_CRITICAL_SECTION LoaderLock;

	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG_PTR ImageProcessAffinityMask;
	GDI_HANDLE_BUFFER GdiHandleBuffer;
	PVOID PostProcessInitRoutine;

	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];

	ULONG SessionId;

	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;

	UNICODE_STRING CSDVersion;

	PVOID ActivationContextData;
	PVOID ProcessAssemblyStorageMap;
	PVOID SystemDefaultActivationContextData;
	PVOID SystemAssemblyStorageMap;

	SIZE_T MinimumStackCommit;

	PVOID *FlsCallback;
	LIST_ENTRY FlsListHead;
	PVOID FlsBitmap;
	ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
	ULONG FlsHighIndex;

	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
	PVOID pContextData;
	PVOID pImageHeaderHash;
	union {
		ULONG TracingFlags;
		struct {
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
} PEB, *PPEB;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
	ULONG Flags;
	PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;
typedef struct _TEB_ACTIVE_FRAME {
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME *Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;
typedef struct _TEB {
	NT_TIB NtTib;

	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB ProcessEnvironmentBlock;

	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG User32Reserved[26];
	ULONG UserReserved[5];
	PVOID WOW32Reserved;
	LCID CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	PVOID SystemReserved1[54];
	NTSTATUS ExceptionCode;
	PVOID ActivationContextStackPointer;
#ifdef _WIN64
	UCHAR SpareBytes[24];
#else
	UCHAR SpareBytes[36];
#endif
	ULONG TxFsContext;

	GDI_TEB_BATCH GdiTebBatch;
	CLIENT_ID RealClientId;
	HANDLE GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	PVOID GdiThreadLocalInfo;
	ULONG_PTR Win32ClientInfo[62];
	PVOID glDispatchTable[233];
	ULONG_PTR glReserved1[29];
	PVOID glReserved2;
	PVOID glSectionInfo;
	PVOID glSection;
	PVOID glTable;
	PVOID glCurrentRC;
	PVOID glContext;

	NTSTATUS LastStatusValue;
	UNICODE_STRING StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];

	PVOID DeallocationStack;
	PVOID TlsSlots[64];
	LIST_ENTRY TlsLinks;

	PVOID Vdm;
	PVOID ReservedForNtRpc;
	PVOID DbgSsReserved[2];

	ULONG HardErrorMode;
#ifdef _WIN64
	PVOID Instrumentation[11];
#else
	PVOID Instrumentation[9];
#endif
	GUID ActivityId;

	PVOID SubProcessTag;
	PVOID EtwLocalData;
	PVOID EtwTraceData;
	PVOID WinSockData;
	ULONG GdiBatchCount;

	union {
		PROCESSOR_NUMBER CurrentIdealProcessor;
		ULONG IdealProcessorValue;
		struct {
			UCHAR ReservedPad0;
			UCHAR ReservedPad1;
			UCHAR ReservedPad2;
			UCHAR IdealProcessor;
		};
	};

	ULONG GuaranteedStackBytes;
	PVOID ReservedForPerf;
	PVOID ReservedForOle;
	ULONG WaitingOnLoaderLock;
	PVOID SavedPriorityState;
	ULONG_PTR SoftPatchPtr1;
	PVOID ThreadPoolData;
	PVOID *TlsExpansionSlots;
#ifdef _WIN64
	PVOID DeallocationBStore;
	PVOID BStoreLimit;
#endif
	ULONG MuiGeneration;
	ULONG IsImpersonating;
	PVOID NlsCache;
	PVOID pShimData;
	ULONG HeapVirtualAffinity;
	HANDLE CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME ActiveFrame;
	PVOID FlsData;

	PVOID PreferredLanguages;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;

	union {
		USHORT CrossTebFlags;
		USHORT SpareCrossTebBits : 16;
	};
	union {
		USHORT SameTebFlags;
		struct {
			USHORT SafeThunkCall : 1;
			USHORT InDebugPrint : 1;
			USHORT HasFiberData : 1;
			USHORT SkipThreadAttach : 1;
			USHORT WerInShipAssertCode : 1;
			USHORT RanProcessInit : 1;
			USHORT ClonedThread : 1;
			USHORT SuppressDebugMsg : 1;
			USHORT DisableUserStackWalk : 1;
			USHORT RtlExceptionAttached : 1;
			USHORT InitialThread : 1;
			USHORT SessionAware : 1;
			USHORT SpareSameTebBits : 4;
		};
	};

	PVOID TxnScopeEnterCallback;
	PVOID TxnScopeExitCallback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	ULONG SpareUlong0;
	PVOID ResourceRetValue;
	PVOID ReservedForWdf;
} TEB, *PTEB;

typedef enum _POOL_TYPE {
	NonPagedPool = 0,
	PagedPool = 1,
	NonPagedPoolMustSucceed = 2,
	DontUseThisType = 3,
	NonPagedPoolCacheAligned = 4,
	PagedPoolCacheAligned = 5,
	NonPagedPoolCacheAlignedMustS = 6,
	MaxPoolType = 7,
	NonPagedPoolSession = 32,
	PagedPoolSession = 33,
	NonPagedPoolMustSucceedSession = 34,
	DontUseThisTypeSession = 35,
	NonPagedPoolCacheAlignedSession = 36,
	PagedPoolCacheAlignedSession = 37,
	NonPagedPoolCacheAlignedMustSSession = 38
} POOL_TYPE;
typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING          TypeName;
	ULONG                   TotalNumberOfHandles;
	ULONG                   TotalNumberOfObjects;
	WCHAR                   Unused1[8];
	ULONG                   HighWaterNumberOfHandles;
	ULONG                   HighWaterNumberOfObjects;
	WCHAR                   Unused2[8];
	ACCESS_MASK             InvalidAttributes;
	GENERIC_MAPPING         GenericMapping;
	ACCESS_MASK             ValidAttributes;
	BOOLEAN                 SecurityRequired;
	BOOLEAN                 MaintainHandleCount;
	USHORT                  MaintainTypeList;
	POOL_TYPE               PoolType;
	ULONG                   DefaultPagedPoolCharge;
	ULONG                   DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;
typedef struct _OBJECT_ALL_INFORMATION {
	ULONG						NumberOfObjectsTypes;
	OBJECT_TYPE_INFORMATION		ObjectTypeInformation[ANYSIZE_ARRAY];
}OBJECT_ALL_INFORMATION, *POBJECT_ALL_INFORMATION;
typedef struct _OBJECT_BASIC_INFORMATION {
	ULONG                   Attributes;
	ACCESS_MASK             DesiredAccess;
	ULONG                   HandleCount;
	ULONG                   ReferenceCount;
	ULONG                   PagedPoolUsage;
	ULONG                   NonPagedPoolUsage;
	ULONG                   Reserved[3];
	ULONG                   NameInformationLength;
	ULONG                   TypeInformationLength;
	ULONG                   SecurityDescriptorLength;
	LARGE_INTEGER           CreationTime;
}OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;
typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING          Name;
	WCHAR                   NameBuffer[ANYSIZE_ARRAY];
}OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;
typedef struct _OBJECT_DATA_INFORMATION {
	BOOLEAN                 InheritHandle;
	BOOLEAN                 ProtectFromClose;
}OBJECT_DATA_INFORMATION, *POBJECT_DATA_INFORMATION;
typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef struct _LSA_LAST_INTER_LOGON_INFO {
	LARGE_INTEGER LastSuccessfulLogon;
	LARGE_INTEGER LastFailedLogon;
	ULONG FailedAttemptCountSinceLastSuccessfulLogon;
} LSA_LAST_INTER_LOGON_INFO, *PLSA_LAST_INTER_LOGON_INFO;
typedef struct _SECURITY__LOGON_SESSION_DATA {
	ULONG               Size;
	LUID                LogonId;
	LSA_UNICODE_STRING  UserName;
	LSA_UNICODE_STRING  LogonDomain;
	LSA_UNICODE_STRING  AuthenticationPackage;
	ULONG               LogonType;
	ULONG               Session;
	PSID                Sid;
	LARGE_INTEGER       LogonTime;

	LSA_UNICODE_STRING  LogonServer;
	LSA_UNICODE_STRING  DnsDomainName;
	LSA_UNICODE_STRING  Upn;

	ULONG UserFlags;

	LSA_LAST_INTER_LOGON_INFO LastLogonInfo;
	LSA_UNICODE_STRING LogonScript;
	LSA_UNICODE_STRING ProfilePath;
	LSA_UNICODE_STRING HomeDirectory;
	LSA_UNICODE_STRING HomeDirectoryDrive;

	LARGE_INTEGER LogoffTime;
	LARGE_INTEGER KickOffTime;
	LARGE_INTEGER PasswordLastSet;
	LARGE_INTEGER PasswordCanChange;
	LARGE_INTEGER PasswordMustChange;
}SECURITY_LOGON_SESSION_DATA, *PSECURITY_LOGON_SESSION_DATA,
LOGON_SESSION_DATA, *PLOGON_SESSION_DATA;

NTSTATUS NTAPI NtQueryObject(
	IN HANDLE               ObjectHandle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	OUT PVOID               ObjectInformation,
	IN ULONG                Length,
	OUT PULONG              ResultLength);

NTSTATUS NTAPI NtSetInformationObject(
	IN HANDLE               ObjectHandle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	IN PVOID               ObjectInformation,
	IN ULONG                Length);

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
#define InitializeObjectAttributes(p, n, a, r, s) { \
(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
(p)->RootDirectory = r; \
(p)->Attributes = a; \
(p)->ObjectName = n; \
(p)->SecurityDescriptor = s; \
(p)->SecurityQualityOfService = NULL; \
}

#define OBJ_INHERIT 0x00000002
#define OBJ_PERMANENT 0x00000010
#define OBJ_EXCLUSIVE 0x00000020
#define OBJ_CASE_INSENSITIVE 0x00000040
#define OBJ_OPENIF 0x00000080
#define OBJ_OPENLINK 0x00000100
#define OBJ_KERNEL_HANDLE 0x00000200
#define OBJ_FORCE_ACCESS_CHECK 0x00000400
#define OBJ_VALID_ATTRIBUTES 0x000007f2

#define DUPLICATE_SAME_ATTRIBUTES 0x00000004

FARPROC WINAPI GetNtProcAddress(LPCSTR func_name);

NTSTATUS NTAPI NtDuplicateObject(
	IN HANDLE               SourceProcessHandle,
	IN HANDLE               SourceHandle,
	IN HANDLE               TargetProcessHandle,
	OUT PHANDLE             TargetHandle,
	IN ACCESS_MASK          DesiredAccess OPTIONAL,
	IN BOOLEAN              InheritHandle,
	IN ULONG                Options);

DWORD NTAPI RtlNtStatusToDosError(NTSTATUS status);

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
);

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
);

NTSTATUS NTAPI NtOpenProcessToken(IN HANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, OUT PHANDLE TokenHandle);

NTSTATUS NTAPI NtDuplicateToken(
	IN HANDLE               ExistingToken,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
	IN SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
	IN TOKEN_TYPE           TokenType,
	OUT PHANDLE             NewToken);

NTSTATUS NTAPI NtAdjustPrivilegesToken(
	IN HANDLE               TokenHandle,
	IN BOOLEAN              DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES    TokenPrivileges,
	IN ULONG                PreviousPrivilegesLength,
	OUT PTOKEN_PRIVILEGES   PreviousPrivileges OPTIONAL,
	OUT PULONG              RequiredLength OPTIONAL);

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
	PTOKEN_SOURCE        TokenSource
);

NTSTATUS NtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS _class, OUT PVOID buffer, IN ULONG buffer_size, OUT PULONG out_len);

NTSTATUS WINAPI NtQueryInformationProcess(IN HANDLE hProcess, IN LONG _class, OUT PVOID buffer, IN ULONG buffer_size, OUT PULONG out_len);
NTSTATUS WINAPI NtQueryInformationThread(IN HANDLE hThread, IN LONG _class, OUT PVOID buffer, IN ULONG buffer_size, OUT PULONG out_len);

NTSTATUS NTAPI NtAllocateLocallyUniqueId(OUT PLUID LocallyUniqueId);

NTSTATUS NTAPI NtOpenThreadToken(
	IN HANDLE               ThreadHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN BOOLEAN              OpenAsSelf,
	OUT PHANDLE             TokenHandle);


typedef NTSTATUS (NTAPI * PRTL_HEAP_COMMIT_ROUTINE)(IN PVOID Base, IN OUT PVOID *CommitAddress, IN OUT PSIZE_T CommitSize);
typedef struct _RTL_HEAP_PARAMETERS {
	ULONG Length;
	SIZE_T SegmentReserve;
	SIZE_T SegmentCommit;
	SIZE_T DeCommitFreeBlockThreshold;
	SIZE_T DeCommitTotalFreeThreshold;
	SIZE_T MaximumAllocationSize;
	SIZE_T VirtualMemoryThreshold;
	SIZE_T InitialCommit;
	SIZE_T InitialReserve;
	PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
	SIZE_T Reserved[2];
} RTL_HEAP_PARAMETERS, *PRTL_HEAP_PARAMETERS;
BOOL RtlFreeHeap(
	PVOID HeapHandle,
	ULONG Flags,
	PVOID BaseAddress
);
PVOID RtlAllocateHeap(
	PVOID HeapHandle,
	ULONG Flags,
	SIZE_T Size
);
PVOID RtlCreateHeap(
	ULONG                Flags,
	PVOID                HeapBase,
	SIZE_T               ReserveSize,
	SIZE_T               CommitSize,
	PVOID                Lock,
	PRTL_HEAP_PARAMETERS Parameters
);
PVOID BsRtlCreateHeap(
	ULONG                Flags,
	SIZE_T               ReserveSize,
	SIZE_T               CommitSize
);
PVOID RtlDestroyHeap(
	PVOID HeapHandle
);
extern "C" {
	NTSTATUS NTAPI LsaFreeReturnBuffer(PVOID Buffer);
	NTSTATUS NTAPI LsaEnumerateLogonSessions(PULONG LogonSessionCount, PLUID * LogonSessionList);
	NTSTATUS NTAPI LsaGetLogonSessionData(PLUID LogonId, PSECURITY_LOGON_SESSION_DATA * ppLogonSessionData);
}

VOID NTAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
BOOL NTAPI RtlCreateUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
VOID NTAPI RtlFreeUnicodeString(PUNICODE_STRING UnicodeString);
NTSTATUS NTAPI NtClose(IN HANDLE Handle);

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
	OUT CLIENT_ID*          ClientID);

NTSTATUS NTAPI NtAllocateVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN ULONG                ZeroBits,
	IN OUT PULONG           RegionSize,
	IN ULONG                AllocationType,
	IN ULONG                Protect);

NTSTATUS NTAPI NtFreeVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                *BaseAddress,
	IN OUT PULONG           RegionSize,
	IN ULONG                FreeType);

NTSTATUS NTAPI NtReadVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	OUT PVOID               Buffer,
	IN ULONG                NumberOfBytesToRead,
	OUT PULONG              NumberOfBytesReaded OPTIONAL);

NTSTATUS NTAPI NtWriteVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL);

NTSTATUS NTAPI NtProtectVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T           NumberOfBytesToProtect,
	IN SIZE_T                NewAccessProtection,
	OUT PSIZE_T              OldAccessProtection);

NTSTATUS NTAPI NtLockVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                *BaseAddress,
	IN OUT PULONG           NumberOfBytesToLock,
	IN ULONG                LockOption);

NTSTATUS NTAPI NtUnlockVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                *BaseAddress,
	IN OUT PULONG           NumberOfBytesToUnlock,
	IN ULONG                LockType);

NTSTATUS NTAPI NtQueryVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID               Buffer,
	IN SIZE_T                Length,
	OUT PSIZE_T              ResultLength OPTIONAL);


PVOID RtlImageDirectoryEntryToData(
	PVOID BaseAddress,
	BOOLEAN 	MappedAsImage,
	USHORT 	Directory,
	PULONG 	Size
);

VOID NTAPI RtlInitAnsiString(
	PANSI_STRING 	DestinationString,
	LPCSTR 	SourceString
);

NTSTATUS NTAPI RtlAnsiStringToUnicodeString(
	PUNICODE_STRING 	DestinationString,
	PANSI_STRING 	SourceString,
	BOOLEAN 	AllocateDestinationString
);

PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(LPVOID BaseAddress);

PPEB NTAPI NtCurrentPeb();


WCHAR NTAPI RtlUpcaseUnicodeChar(IN WCHAR Source);

#define HASH_STRING_ALGORITHM_DEFAULT 0
#define HASH_STRING_ALGORITHM_X65599 1

NTSTATUS NTAPI RtlHashUnicodeString(
	IN  PCUNICODE_STRING String,
	IN  BOOLEAN          CaseInSensitive,
	IN  ULONG            HashAlgorithm,
	OUT PULONG           HashValue
);

VOID NTAPI RtlGetNtVersionNumbers(
	OUT DWORD* MajorVersion,
	OUT DWORD* MinorVersion,
	OUT DWORD* BuildNumber);

#define UNW_FLAG_NHANDLER 0x0
#define UNW_FLAG_EHANDLER 0x1
#define UNW_FLAG_UHANDLER 0x2
#define UNW_FLAG_CHAININFO 0x4
typedef union _UNWIND_CODE {
	struct {
		BYTE CodeOffset;
		BYTE UnwindOp : 4;
		BYTE OpInfo : 4;
	} u;
	USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;
typedef struct _UNWIND_INFO {
	BYTE Version : 3;
	BYTE Flags : 5;
	BYTE SizeOfProlog;
	BYTE CountOfCodes;
	BYTE FrameRegister : 4;
	BYTE FrameOffset : 4;
	UNWIND_CODE UnwindCode[1];
	//union {
	//	//
	//	// If (Flags & UNW_FLAG_EHANDLER)
	//	//
	//	OPTIONAL ULONG ExceptionHandler;
	//	//
	//	// Else if (Flags & UNW_FLAG_CHAININFO)
	//	//
	//	OPTIONAL ULONG FunctionEntry;
	//};
	////
	//// If (Flags & UNW_FLAG_EHANDLER)
	////
	//OPTIONAL ULONG ExceptionData; //offset to PSCOPE_TABLE
} UNWIND_INFO, * PUNWIND_INFO;

#define GetUnwindCodeEntry(info, index) ((info)->UnwindCode[index])

#define GetLanguageSpecificDataPtr(info) ((PVOID)&GetUnwindCodeEntry((info),((info)->CountOfCodes + 1) & ~1))

#define GetExceptionHandler(base, info) ((PVOID)((base) + *(PULONG)GetLanguageSpecificDataPtr(info)))

#define GetChainedFunctionEntry(base, info) ((PRUNTIME_FUNCTION)((base) + *(PULONG)GetLanguageSpecificDataPtr(info)))

#define GetExceptionDataPtr(info) ((PVOID)((PULONG)GetLanguageSpecificData(info) + 1)

NTSTATUS NTAPI NtQuerySystemTime(PLARGE_INTEGER SystemTime);
