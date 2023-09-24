#pragma once

//
// ThreadLocalStoragePointer Tls indexs
//      [0, MMP_START_TLS_INDEX)                         Reserved for ntdll loader
//      [MMP_START_TLS_INDEX, MMP_MAXIMUM_TLS_INDEX)     Reserved for MemoryModule
//

#define MMP_START_TLS_INDEX         0x80                            //128

#define MMP_MAXIMUM_TLS_INDEX       0x100                           //256

#define MMP_TLSP_INDEX_BUFFER_SIZE  (MMP_MAXIMUM_TLS_INDEX / 8)     //32

#if (((MMP_START_TLS_INDEX | MMP_MAXIMUM_TLS_INDEX) & 7) || (MMP_START_TLS_INDEX >= MMP_MAXIMUM_TLS_INDEX))
#error "MMP_START_TLS_INDEX must be smaller than MMP_MAXIMUM_TLS_INDEX, and both are 8-bit aligned."
#endif

#define MmpAllocateTlsp()   (PTLS_VECTOR)(RtlAllocateHeap(\
                                RtlProcessHeap(),\
                                HEAP_ZERO_MEMORY,\
                                sizeof(TLS_VECTOR) + sizeof(PVOID)* MMP_MAXIMUM_TLS_INDEX\
                            ))

typedef struct _TLS_VECTOR {
    union
    {
        ULONG  Length;
        HANDLE ThreadId;
    };

    struct _TLS_VECTOR* PreviousDeferredTlsVector;
    PVOID ModuleTlsData[ANYSIZE_ARRAY];
} TLS_VECTOR, * PTLS_VECTOR;

typedef struct _TLS_ENTRY {
    LIST_ENTRY            TlsEntryLinks;
    IMAGE_TLS_DIRECTORY   TlsDirectory;
    PLDR_DATA_TABLE_ENTRY ModuleEntry;
} TLS_ENTRY, * PTLS_ENTRY;

typedef struct _MMP_TLSP_RECORD {

    LIST_ENTRY InMmpThreadLocalStoragePointer;

    HANDLE UniqueThread;

    // PEB->ThreadLocalStoragePointer allocated by ntdll!Ldr
    PVOID* TlspLdrBlock;

    // PEB->ThreadLocalStoragePointer allocated by MemoryModulePP
    PVOID* TlspMmpBlock;
}MMP_TLSP_RECORD, * PMMP_TLSP_RECORD;

typedef struct _THREAD_CONTEXT {
    PTHREAD_START_ROUTINE ThreadStartRoutine;
    LPVOID ThreadParameter;
}THREAD_CONTEXT, * PTHREAD_CONTEXT;
