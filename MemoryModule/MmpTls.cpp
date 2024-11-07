#include "stdafx.h"

#if (MMPP_USE_TLS)
#include "MmpTlsp.h"
#include "MmpTlsFiber.h"

#include <cassert>
#include <algorithm>
#include <3rdparty/Detours/detours.h>
#include <set>


PVOID NTAPI MmpQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_opt_ LPDWORD ReturnLength) {

    if (ReturnLength)*ReturnLength = 0;

    NTSTATUS status;
    PVOID buffer = nullptr;
    ULONG len = 0;


    do {

        RtlFreeHeap(
            RtlProcessHeap(),
            0,
            buffer
        );
        buffer = nullptr;

        if (len) {
            len *= 2;
            buffer = RtlAllocateHeap(
                RtlProcessHeap(),
                0,
                len
            );
            if (!buffer)return nullptr;
        }

        status = NtQuerySystemInformation(
            SystemInformationClass,
            buffer,
            len,
            &len
        );
        if (NT_SUCCESS(status))break;
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (ReturnLength)*ReturnLength = len;
    return buffer;
}

DWORD NTAPI MmpGetThreadCount() {
    DWORD result = 0;
    auto pid = NtCurrentProcessId();

    auto spi = PSYSTEM_PROCESS_INFORMATION(MmpQuerySystemInformation(SystemProcessInformation, nullptr));
    if (spi) {
        auto p = spi;

        while (true) {

            if (p->UniqueProcessId == pid) {
                OBJECT_ATTRIBUTES oa{};
                InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

                THREAD_BASIC_INFORMATION tbi{};

                NTSTATUS status;
                for (ULONG i = 0; i < p->NumberOfThreads; ++i) {
                    HANDLE hThread;
                    status = NtOpenThread(
                        &hThread,
                        THREAD_QUERY_INFORMATION,
                        &oa,
                        &p->Threads[i].ClientId
                    );

                    if (NT_SUCCESS(status)) {
                        status = NtQueryInformationThread(
                            hThread,
                            ThreadBasicInformation,
                            &tbi,
                            sizeof(tbi),
                            nullptr
                        );
                        if (NT_SUCCESS(status) && !!tbi.TebBaseAddress->ThreadLocalStoragePointer) {
                            ++result;
                        }
                        
                        NtClose(hThread);
                    }
                }

                break;
            }

            if (!p->NextEntryOffset)break;
            p = PSYSTEM_PROCESS_INFORMATION(LPSTR(p) + p->NextEntryOffset);
        }

        RtlFreeHeap(RtlProcessHeap(), 0, spi);
    }

    return result;
}

PMMP_TLSP_RECORD MmpFindTlspRecordLockHeld() {
    PLIST_ENTRY entry = MmpGlobalDataPtr->MmpTls->MmpThreadLocalStoragePointer.Flink;
    PTEB teb = NtCurrentTeb();

    while (entry != &MmpGlobalDataPtr->MmpTls->MmpThreadLocalStoragePointer) {

        auto p = CONTAINING_RECORD(entry, MMP_TLSP_RECORD, InMmpThreadLocalStoragePointer);

        if (p->UniqueThread == NtCurrentThreadId()) {
            assert(p->TlspMmpBlock == teb->ThreadLocalStoragePointer);
            return p;
        }

        entry = entry->Flink;
    }

    return nullptr;
}

DWORD MmpAllocateTlsLockHeld() {
    bool success = false;
    PMMP_TLSP_RECORD record = nullptr;

    if (!NtCurrentTeb()->ThreadLocalStoragePointer) {
        goto __skip_tls;
    }

    //
    // Allocate and replace ThreadLocalStoragePointer for new thread
    //
    EnterCriticalSection(&MmpGlobalDataPtr->MmpTls->MmpTlspLock);

    //
    // Check if we have already initialized
    //
    record = MmpFindTlspRecordLockHeld();
    if (!!record) {
        LeaveCriticalSection(&MmpGlobalDataPtr->MmpTls->MmpTlspLock);
        goto __skip_tls;
    }

    record = PMMP_TLSP_RECORD(RtlAllocateHeap(RtlProcessHeap(), 0, sizeof(MMP_TLSP_RECORD)));
    if (record) {
        record->TlspLdrBlock = (PVOID*)NtCurrentTeb()->ThreadLocalStoragePointer;
        record->TlspMmpBlock = (PVOID*)MmpAllocateTlsp();
        record->UniqueThread = NtCurrentThreadId();
        if (record->TlspMmpBlock) {
            record->TlspMmpBlock = ((PTLS_VECTOR)record->TlspMmpBlock)->ModuleTlsData;

            auto size = CONTAINING_RECORD(record->TlspLdrBlock, TLS_VECTOR, ModuleTlsData)->Length;
            if ((HANDLE)(ULONG_PTR)size != NtCurrentThreadId()) {
                RtlCopyMemory(
                    record->TlspMmpBlock,
                    record->TlspLdrBlock,
                    size * sizeof(PVOID)
                );
            }

            NtCurrentTeb()->ThreadLocalStoragePointer = record->TlspMmpBlock;

            InsertTailList(&MmpGlobalDataPtr->MmpTls->MmpThreadLocalStoragePointer, &record->InMmpThreadLocalStoragePointer);
            success = true;
        }
        else {
            RtlFreeHeap(RtlProcessHeap(), 0, record);
        }
    }

    LeaveCriticalSection(&MmpGlobalDataPtr->MmpTls->MmpTlspLock);

    //
    // Handle MemoryModule Tls data
    //
    if (success) {
        RtlAcquireSRWLockShared(&MmpGlobalDataPtr->MmpTls->MmpTlsListLock);

        auto ThreadLocalStoragePointer = (PVOID*)NtCurrentTeb()->ThreadLocalStoragePointer;
        PLIST_ENTRY entry = MmpGlobalDataPtr->MmpTls->MmpTlsList.Flink;
        while (entry != &MmpGlobalDataPtr->MmpTls->MmpTlsList) {

            PTLS_ENTRY tls = CONTAINING_RECORD(entry, TLS_ENTRY, TlsEntryLinks);
            auto len = tls->TlsDirectory.EndAddressOfRawData - tls->TlsDirectory.StartAddressOfRawData;
            PVOID data = len ? RtlAllocateHeap(RtlProcessHeap(), 0, len) : nullptr;
            if (!data) {
                RtlFreeHeap(RtlProcessHeap(), 0, data);
                success = false;
                break;
            }

            RtlCopyMemory(
                data,
                PVOID(tls->TlsDirectory.StartAddressOfRawData),
                len
            );


            ThreadLocalStoragePointer[tls->TlsDirectory.Characteristics] = data;

            entry = entry->Flink;
        }

        RtlReleaseSRWLockShared(&MmpGlobalDataPtr->MmpTls->MmpTlsListLock);
    }

    if (!success) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    InterlockedIncrement(&MmpGlobalDataPtr->MmpTls->MmpActiveThreadCount);

__skip_tls:
    return ERROR_SUCCESS;
}

DWORD NTAPI MmpUserThreadStart(LPVOID lpThreadParameter) {

    THREAD_CONTEXT Context;

    __try {
        RtlCopyMemory(
            &Context,
            lpThreadParameter,
            sizeof(Context)
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    PVOID cookie;
    LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, nullptr, &cookie);

    __try {
        MmpAllocateTlsLockHeld();
    }
    __finally {
        LdrUnlockLoaderLock(LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, cookie);
    }

    return Context.ThreadStartRoutine(Context.ThreadParameter);
}

#if (defined(_WIN64) || defined(_M_ARM))
VOID NTAPI HookRtlUserThreadStart(
    _In_ PTHREAD_START_ROUTINE Function,
    _In_ PVOID Parameter) {
    THREAD_CONTEXT Context;
    Context.ThreadStartRoutine = PTHREAD_START_ROUTINE(Function);
    Context.ThreadParameter = Parameter;

    return MmpGlobalDataPtr->MmpTls->Hooks.OriginRtlUserThreadStart(MmpUserThreadStart, &Context);
}
#else
VOID
__declspec(naked)
HookRtlUserThreadStart(
    _In_ PTHREAD_START_ROUTINE Function,    //eax
    _In_ PVOID Parameter) {                 //ebx
    __asm {
        // THREAD_CONTEXT Context;
        sub esp, 8;

        // Context.ThreadStartRoutine = PTHREAD_START_ROUTINE(Function);
        mov dword ptr ds : [esp] , eax;

        // Context.ThreadParameter = Parameter;
        mov dword ptr ds : [esp + 4] , ebx;

        mov eax, MmpUserThreadStart;
        mov ebx, esp;

        // Shadow stack for ntdll!RtlUserThreadStart
        sub esp, 8;

        // MmpGlobalDataPtr->MmpTls->Hooks.OriginRtlUserThreadStart(MmpUserThreadStart, &Context);
        mov ecx, MmpGlobalDataPtr;
        mov ecx, dword ptr ds : [ecx + 0x48] ;
        mov ecx, dword ptr ds : [ecx + 0x48] ;
        call ecx;
    }
}
#endif

VOID NTAPI HookLdrShutdownThread(VOID) {

    PMMP_TLSP_RECORD record = nullptr;

    //
    // Find our tlsp record
    //
    EnterCriticalSection(&MmpGlobalDataPtr->MmpTls->MmpTlspLock);

    record = MmpFindTlspRecordLockHeld();
    if (record) {
        RemoveEntryList(&record->InMmpThreadLocalStoragePointer);
        --MmpGlobalDataPtr->MmpTls->MmpActiveThreadCount;
    }

    assert(0 < (int)MmpGlobalDataPtr->MmpTls->MmpActiveThreadCount);

    LeaveCriticalSection(&MmpGlobalDataPtr->MmpTls->MmpTlspLock);

    if (record) {
        //
        // Free MemoryModule Tls data after terminated
        //

        MmpQueuePostponedTls(record);
    }
    else {
        if (MmpGlobalDataPtr->MmpTls->MmpTlsList.Flink != &MmpGlobalDataPtr->MmpTls->MmpTlsList) {
            assert(NtCurrentTeb()->ThreadLocalStoragePointer == nullptr);
        }
    }

    //
    // Call the original function
    //
    MmpGlobalDataPtr->MmpTls->Hooks.OriginLdrShutdownThread();
}

BOOL NTAPI PreHookNtSetInformationProcess() {
    DWORD CurrentTlsPointerSize = CONTAINING_RECORD(NtCurrentTeb()->ThreadLocalStoragePointer, TLS_VECTOR, ModuleTlsData)->Length;
    DWORD CurrentThreadCount = MmpGetThreadCount();
    DWORD ProcessTlsInformationLength = sizeof(PROCESS_TLS_INFORMATION) + (CurrentThreadCount - 1) * sizeof(THREAD_TLS_INFORMATION);
    BOOL success = TRUE;
    NTSTATUS status;

    auto ProcessTlsInformation = PPROCESS_TLS_INFORMATION(RtlAllocateHeap(
        RtlProcessHeap(),
        HEAP_ZERO_MEMORY,
        ProcessTlsInformationLength * 2
    ));
    if (ProcessTlsInformation) {

        ProcessTlsInformation->OperationType = ProcessTlsReplaceVector;
        ProcessTlsInformation->Reserved = 0;
        ProcessTlsInformation->TlsVectorLength = (HANDLE)(ULONG_PTR)CurrentTlsPointerSize == NtCurrentThreadId() ? 0 : CurrentTlsPointerSize;
        ProcessTlsInformation->ThreadDataCount = CurrentThreadCount;

        for (DWORD i = 0; i < CurrentThreadCount; ++i) {
            auto& current = ProcessTlsInformation->ThreadData[i];
            current.TlsVector = (PVOID*)MmpAllocateTlsp();
            if (current.TlsVector) {
                current.TlsVector = ((PTLS_VECTOR)current.TlsVector)->ModuleTlsData;
            }
            else {
                for (DWORD j = 0; j < i; ++j) {
                    RtlFreeHeap(RtlProcessHeap(), 0, CONTAINING_RECORD(ProcessTlsInformation->ThreadData[j].TlsVector, TLS_VECTOR, TLS_VECTOR::ModuleTlsData));
                }

                success = FALSE;
                break;
            }
        }

        if (success) {
            auto tmpTlsInformation = PPROCESS_TLS_INFORMATION(LPBYTE(ProcessTlsInformation) + ProcessTlsInformationLength);
            RtlCopyMemory(
                tmpTlsInformation,
                ProcessTlsInformation,
                ProcessTlsInformationLength
            );

            status = NtSetInformationProcess(
                NtCurrentProcess(),
                PROCESSINFOCLASS::ProcessTlsInformation,
                ProcessTlsInformation,
                ProcessTlsInformationLength
            );

            if (NT_SUCCESS(status)) {
                EnterCriticalSection(&MmpGlobalDataPtr->MmpTls->MmpTlspLock);
                for (DWORD i = 0; i < CurrentThreadCount; ++i) {
                    auto const& LdrTls = ProcessTlsInformation->ThreadData[i];
                    auto const& MmpTls = tmpTlsInformation->ThreadData[i];
                    auto record = PMMP_TLSP_RECORD(RtlAllocateHeap(RtlProcessHeap(), 0, sizeof(MMP_TLSP_RECORD)));
                    assert(record);

                    record->TlspLdrBlock = LdrTls.TlsVector;
                    record->TlspMmpBlock = MmpTls.TlsVector;
                    record->UniqueThread = LdrTls.ThreadId;
                    InsertTailList(&MmpGlobalDataPtr->MmpTls->MmpThreadLocalStoragePointer, &record->InMmpThreadLocalStoragePointer);
                }
                LeaveCriticalSection(&MmpGlobalDataPtr->MmpTls->MmpTlspLock);
            }

        }

        RtlFreeHeap(RtlProcessHeap(), 0, ProcessTlsInformation);
    }

    return success;
}

int MmpSyncThreadTlsData() {
    PSYSTEM_PROCESS_INFORMATION pspi = (PSYSTEM_PROCESS_INFORMATION)MmpQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, nullptr);
    PSYSTEM_PROCESS_INFORMATION current = pspi;
    std::set<HANDLE>threads;
    int count = 0;

    //
    // Build thread id set.
    //

    PLIST_ENTRY entry = MmpGlobalDataPtr->MmpTls->MmpThreadLocalStoragePointer.Flink;
    while (entry != &MmpGlobalDataPtr->MmpTls->MmpThreadLocalStoragePointer) {
        PMMP_TLSP_RECORD j = CONTAINING_RECORD(entry, MMP_TLSP_RECORD, InMmpThreadLocalStoragePointer);
        threads.insert(j->UniqueThread);
        
        entry = entry->Flink;
    }

    while (pspi) {

        if (current->UniqueProcessId == NtCurrentTeb()->ClientId.UniqueProcess) {

            for (ULONG index = 0; index < current->NumberOfThreads; ++index) {
                CLIENT_ID cid = current->Threads[index].ClientId;

                if (threads.find(cid.UniqueThread) == threads.end()) {

                    HANDLE hThread;
                    OBJECT_ATTRIBUTES oa{};
                    NTSTATUS status = NtOpenThread(&hThread, THREAD_QUERY_INFORMATION, &oa, &cid);
                    if (NT_SUCCESS(status)) {

                        THREAD_BASIC_INFORMATION tbi{};
                        status = NtQueryInformationThread(hThread, THREADINFOCLASS::ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
                        if (NT_SUCCESS(status)) {

                            PTEB teb = tbi.TebBaseAddress;
                            if (teb->ThreadLocalStoragePointer) {

                                //
                                // Allocate TLS record
                                //

                                auto record = PMMP_TLSP_RECORD(RtlAllocateHeap(RtlProcessHeap(), 0, sizeof(MMP_TLSP_RECORD)));
                                if (record) {
                                    record->TlspLdrBlock = (PVOID*)teb->ThreadLocalStoragePointer;
                                    record->TlspMmpBlock = (PVOID*)MmpAllocateTlsp();
                                    record->UniqueThread = cid.UniqueThread;
                                    if (record->TlspMmpBlock) {
                                        record->TlspMmpBlock = ((PTLS_VECTOR)record->TlspMmpBlock)->ModuleTlsData;

                                        auto size = CONTAINING_RECORD(record->TlspLdrBlock, TLS_VECTOR, ModuleTlsData)->Length;
                                        if ((HANDLE)(ULONG_PTR)size != record->UniqueThread) {
                                            RtlCopyMemory(
                                                record->TlspMmpBlock,
                                                record->TlspLdrBlock,
                                                size * sizeof(PVOID)
                                            );
                                        }

                                        teb->ThreadLocalStoragePointer = record->TlspMmpBlock;
                                        InsertTailList(&MmpGlobalDataPtr->MmpTls->MmpThreadLocalStoragePointer, &record->InMmpThreadLocalStoragePointer);
                                        InterlockedIncrement(&MmpGlobalDataPtr->MmpTls->MmpActiveThreadCount);

                                        ++count;
                                    }
                                    else {
                                        RtlFreeHeap(RtlProcessHeap(), 0, record);
                                    }
                                }
                            }
                        }

                        NtClose(hThread);
                    }

                }
            }

            break;
        }

        if (!current->NextEntryOffset)break;
        current = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)current + current->NextEntryOffset);
    }

    RtlFreeHeap(RtlProcessHeap(), 0, pspi);
    return count;
}

NTSTATUS NTAPI HookNtSetInformationProcess(
    _In_opt_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength) {

    if (ProcessInformationClass != ProcessTlsInformation) {
        return MmpGlobalDataPtr->MmpTls->Hooks.OriginNtSetInformationProcess(
            ProcessHandle,
            ProcessInformationClass,
            ProcessInformation,
            ProcessInformationLength
        );
    }

    auto ProcessTlsInformation = PPROCESS_TLS_INFORMATION(ProcessInformation);
    auto hProcess = ProcessHandle ? ProcessHandle : NtCurrentProcess();
    auto TlsLength = ProcessInformationLength;
    PPROCESS_TLS_INFORMATION Tls = nullptr;
    NTSTATUS status = STATUS_SUCCESS;

    //
    // Sync thread data with ntdll!Ldr.
    //

    MmpSyncThreadTlsData();

    do {
        if (ProcessTlsInformation->OperationType >= MaxProcessTlsOperation) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        //
        // Allocate new buffer to change it
        //
        Tls = PPROCESS_TLS_INFORMATION(RtlAllocateHeap(RtlProcessHeap(), 0, ProcessInformationLength));
        if (Tls) {
            RtlCopyMemory(
                Tls,
                ProcessInformation,
                ProcessInformationLength
            );
        }
        else {
            status = STATUS_NO_MEMORY;
            break;
        }

        //
        // Convert ReplaceVector to ReplaceIndex
        //
        if (ProcessTlsInformation->OperationType == ProcessTlsReplaceVector) {

            // from MemoryModulePP
            if (!ProcessHandle) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            // reserved 0x80 PVOID for ntdll loader
            if (ProcessTlsInformation->TlsVectorLength >= MMP_START_TLS_INDEX) {
                status = STATUS_NO_MEMORY;
                break;
            }

            Tls->OperationType = ProcessTlsReplaceIndex;
            for (ULONG i = 0; i < Tls->ThreadDataCount; ++i) {
                Tls->ThreadData[i].TlsModulePointer = Tls->ThreadData[i].TlsVector[ProcessTlsInformation->TlsVectorLength];
            }
        }
        else {
            if (ProcessHandle) {
                if (ProcessTlsInformation->TlsIndex >= MMP_START_TLS_INDEX) {
                    status = STATUS_NO_MEMORY;
                    break;
                }
            }
            else {
                if (ProcessTlsInformation->TlsIndex < MMP_START_TLS_INDEX || ProcessTlsInformation->TlsIndex >= MMP_MAXIMUM_TLS_INDEX) {
                    status = STATUS_NO_MEMORY;
                    break;
                }
            }
        }

        status = MmpGlobalDataPtr->MmpTls->Hooks.OriginNtSetInformationProcess(
            hProcess,
            ProcessInformationClass,
            Tls,
            TlsLength
        );

        if (!NT_SUCCESS(status))break;

        //
        // Modify our mapping
        //
        EnterCriticalSection(&MmpGlobalDataPtr->MmpTls->MmpTlspLock);
        for (ULONG i = 0; i < Tls->ThreadDataCount; ++i) {

            if (Tls->ThreadData[i].Flags == 2) {

                BOOL found = FALSE;
                PLIST_ENTRY entry = MmpGlobalDataPtr->MmpTls->MmpThreadLocalStoragePointer.Flink;

                // Find thread-spec tlsp
                while (entry != &MmpGlobalDataPtr->MmpTls->MmpThreadLocalStoragePointer) {

                    PMMP_TLSP_RECORD j = CONTAINING_RECORD(entry, MMP_TLSP_RECORD, InMmpThreadLocalStoragePointer);

                    if (ProcessTlsInformation->OperationType == ProcessTlsReplaceVector) {
                        if (j->TlspMmpBlock[ProcessTlsInformation->TlsVectorLength] == ProcessTlsInformation->ThreadData[i].TlsVector[ProcessTlsInformation->TlsVectorLength]) {
                            found = TRUE;

                            // Copy old data to new pointer
                            RtlCopyMemory(
                                ProcessTlsInformation->ThreadData[i].TlsVector,
                                j->TlspMmpBlock,
                                sizeof(PVOID) * ProcessTlsInformation->TlsVectorLength
                            );

                            // Swap the tlsp
                            std::swap(
                                j->TlspLdrBlock,
                                ProcessTlsInformation->ThreadData[i].TlsVector
                            );
                        }
                    }
                    else {
                        if (j->TlspMmpBlock[ProcessTlsInformation->TlsIndex] == ProcessTlsInformation->ThreadData[i].TlsModulePointer) {
                            found = TRUE;

                            if (ProcessHandle) {
                                j->TlspLdrBlock[ProcessTlsInformation->TlsIndex] = ProcessTlsInformation->ThreadData[i].TlsModulePointer;
                            }

                            ProcessTlsInformation->ThreadData[i].TlsModulePointer = Tls->ThreadData[i].TlsModulePointer;
                        }
                    }

                    if (found)break;
                    entry = entry->Flink;
                }

                ProcessTlsInformation->ThreadData[i].Flags = Tls->ThreadData[i].Flags;
                ProcessTlsInformation->ThreadData[i].ThreadId = Tls->ThreadData[i].ThreadId;
            }

        }
        LeaveCriticalSection(&MmpGlobalDataPtr->MmpTls->MmpTlspLock);

    } while (false);

    RtlFreeHeap(RtlProcessHeap(), 0, Tls);
    return status;
}

NTSTATUS NTAPI MmpAcquireTlsIndex(_Out_ PULONG TlsIndex) {

    *TlsIndex = -1;

    ULONG Index = RtlFindClearBitsAndSet(&MmpGlobalDataPtr->MmpTls->MmpTlsBitmap, 1, 0);
    if (Index != -1) {
        *TlsIndex = Index;
        return STATUS_SUCCESS;
    }

    return STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS NTAPI MmpAllocateTlsEntry(
    _In_ PIMAGE_TLS_DIRECTORY lpTlsDirectory,
    _In_ PLDR_DATA_TABLE_ENTRY lpModuleEntry,
    _Out_ PULONG lpTlsIndex,
    _Out_ PTLS_ENTRY* lpTlsEntry) {
    PTLS_ENTRY Entry = nullptr;
    IMAGE_TLS_DIRECTORY TlsDirectory;
    ULONG Length = 0;
    NTSTATUS status;
    DWORD TlsIndex;

    __try {
        RtlCopyMemory(
            &TlsDirectory,
            lpTlsDirectory,
            sizeof(IMAGE_TLS_DIRECTORY)
        );

        *PULONG(TlsDirectory.AddressOfIndex) = 0;

        *lpTlsIndex = 0;
        *lpTlsEntry = nullptr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    Entry = (PTLS_ENTRY)RtlAllocateHeap(
        NtCurrentPeb()->ProcessHeap,
        HEAP_ZERO_MEMORY,
        sizeof(TLS_ENTRY)
    );
    if (!Entry) {
        return STATUS_NO_MEMORY;
    }

    status = MmpAcquireTlsIndex(&TlsIndex);
    if (!NT_SUCCESS(status)) {
        RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Entry);
        return status;
    }

    RtlCopyMemory(
        &Entry->TlsDirectory,
        &TlsDirectory,
        sizeof(IMAGE_TLS_DIRECTORY)
    );

    Entry->ModuleEntry = lpModuleEntry;
    Entry->TlsDirectory.Characteristics =
        *PULONG(Entry->TlsDirectory.AddressOfIndex) = TlsIndex;

    RtlAcquireSRWLockExclusive(&MmpGlobalDataPtr->MmpTls->MmpTlsListLock);
    InsertTailList(&MmpGlobalDataPtr->MmpTls->MmpTlsList, &Entry->TlsEntryLinks);
    RtlReleaseSRWLockExclusive(&MmpGlobalDataPtr->MmpTls->MmpTlsListLock);

    *lpTlsEntry = Entry;
    *lpTlsIndex = TlsIndex;
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI MmpReleaseTlsEntry(_In_ PLDR_DATA_TABLE_ENTRY lpModuleEntry) {
    
    RtlAcquireSRWLockExclusive(&MmpGlobalDataPtr->MmpTls->MmpTlsListLock);

    for (auto entry = MmpGlobalDataPtr->MmpTls->MmpTlsList.Flink; entry != &MmpGlobalDataPtr->MmpTls->MmpTlsList; entry = entry->Flink) {
        auto p = CONTAINING_RECORD(entry, TLS_ENTRY, TlsEntryLinks);
        if (p->ModuleEntry == lpModuleEntry) {
            RemoveEntryList(&p->TlsEntryLinks);
            RtlClearBit(&MmpGlobalDataPtr->MmpTls->MmpTlsBitmap, p->TlsDirectory.Characteristics);
            RtlFreeHeap(RtlProcessHeap(), 0, p);

            break;
        }
    }

    RtlReleaseSRWLockExclusive(&MmpGlobalDataPtr->MmpTls->MmpTlsListLock);

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI MmpHandleTlsData(_In_ PLDR_DATA_TABLE_ENTRY lpModuleEntry) {
    PIMAGE_TLS_DIRECTORY lpTlsDirectory;
    ULONG DirectorySize;
    NTSTATUS status;
    ULONG TlsIndex;
    PTLS_ENTRY TlsEntry;

    lpTlsDirectory = (PIMAGE_TLS_DIRECTORY)RtlImageDirectoryEntryToData(
        lpModuleEntry->DllBase,
        TRUE,
        IMAGE_DIRECTORY_ENTRY_TLS,
        &DirectorySize
    );

    if (!lpTlsDirectory || !DirectorySize) {
        return STATUS_SUCCESS;
    }

    status = MmpAllocateTlsEntry(
        lpTlsDirectory,
        lpModuleEntry,
        &TlsIndex,
        &TlsEntry
    );
    if (!NT_SUCCESS(status)) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    auto ThreadCount = MmpGlobalDataPtr->MmpTls->MmpActiveThreadCount;
    auto success = true;
    auto Length = sizeof(PROCESS_TLS_INFORMATION) + (ThreadCount - 1) * sizeof(THREAD_TLS_INFORMATION);
    auto ProcessTlsInformation = PPROCESS_TLS_INFORMATION(RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, Length));
    if (!ProcessTlsInformation) {
        MmpReleaseTlsEntry(lpModuleEntry);
        return STATUS_NO_MEMORY;
    }

    ProcessTlsInformation->OperationType = ProcessTlsReplaceIndex;
    ProcessTlsInformation->Reserved = 0;
    ProcessTlsInformation->TlsIndex = TlsIndex;
    ProcessTlsInformation->ThreadDataCount = ThreadCount;

    for (DWORD i = 0; i < ThreadCount; ++i) {
        auto& current = ProcessTlsInformation->ThreadData[i];
        current.TlsModulePointer = RtlAllocateHeap(
            RtlProcessHeap(),
            0,
            lpTlsDirectory->EndAddressOfRawData - lpTlsDirectory->StartAddressOfRawData
        );
        if (!current.TlsModulePointer) {
            for (DWORD j = 0; j < i; ++j) {
                RtlFreeHeap(RtlProcessHeap(), 0, ProcessTlsInformation->ThreadData[j].TlsModulePointer);
            }

            success = false;
            break;
        }

        RtlCopyMemory(
            current.TlsModulePointer,
            PVOID(lpTlsDirectory->StartAddressOfRawData),
            lpTlsDirectory->EndAddressOfRawData - lpTlsDirectory->StartAddressOfRawData
        );
    }

    if (!success) {
        MmpReleaseTlsEntry(lpModuleEntry);
        return STATUS_NO_MEMORY;
    }

    status = HookNtSetInformationProcess(
        nullptr,                        // hack
        PROCESSINFOCLASS::ProcessTlsInformation,
        ProcessTlsInformation,
        (ULONG)Length
    );

    ThreadCount = 0;
    for (DWORD i = 0; i < ProcessTlsInformation->ThreadDataCount; ++i) {
        if (!ProcessTlsInformation->ThreadData[i].Flags) {
            ++ThreadCount;
        }

        RtlFreeHeap(RtlProcessHeap(), 0, ProcessTlsInformation->ThreadData[i].TlsModulePointer);
    }

    if (ThreadCount) {
        EnterCriticalSection(&MmpGlobalDataPtr->MmpTls->MmpTlspLock);
        MmpGlobalDataPtr->MmpTls->MmpActiveThreadCount -= ThreadCount;
        assert(MmpGlobalDataPtr->MmpTls->MmpActiveThreadCount > 0);
        LeaveCriticalSection(&MmpGlobalDataPtr->MmpTls->MmpTlspLock);
    }

    RtlFreeHeap(RtlProcessHeap(), 0, ProcessTlsInformation);
    return status;
}

BOOL NTAPI MmpTlsInitialize() {

    auto tls = CONTAINING_RECORD(NtCurrentTeb()->ThreadLocalStoragePointer, TLS_VECTOR, TLS_VECTOR::ModuleTlsData);
    if (tls && (HANDLE)(ULONG_PTR)tls->Length != NtCurrentThreadId() && tls->Length > MMP_START_TLS_INDEX) {
        RtlRaiseStatus(STATUS_NOT_SUPPORTED);
        return FALSE;
    }

    //
    // Capture thread count
    //
    MmpGlobalDataPtr->MmpTls->MmpActiveThreadCount = MmpGetThreadCount();

    //
    // Initialize tlsp
    //
    InitializeCriticalSection(&MmpGlobalDataPtr->MmpTls->MmpTlspLock);
    InitializeListHead(&MmpGlobalDataPtr->MmpTls->MmpThreadLocalStoragePointer);

    //
    // Initialize tls list
    //
    InitializeListHead(&MmpGlobalDataPtr->MmpTls->MmpTlsList);
    RtlInitializeSRWLock(&MmpGlobalDataPtr->MmpTls->MmpTlsListLock);

    PULONG buffer = PULONG(RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, MMP_TLSP_INDEX_BUFFER_SIZE));
    if (!buffer) RtlRaiseStatus(STATUS_NO_MEMORY);


    RtlFillMemory(buffer, MMP_START_TLS_INDEX / 8, -1);
    RtlInitializeBitMap(&MmpGlobalDataPtr->MmpTls->MmpTlsBitmap, buffer, MMP_MAXIMUM_TLS_INDEX);

    if (NtCurrentTeb()->ThreadLocalStoragePointer) {
        if (!PreHookNtSetInformationProcess()) {
            RtlRaiseStatus(STATUS_UNSUCCESSFUL);
        }
    }

    //
    // Hook functions
    //

    MmpGlobalDataPtr->MmpTls->Hooks.OriginLdrShutdownThread = LdrShutdownThread;
    MmpGlobalDataPtr->MmpTls->Hooks.OriginNtSetInformationProcess = NtSetInformationProcess;
    MmpGlobalDataPtr->MmpTls->Hooks.OriginRtlUserThreadStart = (decltype(&RtlUserThreadStart))GetProcAddress((HMODULE)MmpGlobalDataPtr->MmpBaseAddressIndex->NtdllLdrEntry->DllBase, "RtlUserThreadStart");

    DetourTransactionBegin();
    DetourUpdateThread(NtCurrentThread());
    DetourAttach((PVOID*)&MmpGlobalDataPtr->MmpTls->Hooks.OriginLdrShutdownThread, HookLdrShutdownThread);
    DetourAttach((PVOID*)&MmpGlobalDataPtr->MmpTls->Hooks.OriginNtSetInformationProcess, HookNtSetInformationProcess);
    DetourAttach((PVOID*)&MmpGlobalDataPtr->MmpTls->Hooks.OriginRtlUserThreadStart, HookRtlUserThreadStart);
    DetourTransactionCommit();

    MmpTlsFiberInitialize();

    return TRUE;
}

VOID NTAPI MmpTlsCleanup() {

    DetourTransactionBegin();
    DetourUpdateThread(NtCurrentThread());
    DetourDetach((PVOID*)&MmpGlobalDataPtr->MmpTls->Hooks.OriginLdrShutdownThread, HookLdrShutdownThread);
    DetourDetach((PVOID*)&MmpGlobalDataPtr->MmpTls->Hooks.OriginNtSetInformationProcess, HookNtSetInformationProcess);
    DetourDetach((PVOID*)&MmpGlobalDataPtr->MmpTls->Hooks.OriginRtlUserThreadStart, HookRtlUserThreadStart);
    DetourTransactionCommit();

}

#endif
