//#include <Windows.h>
//#include "../MemoryModule/NativeFunctionsInternal.h"
//
//typedef struct _THREAD_TLS_INFORMATION {
//	ULONG      Flags;
//	union {
//		PVOID* TlsVector;
//		PVOID  TlsModulePointer;
//	};
//	HANDLE     ThreadId;
//} THREAD_TLS_INFORMATION, * PTHREAD_TLS_INFORMATION;
//
//typedef enum _PROCESS_TLS_INFORMATION_TYPE {
//	ProcessTlsReplaceIndex,
//	ProcessTlsReplaceVector,
//	MaxProcessTlsOperation
//} PROCESS_TLS_INFORMATION_TYPE, * PPROCESS_TLS_INFORMATION_TYPE;
//
//typedef struct _PROCESS_TLS_INFORMATION {
//	ULONG                  Reserved; // Reserved bitmask
//	ULONG                  OperationType;
//	ULONG                  ThreadDataCount;
//	union {
//		ULONG              TlsIndex;
//		ULONG              TlsVectorLength;
//	};
//	THREAD_TLS_INFORMATION ThreadData[ANYSIZE_ARRAY];
//} PROCESS_TLS_INFORMATION, * PPROCESS_TLS_INFORMATION;
//
//// Need struct name
//typedef struct _TLS_VECTOR {
//	union {
//		ULONG  Length;
//		HANDLE ThreadId;
//	};
//
//	struct _TLS_VECTOR* PreviousDeferredTlsVector;
//	PVOID ModuleTlsData[ANYSIZE_ARRAY];
//} TLS_VECTOR, * PTLS_VECTOR;
//
//// Need struct name
//typedef struct _TLS_RECLAIM_TABLE_ENTRY {
//	PTLS_VECTOR TlsVector;
//	RTL_SRWLOCK Lock;
//} TLS_RECLAIM_TABLE_ENTRY, * PTLS_RECLAIM_TABLE_ENTRY;
//
//// Need struct name
//typedef struct _TLS_ENTRY {
//	LIST_ENTRY            TlsEntryLinks;
//	IMAGE_TLS_DIRECTORY   TlsDirectory;
//	PLDR_DATA_TABLE_ENTRY ModuleEntry;
//} TLS_ENTRY, * PTLS_ENTRY;
//
////0x10 bytes (sizeof)
//typedef struct _RTL_BITMAP {
//	ULONG SizeOfBitMap;                                                     //0x0
//	ULONG* Buffer;                                                          //0x8
//}RTL_BITMAP, * PRTL_BITMAP;
//
//VOID RtlClearBit(
//	PRTL_BITMAP BitMapHeader,
//	ULONG       BitNumber
//);
//
//VOID RtlInitializeBitMap(
//	PRTL_BITMAP             BitMapHeader,
//	PULONG					BitMapBuffer,
//	ULONG                   SizeOfBitMap
//);
//
//ULONG RtlFindClearBitsAndSet(
//	PRTL_BITMAP BitMapHeader,
//	ULONG       NumberToFind,
//	ULONG       HintIndex
//);
//
//VOID RtlClearBits(
//	PRTL_BITMAP BitMapHeader,
//	ULONG       StartingIndex,
//	ULONG       NumberToClear
//);
//
//VOID RtlSetBit(
//	PRTL_BITMAP BitMapHeader,
//	ULONG       BitNumber
//);
//
//BOOLEAN RemoveEntryList(
//	PLIST_ENTRY Entry
//);
//
//VOID NTAPI RtlAcquireSRWLockExclusive(IN OUT PRTL_SRWLOCK SRWLock);
//VOID NTAPI RtlReleaseSRWLockExclusive(IN OUT PRTL_SRWLOCK SRWLock);
//
//NTSTATUS NTAPI NtSetInformationProcess(
//	IN HANDLE               ProcessHandle,
//	IN ULONG				ProcessInformationClass,
//	IN PVOID                ProcessInformation,
//	IN ULONG                ProcessInformationLength);
//
//#define ProcessTlsInformation ProcessResourceManagement
//
//PUCHAR NtdllBaseTag = 0;
//ULONG LdrpActiveThreadCount = 0;
//ULONG LdrpPotentialTlsLeaks = 0;
//RTL_BITMAP LdrpTlsBitmap;
//LIST_ENTRY LdrpTlsList;
//
//TLS_RECLAIM_TABLE_ENTRY LdrpDelayedTlsReclaimTable[16];
//
//ULONG LdrpStaticTlsBitmapVector[4];
//ULONG LdrpActualBitmapSize = 0;
//
//
//VOID LdrpInit() {
//	RtlCopyMemory(&LdrpTlsBitmap, NtCurrentPeb()->TlsBitmap, sizeof(RTL_BITMAP));
//	PROCESS_TLS_INFORMATION pti;
//
//}
//
//VOID LdrpReleaseTlsIndex(ULONG TlsIndex) {
//	RtlClearBit(&LdrpTlsBitmap, TlsIndex);
//}
//
//#define LDRP_BITMAP_INCREMENT (0x27 - sizeof( PVOID ))
//
//NTSTATUS LdrpAcquireTlsIndex(PULONG TlsIndex, PBOOLEAN AllocatedBitmap) {
//	ULONG  Length;
//	ULONG  Index;
//	PULONG NewBitmapBuffer;
//
//	Length = LdrpTlsBitmap.SizeOfBitMap;
//
//	if (Length == 0) {
//		//
//		// If we're the first caller, then we shall need to be initializing the
//		// bitmap.
//		//
//		// This implies that we don't need to expand as by definition, there
//		// shall exist space for ourselves at the start of the bitmap now.
//		//
//		RtlInitializeBitMap(&LdrpTlsBitmap, LdrpStaticTlsBitmapVector, 4);
//		LdrpActualBitmapSize = 1;
//	}
//	else {
//		Index = RtlFindClearBitsAndSet(&LdrpTlsBitmap, 1, 0);
//
//		//
//		// If we found space in the existing bitmap then there is no reason to
//		// expand buffers, so we'll just return with the existing data.
//		//
//		if (Index != 0xFFFFFFFF) {
//			*TlsIndex = Index;
//			*AllocatedBitmap = FALSE;
//			return STATUS_SUCCESS;
//		}
//
//		//
//		// Check if we need to grow the bitmap itself or if the bitmap still
//		// has space.
//		//
//		if (((LdrpTlsBitmap.SizeOfBitMap + LDRP_BITMAP_INCREMENT) >> 5) > LdrpActualBitmapSize) {
//			//
//			// We'll need to grow it.  Let's go do so now.
//			//
//
//			//
//			// BUG: We set the new size before checking the allocation.  If we
//			// fail, then we leave the TLS variables in an inconsistant state.
//			//
//			LdrpActualBitmapSize = (Length + LDRP_BITMAP_INCREMENT) >> 5;
//			NewBitmapBuffer = (PULONG)RtlAllocateHeap(GetProcessHeap(), (ULONG_PTR)((PUCHAR)NtdllBaseTag + 0x000C0000), LdrpActualBitmapSize);
//			if (!NewBitmapBuffer) return STATUS_NO_MEMORY;
//
//			//
//			// Copy the contents of the previous buffer into the new one.
//			//
//			RtlCopyMemory(NewBitmapBuffer, LdrpTlsBitmap.Buffer, Length + 7);
//
//			//
//			// Free the old buffer if it wasn't the initial static buffer.
//			//
//			if (LdrpTlsBitmap.Buffer != LdrpStaticTlsBitmapVector) {
//				RtlFreeHeap(GetProcessHeap(), 0, LdrpTlsBitmap.Buffer);
//			}
//
//			//
//			// Reinitialize the bitmap as we've changed the buffer pointer.
//			//
//			RtlInitializeBitMap(&LdrpTlsBitmap, NewBitmapBuffer, Length + 4);
//		}
//		else {
//			LdrpTlsBitmap.SizeOfBitMap += 4;
//		}
//	}
//
//	RtlClearBits(&LdrpTlsBitmap, Length + 1, 3);
//	RtlSetBit(&LdrpTlsBitmap, Length);
//
//	*TlsIndex = Index;
//	*AllocatedBitmap = TRUE;
//
//	return STATUS_SUCCESS;
//}
//
//NTSTATUS LdrpAllocateTlsEntry(PIMAGE_TLS_DIRECTORY TlsDirectory, PLDR_DATA_TABLE_ENTRY ModuleEntry, PULONG TlsIndex, PBOOLEAN AllocatedBitmap, PTLS_ENTRY* TlsEntry) {
//
//	PTLS_ENTRY Entry = nullptr;
//	NTSTATUS  Status;
//
//	__try {
//		Entry = (PTLS_ENTRY)RtlAllocateHeap(GetProcessHeap(), (ULONG_PTR)((PUCHAR)NtdllBaseTag + 0x000C0000), sizeof(TLS_ENTRY));
//		if (!Entry) return STATUS_NO_MEMORY;
//		Status = STATUS_SUCCESS;
//		RtlCopyMemory(&Entry->TlsDirectory, TlsDirectory, sizeof(IMAGE_TLS_DIRECTORY));
//	}
//	__except (EXCEPTION_EXECUTE_HANDLER) {
//		//
//		// Also print string and complain.
//		//
//		Status = GetExceptionCode();
//	}
//
//	if (!NT_SUCCESS(Status)) {
//		RtlFreeHeap(GetProcessHeap(), 0, Entry);
//		return Status;
//	}
//
//	//
//	// Validate that the TLS directory entry is sane.
//	//
//	if (Entry->TlsDirectory.StartAddressOfRawData < Entry->TlsDirectory.EndAddressOfRawData) {
//		RtlFreeHeap(GetProcessHeap(), 0, Entry);
//		return STATUS_INVALID_IMAGE_FORMAT;
//	}
//	Entry->ModuleEntry = ModuleEntry;
//
//	//
//	// Insert the entry into our list.
//	//
//
//	InsertTailList(&LdrpTlsList, &Entry->TlsEntryLinks);
//	if (AllocatedBitmap) {
//		Status = LdrpAcquireTlsIndex(TlsIndex, AllocatedBitmap);
//		if (!NT_SUCCESS(Status)) {
//			//
//			// BUG: We don't remove the entry from LdrpTlsList
//			//
//			RtlFreeHeap(GetProcessHeap(), 0, Entry);
//			return Status;
//		}
//	}
//	else {
//		*TlsIndex += 1;
//	}
//
//	//
//	// We reuse the 'Characteristics' field for the real TLS index.
//	//
//	Entry->TlsDirectory.Characteristics = *TlsIndex;
//	__try {
//		*(PULONG)Entry->TlsDirectory.AddressOfIndex = *TlsIndex;
//	}
//	__except (EXCEPTION_EXECUTE_HANDLER) {
//		Status = GetExceptionCode();
//	}
//	if (!NT_SUCCESS(Status)) {
//		if (AllocatedBitmap) {
//			LdrpReleaseTlsIndex(*TlsIndex);
//			if (*AllocatedBitmap) LdrpTlsBitmap.SizeOfBitMap -= 4;
//		}
//
//		//
//		// BUG: We don't remove the entry from LdrpTlsList
//		//
//		RtlFreeHeap(GetProcessHeap(), 0, Entry);
//		return Status;
//	}
//
//	if (TlsEntry) *TlsEntry = Entry;
//	return STATUS_SUCCESS;
//}
//
//PTLS_ENTRY __fastcall LdrpFindTlsEntry(PLDR_DATA_TABLE_ENTRY ModuleEntry) {
//	PTLS_ENTRY  TlsEntry;
//	PLIST_ENTRY ListHead;
//
//	ListHead = &LdrpTlsList;
//
//	for (TlsEntry = CONTAINING_RECORD(LdrpTlsList.Flink, TLS_ENTRY, TlsEntryLinks);
//		&TlsEntry->TlsEntryLinks != ListHead;
//		TlsEntry = CONTAINING_RECORD(TlsEntry->TlsEntryLinks.Flink, TLS_ENTRY, TlsEntryLinks)) {
//
//		if (TlsEntry->ModuleEntry == ModuleEntry) return TlsEntry;
//	}
//
//	return 0;
//}
//
//NTSTATUS LdrpReleaseTlsEntry(PLDR_DATA_TABLE_ENTRY ModuleEntry) {
//	PTLS_ENTRY TlsEntry;
//
//	//
//	// Find the corresponding TLS_ENTRY for this module entry.
//	//
//	TlsEntry = LdrpFindTlsEntry(ModuleEntry);
//	if (!TlsEntry) return STATUS_NOT_FOUND;
//
//	//
//	// Remove it from the global list of outstanding TLS entries.
//	//
//	RemoveEntryList(&TlsEntry->TlsEntryLinks);
//
//	//
//	// Deallocate the TLS index.
//	//
//	LdrpReleaseTlsIndex(TlsEntry->TlsDirectory.Characteristics);
//
//	//
//	// Deallocate the TLS_ENTRY object itself.
//	//
//	RtlFreeHeap(GetProcessHeap(), 0, TlsEntry);
//
//	//
//	// We're done.
//	//
//	return STATUS_SUCCESS;
//}
//
//PVOID* __fastcall LdrpGetNewTlsVector(ULONG TlsBitmapLength) {
//	PTLS_VECTOR TlsVector;
//
//	TlsVector = (PTLS_VECTOR)RtlAllocateHeap(GetProcessHeap(), (ULONG_PTR)((PUCHAR)NtdllBaseTag + 0x000C0000),
//		sizeof(TLS_VECTOR) + (sizeof(PVOID) * TlsBitmapLength) - sizeof(PVOID));
//	if (!TlsVector) return 0;
//	TlsVector->Length = TlsBitmapLength;
//	RtlZeroMemory(TlsVector->ModuleTlsData, TlsBitmapLength * sizeof(PVOID));
//	return TlsVector->ModuleTlsData;
//}
//
//VOID LdrpQueueDeferredTlsData(PVOID TlsVector, PVOID ThreadId) {
//	PTLS_VECTOR              RealTlsVector;
//	PTLS_RECLAIM_TABLE_ENTRY ReclaimEntry;
//
//	RealTlsVector = CONTAINING_RECORD(TlsVector, TLS_VECTOR, ModuleTlsData);
//
//	RealTlsVector->ThreadId = ThreadId;
//
//	ReclaimEntry = &LdrpDelayedTlsReclaimTable[((ULONG_PTR)(ThreadId) >> 2) & 0xF];
//
//	RtlAcquireSRWLockExclusive(&ReclaimEntry->Lock);
//
//	RealTlsVector->PreviousDeferredTlsVector = ReclaimEntry->TlsVector;
//	ReclaimEntry->TlsVector = RealTlsVector;
//
//	RtlReleaseSRWLockExclusive(&ReclaimEntry->Lock);
//}
//
//#define SIZEOF_TLS_INFO(_ThreadCount_) (_ThreadCount_==0)?sizeof(PROCESS_TLS_INFORMATION)-sizeof(THREAD_TLS_INFORMATION):(_ThreadCount_-1)*sizeof(THREAD_TLS_INFORMATION)+sizeof(PROCESS_TLS_INFORMATION)
//NTSTATUS LdrpHandleTlsData(PLDR_DATA_TABLE_ENTRY ModuleEntry) {
//	PIMAGE_TLS_DIRECTORY      TlsDirectory;
//	ULONG                     DirectorySize;
//	ULONG                     TlsIndex;
//	HANDLE                    Heap;
//	PPROCESS_TLS_INFORMATION  TlsInfo;
//	PROCESS_TLS_INFORMATION   OneThreadTlsInfo;
//	NTSTATUS                  Status;
//	BOOLEAN                   AllocatedBitmap;
//	PTLS_ENTRY                TlsEntry;
//	ULONG                     TlsBitmapLength;
//	SIZE_T                    TlsRawDataLength;
//	ULONG                     ThreadIndex;
//	PVOID                     TlsData = nullptr;
//	PVOID* TlsVector;
//	PTHREAD_TLS_INFORMATION   ThreadTlsData;
//	ULONG                     ThreadsCleanedUp;
//
//	if (LdrpActiveThreadCount == 0) return STATUS_SUCCESS;
//	TlsDirectory = (PIMAGE_TLS_DIRECTORY)RtlImageDirectoryEntryToData(ModuleEntry->DllBase, TRUE, IMAGE_DIRECTORY_ENTRY_TLS, &DirectorySize);
//	if (!TlsDirectory) return STATUS_SUCCESS;
//	Heap = NtCurrentPeb()->ProcessHeap;
//
//	TlsInfo = LdrpActiveThreadCount == 1 ? &OneThreadTlsInfo :
//		(decltype(TlsInfo))RtlAllocateHeap(Heap, (ULONG)NtdllBaseTag + 0x000C0000, SIZEOF_TLS_INFO(LdrpActiveThreadCount));
//	if (!TlsInfo) return STATUS_NO_MEMORY;
//
//	do {
//		TlsBitmapLength = LdrpTlsBitmap.SizeOfBitMap;
//		Status = LdrpAllocateTlsEntry(TlsDirectory, ModuleEntry, &TlsIndex, &AllocatedBitmap, &TlsEntry);
//		if (!NT_SUCCESS(Status)) break;
//		TlsInfo->ThreadDataCount = LdrpActiveThreadCount;
//		if (AllocatedBitmap) {
//			TlsInfo->OperationType = ProcessTlsReplaceVector;
//			TlsInfo->TlsVectorLength = TlsBitmapLength;
//			TlsBitmapLength = LdrpTlsBitmap.SizeOfBitMap;
//		}
//		else {
//			TlsInfo->OperationType = ProcessTlsReplaceIndex;
//			TlsInfo->TlsIndex = TlsIndex;
//		}
//		Status = STATUS_SUCCESS;
//		ThreadsCleanedUp = 0;
//
//		//
//		// Calculate the size of the raw TLS data for this module.
//		//
//		TlsRawDataLength = TlsEntry->TlsDirectory.EndAddressOfRawData - TlsEntry->TlsDirectory.StartAddressOfRawData;
//
//		//
//		// Prepare data for each running thread.
//		//
//		for (ThreadIndex = 0; ThreadIndex < TlsInfo->ThreadDataCount; ++ThreadIndex) {
//			TlsData = RtlAllocateHeap(Heap, (ULONG_PTR)((PUCHAR)NtdllBaseTag + 0x000C0000), TlsRawDataLength);
//			if (!TlsData) {
//				Status = STATUS_NO_MEMORY;
//				break;
//			}
//			__try {
//				RtlCopyMemory(TlsData, (PVOID)TlsEntry->TlsDirectory.StartAddressOfRawData, TlsRawDataLength);
//			}
//			__except (EXCEPTION_EXECUTE_HANDLER) {
//				Status = GetExceptionCode();
//			}
//			if (!NT_SUCCESS(Status)) {
//				RtlFreeHeap(Heap, 0, TlsData);
//				break;
//			}
//
//			if (AllocatedBitmap) {
//				TlsVector = LdrpGetNewTlsVector(TlsBitmapLength);
//				if (!TlsVector) {
//					RtlFreeHeap(Heap, 0, TlsData);
//					break;
//				}
//				TlsVector[TlsIndex] = TlsData;
//				TlsInfo->ThreadData[ThreadIndex].TlsVector = TlsVector;
//			}
//			else {
//				TlsInfo->ThreadData[ThreadIndex].TlsModulePointer = TlsData;
//			}
//
//			TlsInfo->ThreadData[ThreadIndex].Flags = 0;
//		}
//
//		//
//		// This is awkward; all the 'break' above really are either goto or
//		// __leave, but we aren't using those.  This is really supposed to
//		// just happen on normal for loop exit.
//		//
//		if (ThreadIndex == TlsInfo->ThreadDataCount) {
//			TlsInfo->Reserved = 0;
//			Status = NtSetInformationProcess(GetCurrentProcess(), ProcessTlsInformation, TlsInfo, 
//				TlsInfo->ThreadDataCount * sizeof(THREAD_TLS_INFORMATION) + sizeof(PROCESS_TLS_INFORMATION) - sizeof(THREAD_TLS_INFORMATION));
//		}
//
//		//
//		// Let's handle each thread that we replaced, as the
//		// ProcessTlsInformation call fills our buffer with the old data
//		// after performing a swap.
//		//
//		for (ThreadTlsData = &TlsInfo->ThreadData[ThreadIndex]; ThreadIndex > 0;) {
//			ThreadIndex -= 1;
//			ThreadTlsData -= 1;
//
//			if (ThreadTlsData->Flags & 0x2) {
//				if (!ThreadTlsData->TlsVector) continue;
//
//				if (!AllocatedBitmap) {
//					RtlFreeHeap(Heap, 0, ThreadTlsData->TlsVector);
//					continue;
//				}
//				else {
//					LdrpQueueDeferredTlsData(ThreadTlsData->TlsVector, ThreadTlsData->ThreadId);
//					continue;
//				}
//			}
//			else {
//				if (ThreadTlsData->Flags & 0x1) {
//					++LdrpPotentialTlsLeaks;
//					continue;
//				}
//				else {
//					++ThreadsCleanedUp;
//					if (AllocatedBitmap) {
//						TlsData = ThreadTlsData->TlsVector[TlsIndex];
//						RtlFreeHeap(Heap, 0, CONTAINING_RECORD(ThreadTlsData->TlsVector, TLS_VECTOR, ModuleTlsData));
//					}
//					RtlFreeHeap(Heap, 0, TlsData);
//					continue;
//				}
//			}
//		}
//
//		if (!NT_SUCCESS(Status)) {
//			LdrpReleaseTlsEntry(ModuleEntry);
//			if (AllocatedBitmap) LdrpTlsBitmap.SizeOfBitMap -= 4;
//		}
//		else if (ThreadsCleanedUp > 0) {
//			LdrpActiveThreadCount -= ThreadsCleanedUp;
//		}
//	} while (0);
//
//	if (TlsInfo != &OneThreadTlsInfo) RtlFreeHeap(Heap, 0, TlsInfo);
//	if (!NT_SUCCESS(Status)) return Status;
//	ModuleEntry->TlsIndex = 0xFFFF;
//	return STATUS_SUCCESS;
//}
//
////struct UNKNOWN {
////    PVOID unknown1;        //+0x0
////    PVOID unknown2;        //+0x8
////    PVOID unknown3;        //+0x10
////    struct {
////        DWORD dwFlags;     //+0x14
////        DWORD unknown4;    //+0x18
////    };
////    PWSTR DllName;         //+0x20
////    PVOID unknown[11];
////};
////
//////#include "../MemoryModule/Native.h"
////
//////size = 0xC0 + DllName->Length + sizeof(wchar_t)
////typedef struct _ALLOCATE_ENTRY_PARAMETER {
////	UNICODE_STRING DllName;						//+0x0
////	UNKNOWN* unknown_structure;					//+0x10
////	PVOID reserved1;							//+0x18
////	struct {
////		DWORD ProcessStatus;					//+0x20
////		DWORD reserved2;						//+0x24
////	};
////	PVOID reserved3;							//+0x28
////	PVOID reserved4;							//+0x30
////	PVOID LdrEntry;								//+0x38
////	PVOID reserved[16];							//+0x40
////	BYTE UnicodeStringBuffer[1];	//+0xC0
////}ALLOCATE_ENTRY_PARAMETER, * PALLOCATE_ENTRY_PARAMETER;
//


typedef struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32 {
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG SEHandlerCount;
	PVOID NextEntrySEHandlerTableEncoded;
} RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32;
typedef struct _RTL_INVERTED_FUNCTION_TABLE {
	ULONG Count;
	ULONG MaxCount;
	ULONG Overflow;
	ULONG NextEntrySEHandlerTableEncoded;
	RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32 Entries[0x200];
} RTL_INVERTED_FUNCTION_TABLE, * PRTL_INVERTED_FUNCTION_TABLE;
