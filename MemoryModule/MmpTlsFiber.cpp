#include "stdafx.h"
#include "MmpTlsp.h"
#include "MmpTlsFiber.h"

#include <vector>
#include <cassert>

typedef struct _MMP_POSTPONED_TLS {

	HANDLE hThread;
	PMMP_TLSP_RECORD lpTlsRecord;
	PTLS_VECTOR lpOldTlsVector;

}MMP_POSTPONED_TLS, * PMMP_POSTPONED_TLS;

std::vector<MMP_POSTPONED_TLS>* MmpPostponedTlsList;

HANDLE MmpPostponedTlsEvent;
CRITICAL_SECTION MmpPostponedTlsLock;

DWORD WINAPI MmpReleasePostponedTlsWorker(PVOID) {

	DWORD code;
	DWORD waitTime = INFINITE;

	while (true) {
		WaitForSingleObject(MmpPostponedTlsEvent, waitTime);

		EnterCriticalSection(&MmpPostponedTlsLock);

		if (MmpPostponedTlsList) {
			auto iter = MmpPostponedTlsList->begin();

			while (iter != MmpPostponedTlsList->end()) {
				GetExitCodeThread(iter->hThread, &code);

				if (code == STILL_ACTIVE) {
					++iter;
				}
				else {

					RtlAcquireSRWLockExclusive(&MmpGlobalDataPtr->MmpTls->MmpTlsListLock);

					auto TlspMmpBlock = (PVOID*)iter->lpOldTlsVector->ModuleTlsData;
					auto entry = MmpGlobalDataPtr->MmpTls->MmpTlsList.Flink;
					while (entry != &MmpGlobalDataPtr->MmpTls->MmpTlsList) {

						auto p = CONTAINING_RECORD(entry, TLS_ENTRY, TlsEntryLinks);
						RtlFreeHeap(RtlProcessHeap(), 0, TlspMmpBlock[p->TlsDirectory.Characteristics]);

						entry = entry->Flink;
					}

					RtlFreeHeap(RtlProcessHeap(), 0, CONTAINING_RECORD(iter->lpTlsRecord->TlspLdrBlock, TLS_VECTOR, TLS_VECTOR::ModuleTlsData));
					RtlFreeHeap(RtlProcessHeap(), 0, iter->lpTlsRecord);
					RtlFreeHeap(RtlProcessHeap(), 0, iter->lpOldTlsVector);

					RtlReleaseSRWLockExclusive(&MmpGlobalDataPtr->MmpTls->MmpTlsListLock);

					CloseHandle(iter->hThread);
					iter = MmpPostponedTlsList->erase(iter);
				}

			}

			waitTime = MmpPostponedTlsList->empty() ? INFINITE : 1000;
		}
		else {
			LeaveCriticalSection(&MmpPostponedTlsLock);
			break;
		}

		LeaveCriticalSection(&MmpPostponedTlsLock);
	}

	return 0;
}

DWORD WINAPI MmpReleasePostponedTlsWorker_Wrap(PVOID) {
	__try {
		return MmpReleasePostponedTlsWorker(nullptr);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return 0;
	}
}

VOID WINAPI MmpQueuePostponedTls(PMMP_TLSP_RECORD record) {
	MMP_POSTPONED_TLS item;

	item.hThread = OpenThread(
		THREAD_QUERY_INFORMATION,
		FALSE,
		(DWORD)(ULONG_PTR)NtCurrentThreadId()
	);

	item.lpOldTlsVector = MmpAllocateTlsp();
	assert(item.lpOldTlsVector);

	item.lpTlsRecord = record;

	RtlCopyMemory(
		item.lpOldTlsVector->ModuleTlsData,
		record->TlspMmpBlock,
		sizeof(PVOID) * MMP_MAXIMUM_TLS_INDEX
	);

	EnterCriticalSection(&MmpPostponedTlsLock);
	
	if (MmpPostponedTlsList) {
		MmpPostponedTlsList->push_back(item);
		SetEvent(MmpPostponedTlsEvent);
	}
	else {
		RtlFreeHeap(RtlProcessHeap(), 0, item.lpOldTlsVector);
	}
	
	LeaveCriticalSection(&MmpPostponedTlsLock);
}

VOID OnExit() {
	EnterCriticalSection(&MmpPostponedTlsLock);

	MmpPostponedTlsList->~vector();
	HeapFree(RtlProcessHeap(), 0, MmpPostponedTlsList);
	MmpPostponedTlsList = nullptr;

	CloseHandle(MmpPostponedTlsEvent);

	LeaveCriticalSection(&MmpPostponedTlsLock);
}

VOID MmpTlsFiberInitialize() {
	InitializeCriticalSection(&MmpPostponedTlsLock);
	MmpPostponedTlsEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
	MmpPostponedTlsList = new(HeapAlloc(GetProcessHeap(), 0, sizeof(std::vector<MMP_POSTPONED_TLS>))) std::vector<MMP_POSTPONED_TLS>();
	
	atexit(OnExit);

	CreateThread(nullptr, 0, MmpReleasePostponedTlsWorker_Wrap, nullptr, 0, nullptr);
}
