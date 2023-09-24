#include "stdafx.h"
#include "MmpTlsp.h"
#include "MmpTlsFiber.h"

#include <vector>

typedef struct _MMP_POSTPONED_TLS {

	HANDLE hThread;
	PMMP_TLSP_RECORD lpTlsRecord;
	PTLS_VECTOR lpOldTlsVector;

}MMP_POSTPONED_TLS, * PMMP_POSTPONED_TLS;

std::vector<MMP_POSTPONED_TLS>MmpPostponedTlsList;

HANDLE MmpPostponedTlsEvent;
CRITICAL_SECTION MmpPostponedTlsLock;

DWORD WINAPI MmpReleasePostponedTlsWorker(PVOID) {

	DWORD code;

	while (true) {
		WaitForSingleObject(MmpPostponedTlsEvent, INFINITE);

		EnterCriticalSection(&MmpPostponedTlsLock);

		auto iter = MmpPostponedTlsList.begin();

		while (iter != MmpPostponedTlsList.end()) {
			const auto& item = *iter;
			GetExitCodeThread(item.hThread, &code);

			if (code == STILL_ACTIVE) {
				++iter;
			}
			else {

				RtlAcquireSRWLockExclusive(&MmpGlobalDataPtr->MmpTls->MmpTlsListLock);

				auto TlspMmpBlock = (PVOID*)item.lpOldTlsVector->ModuleTlsData;
				auto entry = MmpGlobalDataPtr->MmpTls->MmpTlsList.Flink;
				while (entry != &MmpGlobalDataPtr->MmpTls->MmpTlsList) {

					auto p = CONTAINING_RECORD(entry, TLS_ENTRY, TlsEntryLinks);
					RtlFreeHeap(RtlProcessHeap(), 0, TlspMmpBlock[p->TlsDirectory.Characteristics]);

					entry = entry->Flink;
				}

				RtlFreeHeap(RtlProcessHeap(), 0, CONTAINING_RECORD(item.lpTlsRecord->TlspLdrBlock, TLS_VECTOR, TLS_VECTOR::ModuleTlsData));
				RtlFreeHeap(RtlProcessHeap(), 0, item.lpTlsRecord);
				RtlFreeHeap(RtlProcessHeap(), 0, item.lpOldTlsVector);

				RtlReleaseSRWLockExclusive(&MmpGlobalDataPtr->MmpTls->MmpTlsListLock);

				CloseHandle(item.hThread);
				iter = MmpPostponedTlsList.erase(iter);
			}

		}

		LeaveCriticalSection(&MmpPostponedTlsLock);
	}

	return 0;
}

VOID WINAPI MmpQueuePostponedTls(PMMP_TLSP_RECORD record) {
	MMP_POSTPONED_TLS item;

	item.hThread = OpenThread(
		THREAD_QUERY_INFORMATION,
		FALSE,
		(DWORD)(ULONG_PTR)NtCurrentThreadId()
	);

	item.lpOldTlsVector = MmpAllocateTlsp();

	item.lpTlsRecord = record;

	RtlCopyMemory(
		item.lpOldTlsVector->ModuleTlsData,
		record->TlspMmpBlock,
		sizeof(PVOID) * MMP_MAXIMUM_TLS_INDEX
	);

	EnterCriticalSection(&MmpPostponedTlsLock);
	
	MmpPostponedTlsList.push_back(item);
	SetEvent(MmpPostponedTlsEvent);
	
	LeaveCriticalSection(&MmpPostponedTlsLock);
}

VOID MmpTlsFiberInitialize() {
	InitializeCriticalSection(&MmpPostponedTlsLock);
	MmpPostponedTlsEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
}
