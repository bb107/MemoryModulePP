#pragma once

typedef struct _SEARCH_CONTEXT {
	union {
		IN PVOID  MemoryBuffer;
		size_t InBufferPtr;
	};
	union {
		IN DWORD BufferLength;
		size_t reserved0;
	};

	union {
		OUT PVOID  MemoryBlockInSection;
		size_t OutBufferPtr;
	};
	union {
		DWORD RemainingLength;
		size_t reserved1;
	};
}SEARCH_CONTEXT, * PSEARCH_CONTEXT;

NTSTATUS NTAPI RtlFindMemoryBlockFromModuleSection(
	IN HMODULE hModule	OPTIONAL,
	IN LPCSTR lpSectionName	OPTIONAL,
	IN OUT PSEARCH_CONTEXT SearchContext
);