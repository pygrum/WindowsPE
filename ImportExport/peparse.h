#pragma once
#include <Windows.h>

#define PE_MAXIMUM_IMPORTS 256
#define PE_MAXIMUM_EXPORTS 256

typedef struct _PE_IMPORT_CONTEXT {
	LPSTR szName;
	DWORD ImportCount;
	LPSTR ImportTable[ PE_MAXIMUM_IMPORTS ];
	struct _PE_IMPORT_CONTEXT *Next;
} PE_IMPORT_CONTEXT, *PPE_IMPORT_CONTEXT;

typedef struct _PE_SECTION_CONTEXT {
	LPCSTR szName;
	DWORD dwSize;
	DWORD StartAddr;
	struct _PE_SECTION_CONTEXT *Next;
} PE_SECTION_CONTEXT, *PPE_SECTION_CONTEXT;

typedef struct _PE_CONTEXT {
	BOOL isX64;
	HANDLE hHeap;
	LPVOID pImageBase;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_FILE_HEADER pFileHeader;
	DWORD CompileTime;
	WORD SectionCount;
	PPE_SECTION_CONTEXT SectionCtxList;
	PPE_IMPORT_CONTEXT ImportCtxList;
	LPSTR ExportList[ PE_MAXIMUM_EXPORTS ];
	DWORD ExportCount;
} PE_CONTEXT, *PPE_CONTEXT;

#define PE_SUCCESS 0
#define PE_INVALID_PE 1
#define PE_CTX_ALLOC_FAILED 2
#define PE_CTX_FREE_FAILED 3
#define PE_SECTION_CTX_ALLOC_FAILED 4
#define PE_SECTION_CTX_FREE_FAILED 5
#define PE_IMPORT_CTX_ALLOC_FAILED 6

// PEParseFromBuffer parses a PE file's information into a PE_CONTEXT structure.
// If unsuccessful, if returns a non-zero value. Use PEGetLastError() to get error information.
DWORD PEParseFromBuffer(LPVOID lpBuffer, PPE_CONTEXT *pCtx);
DWORD PEFreeCtx(PPE_CONTEXT pCtx);