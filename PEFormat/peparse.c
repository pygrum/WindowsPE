#include <stdio.h>

#include "peparse.h"

DWORD PEParseFromBuffer(LPVOID lpBuffer, PPE_CONTEXT* Ctx)
{
	HANDLE hHeap;
	PIMAGE_NT_HEADERS pNtHeaders;
	WORD wSectionCount;
	LPVOID pSection;
	PPE_SECTION_CONTEXT pLastSectionCtx = NULL;
	PPE_CONTEXT pCtx;

	hHeap = GetProcessHeap();
	pCtx = (PPE_CONTEXT)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(PE_CONTEXT));
	if (!pCtx)
		return PE_CTX_ALLOC_FAILED;
	*Ctx = pCtx;
	pCtx->hHeap = hHeap;

	pCtx->pImageBase = lpBuffer;
	pCtx->pDosHeader = (PIMAGE_DOS_HEADER)lpBuffer;
	// Validate magic bytes
	if (pCtx->pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		HeapFree(hHeap, 0, pCtx);
		return PE_INVALID_PE;
	}
	// manual verification that e_lfanew is indeed imagebase + 0x3c
	// printf("%d = %d\n", pCtx->pDosHeader->e_lfanew, *(DWORD*)((CHAR*)lpBuffer + 0x3c));
	pNtHeaders = (PIMAGE_NT_HEADERS)((CHAR*)lpBuffer + pCtx->pDosHeader->e_lfanew);
	// Validate NT signature to check if valid PE
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		HeapFree(hHeap, 0, pCtx);
		return PE_INVALID_PE;
	}

	pCtx->pFileHeader = &pNtHeaders->FileHeader;
	if (pCtx->pFileHeader->Machine == IMAGE_FILE_MACHINE_AMD64)
		pCtx->isX64 = TRUE;
	else
		pCtx->isX64 = FALSE;
	
	pCtx->CompileTime = pCtx->pFileHeader->TimeDateStamp;

	// Parse headers
	pCtx->SectionCount = pCtx->pFileHeader->NumberOfSections;
	pSection = (CHAR*)&pNtHeaders->OptionalHeader + pCtx->pFileHeader->SizeOfOptionalHeader;

	for (WORD i = 0; i < pCtx->SectionCount; i++)
	{
		PPE_SECTION_CONTEXT pSectionCtx;
		PIMAGE_SECTION_HEADER pSectionHeader;

		pSectionHeader = (PIMAGE_SECTION_HEADER)pSection;
		pSectionCtx = (PPE_SECTION_CONTEXT)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(PE_SECTION_CONTEXT));
		if (!pSectionCtx)
			return PE_SECTION_CTX_ALLOC_FAILED;
		pSectionCtx->szName = pSectionHeader->Name;
		pSectionCtx->dwSize = pSectionHeader->SizeOfRawData;
		pSectionCtx->Next = NULL;
		// Attach to linked list
		if (pLastSectionCtx)
			pLastSectionCtx->Next = pSectionCtx;
		else // otherwise, set as first section in section context list
			pCtx->SectionCtxList = pSectionCtx;
		pLastSectionCtx = pSectionCtx;
		// set to next section header
		pSection = (CHAR*)pSection + sizeof(IMAGE_SECTION_HEADER);
	}
	return PE_SUCCESS;
}

DWORD PEFreeCtx(PPE_CONTEXT pCtx)
{
	BOOL status;
	PPE_SECTION_CONTEXT pSectionContext = pCtx->SectionCtxList;
	do
	{
		PPE_SECTION_CONTEXT Next = pSectionContext->Next;
		status = HeapFree(pCtx->hHeap, 0, pSectionContext);
		if (!status)
			return PE_SECTION_CTX_FREE_FAILED;

		pSectionContext = Next;
	} while (pSectionContext != NULL);
	status = HeapFree(pCtx->hHeap, 0, pCtx);
	if (!status)
		return PE_CTX_FREE_FAILED;
	return PE_SUCCESS;
}