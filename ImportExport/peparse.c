#include <stdio.h>

#include "peparse.h"

DWORD_PTR RvaToRaw(PPE_CONTEXT Ctx, DWORD RVA);

DWORD PEParseFromBuffer(LPVOID lpBuffer, PPE_CONTEXT* Ctx)
{
	HANDLE hHeap;
	PIMAGE_NT_HEADERS pNtHeaders;
	IMAGE_DATA_DIRECTORY ImportDirectory, ExportDirectory;
	DWORD dwDataDirectorySize;
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
	pCtx->pNtHeaders = pNtHeaders;
	pCtx->pFileHeader = &pNtHeaders->FileHeader;
	if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
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

		// parse section headers
		pSectionHeader = (PIMAGE_SECTION_HEADER)pSection;
		pSectionCtx = (PPE_SECTION_CONTEXT)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(PE_SECTION_CONTEXT));
		if (!pSectionCtx)
			return PE_SECTION_CTX_ALLOC_FAILED;

		pSectionCtx->szName = pSectionHeader->Name;
		pSectionCtx->dwSize = pSectionHeader->SizeOfRawData;
		pSectionCtx->StartAddr = pSectionHeader->VirtualAddress;
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

	// Imports
	DWORD ImportCount = 0;
	ImportDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToRaw(pCtx, ImportDirectory.VirtualAddress));
	if (pImageImportDescriptor)
	{
		PPE_IMPORT_CONTEXT pLastImportCtx = NULL;
		for (; pImageImportDescriptor->Characteristics; pImageImportDescriptor++)
		{
			PPE_IMPORT_CONTEXT pImportCtx = NULL;
			pImportCtx = (PPE_IMPORT_CONTEXT)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(PE_IMPORT_CONTEXT));
			if (!pImportCtx)
				return PE_IMPORT_CTX_ALLOC_FAILED;
			PIMAGE_THUNK_DATA pImageImportEntry;
			DWORD ImportEntryCount = 0;
			pImportCtx->szName = RvaToRaw(pCtx, pImageImportDescriptor->Name);
			// First original thunk is the first IAT entry.

			for (pImageImportEntry = RvaToRaw(pCtx, pImageImportDescriptor->OriginalFirstThunk);
				pImageImportEntry->u1.AddressOfData != NULL;
				pImageImportEntry++)
			{
				PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)pImageImportEntry->u1.AddressOfData;
				if (ImportEntryCount <= PE_MAXIMUM_IMPORTS)
					pImportCtx->ImportTable[ImportEntryCount] = RvaToRaw(pCtx, pImportName->Name);
				ImportEntryCount++;
			}
			pImportCtx->ImportCount = ImportEntryCount;
			if (pLastImportCtx)
				pLastImportCtx->Next = pImportCtx;
			else
				pCtx->ImportCtxList = pImportCtx;
			pLastImportCtx = pImportCtx;
			ImportCount++;
		}
	}

	// Exports
	DWORD ExportCount = 0;
	ExportDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY pImageExportData = (PIMAGE_EXPORT_DIRECTORY)(RvaToRaw(pCtx, ExportDirectory.VirtualAddress));
	if (pImageExportData)
	{
		DWORD* pNameTable = RvaToRaw(pCtx, pImageExportData->AddressOfNames);
		for (int i = 0; i < pImageExportData->NumberOfNames; i++)
		{
			if (ExportCount <= PE_MAXIMUM_EXPORTS)
				pCtx->ExportList[i] = RvaToRaw(pCtx, pNameTable[i]);
			ExportCount++;
		}
		pCtx->ExportCount = ExportCount;
	}
	return PE_SUCCESS;
}

DWORD_PTR RvaToRaw(PPE_CONTEXT Ctx, DWORD RVA) {
	PIMAGE_FILE_HEADER lpFileHeader = Ctx->pFileHeader;
	BYTE* lpOptionalHeader = &Ctx->pNtHeaders->OptionalHeader;
	PIMAGE_SECTION_HEADER lpSections = (PIMAGE_SECTION_HEADER)(lpOptionalHeader + lpFileHeader->SizeOfOptionalHeader);
	for (int i = 0; i < lpFileHeader->NumberOfSections; ++i)
	{
		IMAGE_SECTION_HEADER section = lpSections[i];
		// If RVA is located within section, find the offset relative to section's VA after loading, and then use that as an offset from 
		// PointerToRawData. 
		// My guess is that windows loader assumes that sections are already mapped in memory correctly, and we need to manually find the real offset if they aren't.
		if (RVA >= section.VirtualAddress && RVA <= section.VirtualAddress + section.Misc.VirtualSize)
			return (CHAR*)Ctx->pImageBase + section.PointerToRawData + (RVA - section.VirtualAddress);
	}
	return NULL;
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