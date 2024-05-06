#include <stdio.h>

#include "peparse.h"

int main(int argc, char** argv)
{
	HANDLE hFile;
	HANDLE hProcHeap;
	CHAR* pFileBuf;
	BOOL status;
	DWORD dwFileSize, dwBytesRead;
	DWORD ldrStatus;
	PPE_CONTEXT Context = NULL;
	PPE_SECTION_CONTEXT pSectionContext = NULL;
	PPE_IMPORT_CONTEXT pImportContext = NULL;

	if (argc < 2)
	{
		printf(
			"A tool for loading portable executables into memory and extracting information from them.\n\n"
			"Usage: %s PE\n\n"
			"Args:\n"
			"    PE: The path to the PE to load\n",
			argv[0]
		);
		return 1;
	}
	hFile = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile failed (%d)\n", GetLastError());
		return 1;
	}
	dwFileSize = GetFileSize(hFile, (LPDWORD)NULL);
	hProcHeap = GetProcessHeap();
	pFileBuf = (CHAR*)HeapAlloc(hProcHeap, HEAP_ZERO_MEMORY, dwFileSize);
	if (!pFileBuf)
	{
		printf("HeapAlloc failed (%d)\n", GetLastError());
		return 1;
	}
	status = ReadFile(hFile, (LPVOID)pFileBuf, dwFileSize, &dwBytesRead, (LPOVERLAPPED)NULL);
	if (!status)
	{
		printf("ReadFile failed (%d)\n", GetLastError());
		HeapFree(hProcHeap, 0, (LPVOID)pFileBuf);
		return 1;
	}
	ldrStatus = PEParseFromBuffer((LPVOID)pFileBuf, &Context);
	if (ldrStatus)
	{
		printf("PEParseFromBuffer failed (%d)\n", ldrStatus);
		HeapFree(hProcHeap, 0, (LPVOID)pFileBuf);
		return 1;
	}
	printf("Done!\n\n");
	
	printf("Name:                   %s\n", argv[1]);
	printf("Is 64-bit:              %d\n", Context->isX64);
	printf("Compile time (epoch):   %d\n", Context->CompileTime);
	printf("\nSections (%d)\n========\n", Context->SectionCount);
	for (pSectionContext = Context->SectionCtxList; pSectionContext != NULL; pSectionContext = pSectionContext->Next)
	{
		printf("\n");
		printf("Name: %s\n", pSectionContext->szName);
		printf("Size: %d bytes\n", pSectionContext->dwSize);
		printf("RVA: %x\n", pSectionContext->StartAddr);
	}
	
	if (Context->ImportCtxList)
	{
		printf("\nImports\n=======");
		for (pImportContext = Context->ImportCtxList; pImportContext != NULL; pImportContext = pImportContext->Next)
		{
			printf("\n");
			printf("Library name: %s\n", pImportContext->szName);
			for (DWORD i = 0; i < pImportContext->ImportCount; i++)
			{
				printf("\t* %s\n", pImportContext->ImportTable[i]);
			}
		}
		printf("\n");
	}

	if (Context->ExportCount)
	{
		printf("\nExports (%d)\n=======\n", Context->ExportCount);
		for (int i = 0; i < Context->ExportCount; i++)
		{
			printf("* %s\n", Context->ExportList[i]);
		}
		printf("\n");
	}
	PEFreeCtx(Context);
	HeapFree(hProcHeap, 0, pFileBuf);
}
