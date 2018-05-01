#include <stdio.h>
#include <Windows.h>

#define ARG_FILENAME 1
#define ARG_SECTION_NAME 2
#define ARG_SECTION_SIZE 3

unsigned long AlignSize(unsigned long desireOfSize, unsigned long alignment)
{
	unsigned long reminder = 0;

	if (desireOfSize < alignment)
	{
		return alignment;
	}

	reminder = desireOfSize % alignment;
	if (reminder > 0)
	{
		desireOfSize += alignment - reminder;
	}

	return desireOfSize;
}

BOOL SaveImageFile(char* csFileName, void* lpImageFile, unsigned long imageSize)
{
	BOOL bRet			= FALSE;

	HANDLE hFile		= NULL;
	DWORD dwWritten		= 0;

	hFile = CreateFileA(csFileName, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		printf("[-] Failed to open file %s: 0x%08x\n", csFileName, GetLastError());
		goto release;
	}

	if (! WriteFile(hFile, lpImageFile, imageSize, &dwWritten, NULL))
	{
		printf("[-] Cannot write the data of image file: 0x%08x\n", GetLastError());
		goto release;
	}

	bRet = TRUE;

release:
	
	if (hFile != NULL)
	{
		CloseHandle(hFile);
	}

	return bRet;
}

void AddSection(char* csFileName, char* csSectionName, unsigned long sectionSize)
{
	HANDLE hFile								= NULL;
	LPVOID lpImageBase							= NULL;
	HANDLE hFileMapping							= NULL;

	DWORD i										= 0;

	DWORD dwSizeOfImage							= 0;
	DWORD dwRawSizeOfImage						= 0;
	DWORD dwRawSizeOfDupImage					= 0;
	DWORD dwSizeOfHeaders						= 0;
	DWORD dwSizeOfSections						= 0;
	DWORD dwSizeOfSectionGap					= 0;

	DWORD dwHeadersPadding						= 0;

	PCHAR lpDupImgLocation						= NULL;
	PCHAR lpDuplicateImage						= NULL;

	LPVOID lpFirstSection						= NULL;

	CHAR szDupImgFileName[4096]					= { 0 };

	PIMAGE_NT_HEADERS lpImageNtHdr				= NULL;
	PIMAGE_SECTION_HEADER lpSectionHdr			= NULL;
	PIMAGE_SECTION_HEADER lpLastSectionHdr		= NULL;

	IMAGE_SECTION_HEADER insertSectionHdr		= { 0 };

	hFile = CreateFileA(csFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		printf("[-] Failed to open file %s: 0x%08x\n", csFileName, GetLastError());
		goto release;
	}

	hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == NULL)
	{
		printf("[-] Failed to create the mapping area of file: 0x%08x\n", GetLastError());
		CloseHandle(hFile);
		goto release;
	}

	lpImageBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (lpImageBase == NULL)
	{
		printf("[-] Failed to map the file to memory: 0x%08x\n", GetLastError());
		goto release;
	}

	// Retrieve the basic structrue pointer of the image file
	dwRawSizeOfImage = GetFileSize(hFile, NULL);

	lpImageNtHdr = (PIMAGE_NT_HEADERS) (((PIMAGE_DOS_HEADER) lpImageBase)->e_lfanew + (LONG) lpImageBase);
	lpSectionHdr = (PIMAGE_SECTION_HEADER) ((LONG) &lpImageNtHdr->OptionalHeader + 
		lpImageNtHdr->FileHeader.SizeOfOptionalHeader);
	lpLastSectionHdr = lpSectionHdr + (lpImageNtHdr->FileHeader.NumberOfSections - 1);

	lpFirstSection = (LPVOID) (lpImageNtHdr->OptionalHeader.SizeOfHeaders + (LONG) lpImageBase);

	// Setup the basic information of new section header
	ZeroMemory(&insertSectionHdr, sizeof(insertSectionHdr));
	strncpy(insertSectionHdr.Name, csSectionName, strlen(csSectionName));

	insertSectionHdr.SizeOfRawData = AlignSize(sectionSize, lpImageNtHdr->OptionalHeader.FileAlignment);
	insertSectionHdr.Misc.VirtualSize = sectionSize;
	insertSectionHdr.PointerToRawData = lpLastSectionHdr->PointerToRawData + lpLastSectionHdr->SizeOfRawData;
	insertSectionHdr.VirtualAddress = AlignSize(lpLastSectionHdr->VirtualAddress + lpLastSectionHdr->Misc.VirtualSize,
		lpImageNtHdr->OptionalHeader.SectionAlignment);
	insertSectionHdr.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

	// The free space between section header and first secton data
	dwSizeOfSectionGap = (LONG) lpFirstSection - (ULONG) lpSectionHdr -
		lpImageNtHdr->FileHeader.NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER;

	if (dwSizeOfSectionGap >= IMAGE_SIZEOF_SECTION_HEADER)
	{
		printf("[+] Section gapping good to go :)\n");

		dwSizeOfHeaders = lpImageNtHdr->OptionalHeader.SizeOfHeaders;
		// TODO: The user supplied size may out of range of type of DWORD
		dwSizeOfImage = lpImageNtHdr->OptionalHeader.SizeOfImage;
		dwRawSizeOfDupImage = dwRawSizeOfImage;
	}
	else 
	{
		printf("[*] Not enough space, try to adjust the section offset...\n");

		dwSizeOfHeaders = AlignSize(lpImageNtHdr->OptionalHeader.SizeOfHeaders + IMAGE_SIZEOF_FILE_HEADER,
			lpImageNtHdr->OptionalHeader.FileAlignment);
		dwHeadersPadding = dwSizeOfHeaders - lpImageNtHdr->OptionalHeader.SizeOfHeaders;

		dwSizeOfImage = lpImageNtHdr->OptionalHeader.SizeOfImage
			- AlignSize(lpImageNtHdr->OptionalHeader.SizeOfHeaders, lpImageNtHdr->OptionalHeader.SectionAlignment)
			+ AlignSize(dwSizeOfHeaders, lpImageNtHdr->OptionalHeader.SectionAlignment);
		dwRawSizeOfDupImage = dwRawSizeOfImage + dwHeadersPadding;
	}

	dwSizeOfImage += AlignSize(insertSectionHdr.Misc.VirtualSize, lpImageNtHdr->OptionalHeader.SectionAlignment);
	dwRawSizeOfDupImage += insertSectionHdr.SizeOfRawData;

	lpDuplicateImage = (PCHAR) LocalAlloc(LPTR, dwRawSizeOfDupImage);
	lpDupImgLocation = lpDuplicateImage;

	if (lpDuplicateImage == NULL)
	{
		printf("Failed to alloc the memory for image file: 0x%08x\n", GetLastError());
		goto release;
	}

	// Copy the PE header
	CopyMemory(lpDupImgLocation, lpImageBase, lpImageNtHdr->OptionalHeader.SizeOfHeaders);
	
	// Copy the new section header
	lpDupImgLocation = (PCHAR) ((DWORD) lpDupImgLocation + ((DWORD) (lpSectionHdr + lpImageNtHdr->FileHeader.NumberOfSections)
		- (DWORD) lpImageBase));
	CopyMemory(lpDupImgLocation, &insertSectionHdr, IMAGE_SIZEOF_SECTION_HEADER);
	
	// Copy the section data
	lpDupImgLocation = lpDuplicateImage + dwSizeOfHeaders;
	dwSizeOfSections = lpLastSectionHdr->PointerToRawData + lpLastSectionHdr->SizeOfRawData - lpSectionHdr->PointerToRawData;
	CopyMemory(lpDupImgLocation, lpFirstSection, dwSizeOfSections);

	// Copy reset of data, cert file etc.
	lpDupImgLocation = lpDupImgLocation + dwSizeOfSections + insertSectionHdr.SizeOfRawData;
	CopyMemory(lpDupImgLocation, (LPVOID) ((DWORD) lpFirstSection + dwSizeOfSections),
		dwRawSizeOfImage - lpImageNtHdr->OptionalHeader.SizeOfHeaders - dwSizeOfSections);

	// Fix the offset of section headers
	if (dwHeadersPadding > 0)
	{
		lpSectionHdr = (PIMAGE_SECTION_HEADER) ((DWORD) lpSectionHdr - (DWORD) lpImageBase + (DWORD) lpDuplicateImage);

		for (i = 0; i <= lpImageNtHdr->FileHeader.NumberOfSections; i++)
		{
			lpSectionHdr[i].PointerToRawData += dwHeadersPadding;
		}
	}

	// Overwrite the original header infos
	lpImageNtHdr = (PIMAGE_NT_HEADERS) ((DWORD) lpImageNtHdr - (DWORD) lpImageBase + (DWORD) lpDuplicateImage);
	lpImageNtHdr->FileHeader.NumberOfSections += 1;
	lpImageNtHdr->OptionalHeader.SizeOfHeaders = dwSizeOfHeaders;
	lpImageNtHdr->OptionalHeader.SizeOfImage = dwSizeOfImage;
	lpImageNtHdr->OptionalHeader.CheckSum = 0;

	ZeroMemory(szDupImgFileName, sizeof(szDupImgFileName));
	snprintf(szDupImgFileName, sizeof(szDupImgFileName), "%s_%s.exe", csFileName, csSectionName);

	if (! SaveImageFile(szDupImgFileName, lpDuplicateImage, dwRawSizeOfDupImage))
	{
		printf("[-] Failed to dump the new image file...\n");
		goto release;
	}

	printf("[+] Raw Size: 0x%x, Virtual Size: 0x%x\n", dwRawSizeOfDupImage, dwSizeOfImage);
	printf("[+] Section %s added, image saved to %s\n", csSectionName, szDupImgFileName);

release:
	if (hFile != NULL)
	{
		CloseHandle(hFile);
	}

	if (hFileMapping != NULL)
	{
		CloseHandle(hFileMapping);
	}

	if (lpImageBase != NULL)
	{
		UnmapViewOfFile(lpImageBase);
	}

	if (lpDuplicateImage != NULL)
	{
		LocalFree(lpDuplicateImage);
	}
}

int main(int argc, char** argv)
{
	char *lpFileName = NULL;

	unsigned long sectionSize = 0, sectionNameLength = 0;
	char szSectionName[IMAGE_SIZEOF_SHORT_NAME * 2] = { 0 };

	if (argc < 4)
	{
		printf("AddSection <exeName> <sectionName> <sectionSize>\n");
		return 0;
	}

	lpFileName = argv[ARG_FILENAME];

	sectionSize = atoi(argv[ARG_SECTION_SIZE]);
	sectionNameLength = strlen(argv[ARG_SECTION_NAME]);

	if (sectionNameLength > IMAGE_SIZEOF_SHORT_NAME)
	{
		sectionNameLength = IMAGE_SIZEOF_SHORT_NAME;
		printf("[*] The section name will be truncate because out of limit\n");
	}

	ZeroMemory(szSectionName, sizeof(szSectionName));
	strncpy(szSectionName, argv[ARG_SECTION_NAME], sectionNameLength);

	AddSection(lpFileName, szSectionName, sectionSize);

	return 0;
}