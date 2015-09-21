#include "PEDiy.h"

#define offsetof(x,y) (ULONG)(&((x*)0)->y)
#define ALIGN(a,b) ((a-1)/b+1)*b

bool PE_Add_Section(char* fileName, void* sec, ULONG secsize, char* secName,ULONG secChara)
{

	HANDLE hFile = CreateFile(fileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (!hFile)
	{
		return false;
	}
	PIMAGE_SECTION_HEADER pSecHeader=NULL;
	do
	{
		ULONG ntHeaderOffset;
		ULONG Numberofbyte=0;
		SetFilePointer(hFile, offsetof(IMAGE_DOS_HEADER,e_lfanew), NULL, FILE_BEGIN);
		if (!ReadFile(hFile, &ntHeaderOffset, 4, &Numberofbyte, NULL))
		{
			break;
		}
		ULONG numOfsectionsOffset = ntHeaderOffset + offsetof(IMAGE_NT_HEADERS,FileHeader) + offsetof(IMAGE_FILE_HEADER, NumberOfSections);
		USHORT numofsection=0;
		SetFilePointer(hFile, numOfsectionsOffset, NULL, FILE_BEGIN);
		if (!ReadFile(hFile, &numofsection, 2, &Numberofbyte, NULL) || !numofsection)
		{
			break;
		}
		ULONG secalignOffset = ntHeaderOffset + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + offsetof(IMAGE_OPTIONAL_HEADER,SectionAlignment);
		ULONG secalign = 0;
		SetFilePointer(hFile, secalignOffset, NULL, FILE_BEGIN);
		if (!ReadFile(hFile, &secalign, 4, &Numberofbyte, NULL) || !secalign)
		{
			break;
		}
		ULONG sizeofoptionalheaderOffset = ntHeaderOffset + offsetof(IMAGE_NT_HEADERS, FileHeader) + offsetof(IMAGE_FILE_HEADER,SizeOfOptionalHeader);
		USHORT sizeofoptionalheader=0;
		SetFilePointer(hFile, sizeofoptionalheaderOffset, NULL, FILE_BEGIN);
		if (!ReadFile(hFile, &sizeofoptionalheader, 2, &Numberofbyte, NULL) || !sizeofoptionalheader)
		{
			break;
		}
		ULONG firstsectionOffset = ntHeaderOffset + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + sizeofoptionalheader;
		pSecHeader = new IMAGE_SECTION_HEADER[numofsection];
		SetFilePointer(hFile, firstsectionOffset, NULL, FILE_BEGIN);
		if (!ReadFile(hFile, pSecHeader, sizeof(IMAGE_SECTION_HEADER)*numofsection, &Numberofbyte, NULL))
		{
			break;
		}
		PIMAGE_SECTION_HEADER lastSecHeader = &pSecHeader[numofsection - 1];
		IMAGE_SECTION_HEADER newSec;
		memset(&newSec, 0, sizeof(IMAGE_SECTION_HEADER));
		memcpy((char*)newSec.Name,secName, min(strlen(secName), 8));
		newSec.VirtualAddress = lastSecHeader->VirtualAddress + ALIGN(lastSecHeader->Misc.VirtualSize, secalign);
		newSec.Misc.VirtualSize = secsize;
		newSec.PointerToRawData = lastSecHeader->PointerToRawData + lastSecHeader->SizeOfRawData;
		newSec.SizeOfRawData = secsize;
		newSec.Characteristics = secChara;


		ULONG newSecOffset = firstsectionOffset + numofsection*sizeof(IMAGE_SECTION_HEADER);
		SetFilePointer(hFile, newSecOffset, NULL, FILE_BEGIN);
		if (!WriteFile(hFile, &newSec, sizeof(IMAGE_SECTION_HEADER), &Numberofbyte, NULL))
		{
			break;
		}

		SetFilePointer(hFile, numOfsectionsOffset, NULL, FILE_BEGIN);
		numofsection++;
		if (!WriteFile(hFile, &numofsection, 2, &Numberofbyte, NULL))
		{
			break;
		}
		ULONG sizeofimageOffset = ntHeaderOffset + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + offsetof(IMAGE_OPTIONAL_HEADER,SizeOfImage);
		ULONG sizeofimage = newSec.VirtualAddress + newSec.Misc.VirtualSize;
		SetFilePointer(hFile, sizeofimageOffset, NULL, FILE_BEGIN);
		if (!WriteFile(hFile, &sizeofimage, 4, &Numberofbyte, NULL))
		{
			break;
		}


		SetFilePointer(hFile, 0, NULL, FILE_END);
		if (!WriteFile(hFile, sec, secsize, &Numberofbyte, NULL))
		{
			break;
		}

		delete[] pSecHeader;
		CloseHandle(hFile);
		return true;
	} while (0);
	if (pSecHeader)
	{
		delete[] pSecHeader;
	}
	CloseHandle(hFile);
	return false;
}