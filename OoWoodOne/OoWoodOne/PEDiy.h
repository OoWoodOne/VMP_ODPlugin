#ifndef _PEDIY_
#define _PEDIY_
#include <Windows.h>

bool PE_Add_Section(char* fileName, void* sec, ULONG secsize, char* secName, ULONG secChara = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);


#endif