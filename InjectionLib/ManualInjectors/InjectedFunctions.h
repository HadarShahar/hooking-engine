#pragma once
#include "../pch.h"

struct InjData
{
	PBYTE pImageBase;
	/////////////////////////////////////////////////////////////////////// Functions from Kernel32.dll
	decltype(&LoadLibraryA)	  pLoadLibraryA		= &LoadLibraryA;
	decltype(&GetProcAddress) pGetProcAddress	= &GetProcAddress;
	decltype(&VirtualProtect) pVirtualProtect	= &VirtualProtect;
	///////////////////////////////////////////////////////////////////////
};

typedef BOOL(WINAPI *_DllMain)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

bool loader(InjData *pInjData);
int loaderEnd();

bool unloader(InjData *pInjData);
int unloaderEnd();
