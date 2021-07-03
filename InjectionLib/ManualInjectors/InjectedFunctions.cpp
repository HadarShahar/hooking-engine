/*************************************************************************************
Important project settings:
config: Release x64
Project\Settings\C/C++\Code Generation\Security Check\Disable Security Check (/GS-) 
Project\Settings\C/C++\Optimization\Disabled (/Od)
*************************************************************************************/
#include "pch.h"
#include "InjectedFunctions.h"

bool loader(InjData *pInjData)
{
	auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pInjData->pImageBase);
	auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pInjData->pImageBase + pDosHeader->e_lfanew);
	auto pOptionalHeader = &pNtHeaders->OptionalHeader;

	/////////////////////////////////////////////////////////////////////// Calc and apply relocations.
	auto delta = reinterpret_cast<ULONG_PTR>(pInjData->pImageBase - pOptionalHeader->ImageBase);
	if (delta)
	{
		auto pRelocDataDir = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		auto pRelocDir = pInjData->pImageBase + pRelocDataDir->VirtualAddress;
		auto pRelocDirEnd = pRelocDir + pRelocDataDir->Size;

		auto pRelocIterator = pRelocDir;
		while (pRelocIterator < pRelocDirEnd)
		{
			auto pBaseReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pRelocIterator);
			auto relocEntries = reinterpret_cast<PWORD>(pRelocIterator + sizeof(IMAGE_BASE_RELOCATION));
			auto relocCount = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			for (auto i = 0; i < relocCount; ++i)
			{
				// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
				auto relocType = relocEntries[i] >> 12;
				auto relocOffset = relocEntries[i] & 0xFFF;
				if (relocType == IMAGE_REL_BASED_ABSOLUTE) // The base relocation is skipped.
				{
					continue;
				}
				*reinterpret_cast<PULONG_PTR>(
					pInjData->pImageBase + pBaseReloc->VirtualAddress + relocOffset) += delta;
			}
			pRelocIterator += pBaseReloc->SizeOfBlock;
		}
	}


	/////////////////////////////////////////////////////////////////////// Load imports and update IAT.
	auto pImportDataDir = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	auto pImportDes = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
		pInjData->pImageBase + pImportDataDir->VirtualAddress);

	// At the end of the import descriptor array, the Characteristics is 0.
	for (auto index = 0; pImportDes[index].Characteristics; ++index)
	{
		auto hModule = pInjData->pLoadLibraryA(reinterpret_cast<LPCSTR>(
			pInjData->pImageBase + pImportDes[index].Name));
		if (!hModule)
		{
			return false;
		}

		auto pThunkILT = reinterpret_cast<PIMAGE_THUNK_DATA>(
			pInjData->pImageBase + pImportDes[index].OriginalFirstThunk);
		auto pThunkIAT = reinterpret_cast<PIMAGE_THUNK_DATA>(
			pInjData->pImageBase + pImportDes[index].FirstThunk);
		while (pThunkILT->u1.AddressOfData)
		{
			ULONG_PTR importAddr = 0;
			if (pThunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal.
				// If the second parameter of GetProcAddress is an ordinal value, 
				// it must be in the low-order word; the high-order word must be zero. 
				auto ordinal = pThunkILT->u1.Ordinal & 0xFFFF;
				importAddr = reinterpret_cast<ULONGLONG>(
					pInjData->pGetProcAddress(hModule, reinterpret_cast<LPCSTR>(ordinal)));
			}
			else
			{
				// Import by name.
				auto name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
					pInjData->pImageBase + pThunkILT->u1.AddressOfData)->Name;
				importAddr = reinterpret_cast<ULONGLONG>(pInjData->pGetProcAddress(hModule, name));
			}

			if (!importAddr)
			{
				return false;
			}
			pThunkIAT->u1.Function = importAddr;
			pThunkILT++;
			pThunkIAT++;
		}
	}

	///////////////////////////////////////////////////////////////////// Adjust the memory protection of each section.
	auto numOfSections = pNtHeaders->FileHeader.NumberOfSections;
	auto pSectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(
		reinterpret_cast<PBYTE>(pOptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

	DWORD oldProtect{};
	DWORD newProtect = PAGE_READWRITE;
	for (int i = 0; i < numOfSections; ++i)
	{
		const auto pSectionHeader = &pSectionHeaders[i];
		
		bool canExecute	= pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE;
		bool canRead	= pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ;
		bool canWrite	= pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE;
		if (canExecute)
		{
			if (canWrite)
				newProtect = PAGE_EXECUTE_READWRITE;
			else
				newProtect = canRead ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
		}
		else
		{
			newProtect = canWrite ? PAGE_READWRITE : PAGE_READONLY;
		}

		// If newProtect is different from the current protection
		if (newProtect != PAGE_READWRITE &&
			!pInjData->pVirtualProtect(pInjData->pImageBase + pSectionHeader->VirtualAddress,
				pSectionHeader->Misc.VirtualSize, newProtect, &oldProtect))
		{
			return false;
		}
	}
	
	/////////////////////////////////////////////////////////////////////// TODO: Support exception handling.
	//auto pExceptionDataDir = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	//auto pExceptionDir = reinterpret_cast<PRUNTIME_FUNCTION>(pInjData->pImageBase + pExceptionDataDir->VirtualAddress);
	//auto entryCount = pExceptionDataDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
	//if (!pInjData->pRtlAddFunctionTable(pExceptionDir, entryCount, 
	//	reinterpret_cast<DWORD64>(pInjData->pImageBase)))
	//{
	//		return false;
	//}

	/////////////////////////////////////////////////////////////////////// Execute TLS callbacks.
	auto pTLSDataDir = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (pTLSDataDir->Size)
	{
		auto pTLSDir = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(pInjData->pImageBase + pTLSDataDir->VirtualAddress);
		auto pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLSDir->AddressOfCallBacks);
		while (pCallback && *pCallback)
		{
			(*pCallback)(pInjData->pImageBase, DLL_PROCESS_ATTACH, nullptr);
			pCallback++;
		}
	}

	/////////////////////////////////////////////////////////////////////// Call DllMain.
	auto dllMain = reinterpret_cast<_DllMain>(pInjData->pImageBase + pOptionalHeader->AddressOfEntryPoint);
	return dllMain(reinterpret_cast<HINSTANCE>(pInjData->pImageBase), DLL_PROCESS_ATTACH, nullptr);
}
int loaderEnd() { return 1; }




bool unloader(InjData *pInjData)
{
	auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pInjData->pImageBase);
	auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pInjData->pImageBase + pDosHeader->e_lfanew);
	auto pOptionalHeader = &pNtHeaders->OptionalHeader;

	/////////////////////////////////////////////////////////////////////// Execute TLS callbacks.
	auto pTLSDataDir = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (pTLSDataDir->Size)
	{
		auto pTLSDir = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(pInjData->pImageBase + pTLSDataDir->VirtualAddress);
		auto pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLSDir->AddressOfCallBacks);
		while (pCallback && *pCallback)
		{
			(*pCallback)(pInjData->pImageBase, DLL_PROCESS_DETACH, nullptr);
			pCallback++;
		}
	}

	/////////////////////////////////////////////////////////////////////// Call DllMain.
	auto dllMain = reinterpret_cast<_DllMain>(pInjData->pImageBase + pOptionalHeader->AddressOfEntryPoint);
	return dllMain(reinterpret_cast<HINSTANCE>(pInjData->pImageBase), DLL_PROCESS_DETACH, nullptr);
}
int unloaderEnd() { return 2; }
