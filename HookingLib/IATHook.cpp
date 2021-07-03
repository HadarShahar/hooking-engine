#include "pch.h"
#include "IATHook.h"
#include <string.h>

IATHook::IATHook(const std::string& funcToHook, const std::string& dllToHook, PVOID pNewFunc)
	: AbstractHook(funcToHook, dllToHook)
{
	auto pImageBase = reinterpret_cast<PBYTE>(GetModuleHandle(nullptr));
	auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pImageBase);
	auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pImageBase + pDosHeader->e_lfanew);

	auto pImportDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	auto pImportDes = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pImageBase + pImportDataDir->VirtualAddress);

	int index = 0;
	while (pImportDes[index].Characteristics)
	{
		auto dllName = reinterpret_cast<char*>(pImageBase + pImportDes[index].Name);
		// Case-insensitive comparison of the dll names.
		if (!_stricmp(dllToHook.c_str(), dllName))
			break;
		index++;
	}
	if (!pImportDes[index].Characteristics)
	{
		throw std::runtime_error("The dll " + dllToHook + " was not found in the import directory.");
	}

	auto pThunkILT = reinterpret_cast<PIMAGE_THUNK_DATA>(pImageBase + pImportDes[index].OriginalFirstThunk);
	auto pThunkIAT = reinterpret_cast<PIMAGE_THUNK_DATA>(pImageBase + pImportDes[index].FirstThunk);
	while (pThunkILT->u1.AddressOfData && !(pThunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG))
	{
		auto funcName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pImageBase + pThunkILT->u1.AddressOfData)->Name;
		if (funcToHook == funcName)
		{
			m_pIatEntry = pThunkIAT;
			break;
		}
		pThunkIAT++;
		pThunkILT++;
	}
	if (!m_pIatEntry)
	{
		throw std::runtime_error("The function " + funcToHook + " was not found in the import directory.");
	}

	m_pOriginalFunc = reinterpret_cast<PVOID>(m_pIatEntry->u1.Function);

	if (!overrideFunctionPointer(pNewFunc))
	{
		throw std::runtime_error("Could not override the function pointer in the IAT.");
	}
}

IATHook::~IATHook()
{
	if (m_pIatEntry && m_pOriginalFunc)
	{
		overrideFunctionPointer(m_pOriginalFunc);
	}
}

bool IATHook::overrideFunctionPointer(PVOID pNewFunc)
{
	DWORD oldProtect{};
	auto success = VirtualProtect(&m_pIatEntry->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProtect);
	if (success)
	{
		m_pIatEntry->u1.Function = reinterpret_cast<ULONG_PTR>(pNewFunc);
		success = VirtualProtect(&m_pIatEntry->u1.Function, sizeof(PVOID), oldProtect, &oldProtect);
	}
	return success;
}