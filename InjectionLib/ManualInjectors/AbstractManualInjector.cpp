#include "pch.h"
#include "AbstractManualInjector.h"

bool AbstractManualInjector::inject()
{
	PBYTE pLocalData = getDllData();
	if (!pLocalData)
	{
		return false;
	}
	auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pLocalData);
	auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pLocalData + pDosHeader->e_lfanew);
	auto pOptionalHeader = &pNtHeaders->OptionalHeader;

	auto pPreferredImageBase = reinterpret_cast<PBYTE>(pOptionalHeader->ImageBase);
	m_pRemoteBase = reinterpret_cast<PBYTE>(VirtualAllocEx(
		m_hProcess,
		pPreferredImageBase,
		pOptionalHeader->SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	));
	if (!m_pRemoteBase) // Coud not allocate memory at the preferred image base.
	{
		m_pRemoteBase = reinterpret_cast<PBYTE>(VirtualAllocEx(
			m_hProcess,
			nullptr,
			pOptionalHeader->SizeOfImage,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE
		));
		if (!m_pRemoteBase)
		{
			std::cerr << "VirtualAllocEx failed.\n";
			return false;
		}
	}
	std::cout << "Remote image base: 0x" << static_cast<void*>(m_pRemoteBase) << '\n';

	// Write the PE headers.
	if (!writeMemory(m_pRemoteBase, pLocalData, pOptionalHeader->SizeOfHeaders))
	{
		VirtualFreeEx(m_hProcess, m_pRemoteBase, 0, MEM_RELEASE);
		m_pRemoteBase = nullptr;
		return false;
	}

	if (!mapSections(pNtHeaders, pLocalData))
	{
		VirtualFreeEx(m_hProcess, m_pRemoteBase, 0, MEM_RELEASE);
		m_pRemoteBase = nullptr;
		return false;
	}

	return injectAndRunLoader();
}

bool AbstractManualInjector::mapSections(PIMAGE_NT_HEADERS pNtHeaders, PBYTE pLocalData) const
{
	auto numOfSections = pNtHeaders->FileHeader.NumberOfSections;
	auto pSectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(
		reinterpret_cast<PBYTE>(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

	for (int i = 0; i < numOfSections; ++i)
	{
		const auto& header = pSectionHeaders[i];
		if (!header.SizeOfRawData) // for .bss
		{
			// VirtualAllocEx already initializes the memory it allocates to zero.
			continue;
		}

		auto pRemoteHeader = m_pRemoteBase + header.VirtualAddress;
		if (!writeMemory(pRemoteHeader, pLocalData + header.PointerToRawData, header.SizeOfRawData))
		{
			return false;
		}
		// The injected loader adjust the memory protection of each section. 
	}
	return true;
}

bool AbstractManualInjector::injectAndRunLoader()
{
	InjData data{ .pImageBase = m_pRemoteBase };

	m_pRemoteData = reinterpret_cast<InjData*>(injectData(&data, sizeof(InjData)));
	if (!m_pRemoteData)
	{
		return false;
	}

	SIZE_T loaderSize = reinterpret_cast<PBYTE>(&loaderEnd) - reinterpret_cast<PBYTE>(&loader);
	std::cout << "Loader size: " << loaderSize << " bytes.\n";
	auto pRemoteLoader = injectData(&loader, loaderSize, PAGE_EXECUTE_READWRITE);
	if (!pRemoteLoader)
	{
		return false;
	}

	std::cout << "Loader was injected successfully, running it now...\n";
	bool success = runRemoteThread(pRemoteLoader, m_pRemoteData);  // Run the injected loader.	
	VirtualFreeEx(m_hProcess, pRemoteLoader, 0, MEM_RELEASE);
	return success;
}

bool AbstractManualInjector::eject()
{
	if (!m_pRemoteBase || !m_pRemoteData) // The dll wasn't injected successfully.
	{
		return false;
	}
	auto success = injectAndRunUnloader();
	VirtualFreeEx(m_hProcess, m_pRemoteBase, 0, MEM_RELEASE);
	m_pRemoteBase = nullptr;
	VirtualFreeEx(m_hProcess, m_pRemoteData, 0, MEM_RELEASE);
	m_pRemoteData = nullptr;
	return success;
}

bool AbstractManualInjector::injectAndRunUnloader()
{
	SIZE_T unloaderSize = reinterpret_cast<PBYTE>(&unloaderEnd) - reinterpret_cast<PBYTE>(&unloader);
	std::cout << "Unloader size: " << unloaderSize << " bytes.\n";
	auto pRemoteUnloader = injectData(&unloader, unloaderSize, PAGE_EXECUTE_READWRITE);
	if (!pRemoteUnloader)
	{
		return false;
	}

	std::cout << "Unloader was injected successfully.\n";
	bool success = runRemoteThread(pRemoteUnloader, m_pRemoteData);  // Run the injected unloader.	
	VirtualFreeEx(m_hProcess, pRemoteUnloader, 0, MEM_RELEASE);
	return success;
}