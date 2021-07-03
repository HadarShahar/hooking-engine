#pragma once
#include "../pch.h"
#include "../AbstractInjector.h"
#include "InjectedFunctions.h"

class AbstractManualInjector : public AbstractInjector
{
public:
	AbstractManualInjector(DWORD targetPID, 
		const std::optional<std::wstring>& dllPath = std::nullopt)
		: AbstractInjector(targetPID, dllPath) {};

	AbstractManualInjector(const std::wstring& processImage, 
		const std::optional<std::wstring>& dllPath = std::nullopt)
		: AbstractInjector(processImage, dllPath) {};

	virtual bool inject() override;
	virtual bool eject() override;
	
private:
	virtual PBYTE getDllData() = 0;
	bool mapSections(PIMAGE_NT_HEADERS pNtHeaders, PBYTE pLocalData) const;
	bool injectAndRunLoader();
	bool injectAndRunUnloader();

	PBYTE m_pRemoteBase = nullptr;
	InjData *m_pRemoteData = nullptr;
};
