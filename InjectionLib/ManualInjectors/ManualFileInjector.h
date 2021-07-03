#pragma once
#include "../pch.h"
#include "AbstractManualInjector.h"

// Injects a resource from the current module.
class ManualFileInjector : public AbstractManualInjector
{
public:
	ManualFileInjector(DWORD targetPID, const std::wstring& dllPath)
		: AbstractManualInjector(targetPID, dllPath) {};

	ManualFileInjector(const std::wstring& processImage, const std::wstring& dllPath)
		: AbstractManualInjector(processImage, dllPath) {};

private:
	virtual PBYTE getDllData() override;
	
	std::vector<BYTE> m_fileBuffer;
};
