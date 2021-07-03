#pragma once
#include "../pch.h"
#include "AbstractManualInjector.h"

// Injects a resource from the current module.
class ManualResourceInjector : public AbstractManualInjector
{
public:
	ManualResourceInjector(DWORD targetPID, int resourceID)
		: AbstractManualInjector(targetPID), m_resourceID(resourceID) {};

	ManualResourceInjector(const std::wstring& processImage, int resourceID)
		: AbstractManualInjector(processImage), m_resourceID(resourceID) {};

private:
	virtual PBYTE getDllData() override;
	
	int m_resourceID;
};
