#pragma once
#include "pch.h"
#include "AbstractInjector.h"

class WindowsHookInjector : public AbstractInjector
{
public:
	WindowsHookInjector(DWORD targetPID, const std::wstring& dllPath)
		: AbstractInjector(targetPID, dllPath) {};

	WindowsHookInjector(const std::wstring& processImage, const std::wstring& dllPath)
		: AbstractInjector(processImage, dllPath) {};

	virtual bool inject() override;
	virtual bool eject() override;

private:
	HHOOK m_hHook = nullptr;
};