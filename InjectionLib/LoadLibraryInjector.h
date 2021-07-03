#pragma once
#include "pch.h"
#include "AbstractInjector.h"

class LoadLibraryInjector : public AbstractInjector
{
public:
	LoadLibraryInjector(DWORD targetPID, const std::wstring& dllPath)
		: AbstractInjector(targetPID, dllPath) {};

	LoadLibraryInjector(const std::wstring& processImage, const std::wstring& dllPath)
		: AbstractInjector(processImage, dllPath) {};

	virtual bool inject() override;
	virtual bool eject() override;

private:
	HANDLE getRemoteDllHandle() const; 
};