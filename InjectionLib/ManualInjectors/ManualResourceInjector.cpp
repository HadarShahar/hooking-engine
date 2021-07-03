#include "pch.h"
#include "ManualResourceInjector.h"

PBYTE ManualResourceInjector::getDllData()
{
	// RT_RCDATA = Application-defined resource (raw data).
	auto hResInfo = FindResourceW(nullptr, MAKEINTRESOURCE(m_resourceID), RT_RCDATA);
	if (!hResInfo)
	{
		std::cerr << "FindResourceW failed.\n";
		return nullptr;
	}
	auto hResData = LoadResource(nullptr, hResInfo);
	if (!hResData)
	{
		std::cerr << "LoadResource failed.\n";
		return nullptr;
	}
	return reinterpret_cast<PBYTE>(LockResource(hResData));
}