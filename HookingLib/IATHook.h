#pragma once
#include "pch.h"
#include "AbstractHook.h"

class IATHook : public AbstractHook
{
public:
	IATHook(const std::string& funcToHook, const std::string& dllToHook, PVOID pNewFunc);
	~IATHook();

private:
	bool overrideFunctionPointer(PVOID pNewFunc);

	PIMAGE_THUNK_DATA m_pIatEntry = nullptr;
};

