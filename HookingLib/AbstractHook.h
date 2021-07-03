#pragma once
#include "pch.h"

class AbstractHook
{
protected:
	AbstractHook(const std::string& funcToHook, const std::string& dllToHook)
		: m_funcToHook(funcToHook), m_dllToHook(dllToHook) {};

public:
	AbstractHook(const AbstractHook&) = delete;
	AbstractHook& operator=(const AbstractHook&) = delete;

	virtual ~AbstractHook() = default;
	PVOID getOriginalFunc() const { return m_pOriginalFunc; }

protected:
	const std::string m_funcToHook;
	const std::string m_dllToHook;
	PVOID m_pOriginalFunc = nullptr;
};
