#pragma once
#include "pch.h"
#include "AbstractHook.h"
#include "../distorm/include/distorm.h"

class InlineHook : public AbstractHook
{
public:
	InlineHook(const std::string& funcToHook, const std::string& dllToHook, PVOID pNewFunc);
	~InlineHook();

private:
	void createBridgeToOriginalFunc();
	void createBridgeToNewFunc(PVOID pNewFunc);
	
	static PVOID allocateBridgeWithinDistance(PVOID pSrc, SIZE_T bridgeSize, SIZE_T maxDistance);
	static void createRelativeTrampoline(PVOID pSrc, PVOID pDst);
	static void createAbsoluteTrampoline(PVOID pSrc, PVOID pDst);
	static void writeLE(BYTE *arr, uint32_t n)
	{
		for (int i = 0; i < sizeof(n); ++i)
			arr[i] = (n >> (8 * i)) & 0xFF;
	}

	PVOID m_pFuncToHook = nullptr;
	PVOID m_pBridgeToNewFunc = nullptr;
	PVOID m_pBridgeToOriginalFunc = nullptr;
	SIZE_T m_copiedInstSize = 0;

	static constexpr SIZE_T RELATIVE_TRAMPOLINE_SIZE = 5;	// Bytes.
	static constexpr SIZE_T ABSOLUTE_TRAMPOLINE_SIZE = 14;	// Bytes.
};
