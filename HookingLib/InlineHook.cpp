#include "pch.h"
#include "InlineHook.h"
#include <fstream>

InlineHook::InlineHook(const std::string& funcToHook, const std::string& dllToHook, PVOID pNewFunc)
	: AbstractHook(funcToHook, dllToHook)
{
	auto hModule = LoadLibraryA(dllToHook.c_str());
	if (!hModule)
	{
		throw std::runtime_error("The dll " + dllToHook + " was not found.");
	}
	m_pFuncToHook = GetProcAddress(hModule, funcToHook.c_str());
	if (!m_pFuncToHook)
	{
		throw std::runtime_error("The function " + funcToHook + " was not found.");
	}

	createBridgeToOriginalFunc();
	// The "original" function for the class users is now the bridge 
	// that calls the real original function (funcToHook).
	m_pOriginalFunc = m_pBridgeToOriginalFunc;

	createBridgeToNewFunc(pNewFunc);
}

InlineHook::~InlineHook()
{
	if (m_pBridgeToOriginalFunc)
	{
		if (m_copiedInstSize)
		{
			DWORD oldProtect{};
			auto success = VirtualProtect(m_pFuncToHook, m_copiedInstSize, PAGE_EXECUTE_READWRITE, &oldProtect);
			if (success)
			{
				// Restore the instructions that were overridden in the original function.
				memcpy(m_pFuncToHook, m_pBridgeToOriginalFunc, m_copiedInstSize);
				success = VirtualProtect(m_pFuncToHook, m_copiedInstSize, oldProtect, &oldProtect);
			}
		}
		VirtualFree(m_pBridgeToOriginalFunc, 0, MEM_RELEASE);
	}

	if (m_pBridgeToNewFunc)
	{
		VirtualFree(m_pBridgeToNewFunc, 0, MEM_RELEASE);
	}
}

void InlineHook::createBridgeToOriginalFunc()
{
	// Disassemble the first instructions of m_pFuncToHook.
	constexpr int MAX_INSTRUCTIONS_TO_DISASM = 20;
	constexpr int SIZE_TO_DISASM = 50;
	_DecodeResult res;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS_TO_DISASM];
	unsigned int decodedInstructionsCount = 0;

#ifdef _WIN64
	_DecodeType dt = Decode64Bits;
#else
	_DecodeType dt = Decode32Bits;
#endif

	_OffsetType offset = 0;
	res = distorm_decode(offset,				// offset for buffer
		reinterpret_cast<PBYTE>(m_pFuncToHook),	// buffer to disassemble
		SIZE_TO_DISASM,
		dt,
		decodedInstructions,
		MAX_INSTRUCTIONS_TO_DISASM,
		&decodedInstructionsCount
	);

	m_copiedInstSize = 0;
	for (UINT i = 0; i < decodedInstructionsCount; ++i)
	{
		if (m_copiedInstSize >= RELATIVE_TRAMPOLINE_SIZE)
		{
			break;
		}
		m_copiedInstSize += decodedInstructions[i].size;
	}

	m_pBridgeToOriginalFunc = VirtualAlloc(
		nullptr,
		m_copiedInstSize + ABSOLUTE_TRAMPOLINE_SIZE,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (!m_pBridgeToOriginalFunc)
	{
		throw std::runtime_error("VirtualAlloc failed.");
	}

	/////////////////////////////// just for deubug!!!
	//std::ofstream out("C:\\Users\\user\\Desktop\\debug.txt"); 
	//out << std::hex;
	//out << m_pBridgeToOriginalFunc << " " << m_pFuncToHook << '\n';

	// Copy the first instructions of m_pFuncToHook to m_pBridgeToOriginalFunc.
	memcpy(m_pBridgeToOriginalFunc, m_pFuncToHook, m_copiedInstSize);
	createAbsoluteTrampoline(reinterpret_cast<PBYTE>(m_pBridgeToOriginalFunc) + m_copiedInstSize,
							 reinterpret_cast<PBYTE>(m_pFuncToHook) + m_copiedInstSize);
}

void InlineHook::createBridgeToNewFunc(PVOID pNewFunc)
{
#ifdef _WIN64
	// This bridge must be within 2GB of m_pFuncToHook, so a relative jump instruction can jump to it.
	// This bridge is just an absolute trampoline to pNewFunc.
	m_pBridgeToNewFunc = allocateBridgeWithinDistance(m_pFuncToHook, ABSOLUTE_TRAMPOLINE_SIZE, 1u << 31);
	if (!m_pBridgeToNewFunc)
	{
		throw std::runtime_error("Could not find a free memory block within 2GB of 0x" +
			std::to_string(reinterpret_cast<ULONG_PTR>(m_pFuncToHook)));
	}
	createAbsoluteTrampoline(m_pBridgeToNewFunc, pNewFunc);
	auto pDst = m_pBridgeToNewFunc;
#else
	// On 32 bit, another bridge is not necessary because a relative jump is enough.
	auto pDst = pNewFunc;
#endif

	DWORD oldProtect{};
	auto success = VirtualProtect(m_pFuncToHook, m_copiedInstSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (success)
	{
		createRelativeTrampoline(m_pFuncToHook, pDst);
		success = VirtualProtect(m_pFuncToHook, m_copiedInstSize, oldProtect, &oldProtect);
	}
	if (!success)
	{
		throw std::runtime_error("VirtualProtect failed.");
	}
}

PVOID InlineHook::allocateBridgeWithinDistance(PVOID pSrc, SIZE_T bridgeSize, SIZE_T maxDistance)
{
	// Locate a free memory block within maxDistance of pSrc.
	auto pQueriedAddr = reinterpret_cast<PBYTE>(pSrc) + maxDistance;
	MEMORY_BASIC_INFORMATION memInfo{ 0 };

	SYSTEM_INFO systemInfo{ 0 };
	GetSystemInfo(&systemInfo); // Get the memory page size.

	PVOID pBridge = nullptr;
	while (!pBridge && pQueriedAddr > reinterpret_cast<PBYTE>(pSrc))
	{
		if (VirtualQuery(pQueriedAddr, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			if (memInfo.State == MEM_FREE)
			{
				pBridge = VirtualAlloc(
					pQueriedAddr,
					bridgeSize,
					MEM_COMMIT | MEM_RESERVE,
					PAGE_EXECUTE_READWRITE
				);
			}
		}
		pQueriedAddr -= systemInfo.dwPageSize;
	}
	return pBridge;
}

void InlineHook::createRelativeTrampoline(PVOID pSrc, PVOID pDst)
{
	auto distance = reinterpret_cast<ULONG_PTR>(pDst) - reinterpret_cast<ULONG_PTR>(pSrc) - RELATIVE_TRAMPOLINE_SIZE;
	*reinterpret_cast<PBYTE>(pSrc) = 0xE9; // Relative jump opcode.
	writeLE(reinterpret_cast<PBYTE>(pSrc) + 1, distance & 0xFFFFFFFF);
}

void InlineHook::createAbsoluteTrampoline(PVOID pSrc, PVOID pDst)
{
	// Placeholders for the address in the trampoline:
	constexpr BYTE LB = 0; 	// For the 4 lower bytes.
	constexpr BYTE HB = 0; 	// For the 4 higher bytes (just for x64).
	BYTE trampoline[ABSOLUTE_TRAMPOLINE_SIZE]
	{
		0x68, LB, LB, LB, LB,                   // push LBLBLBLB
#ifdef _WIN64
		0xC7, 0x44, 0x24, 0x04, HB, HB, HB, HB, // mov  DWORD PTR [rsp+0x4], HBHBHBHB
#endif
		0xC3                                    // ret  
	};

	auto dstAddr = reinterpret_cast<ULONG_PTR>(pDst);
	writeLE(&trampoline[1], dstAddr & 0xFFFFFFFF);  // patch the 4 lower bytes.
#ifdef _WIN64
	writeLE(&trampoline[9], dstAddr >> 32);         // patch the 4 higher bytes.
#endif
	memcpy(pSrc, &trampoline, ABSOLUTE_TRAMPOLINE_SIZE);
}