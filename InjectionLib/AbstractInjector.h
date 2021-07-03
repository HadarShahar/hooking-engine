#pragma once
#include "pch.h"
#include "../InterprocessCommunication/SharedMemory.h"

class AbstractInjector
{
public:
	AbstractInjector(DWORD targetPID, const std::optional<std::wstring>& dllPath);
	AbstractInjector(const std::wstring& processImage, const std::optional<std::wstring>& dllPath);
	
	AbstractInjector(const AbstractInjector&) = delete;
	AbstractInjector& operator=(const AbstractInjector&) = delete;

	AbstractInjector(AbstractInjector&& other) noexcept;
	AbstractInjector& operator=(AbstractInjector&& other) noexcept;

	virtual ~AbstractInjector();

	virtual bool inject() = 0;
	virtual bool eject() = 0;

	static DWORD pidof(const std::wstring& processImage);

protected:
	void setDllPath(const std::wstring& dllPath);
	void validateDll(const std::wstring& dllPath) const;
	void validatePlatforms(PIMAGE_NT_HEADERS pNtHeaders) const;
	bool isTargetProcessX86() const;

	bool writeMemory(LPVOID pRemoteAddr, LPCVOID pLocalData, SIZE_T dataSize) const;
	LPVOID injectData(LPCVOID pLocalData, SIZE_T dataSize, DWORD memProtect = PAGE_READWRITE) const;
	DWORD getAnyRemoteThreadID() const;
	bool runRemoteThread(LPVOID pThreadFunc, LPVOID pThreadParam);

	DWORD m_targetPID{};
	HANDLE m_hProcess = nullptr;

	// Optional because a manual mapping injector can get the injected dll from a PE resource.
	std::optional<std::wstring> m_fullDllPath;

	// Shared memory to exchange data with the injected dll.
	SharedMemory<char*> m_dbgSharedMemory;
};