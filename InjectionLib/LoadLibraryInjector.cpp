#include "pch.h"
#include "LoadLibraryInjector.h"

bool LoadLibraryInjector::inject()
{
	// +1 because the length doesn't include the terminating null characters
	auto pRemotePath = injectData(m_fullDllPath.value().c_str(),
								  (m_fullDllPath.value().length() + 1) * sizeof(wchar_t));
	if (!pRemotePath)
	{
		return false;
	}

	bool success = runRemoteThread(&LoadLibraryW, pRemotePath);
	VirtualFreeEx(m_hProcess, pRemotePath, 0, MEM_RELEASE);
	return success;
}

bool LoadLibraryInjector::eject()
{
	HANDLE hInjectedDll = getRemoteDllHandle();
	if (!hInjectedDll)
	{
		return false;
	}
	return runRemoteThread(&FreeLibrary, static_cast<LPVOID>(hInjectedDll));
}

HANDLE LoadLibraryInjector::getRemoteDllHandle() const
{
	HANDLE hSsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_targetPID);
	HANDLE hInjectedDll = nullptr;
	if (hSsnapshot != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 me32{};
		me32.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hSsnapshot, &me32))
		{
			do {
				if (m_fullDllPath == me32.szExePath)
				{
					hInjectedDll = me32.hModule;
					break;
				}
			} while (Module32Next(hSsnapshot, &me32));
		}
		CloseHandle(hSsnapshot);
	}
	return hInjectedDll;
}
