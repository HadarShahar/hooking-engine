// Sample injection command:	Injector.exe -ll CreateProcessHookDll.dll chrome.exe
#include "../../HookingLib/AbstractHook.h"
#include "../../HookingLib/InlineHook.h"
#include "../../HookingLib/IATHook.h"
#include "../../InterprocessCommunication/SharedMemory.h"
#include <iostream>
#include <string>
#include <stdexcept>
#include <fstream>
#include <Windows.h>
#include <debugapi.h>

// https://doxygen.reactos.org/d9/dd7/dll_2win32_2kernel32_2client_2proc_8c.html#a13a0f94b43874ed5a678909bc39cc1ab
typedef BOOL(WINAPI *_CreateProcessInternalW)(
	HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, 
	BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE);

AbstractHook *g_pHook = nullptr;

BOOL WINAPI HookedCreateProcessInternalW(
	HANDLE hToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	PHANDLE hNewToken)
{
	MessageBoxW(nullptr, lpCommandLine, L"From HookedCreateProcessInternalW", MB_ICONINFORMATION);

	return reinterpret_cast<_CreateProcessInternalW>(g_pHook->getOriginalFunc())(
		hToken,
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation,
		hNewToken
		);
}

// This function is called if the dll is injected using SetWindowsHookEx
// and idHook is WH_CALLWNDPROC.
// It just calls the next hook procedure in the hook chain.
extern "C" __declspec(dllexport)
LRESULT CALLBACK CallWndProc(
	_In_ int    nCode,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
)
{
	return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		try
		{
			// A process is loading the DLL.
			g_pHook = new InlineHook("CreateProcessInternalW", "kernelbase.dll", &HookedCreateProcessInternalW);
		}
		catch (const std::exception& e)
		{
			SharedMemory<char*> sm(DEBUG_SHARED_MEMORY_NAME);
			sm << e.what();
		}
		break;
	case DLL_THREAD_ATTACH:
		// A process is creating a new thread.
		break;
	case DLL_THREAD_DETACH:
		// A thread exits normally.
		break;
	case DLL_PROCESS_DETACH:
		// A process unloads the DLL.
		delete g_pHook;
		break;
	}
	return TRUE;
}
