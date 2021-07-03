#include "pch.h"
#include "WindowsHookInjector.h"

bool WindowsHookInjector::inject()
{
    HMODULE hModule = LoadLibraryW(m_fullDllPath.value().c_str());
    if (!hModule)
    {
        return false;
    }

    HOOKPROC pfn = reinterpret_cast<HOOKPROC>(GetProcAddress(hModule, "CallWndProc"));
    if (!pfn)
    {
        std::cerr << "The function CallWndProc was not found in the dll.\n";
        return false;
    }

    // Only used to inject a DLL into the process.
    m_hHook = SetWindowsHookEx(WH_CALLWNDPROC, pfn, hModule, this->getAnyRemoteThreadID());
    m_dbgSharedMemory.prettyPrint();
    m_dbgSharedMemory.clear();
    if (!m_hHook)
    {
        std::cerr << "SetWindowsHookEx failed.\n";
        return false;
    }
    return true;
}

bool WindowsHookInjector::eject()
{
    return UnhookWindowsHookEx(m_hHook);
}