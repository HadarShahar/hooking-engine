#include "../../HookingLib/AbstractHook.h"
#include "../../HookingLib/InlineHook.h"
#include "../../HookingLib/IATHook.h"
#include <iostream>
#include <stdexcept>
#include <Windows.h>

AbstractHook *g_pHook = nullptr;

int HookedMessageBoxW(
	HWND    hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT    uType
)
{
	return reinterpret_cast<decltype(&HookedMessageBoxW)>
		(g_pHook->getOriginalFunc())(hWnd, L"from HookedMessageBoxW", lpCaption, uType);
}

int main()
{
	MessageBoxW(0, L"from main", L"Test1", MB_ICONINFORMATION);
	try
	{
		g_pHook = new InlineHook("MessageBoxW", "user32.dll", &HookedMessageBoxW);
		//g_pHook = new IATHook("MessageBoxW", "user32.dll", &HookedMessageBoxW);
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << '\n';
		return EXIT_FAILURE;
	}
	MessageBoxW(0, L"from main", L"Test2", MB_ICONINFORMATION);

	delete g_pHook; // Unhook.
	g_pHook = nullptr;
	MessageBoxW(0, L"from main", L"Test3", MB_ICONINFORMATION);
	
	return EXIT_SUCCESS;
}
