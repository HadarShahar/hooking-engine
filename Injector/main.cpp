#include "../InjectionLib/AbstractInjector.h"
#include "../InjectionLib/LoadLibraryInjector.h"
#include "../InjectionLib/WindowsHookInjector.h"
#include "../InjectionLib/ManualInjectors/AbstractManualInjector.h"
#include "../InjectionLib/ManualInjectors/ManualFileInjector.h"
#include <iostream>
#include <string_view>

constexpr std::wstring_view LOAD_LIBRARY_INJECTOR_FLAG{ L"-ll" };
constexpr std::wstring_view WINDOWS_HOOK_INJECTOR_FLAG{ L"-wh" };
constexpr std::wstring_view MANUAL_FILE_INJECTOR_FLAG { L"-mf" };

void printUsage(wchar_t *programName);
std::unique_ptr<AbstractInjector> createInjector(int argc, wchar_t *argv[]);

int wmain(int argc, wchar_t *argv[])
{
	std::unique_ptr<AbstractInjector> injector;
	try
	{
		injector = createInjector(argc, argv);
		if (!injector)
		{
			printUsage(argv[0]);
			return EXIT_FAILURE;
		}
	}
	catch (const std::runtime_error& e)
	{
		std::cerr << e.what() << '\n';
		return EXIT_FAILURE;
	}

	if (!injector->inject())
	{
		std::cerr << "Error while injecting the dll (error code " << GetLastError() << ").\n";
		return EXIT_FAILURE;
	}

	std::cout << "DLL was injected successfully, press ENTER to eject the dll and exit.\n";
	std::cin.get();

	if (!injector->eject())
	{
		std::cerr << "Error while ejecting the dll (error code " << GetLastError() << ").\n";
		return EXIT_FAILURE;
	}

	std::cout << "DLL was ejected successfully.\n";
	return EXIT_SUCCESS;
}


void printUsage(wchar_t *programName)
{
	std::wcout << "Usage: " << programName << " (injector_type) (dll_path) (PID/process_name)\n\n"
		<< "Injector types:\n"
		<< LOAD_LIBRARY_INJECTOR_FLAG << "\t Load library injector.\n"
		<< WINDOWS_HOOK_INJECTOR_FLAG << "\t Windows hook injector.\n"
		<< MANUAL_FILE_INJECTOR_FLAG << "\t Manual mapping file injector.\n";
}

std::unique_ptr<AbstractInjector> createInjector(int argc, wchar_t *argv[])
{
	if (argc < 3)
	{
		return nullptr;
	}
	auto injectorType = argv[1];
	auto dllPath = argv[2];

	wchar_t *p = nullptr; // will receive the next char after the number.
	DWORD targetPID = std::wcstoul(argv[3], &p, 10); // base 10.
	if (*p)
	{
		// conversion failed because the input wasn't a number => it's the process name.
		targetPID = AbstractInjector::pidof(argv[3]);
	}

	if (injectorType == LOAD_LIBRARY_INJECTOR_FLAG)
	{
		std::cout << "Creating LoadLibraryInjector...\n";
		return std::make_unique<LoadLibraryInjector>(targetPID, dllPath);
	}
	else if (injectorType == WINDOWS_HOOK_INJECTOR_FLAG)
	{
		std::cout << "Creating WindowsHookInjector...\n";
		return std::make_unique<WindowsHookInjector>(targetPID, dllPath);
	}
	else if (injectorType == MANUAL_FILE_INJECTOR_FLAG)
	{
		std::cout << "Creating ManualFileInjector...\n";
		return std::make_unique<ManualFileInjector>(targetPID, dllPath);
	}

	return nullptr;
}
