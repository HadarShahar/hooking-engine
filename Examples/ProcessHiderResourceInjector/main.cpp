// Currently the resource is x64 bit dll, so the target process must be x64 as well!!!
#include "../../InjectionLib/AbstractInjector.h"
#include "../../InjectionLib/ManualInjectors/ManualResourceInjector.h"
#include "resource.h"
#include <iostream>
#include <memory>

const std::wstring TARGT_PROCESS_IMAGE{ L"Taskmgr.exe" };

int main()
{
	std::unique_ptr<AbstractInjector> injector;
	try
	{
		injector = std::make_unique<ManualResourceInjector>(TARGT_PROCESS_IMAGE, IDR_RCDATA1);
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