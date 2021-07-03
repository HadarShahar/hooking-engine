#include "pch.h"
#include "AbstractInjector.h"

AbstractInjector::AbstractInjector(DWORD targetPID, const std::optional<std::wstring>& dllPath)
	: m_targetPID(targetPID)
	, m_dbgSharedMemory(DEBUG_SHARED_MEMORY_NAME)
{
	//// Enable DEBUG privilege
	//if (!EnablePrivilege())
	//{
	//	throw std::runtime_error("Could not enable SeDebugPrivilege	privilege.");
	//}

	auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetPID);
	if (!hProcess)
	{
		switch (GetLastError())
		{
		case ERROR_ACCESS_DENIED:
			throw std::runtime_error("Could not get a handle to the process, access is denied.");
		case ERROR_INVALID_PARAMETER:
			throw std::runtime_error("Cound not find the process.");;
		default:
			throw std::runtime_error("Could not get a handle to the process.");
		}
	}
	m_hProcess = hProcess;

	if (dllPath)
	{
		setDllPath(dllPath.value());
	}
}

AbstractInjector::AbstractInjector(const std::wstring& processImage, const std::optional<std::wstring>& dllPath)
	: AbstractInjector(pidof(processImage), dllPath)
{}

AbstractInjector::AbstractInjector(AbstractInjector&& other) noexcept
	: m_targetPID(std::exchange(other.m_targetPID, 0))
	, m_hProcess(std::exchange(other.m_hProcess, nullptr))
	, m_fullDllPath(std::move(other.m_fullDllPath))
	, m_dbgSharedMemory(std::move(other.m_dbgSharedMemory))
{}

AbstractInjector& AbstractInjector::operator=(AbstractInjector&& other) noexcept
{
	if (this == &other) return *this;
	
	if (m_hProcess)
	{
		CloseHandle(m_hProcess);
	}
	m_targetPID = std::exchange(other.m_targetPID, 0);
	m_hProcess = std::exchange(other.m_hProcess, nullptr);
	m_fullDllPath = std::move(other.m_fullDllPath);
	m_dbgSharedMemory = std::move(other.m_dbgSharedMemory);
	return *this;
}

AbstractInjector::~AbstractInjector()
{
	if (m_hProcess)
	{
		CloseHandle(m_hProcess);
	}
}

void AbstractInjector::setDllPath(const std::wstring& dllPath)
{
	validateDll(dllPath); // throws exception if it's invalid.
	m_fullDllPath = std::filesystem::absolute(dllPath).native();
}

void AbstractInjector::validateDll(const std::wstring& dllPath) const
{
	DWORD dwAttrib = GetFileAttributesW(dllPath.c_str());
	if (dwAttrib == INVALID_FILE_ATTRIBUTES || dwAttrib & FILE_ATTRIBUTE_DIRECTORY)
	{
		throw std::runtime_error("The file doesn't exist.");
	}

	std::ifstream file(dllPath, std::ios::binary);
	if (!file)
	{
		throw std::runtime_error("Could not open the file.");
	}

	IMAGE_DOS_HEADER dosHeader;
	file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));
	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		throw std::runtime_error("The file is not a PE.");
	}
	file.seekg(dosHeader.e_lfanew, std::ios::beg);

	// Read the Signature + File header.
	constexpr auto initialSize = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	std::vector<BYTE> NtHeaders(initialSize);
	file.read(reinterpret_cast<char*>(NtHeaders.data()), initialSize);

	// Read the optional header.
	auto optionalHeaderSize = reinterpret_cast<PIMAGE_FILE_HEADER>(
		NtHeaders.data() + sizeof(DWORD))->SizeOfOptionalHeader;
	NtHeaders.reserve(initialSize + optionalHeaderSize);
	file.read(reinterpret_cast<char*>(NtHeaders.data() + initialSize), optionalHeaderSize);

	auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(NtHeaders.data());
	validatePlatforms(pNtHeaders);
}

void AbstractInjector::validatePlatforms(PIMAGE_NT_HEADERS pNtHeaders) const
{
	bool dllIsX86 = pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
	bool processIsX86 = isTargetProcessX86();
	auto getArchName = [](bool isX86) { return isX86 ? "32-bit" : "64-bit"; };
	if (dllIsX86 != processIsX86)
	{
		std::stringstream os;
		os << "Platforms don't match. The dll is " << getArchName(dllIsX86)
			<< " and the target process is " << getArchName(processIsX86) << '.';
		throw std::runtime_error(os.str());
	}
}

bool AbstractInjector::isTargetProcessX86() const
{
	SYSTEM_INFO systemInfo{ 0 };
	GetNativeSystemInfo(&systemInfo);

	// x86 OS
	if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
	{
		return true;
	}

	BOOL isWow64 = FALSE;
	// If IsWow64Process() set isWow64 to true, the process is 32-bit running on a 64-bit OS.
	if (!IsWow64Process(m_hProcess, &isWow64))
	{
		throw std::runtime_error("IsWow64Process() failed.");
	}
	return isWow64;
}


bool AbstractInjector::writeMemory(LPVOID pRemoteAddr, LPCVOID pLocalData, SIZE_T dataSize) const
{
	SIZE_T bytesWritten{};
	auto success = WriteProcessMemory(m_hProcess, pRemoteAddr, pLocalData, dataSize, &bytesWritten);
	if (!success || bytesWritten != dataSize)
	{
		std::cerr << "WriteProcessMemory failed.\n";
		return false;
	}
	return true;
}

LPVOID AbstractInjector::injectData(LPCVOID pLocalData, SIZE_T dataSize, DWORD memProtect) const
{
	LPVOID pRemoteAddr = VirtualAllocEx(
		m_hProcess,
		nullptr,
		dataSize,
		MEM_COMMIT | MEM_RESERVE,
		memProtect
	);
	if (!pRemoteAddr)
	{
		std::cerr << "VirtualAllocEx failed.\n";
		return nullptr;
	}
	if (!writeMemory(pRemoteAddr, pLocalData, dataSize))
	{
		VirtualFreeEx(m_hProcess, pRemoteAddr, 0, MEM_RELEASE);
		return nullptr;
	}
	return pRemoteAddr;
}

bool AbstractInjector::runRemoteThread(LPVOID pThreadFunc, LPVOID pThreadParam)
{
	HANDLE hThread = CreateRemoteThread(
		m_hProcess,
		nullptr,
		0,
		static_cast<LPTHREAD_START_ROUTINE>(pThreadFunc),
		pThreadParam,
		0,
		nullptr);
	if (!hThread)
	{
		std::cerr << "CreateRemoteThread failed.\n";
		return false;
	}
	WaitForSingleObject(hThread, INFINITE);

	DWORD threadExitCode{};
	if (!GetExitCodeThread(hThread, &threadExitCode))
	{
		std::cerr << "GetExitCodeThread failed.\n";
		return false;
	}
	CloseHandle(hThread);
	
	m_dbgSharedMemory.prettyPrint();
	m_dbgSharedMemory.clear();

	std::cout << "Remote thread exit code: 0x" << std::hex << threadExitCode << '\n';
	// When it fails, my function returns false (=0), and LoadLibraryA returns NULL.
	if (!threadExitCode)
	{
		std::cerr << "Remote thread failed.\n";
		return false;
	}
	return true; 	// TODO: better exit code checking.

	//// Macro from Ntdef.h
	//// #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
	////if (static_cast<NTSTATUS>(threadExitCode) >= 0)
	//if (static_cast<NTSTATUS>(threadExitCode) > 0) 
	//{
	//	return true;
	//}
	//return false;
}

DWORD AbstractInjector::pidof(const std::wstring& processImage)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	DWORD pid{};
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 pe32{};
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnapshot, &pe32))
		{
			do {
				if (processImage == pe32.szExeFile)
				{
					pid = pe32.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnapshot, &pe32));
		}
		CloseHandle(hSnapshot);
	}
	if (!pid)
	{
		throw std::runtime_error("Cound not find the process.");
	}
	return pid;
}

DWORD AbstractInjector::getAnyRemoteThreadID() const
{
	// when the first param is TH32CS_SNAPTHREAD, the second param is ignored
	HANDLE hSsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	DWORD remoteThreadID{};
	if (hSsnapshot != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te32{};
		te32.dwSize = sizeof(THREADENTRY32);
		if (Thread32First(hSsnapshot, &te32))
		{
			do {
				if (m_targetPID == te32.th32OwnerProcessID)
				{
					remoteThreadID = te32.th32ThreadID;
					break;
				}
			} while (Thread32Next(hSsnapshot, &te32));
			remoteThreadID = te32.th32ThreadID;
		}
		CloseHandle(hSsnapshot);
	}
	return remoteThreadID;
}



//// THREAD EXECUTION HIJACKING (A.K.A SUSPEND, INJECT, AND RESUME (SIR))
//bool hijackRemoteThread(PVOID pThreadFunc, PVOID pThreadParam)
//{
//	auto remoteThreadID = getAnyRemoteThreadID(m_targetPID);
//	auto hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, remoteThreadID);
//	if (!hThread)
//	{
//		std::cerr << "OpenThread failed.\n";
//		return false;
//	}
//
//	SuspendThread(hThread);
//	CONTEXT context{ 0 };
//	context.ContextFlags = CONTEXT_ALL;
//	GetThreadContext(hThread, &context);
//
//	// change its instruction pointer to the thread function
//	context.Rip = reinterpret_cast<ULONG_PTR>(pThreadFunc);
//
//	// pass the parameter to the thread function according to the x64 calling convention
//	// https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-160#parameter-passing
//	context.Rcx = reinterpret_cast<ULONG_PTR>(pThreadParam);
//
//	// TODO check if it's in the middle of a syscall
//
//	BOOL success = SetThreadContext(hThread, &context);
//	int suspendCount = ResumeThread(hThread);
//	return true;
//}