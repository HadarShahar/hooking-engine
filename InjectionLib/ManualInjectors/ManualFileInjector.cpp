#include "pch.h"
#include "ManualFileInjector.h"

PBYTE ManualFileInjector::getDllData()
{
	// Open and seek to the end.
	std::ifstream file(m_fullDllPath.value(), std::ios::binary | std::ios::ate);
	if (!file)
	{
		std::cerr << "Could not open the file.\n";
		return nullptr;
	}
	auto fileSize = file.tellg();
	file.seekg(0, std::ios::beg);

	m_fileBuffer.reserve(fileSize);
	file.read(reinterpret_cast<char*>(m_fileBuffer.data()), fileSize);
	return m_fileBuffer.data();
}