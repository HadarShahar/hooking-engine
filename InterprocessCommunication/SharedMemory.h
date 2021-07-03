#pragma once
#include "SharedMemoryBase.h"

const std::string DEBUG_SHARED_MEMORY_NAME{ "DEBUG_SHARED_MEMORY" };

// Fixed size shared memory.
template<typename T>
class SharedMemory : public SharedMemoryBase<T>
{
public:
	SharedMemory(const std::string& name)
		: SharedMemoryBase<T>(name, sizeof(T)) {}

	const T& data() const { return *this->m_pRawData; }

	SharedMemory& operator<<(const T& value)
	{
		*this->m_pRawData = value;
		return *this;
	}

	friend std::ostream& operator<<(std::ostream& out, const SharedMemory& sm)
	{
		return out << *sm.m_pRawData;
	}
};


// Dynamic size shared memory for char*.
// The first DWORD in the shared memory is the current size of the data in memory.
template<>
class SharedMemory<char*> : public SharedMemoryBase<char>
{
public:
	SharedMemory(const std::string& name)
		: SharedMemoryBase<char>(name, sizeof(DWORD) + DATA_CAPACITY)
		, m_pSize(reinterpret_cast<DWORD*>(m_pRawData))
		, m_pData(m_pRawData + sizeof(DWORD)) {}

	DWORD size() const { return *m_pSize; }
	const char* data() const { return m_pData; }

	template<typename U>
	SharedMemory& operator<<(U&& value);

	friend std::ostream& operator<<(std::ostream& out, const SharedMemory& sm)
	{
		return out << sm.m_pData;
	}

	void prettyPrint() const
	{
		if (*m_pSize)
		{
			std::cout << "======================================================================\n";
			std::cout << "From shared memory:\n";
			std::cout << m_pData << '\n';
			std::cout << "======================================================================\n";
		}
	}

private:
	DWORD *m_pSize = nullptr;						// Points to the first DWORD in the shared memory.
	char *m_pData = nullptr;						// Points to the char after the first DWORD in the shared memory.
	static constexpr DWORD DATA_CAPACITY = 1024;	// Excluding the first DWORD in the beginning.
};




template<typename U>
SharedMemory<char*>& SharedMemory<char*>::operator<<(U&& value)
{
	std::stringstream os;
	os << std::forward<U>(value);
	const std::string str = os.str();
	if (*m_pSize + str.length() + 1 > DATA_CAPACITY)
	{
		throw std::runtime_error("SharedMemory<char*> has reached its maximum capacity.");
	}
	std::memcpy(m_pData + *m_pSize, str.c_str(), str.length() + 1);
	*m_pSize += str.length();
	return *this;
}
