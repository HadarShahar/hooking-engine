#pragma once
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <utility>
#include <Windows.h>

template<typename T>
class SharedMemoryBase
{
protected:
	SharedMemoryBase(const std::string& name, DWORD capacity);

public:
	SharedMemoryBase(const SharedMemoryBase&) = delete;
	SharedMemoryBase& operator=(const SharedMemoryBase&) = delete;

	SharedMemoryBase(SharedMemoryBase&& other) noexcept;
	SharedMemoryBase& operator=(SharedMemoryBase&& other) noexcept;

	virtual ~SharedMemoryBase();

	void clear() { std::memset(m_pRawData, 0, m_capacity); }

protected:
	std::string m_name;
	DWORD m_capacity{ 0 };

	HANDLE m_hMapFile = nullptr;
	T *m_pRawData = nullptr;
};



template<typename T>
SharedMemoryBase<T>::SharedMemoryBase(const std::string& name, DWORD capacity)
	: m_name(name), m_capacity(capacity)
{
	// If the object exists before the function call, the function returns 
	// a handle to the existing object(with its current size, not the specified size).
	m_hMapFile = CreateFileMappingA(
		INVALID_HANDLE_VALUE,			// use paging file
		nullptr,						// default security
		PAGE_READWRITE,					// read/write access
		0,								// maximum object size (high-order DWORD)
		m_capacity,						// maximum object size (low-order DWORD)
		name.c_str());					// name of mapping object
	if (!m_hMapFile)
	{
		throw std::runtime_error("Could not create file mapping object.");
	}

	// The initial contents of the pages in a file mapping object backed by the paging file are 0.
	m_pRawData = reinterpret_cast<T*>(MapViewOfFile(m_hMapFile,
		FILE_MAP_ALL_ACCESS, // read/write permission
		0,
		0,
		m_capacity));
	if (!m_pRawData)
	{
		throw std::runtime_error("Could not map view of file.");
	}
}

template<typename T>
SharedMemoryBase<T>::~SharedMemoryBase()
{
	if (m_pRawData)
	{
		UnmapViewOfFile(m_pRawData);
	}
	if (m_hMapFile)
	{
		CloseHandle(m_hMapFile);
	}
}

template<typename T>
SharedMemoryBase<T>::SharedMemoryBase(SharedMemoryBase<T>&& other) noexcept
	: m_name(std::move(other.m_name))
	, m_capacity(std::exchange(other.m_capacity, 0))
	, m_hMapFile(std::exchange(other.m_hMapFile, nullptr))
	, m_pRawData(std::exchange(other.m_pRawData, nullptr))
{}

template<typename T>
SharedMemoryBase<T>& SharedMemoryBase<T>::operator=(SharedMemoryBase<T>&& other) noexcept
{
	if (this == &other) return *this;

	if (m_pRawData)
	{
		UnmapViewOfFile(m_pRawData);
	}
	if (m_hMapFile)
	{
		CloseHandle(m_hMapFile);
	}

	m_name = std::move(other.m_name);
	m_capacity = std::exchange(other.m_capacity, 0);
	m_hMapFile = std::exchange(other.m_hMapFile, nullptr);
	m_pRawData = std::exchange(other.m_pRawData, nullptr);
	return *this;
}



//template<typename T>
//void SharedMemoryBase<T>::reserve(DWORD newCapacity)
//{
//	if (newCapacity > m_capacity)
//	{
//		SharedMemoryBase<T> sm(m_name, newCapacity);
//		std::memcpy(sm.m_pRawData, m_pRawData, m_capacity);
//		swap(*this, sm);
//	}
//}

//friend void swap(SharedMemoryBase& first, SharedMemoryBase& second)
//{
//	using std::swap;
//	swap(first.m_name, second.m_name);
//	swap(first.m_capacity, second.m_capacity);
//	swap(first.m_hMapFile, second.m_hMapFile);
//	swap(first.m_pRawData, second.m_pRawData);
//}