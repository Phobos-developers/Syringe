#ifndef DEBUGGER_VIRTUAL_MEMORY_HANDLE_HPP
#define DEBUGGER_VIRTUAL_MEMORY_HANDLE_HPP

#include <stdexcept>
#include <string.hpp>

#include "typedefs.hpp"

/*!
* @autor multfinite
* @brief Manage virtual memory allocation in any process.
* @brief Should be used when need to allocate a memory space in different process.
* @brief It wraps WINAPI calls.
*/
class VirtualMemoryHandle final
{
public:
	struct OutOfRangeException		: std::runtime_error 
	{
		VirtualMemoryHandle			const&	Handle;
		void*									const		Where;
		size_t								const		Size;

		OutOfRangeException(VirtualMemoryHandle const& handle, void* pWhere, size_t size)	:
			Handle(handle), Where(pWhere), Size(size),
			std::runtime_error(Utilities::string_format("Out of range while access VMH [address = 0x%x] at 0x%x, count: %u", (DWORD) Handle[0], (DWORD) pWhere, size)) {}
	};
	struct WriteMemoryException		: std::runtime_error
	{
		VirtualMemoryHandle			const&	Handle;
		void*									const		Where;
		size_t								const		Size;
		size_t								const		WrittenSize;
		DWORD								const		LastError;

		WriteMemoryException(VirtualMemoryHandle const& handle, void* pWhere, size_t size, size_t writtenSize)	:
			Handle(handle), Where(pWhere), Size(size), WrittenSize(writtenSize), LastError(GetLastError()),
			std::runtime_error(Utilities::string_format("VMH Write error [address = 0x%x] at 0x%x, count: %u, written: %u", (DWORD) Handle[0], (DWORD) pWhere, size, writtenSize)) {}
	};
	struct ReadMemoryException		: std::runtime_error
	{
		VirtualMemoryHandle			const&	Handle;
		void*									const		Where;
		size_t								const		Size;
		size_t								const		ReaddenSize;
		DWORD								const		LastError;

		ReadMemoryException(VirtualMemoryHandle const& handle, void* pWhere, size_t size, size_t readdenSize)	:
			Handle(handle), Where(pWhere), Size(size), ReaddenSize(readdenSize), LastError(GetLastError()),
			std::runtime_error(Utilities::string_format("VMH Read error [address = 0x%x] at 0x%x, count: %u, readden: %u", (DWORD) Handle[0], (DWORD) pWhere, size, readdenSize)) {}
	};
private:
	LPVOID		_value			{ nullptr };
	HANDLE		_process		{ nullptr };
	SIZE_T		_size				= 0;
	bool			_freeMemory = true;
public:
	VirtualMemoryHandle() noexcept;
	VirtualMemoryHandle(HANDLE process,  SIZE_T size, bool freeMemory = true) noexcept : VirtualMemoryHandle(process, nullptr, size, freeMemory) { }
	VirtualMemoryHandle(HANDLE process, LPVOID address, SIZE_T size, bool freeMemory = true) noexcept
		: _process(process), _freeMemory(freeMemory)
	{
		if (process && size) 
		{
			this->_value = VirtualAllocEx(process, address, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			_size = size;
		}
	}
	VirtualMemoryHandle(LPVOID allocated, SIZE_T size, HANDLE process, bool freeMemory = true) noexcept
		: _value(allocated), _process(process), _size(size), _freeMemory(freeMemory) { }
	
	VirtualMemoryHandle(VirtualMemoryHandle&& other) noexcept :
		_value(std::exchange(other._value, nullptr)),
		_process(std::exchange(other._process, nullptr)),
	    _size(std::exchange(other._size, 0)),
		_freeMemory(other._freeMemory) { }
	VirtualMemoryHandle& operator=(VirtualMemoryHandle&& other) noexcept
	{
		if(this != &other)
		{
			_value = std::exchange(other._value, nullptr);
			_process = std::exchange(other._process, nullptr);
			_size = std::exchange(other._size, 0);
			_freeMemory = other._freeMemory;
		}
		return *this;
	}

	VirtualMemoryHandle(VirtualMemoryHandle const&) = delete;
	VirtualMemoryHandle& operator=(VirtualMemoryHandle& other) = delete;
	
	~VirtualMemoryHandle() noexcept
	{
		if (_freeMemory && this->_value && this->_process)			
			VirtualFreeEx(this->_process, this->_value, 0, MEM_RELEASE);			
	}

	friend bool operator==(VirtualMemoryHandle const& lhs, VirtualMemoryHandle const& rhs)
	{	return (lhs._process == rhs._process) && (lhs._value == rhs._value);	}

	size_t Size() const noexcept { return _size; }
	BYTE* Pointer(size_t offset = 0) const noexcept { return static_cast<BYTE*>(this->_value) + offset; }
	BYTE* operator[](size_t offset) const {  return static_cast<BYTE*>(_value) + offset; }
	
	void Write(void* const data, size_t count, size_t offset = 0) const
	{
		BYTE* dest = operator[](offset);
		BYTE* pLast = dest + count;
	
		BYTE* max = operator[](_size);
		if (max < pLast)
			throw OutOfRangeException { *this, (void*) dest, count };
		SIZE_T writtenCount = 0;
		const bool result = WriteProcessMemory(_process, dest, data, count, &writtenCount) != FALSE;
		if (!result)
			throw WriteMemoryException { *this, (void*) dest, count, writtenCount };
		if (writtenCount != count)
			throw WriteMemoryException { *this, (void*) dest, count, writtenCount };
	}	
	void Read(size_t offset, size_t count, void* const buffer) const
	{
		BYTE* pFirst = operator[](offset);
		BYTE* pLast = pFirst + count;
	
		BYTE* max = operator[](_size);
		if (max < pLast)
			throw OutOfRangeException { *this, (void*) pFirst, count };
	
		SIZE_T readdenBytes;
		const bool result = ReadProcessMemory(_process, pFirst, buffer, count, &readdenBytes) != FALSE;
		if (!result)
			throw ReadMemoryException { *this, (void*) pFirst, count, readdenBytes };
		if (readdenBytes != count)
			throw ReadMemoryException { *this, (void*) pFirst, count, readdenBytes };
	}

	bool IsOwned(Address address) const noexcept
	{
		Address const		min		= _value;
		Address const		max		= reinterpret_cast<BYTE*>(min) + _size;

		return address >= min && address < max;
	}
};

#endif //DEBUGGER_VIRTUAL_MEMORY_HANDLE_HPP
