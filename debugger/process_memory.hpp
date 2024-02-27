#ifndef DEBUGGER_PROCESS_MEMORY_HPP
#define DEBUGGER_PROCESS_MEMORY_HPP

#include <list>

#include "virtual_memory_handle.hpp"

/*!
* @autor multfinite
* @brief First, it provides functions to read\\write\\allocate\\free memory of process.
* @brief Second, it is container of VirtualMemoryHandle instances.
* @brief Used by Debugger to manipulate memory of debugged process.
* @brief It wraps WINAPI calls.
* @brief Should be used when needs to access memory of different process.
*/
class ProcessMemory final
{
private:
	HANDLE _process { nullptr };
	bool _freeMemory = true;
	
public:
	std::list<VirtualMemoryHandle> MemoryHandles;
	
	ProcessMemory() noexcept = default;
	ProcessMemory(HANDLE process, bool freeMemory = true) : _process(process), _freeMemory(freeMemory) { }
	~ProcessMemory() = default;

	ProcessMemory(ProcessMemory& other) = delete;
	ProcessMemory& operator=(ProcessMemory& other) = delete;
	
	ProcessMemory(ProcessMemory&& other) noexcept :
		_process(std::exchange(other._process, nullptr)),
		MemoryHandles(std::exchange(other.MemoryHandles, {})) { }
	ProcessMemory& operator=(ProcessMemory&& other) noexcept
	{
		_process = std::exchange(other._process, nullptr);
		MemoryHandles = std::exchange(other.MemoryHandles, {});
		return  *this;
	}

	bool Read(void const* address, void* buffer, DWORD size) { return (ReadProcessMemory(_process, address, buffer, size, nullptr) != FALSE); }
	bool ReadSingleByte(Address address, BYTE* returnValue)
	{
		SIZE_T sz = 0;
		bool const result = ReadProcessMemory(_process, address, returnValue, sizeof(BYTE), &sz);
		return result;
	}
	bool Write(void* address, void const* buffer, DWORD size) { return (WriteProcessMemory(_process, address, buffer, size, nullptr) != FALSE); }
	
	VirtualMemoryHandle& Allocate(size_t size)
	{
		return MemoryHandles.emplace_back(_process, size, _freeMemory);
	}
	VirtualMemoryHandle& Allocate(BYTE* pData, size_t size)
	{
		auto& vmh = MemoryHandles.emplace_back(_process, size, _freeMemory);
		vmh.Write(pData, size, 0);
		return vmh;
	}
	template<typename TInput>
	VirtualMemoryHandle& Allocate(TInput& val)
	{
		size_t const size = sizeof(TInput);
		auto& vmh = MemoryHandles.emplace_back(_process, size, _freeMemory);
		vmh.Write(&val, size, 0);
		return vmh;
	}
	
	bool Free(VirtualMemoryHandle& handle)
	{
		std::list<VirtualMemoryHandle>::iterator iterator = std::find(MemoryHandles.begin(), MemoryHandles.end(), handle);
		const bool contains = iterator != MemoryHandles.end();
		if (contains)			
			MemoryHandles.erase(iterator);			
		return contains;
	}	

	bool IsVirtualAddress(Address address) const noexcept
	{
		for (VirtualMemoryHandle const& mh : MemoryHandles)			
			if (mh.IsOwned(address))
				return true;			
		return false;
	}
};
#endif //DEBUGGER_PROCESS_MEMORY_HPP