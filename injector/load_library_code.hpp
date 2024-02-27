#ifndef INJECTOR_LOAD_LIBRARY_CODE_HPP
#define INJECTOR_LOAD_LIBRARY_CODE_HPP

#include <macro.hpp>

#include "framework.hpp"
#include "asm.hpp"

namespace Injector
{	
	using PECOFF::LoadLibraryFunction;

	struct library_name_out_of_range_error : std::exception {};	
	
	BYTE const LoadLibraryCodeData[] =
	{
		PUSH_INTO_STACK(INIT_PTR), // 0, 1-2-3-4 - pointer to libname, 
		CALL_PTR32(INIT_PTR), // 5-6, 7-8-9-10 - pointer to imported in process LoadLibraryA function.
		MOV_EAX_TO(INIT_PTR), // 11, 12-13-14-15 - address for handle. It is return value of the function.
	};
	static constexpr size_t LoadLibraryCodeDataSize = sizeof(LoadLibraryCodeData);
	#pragma pack(push, 1)
	struct LoadLibraryCode
	{
		BYTE arr1[1] { 0 };
		LPCSTR LibraryFileName { nullptr };
		BYTE arr2[2] { 0, 0 };
		LoadLibraryFunction LoadLibraryA { nullptr };
		BYTE arr3[1] { 0 };
		HMODULE* RefHandlePointer { nullptr };
		//BYTE arr4[1] { 0 };

		LoadLibraryCode() noexcept = default;
		LoadLibraryCode(
			LPCSTR libFileName,
			LoadLibraryFunction loadLibraryFunction,
			HMODULE* refHandlePointer)
		{
			memcpy(this, &LoadLibraryCodeData, LoadLibraryCodeDataSize);
			LibraryFileName = libFileName;
			LoadLibraryA = loadLibraryFunction;
			RefHandlePointer = refHandlePointer;
		}
	};
	static constexpr size_t LoadLibraryCodeSize = sizeof(LoadLibraryCode);
	#pragma pack(pop)
	static_assert(LoadLibraryCodeDataSize == LoadLibraryCodeSize, "The code and data are not equals");
	
	class LoadLibraryCodeHandle final
	{		
		ProcessMemory& _processMemory;
	
		size_t _libraryNameLength = 0;
		CHAR* _libraryNameBuffer = new CHAR[MaxLibraryNameLength + 1];
		VirtualMemoryHandle& _libraryNameMemoryHandle;

		HMODULE _handleBuffer = nullptr;
		VirtualMemoryHandle& _handleMemoryHandle;

		LoadLibraryCode _code;
		VirtualMemoryHandle& _codeMemoryHandle;	

	public:
		LoadLibraryCodeHandle(
			LoadLibraryFunction loadLibFunction, 
			ProcessMemory& processMemory) :
				_processMemory(processMemory),
				_libraryNameMemoryHandle(processMemory.Allocate(MaxLibraryNameLength + 1)),
				_handleMemoryHandle(processMemory.Allocate(sizeof(HMODULE))),
				_codeMemoryHandle(processMemory.Allocate(LoadLibraryCodeDataSize))
		{			
			memcpy(&_code, LoadLibraryCodeData, LoadLibraryCodeDataSize);

			_code.LoadLibraryA = loadLibFunction;
			_code.LibraryFileName = reinterpret_cast<LPCSTR>(_libraryNameMemoryHandle.Pointer());
			_code.RefHandlePointer = reinterpret_cast<HMODULE*>(_handleMemoryHandle.Pointer());

			_codeMemoryHandle.Write(&_code, LoadLibraryCodeDataSize, 0);
		}
		~LoadLibraryCodeHandle()
		{
			_handleBuffer = nullptr;
			_libraryNameLength = 0;

			delete[] _libraryNameBuffer;

			_processMemory.Free(_codeMemoryHandle);
			_processMemory.Free(_handleMemoryHandle);
			_processMemory.Free(_libraryNameMemoryHandle);
		}

		void SetLibraryName(string_view const& libraryName)
		{
			if (libraryName.size() > MaxLibraryNameLength)
				throw library_name_out_of_range_error();
			
			_libraryNameMemoryHandle.Write(const_cast<char*>(libraryName.data()), libraryName.size() + 1, 0);

			_libraryNameLength = libraryName.size();
		}
		string_view const& LibraryName() const
		{
			if (_libraryNameLength == 0)
				return nullptr;

			_libraryNameMemoryHandle.Read(0, _libraryNameLength + 1, _libraryNameBuffer);
			return _libraryNameBuffer;
		}

		HMODULE Handle() const
		{ 
			_handleMemoryHandle.Read(0, sizeof(HMODULE), const_cast<HMODULE*>(&_handleBuffer));

			return _handleBuffer;
		}

		Address Instruction() const { return _codeMemoryHandle.Pointer(); }
	};
}
#endif //INJECTOR_LOAD_LIBRARY_CODE_HPP