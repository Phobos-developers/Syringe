#ifndef INJECTOR_GET_FUNCTION_CODE_HPP
#define INJECTOR_GET_FUNCTION_CODE_HPP

#include <macro.hpp>

#include "framework.hpp"
#include "asm.hpp"

namespace Injector
{
	using PECOFF::GetProcAddressFunction;

	BYTE const GetProcAddressCodeData[] =
	{
		PUSH_INTO_STACK(INIT_PTR), // 0, 1-2-3-4 - pointer to procName,
		PUSH_INTO_STACK(INIT_PTR), // 5, 6-7-8-9 - HMODULE (void*) , i.e. handle.
		CALL_PTR32(INIT_PTR), // 10-11, 12-13-14-15 - pointer to imported in process GetProcAddress function.
		MOV_EAX_TO(INIT_PTR), // 16, 17-18-19-20 - address for FARPROC (void*).
	};
	static constexpr size_t GetProcAddressCodeDataSize = sizeof(GetProcAddressCodeData);	
	#pragma pack(push, 1)
	struct GetProcAddressCode
	{
		BYTE arr1[1] { 0 };
		LPCSTR ProcName = nullptr;
		BYTE arr2[1] { 0 };
		HMODULE Handle = nullptr;
		BYTE arr3[2] { 0, 0 };
		GetProcAddressFunction GetProcAddressFunc;
		BYTE arr4[1] { 0 };
		FARPROC* RefFunctionPointer;
		//BYTE arr5[2] { 0, 0 };

		GetProcAddressCode() noexcept = default;
		GetProcAddressCode(
			LPCSTR procName, HMODULE handle, 
			GetProcAddressFunction gpaFunction,
			FARPROC* refFunctionPointer)
		{
			memcpy(this, &GetProcAddressCodeData, GetProcAddressCodeDataSize);
			ProcName = procName;
			Handle = handle;
			GetProcAddressFunc = gpaFunction;
			RefFunctionPointer = refFunctionPointer;
		}
	};
	static constexpr size_t GetProcAddressCodeSize = sizeof(GetProcAddressCode);
	#pragma pack(pop)
	static_assert(GetProcAddressCodeDataSize == GetProcAddressCodeSize, "The code and data are not equals");
	
	struct ProcNameOutOfRangeException : std::exception {};
	
	class GetFunctionCodeHandle final
	{		
		ProcessMemory& _processMemory;
	
		size_t _procNameLength = 0;
		CHAR* _procNameBuffer = new CHAR[MaxProcNameLength + 1];
		VirtualMemoryHandle& _procNameMemoryHandle;
	
		FARPROC _funcBuffer { nullptr };
		VirtualMemoryHandle& _funcMemoryHandle;
	
		GetProcAddressCode _code;
		VirtualMemoryHandle& _codeMemoryHandle;	
	
	public:
		GetFunctionCodeHandle(
			GetProcAddressFunction getProcAddressFunction, 
			ProcessMemory& processMemory) :
				_processMemory(processMemory),
				_procNameMemoryHandle(processMemory.Allocate(MaxLibraryNameLength + 1)),
				_funcMemoryHandle(processMemory.Allocate(sizeof(FARPROC))),
				_codeMemoryHandle(processMemory.Allocate(GetProcAddressCodeDataSize)),
				_code()
		{			
			memcpy(&_code, GetProcAddressCodeData, GetProcAddressCodeDataSize);

			_code.ProcName = reinterpret_cast<cstring>(_procNameMemoryHandle.Pointer());
			_code.GetProcAddressFunc = getProcAddressFunction;
			_code.RefFunctionPointer = reinterpret_cast<FARPROC*>(_funcMemoryHandle.Pointer());
	
			_codeMemoryHandle.Write(&_code, GetProcAddressCodeDataSize, 0);
		}
		~GetFunctionCodeHandle()
		{
			_procNameLength = 0;
	
			delete[] _procNameBuffer;
	
			_processMemory.Free(_codeMemoryHandle);
			_processMemory.Free(_procNameMemoryHandle);
		}
	
		void SetProcName(string_view const& procName)
		{
			if (procName.size() > MaxLibraryNameLength)
				throw ProcNameOutOfRangeException();
			
			_procNameMemoryHandle.Write(const_cast<char*>(procName.data()), procName.size() + 1, 0);
	
			_procNameLength = procName.size();
		}
		string_view const& ProcName() const
		{
			if (_procNameLength == 0)
				return nullptr;
	
			_procNameMemoryHandle.Read(0, _procNameLength + 1, _procNameBuffer);
			return _procNameBuffer;
		}
	
		void SetHandle(HMODULE handle)
		{
			_code.Handle = handle;
			_codeMemoryHandle.Write(&_code, GetProcAddressCodeDataSize, 0);
		}	
		HMODULE Handle() const	{	return _code.Handle;	}
	
		FARPROC Function() const
		{	
			_funcMemoryHandle.Read(0, sizeof(FARPROC), const_cast<FARPROC*>(&_funcBuffer));
			return _funcBuffer;
		}	
	
		Address Instruction() const { return _codeMemoryHandle.Pointer(); }
	};	
}
#endif //INJECTOR_GET_FUNCTION_CODE_HPP