#ifndef INJECTOR_TYPEDEFS_HPP
#define INJECTOR_TYPEDEFS_HPP

#include <typedefs.hpp>

#include <string>

using Address							= void*;
using RegistersPtr					= void*;
using cstring							= const char*;

namespace Injector
{
#pragma pack(push, 1)
	struct HandshakeInfo
	{
		int									cbSize;
		int									num_hooks;
		unsigned int					checksum;
		DWORD							exeFilesize;
		DWORD							exeTimestamp;
		unsigned int					exeCRC;
		int									cchMessage;
		char* Message;
	};

	struct HandshakeResult
	{
		bool								Success;
		HRESULT						Code;
		char* Message;
	};

	struct InjectionContext
	{
		cstring			Executable;
		cstring			Arguments;

		size_t			ModuleCount;
		HMODULE*	ModuleHandles;
		cstring			ModuleNames;
		size_t			NameStepLength;
	};
#pragma pack(pop)

	using HookFunction				= DWORD(__cdecl*)(RegistersPtr registers);
	using InitFunction					= DWORD(__cdecl*)(Injector::InjectionContext* pInjectionContext);
	
	using HandshakeFunction		= HRESULT(__cdecl* )(Injector::HandshakeInfo* pHandshakeInfo);
}	

#endif //INJECTOR_TYPEDEFS_HPP