#ifndef INJECTOR_HOOK_RETRIEVER_HPP
#define INJECTOR_HOOK_RETRIEVER_HPP

#include <portable_executable.hpp>
#include <process_memory.hpp>

#include "framework.hpp"
#include "module.hpp"
#include "misc_code.hpp"
#include "get_function_code.hpp"

namespace Injector
{
	using namespace PECOFF;

	class HookRetriever final
	{
	public:
		static size_t constexpr				ProcNameLength = sizeof(char) * (MaxProcNameLength + 1);
	public:
		ProcessMemory&						Memory;
		Kernel32&									Kernel;
		list<Module>&							Modules;

		size_t										BreakpointOffset;
		size_t const								TotalHookCount;

		VirtualMemoryHandle*				InitFuncNameVmh;
		VirtualMemoryHandle*				FuncNamesVmh;
		VirtualMemoryHandle*				InitFunctionsVmh;
		VirtualMemoryHandle*				HookFunctionsVmh;
		VirtualMemoryHandle*				ProgramVmh;

		PrefixCode									PrxCode;
		vector<GetProcAddressCode>		CodeBlocks;
		PostfixCode								PstxCode;

		HookRetriever(
			ProcessMemory& memory,
			Kernel32& kernel,
			list<Module>& modules);
		~HookRetriever();
		
		Address breakpoint() const;
		Address instruction() const;
	};
}
#endif //INJECTOR_HOOK_RETRIEVER_HPP