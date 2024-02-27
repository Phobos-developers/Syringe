#ifndef INJECTOR_MODULE_RETRIEVER_HPP
#define INJECTOR_MODULE_RETRIEVER_HPP

#include <portable_executable.hpp>
#include <process_memory.hpp>

#include "framework.hpp"
#include "module.hpp"
#include "misc_code.hpp"
#include "load_library_code.hpp"

namespace Injector
{
	using namespace PECOFF;

	class ModuleRetriever final
	{
	public:
		static size_t constexpr LibraryNameLength = sizeof(char) * (MaxLibraryNameLength + 1);

	public:
		ProcessMemory&				Memory;
		Kernel32&							Kernel;
		list<Module>&					Modules;

		VirtualMemoryHandle*		LibNamesVmh;
		VirtualMemoryHandle*		ModuleHandlesVmh;
		VirtualMemoryHandle*		ProgramVmh;

		PrefixCode							PrxCode;
		vector<LoadLibraryCode>	CodeBlocks;
		PostfixCode						PstxCode;

		size_t								BreakpointOffset;
		
		ModuleRetriever(
			ProcessMemory& memory,
			Kernel32& kernel,
			list<Module>& modules);
		~ModuleRetriever();

		Address breakpoint() const;
		Address instruction() const;
	};
}
#endif //INJECTOR_MODULE_RETRIEVER_HPP