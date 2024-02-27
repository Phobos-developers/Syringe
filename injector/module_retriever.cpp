#include "module_retriever.hpp"

namespace Injector
{
	inline Address write_string(string str, VirtualMemoryHandle& vmh, size_t index)
	{
		vmh.Write(const_cast<char*>(str.c_str()), str.size() + 1, ModuleRetriever::LibraryNameLength * index);
		return vmh.Pointer(ModuleRetriever::LibraryNameLength * index);
	}

	ModuleRetriever::ModuleRetriever(
		ProcessMemory& memory,
		Kernel32& kernel,
		list<Module>& modules)	:
			Memory(memory), Kernel(kernel),
			Modules(modules)
	{		
		LoadLibraryFunction llFunc = reinterpret_cast<LoadLibraryFunction>(reinterpret_cast<BYTE*>(Kernel.LoadLibraryFunc));
		//LoadLibraryFunction llFunc = reinterpret_cast<LoadLibraryFunction>(reinterpret_cast<BYTE*>(Kernel.LoadLibraryFunc) + imageOffset);
		
		LibNamesVmh = &Memory.Allocate(LibraryNameLength * Modules.size());
		ModuleHandlesVmh = &Memory.Allocate(sizeof(HMODULE) * Modules.size());
		
		CodeBlocks.reserve(Modules.size());
		
		for (size_t index = 0; index < Modules.size(); ++index)
		{				
			Module& mdl = *std::next(Modules.begin(), index);
			
			size_t const libNameOffset = index * LibraryNameLength;
			write_string(mdl.FileName, *LibNamesVmh, index);

			Address const refLibName = LibNamesVmh->Pointer(libNameOffset);			
			Address const refModuleHandle = ModuleHandlesVmh->Pointer(index * sizeof(HMODULE));

			LoadLibraryCode& block = CodeBlocks.emplace_back(
				static_cast<LPCSTR>(refLibName), 
				llFunc, 
				static_cast<HMODULE*>(refModuleHandle));
		}

		size_t const codeSize = CodeBlocks.size() * sizeof(LoadLibraryCode);
		size_t const base = PrefixCodeSize + codeSize;
		size_t const programSize = base + PostfixCodeSize;

		BreakpointOffset = base + 2;

		ProgramVmh = &Memory.Allocate(programSize);
		ProgramVmh->Write(&PrxCode, PrefixCodeSize, 0);
		ProgramVmh->Write(CodeBlocks.data(), codeSize, PrefixCodeSize);
		ProgramVmh->Write(&PstxCode, PostfixCodeSize, base);
	}
	ModuleRetriever::~ModuleRetriever()
	{
		BreakpointOffset = 0;

		Memory.Free(*ProgramVmh);
		Memory.Free(*ModuleHandlesVmh);
		Memory.Free(*LibNamesVmh);
	}

	Address ModuleRetriever::breakpoint() const { return ProgramVmh->Pointer(BreakpointOffset); }
	Address ModuleRetriever::instruction() const { return ProgramVmh->Pointer(); }
}