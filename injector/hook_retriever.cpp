#include "hook_retriever.hpp"

namespace Injector
{
	inline size_t calculate_total_hook_count(list<Module> const& modules)
	{
		size_t total = 0;
		for (auto& mdl : modules)
			total += mdl.Hooks.size();
		return total;
	}
	inline Address write_string(string str, VirtualMemoryHandle& vmh, size_t index)
	{
		vmh.Write(const_cast<char*>(str.c_str()), str.size() + 1, HookRetriever::ProcNameLength * index);
		return vmh.Pointer(HookRetriever::ProcNameLength * index);
	}

	HookRetriever::HookRetriever(
		ProcessMemory& memory,
		Kernel32& kernel,
		list<Module>& modules)	:
			Memory(memory), Kernel(kernel),
			Modules(modules),
			TotalHookCount(calculate_total_hook_count(modules))
	{
		InitFuncNameVmh							= &Memory.Allocate(ProcNameLength);
		InitFunctionsVmh							= &Memory.Allocate(sizeof(FARPROC) * Modules.size());
		Address const initFunctionName		= write_string(InitializerFunctionName, *InitFuncNameVmh, 0);

		FuncNamesVmh								= &Memory.Allocate(ProcNameLength * TotalHookCount);
		HookFunctionsVmh							= &Memory.Allocate(sizeof(FARPROC) * TotalHookCount);
		
		CodeBlocks.reserve(TotalHookCount + Modules.size());				
		
		size_t thkIndex = 0;
		for (size_t index = 0; index < Modules.size(); ++index)
		{				
			Module&		mdl						= *std::next(Modules.begin(), index);
			HMODULE		handle					= mdl.get_handle();

			Address const refInitFunction		= InitFunctionsVmh->Pointer(index * sizeof(FARPROC));
			CodeBlocks.emplace_back((LPCSTR) initFunctionName, handle, Kernel.GetProcAddressFunc, (FARPROC*)refInitFunction);

			for (auto& hook : mdl.Hooks)
			{
				Address const funcName = write_string(hook.FunctionName, *FuncNamesVmh, thkIndex);
				Address const refHookFunction = HookFunctionsVmh->Pointer(thkIndex++ * sizeof(FARPROC));

				CodeBlocks.emplace_back((LPCSTR) funcName, handle, Kernel.GetProcAddressFunc, (FARPROC*) refHookFunction);
			}
		}
		
		size_t const codeSize = CodeBlocks.size() * sizeof(GetProcAddressCode);
		size_t const base = PrefixCodeSize + codeSize;
		size_t const programSize = base + PostfixCodeSize;

		BreakpointOffset = base + 2;

		ProgramVmh = &Memory.Allocate(programSize);
		ProgramVmh->Write(&PrxCode, PrefixCodeSize, 0);
		ProgramVmh->Write(CodeBlocks.data(), codeSize, PrefixCodeSize);
		ProgramVmh->Write(&PstxCode, PostfixCodeSize, base);
	}
	HookRetriever::~HookRetriever()
	{
		Memory.Free(*InitFuncNameVmh);
		Memory.Free(*FuncNamesVmh);
		Memory.Free(*InitFunctionsVmh);
		Memory.Free(*HookFunctionsVmh);
		Memory.Free(*ProgramVmh);
	}
	
	Address HookRetriever::breakpoint() const { return ProgramVmh->Pointer(BreakpointOffset); }
	Address HookRetriever::instruction() const { return ProgramVmh->Pointer(); }
}