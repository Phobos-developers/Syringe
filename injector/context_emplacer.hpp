#ifndef INJECTOR_CONTEXT_EMPLACER_HPP
#define INJECTOR_CONTEXT_EMPLACER_HPP

#include <macro.hpp>

#include <process_memory.hpp>
#include <dll_info.hpp>

#include "framework.hpp"
#include "asm.hpp"

namespace Injector
{
	class ContextEmplacer final
	{
	private:
	public:
		DllMap&											Dlls;

		string_view const&							ExecutableName;
		string_view const&							Arguments;

		string											SharedMemoryName;
		HANDLE											SharedMemory { nullptr };
		BYTE*											SharedMemoryPointer { nullptr };

		size_t*											DataSize;
		size_t*											ExecutableNameSize;
		char*											ExecutableNameInStruct;
		size_t*											ArgumentsSize;
		char*											ArgumentsInStruct;
		size_t*											NameLength;
		size_t*											ModuleSize;
		HMODULE*									Handles;
		char*											Names;
		
		ContextEmplacer(
			string_view const& executableName,
			string_view const& arguments,
			string_view const& mapFileName,
			map<LPVOID, DllInfo>& dlls);
		~ContextEmplacer();
	};
}
#endif //INJECTOR_CONTEXT_EMPLACER_HPP