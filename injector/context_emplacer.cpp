#include "context_emplacer.hpp"

namespace Injector
{
	ContextEmplacer::ContextEmplacer(
		string_view const& executableName,
		string_view const& arguments,
		string_view const& mapFileName,
		map<LPVOID, DllInfo>& dlls)	:
			Dlls(dlls),
			ExecutableName(executableName),
			Arguments(arguments),
			SharedMemoryName(mapFileName)
	{						
		size_t maxNameLength = 0;
		for (auto& pair : Dlls)
		{
			HMODULE const handle = static_cast<HMODULE>(pair.second.Base);				
			string_view const& fn = pair.second.FileName;
			maxNameLength = fn.length() > maxNameLength ? fn.length() : maxNameLength;					
		}
		
		size_t const handlesSize = sizeof(HMODULE) * Dlls.size();
		size_t const namesSize = sizeof(BYTE) * Dlls.size() * (maxNameLength + 1);
		size_t const totalSize = 
				sizeof(size_t)
			+ sizeof(size_t)
			+ ExecutableName.size() + 1
			+ sizeof(size_t)
			+ Arguments.size() + 1
			+ sizeof(size_t)
			+ sizeof(size_t)
			+ handlesSize
			+ namesSize;

		SharedMemory = CreateFileMapping(
			INVALID_HANDLE_VALUE,
			NULL,
			PAGE_READWRITE,
			0,
			totalSize,
			SharedMemoryName.data());
		SharedMemoryPointer = static_cast<BYTE*>(MapViewOfFile(
			SharedMemory,
			FILE_MAP_ALL_ACCESS,
			0, 0, totalSize));
		
		DataSize								= offset_ptr<size_t>(SharedMemoryPointer, 0);
		ExecutableNameSize				= offset_ptr<size_t>(DataSize, sizeof(size_t));
		ExecutableNameInStruct			= offset_ptr<char>(ExecutableNameSize, sizeof(size_t));
		ArgumentsSize						= offset_ptr<size_t>(ExecutableNameInStruct, ExecutableName.size() + 1);
		ArgumentsInStruct					= offset_ptr<char>(ArgumentsSize, sizeof(size_t));
		NameLength							= offset_ptr<size_t>(ArgumentsInStruct, Arguments.size() + 1);
		ModuleSize							= offset_ptr<size_t>(NameLength, sizeof(size_t));
		Handles									= offset_ptr<HMODULE>(ModuleSize, sizeof(size_t));
		Names									= offset_ptr<char>(Handles, handlesSize);

		*DataSize								= totalSize;
		*ExecutableNameSize				= ExecutableName.size();
		memcpy(ExecutableNameInStruct, ExecutableName.data(), ExecutableName.size() + 1);
		*ArgumentsSize						= Arguments.size();
		memcpy(ArgumentsInStruct, Arguments.data(), Arguments.size() + 1);
		*NameLength							= maxNameLength;
		*ModuleSize							= Dlls.size();
					
		char* refName = reinterpret_cast<char*>(Names);
		HMODULE* refHandle = Handles;
		for (auto& pair : Dlls)
		{
			string_view const& name = pair.second.FileName;
			memcpy(refName, name.data(), name.size() + 1);

			HMODULE const handle = static_cast<HMODULE>(pair.second.Base);
			*refHandle = handle;
			
			refName += (maxNameLength + 1);
			refHandle++;
		}
	}
	ContextEmplacer::~ContextEmplacer()
	{
		UnmapViewOfFile(SharedMemoryPointer);
		CloseHandle(SharedMemory);
	}
}