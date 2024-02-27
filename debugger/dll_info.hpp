#ifndef DEBUGGER_DLL_INFO_HPP
#define DEBUGGER_DLL_INFO_HPP

#include <portable_executable.hpp>
#include <file.hpp>
#include <handle.win.hpp>
#include <winapi.utilities.hpp>

#include "typedefs.hpp"

/*!
* @author multfinite
* @brief Just container for dynamic loaded module (DLL) data inside process.
* @brief Used by debugger.
*/
struct DllInfo
{
	HMODULE								Handle					{ nullptr };
	LPVOID									Base						{ nullptr };
	DWORD									FileSize					{ 0 };
	std::string								FileName;
	DWORD									ImageSize				{ 0 };
	bool										Unloaded				{ false };
	PECOFF::PortableExecutable	PE;
	unsigned int							Checksum				{ 0 };
	Utilities::FileVersionInformation	FVI;

public:
	DllInfo() = default;
	DllInfo(LOAD_DLL_DEBUG_INFO& info) :
		FileName(Utilities::GetFileNameFromHandle(info.hFile)),
		PE(Utilities::file_open_binary(FileName)),
		ImageSize(PE.PEHeader.OptionalHeader.SizeOfImage),
		Base(info.lpBaseOfDll),
		FileSize(GetFileSize(info.hFile, nullptr)),
		Checksum(Utilities::CRC32::compute_stream(Utilities::file_open_binary(FileName)))
	{
		GetModuleHandleEx(
			GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			(LPCTSTR)Base,
			&Handle
		);
	}
	~DllInfo() = default;
	bool OwnsAddress(Address address) const { return (address >= Base) && (address < reinterpret_cast<BYTE*>(Base) + ImageSize); };

	void LoadVersion()
	{
		try
		{
			FVI.Load(FileName);
		}
		catch(...) {}
	}
};

using DllBase		= LPVOID;
using DllMap		= std::map<DllBase, DllInfo>;

#endif //DEBUGGER_DLL_INFO_HPP