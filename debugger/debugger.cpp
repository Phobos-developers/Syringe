#include "debugger.hpp"
#include <filesystem>

namespace Debugger
{
	ProcessHandle DebugLoop::InitProcess(string_view const& executablePath, string_view const& arguments)
	{
		SetEnvironmentVariable("_NO_DEBUG_HEAP", "1");

		if (CreateProcess(
			executablePath.data(), const_cast<LPSTR>(arguments.data()),
			nullptr, nullptr, false,
			DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED,
			nullptr, nullptr, &StartupInfo, &ProcessInfo) == FALSE)
		{
			throw process_creation_error();
		}

		return OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessInfo.dwProcessId);
		//_dbgProcessHandle = ProcessHandle(OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessInfo.dwProcessId));	
	}
	DebugLoop::DebugLoop(string_view const& executablePath, string_view const& arguments, bool freeMemory) :
		OnProcessCreated(this),
		OnBreakpoint(this),
		OnUnregisteredBreakpoint(this),
		OnSingleStep(this),
		OnAccessViolation(this),
		OnDllLoaded(this),
		OnDllUnloaded(this),
		OnThreadAdded(this),
		OnThreadRemoved(this),
		ExecutablePath(executablePath)
	{
		SetEnvironmentVariable("_NO_DEBUG_HEAP", "1");

		string exePath = executablePath.data();
		string args = arguments.data();

		if (CreateProcess(
			executablePath.data(), 
			const_cast<LPSTR>(arguments.data()),
			nullptr, nullptr, false,
			DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED,
			nullptr, nullptr, &StartupInfo, &ProcessInfo) == FALSE)
		{
			throw process_creation_error();
		}

		_dbgProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessInfo.dwProcessId);
		Memory = ProcessMemory { _dbgProcessHandle, freeMemory };
		ThreadMgr = ThreadManager { _dbgProcessHandle };
		
		MainThread = &ThreadMgr.FindOrEmplace(ProcessInfo.dwThreadId, ProcessInfo.hThread);
	}
	DebugLoop::~DebugLoop()
	{
		CloseHandle(_dbgProcessHandle);
	}

	DllInfo& DebugLoop::Find(string_view const& dllBaseName)
	{
		for (auto& pair : Dlls)
		{
			std::filesystem::path dllPath = pair.second.FileName;
			if(dllBaseName == dllPath.filename())
				return pair.second;
		}
		throw dll_not_found_error { dllBaseName };
	}
	
	void DebugLoop::SetBreakpoint(Address address)
	{
		Breakpoint& bp = Breakpoints[address];
		Memory.Write(bp.Addr, &INT3, sizeof(BYTE));
		bp.IsWritten = true;
	}
	void DebugLoop::SetBreakpoint(Breakpoint& bp)
	{
		Memory.Write(bp.Addr, &INT3, sizeof(BYTE));
		bp.IsWritten = true;
	}
	void DebugLoop::RestoreBreakpoint(Address address)
	{
		Breakpoint& bp = Breakpoints[address];
		Memory.Write(bp.Addr, &bp.OpCode, sizeof(BYTE));
		bp.IsWritten = false;
	}
	void DebugLoop::RestoreOpcode(Breakpoint& bp)
	{
		Memory.Write(bp.Addr, &bp.OpCode, sizeof(BYTE));
		bp.IsWritten = false;
	}
	DebugLoop::Breakpoint& DebugLoop::AddBreakpoint(Address address, bool write)
	{
		Breakpoint& bp = Breakpoints.emplace(address, Breakpoint { address }).first->second;
		Memory.Read(bp.Addr, &bp.OpCode, sizeof(BYTE));
		if(write)
			SetBreakpoint(bp);
		return bp;
	}
	bool DebugLoop::RemoveBreakpoint(Address address)
	{
		if(auto const it = Breakpoints.find(address); it != Breakpoints.end())
		{
			Breakpoint& bp = it->second;
			if(bp.IsWritten)
				RestoreOpcode(bp);
			
			Breakpoints.erase(it);

			return true;
		}
		return false;
	}
}