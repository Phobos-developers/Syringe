#ifndef DEBUGGER_DEBUGGER_HPP
#define DEBUGGER_DEBUGGER_HPP

#include "typedefs.hpp"

#include <events.hpp>
#include <map>
#include <string>
#include <string_view>

#include "dll_info.hpp"
#include "thread_manager.hpp"
#include "process_memory.hpp"

namespace Debugger
{
	using namespace Utilities;
	using std::map;
	using std::string;
	using std::string_view;

	/*!
	* @author multfinite
	* @brief This class provides generic way to implement debuf loop.
	* @brief First, it handles basic debug loop events: DLL load\\unload, Thread create\\exit.
	* @brief Second, it allow to set breakpoints and handles event when (any) breakpoint reached. Also able to use single step mode.
	* @brief Thrid, it will notice when access violation occurs.
	*/
	class DebugLoop
	{		
	public:
		struct Breakpoint;

		using ExceptionCode						= DWORD;
		using ThreadCreationFlags				= DWORD;
		using ThreadProcessParameter		= LPVOID;

		using BreakpointEvent					= ObjectEvent<DebugLoop, Thread&, Breakpoint&>;
		using AccessViolationEvent				= ObjectEvent<DebugLoop, Thread&, Address>;
		using ThreadEvent							= ObjectEvent<DebugLoop, Thread&, Address>;
		using DllEvent								= ObjectEvent<DebugLoop, DllInfo&>;
		using DebuggerEvent						= ObjectEvent<DebugLoop>;
		using ThreadActionEvent					= ObjectEvent<DebugLoop, Thread&>; 

		using BreakpointMap						= map<Address, Breakpoint>;

		BYTE INT3 = 0xCC;
	public:
		/*!
		* @author multfinite
		* @brief Just a container for breakpoint.
		* @brief OnReached event can be used to be noticed when breakpoint reached.
		*/
		struct Breakpoint final
		{
			using Event	= ObjectEvent<Breakpoint, DebugLoop&, Thread&>;

			Event			OnReached;
			
			Address			Addr;
			BYTE				OpCode;
			bool				IsWritten;

			Breakpoint() noexcept;
			Breakpoint(Address address);
			~Breakpoint();
			
			Breakpoint(Breakpoint&& other) noexcept;
			Breakpoint& operator=(Breakpoint&& other) noexcept;

			Breakpoint(Breakpoint& other) = delete;
			Breakpoint& operator=(Breakpoint const& other) = delete;
		};

		struct process_creation_error : std::exception {	};
		struct dll_not_found_error : std::exception
		{
			string const BaseName;
			dll_not_found_error(string_view const& baseName) :
				BaseName(baseName)
			{ }
		};

		DebuggerEvent								OnProcessCreated;
		BreakpointEvent								OnBreakpoint;
		ThreadEvent									OnUnregisteredBreakpoint;
		ThreadEvent									OnSingleStep;
		AccessViolationEvent						OnAccessViolation;

		DllEvent											OnDllLoaded;
		DllEvent											OnDllUnloaded;

		ThreadActionEvent							OnThreadAdded;
		ThreadActionEvent							OnThreadRemoved;

		STARTUPINFO								StartupInfo{};
		CREATE_PROCESS_DEBUG_INFO		ProcessDebugInfo{};
		PROCESS_INFORMATION				ProcessInfo{};
		//MODULEINFO								ProcessModuleInfo;
				
		BreakpointMap								Breakpoints;		
		DllMap											Dlls;

		Thread*											MainThread;
		map<ThreadId, Breakpoint*>			DefferedBreakpoints;
	private:
		ProcessHandle								_dbgProcessHandle;
	public:
		ProcessMemory								Memory;
		ThreadManager								ThreadMgr;

		string	const									ExecutablePath;
	private:
		ProcessHandle InitProcess(string_view const& executablePath, string_view const& arguments);
	public:
		DebugLoop(string_view const& executablePath, string_view const& arguments, bool freeMemory = true);
		~DebugLoop();
		DllInfo& Find(string_view const& dllBaseName);
		ProcessHandle Process() const { return _dbgProcessHandle; }
		
		void SetBreakpoint(Address address);
		void SetBreakpoint(Breakpoint& bp);
		void RestoreBreakpoint(Address address);
		void RestoreOpcode(Breakpoint& bp);
		Breakpoint& AddBreakpoint(Address address, bool write = true);
		bool RemoveBreakpoint(Address address);
		
		void Run();
	private:
		DWORD HandleException(DEBUG_EVENT& dbgEvent);
		DWORD HandleBreakpoint(DEBUG_EVENT& dbgEvent);
		DWORD HandleSingleStep(DEBUG_EVENT& dbgEvent);		
		DWORD HandleAccessViolation(DEBUG_EVENT& dbgEvent);
	};
}
#endif //DEBUGGER_DEBUGGER_HPP