#include "debugger.hpp"

namespace Debugger
{
	void DebugLoop::Run()
	{
		//Log::WriteLine(
			//__FUNCTION__ ": Running process to debug. cmd = \"%s %.*s\"",
			//exe.c_str(), printable(arguments));
		//DebugProcess(arguments);

		DEBUG_EVENT dbgEvent;
		
		MainThread->Resume();

		//Log::WriteLine(__FUNCTION__ ": Entering debug loop...");

		auto exit_code = static_cast<DWORD>(-1);

		for (;;)
		{
			WaitForDebugEvent(&dbgEvent, INFINITE);

			DWORD continueStatus = DBG_CONTINUE;

			switch (dbgEvent.dwDebugEventCode)
			{
			case CREATE_PROCESS_DEBUG_EVENT:
				{
					ProcessInfo.hProcess = dbgEvent.u.CreateProcessInfo.hProcess;
					ProcessInfo.dwThreadId = dbgEvent.dwProcessId;
					ProcessInfo.hThread = dbgEvent.u.CreateProcessInfo.hThread;
					ProcessInfo.dwThreadId = dbgEvent.dwThreadId;

					ProcessDebugInfo = dbgEvent.u.CreateProcessInfo;

					OnProcessCreated();
					
					CloseHandle(dbgEvent.u.CreateProcessInfo.hFile);
				}	break;
			case CREATE_THREAD_DEBUG_EVENT:
				{
					Thread& thread = ThreadMgr.FindOrEmplace(
						dbgEvent.dwThreadId, 
						dbgEvent.u.CreateThread.hThread);				
					OnThreadAdded(thread); 
				}	break;
			case EXIT_THREAD_DEBUG_EVENT:
				{
					Thread& thread = ThreadMgr[dbgEvent.dwThreadId];
					OnThreadRemoved(thread);
					ThreadMgr.Remove(thread);
				}	break;
			case EXCEPTION_DEBUG_EVENT:
				{
					continueStatus = HandleException(dbgEvent);
				}	break;
			case LOAD_DLL_DEBUG_EVENT:
				{
					auto const		base	= dbgEvent.u.LoadDll.lpBaseOfDll;
					auto				p		= Dlls.emplace(base, dbgEvent.u.LoadDll);
					p.first->second.LoadVersion();
					OnDllLoaded(p.first->second);
				}	break;
			case UNLOAD_DLL_DEBUG_EVENT:
				{
					auto const base = dbgEvent.u.UnloadDll.lpBaseOfDll;
					DllInfo& dll = Dlls[base];
					dll.Unloaded = true;
					OnDllUnloaded(dll);
				}	break;
			case OUTPUT_DEBUG_STRING_EVENT:
				{ } break;
			}

			if (dbgEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
			{
				exit_code = dbgEvent.u.ExitProcess.dwExitCode;
				break;
			}
			else if (dbgEvent.dwDebugEventCode == RIP_EVENT)
			{
				break;
			}

			ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);
		}

		CloseHandle(ProcessInfo.hProcess);

		//Log::WriteLine(
			//__FUNCTION__ ": Done with exit code %X (%u).", exit_code, exit_code);
		//Log::WriteLine();
	}	
}