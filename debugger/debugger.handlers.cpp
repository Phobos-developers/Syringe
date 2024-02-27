#include "debugger.hpp"
#include <macro.hpp>

namespace Debugger
{
	DWORD DebugLoop::HandleException(DEBUG_EVENT& dbgEvent)
	{
		auto const exceptCode = dbgEvent.u.Exception.ExceptionRecord.ExceptionCode;
		auto const exceptAddress = dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress;
	
		switch (exceptCode)
		{
		case(EXCEPTION_BREAKPOINT):
			return HandleBreakpoint(dbgEvent);
		case(EXCEPTION_SINGLE_STEP):
			return HandleSingleStep(dbgEvent);
		case(EXCEPTION_ACCESS_VIOLATION):
			return HandleAccessViolation(dbgEvent);
		default:
			return DBG_CONTINUE;
		}
	}

	DWORD DebugLoop::HandleBreakpoint(DEBUG_EVENT& dbgEvent)
	{
		auto const address = dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress;
		auto const threadId = dbgEvent.dwThreadId;
		
		Thread& thread = ThreadMgr[threadId];
		thread.LastBreakpoint = address;
		
		if(auto const it = Breakpoints.find(address); it != Breakpoints.end())			
		{
			Breakpoint& bp = it->second;
			OnBreakpoint(thread, bp);
			bp.OnReached(*this, thread);
			
			RestoreOpcode(bp);

			auto* pBp = &bp;
			DefferedBreakpoints.emplace(threadId, pBp);
			
			thread.EnableSingleStep();
		}
		else
			OnUnregisteredBreakpoint(
				thread,
				dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress);

		return DBG_CONTINUE;
	}

	DWORD DebugLoop::HandleSingleStep(DEBUG_EVENT& dbgEvent)
	{
		auto const address = dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress;
		auto const threadId = dbgEvent.dwThreadId;
		
		Thread& thread = ThreadMgr[threadId];
		if(auto const it = DefferedBreakpoints.find(threadId); it != DefferedBreakpoints.end())
		{
			Breakpoint& bp = reference_cast(it->second);
			if(bp.Addr == thread.LastBreakpoint)
			{
				SetBreakpoint(bp);
				thread.DisableSingleStep();

				DefferedBreakpoints.erase(it);
				
				return DBG_CONTINUE;
			}				
		}

		OnSingleStep(thread, address);
		return DBG_CONTINUE;
	}
	
	DWORD DebugLoop::HandleAccessViolation(DEBUG_EVENT& dbgEvent)
	{
		auto const exceptCode = dbgEvent.u.Exception.ExceptionRecord.ExceptionCode;
		auto const exceptAddress = dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress;
		auto const threadId = dbgEvent.dwThreadId;
		
		Thread& thread = ThreadMgr[threadId];
		
		OnAccessViolation(thread, exceptAddress);
		
		return DBG_EXCEPTION_NOT_HANDLED;
	}
}