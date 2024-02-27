#ifndef DEBUGGER_THREAD_HPP
#define DEBUGGER_THREAD_HPP

#include "typedefs.hpp"

/*!
* @autor multfinite
* @brief Thread representation for debugged process. It keeps thread-related data and provides manipulation function over it (like get\\set context, resume\\pause and etc).
* @brief Used by ThreadManager and Debugger class as thread information container.
* @brief It wraps WINAPI calls.
* @brief Not copyable.
* @brief Moveable.
*/
class Thread
{
public:
	ThreadId				Id									{ 0 };
	ThreadHandle			Handle							{ nullptr };
	ProcessId				OwnerId						{ 0 };
	Address					LastBreakpoint				{ nullptr };
	CONTEXT				Context							{ };
	
	Thread(Thread& other)								= delete;
	Thread& operator=(Thread const& other)		= delete;

	~Thread()
	{
		ProcessId const currentId = GetCurrentProcessId();
		if (Handle && currentId == OwnerId)
			CloseHandle(Handle);
	}
	Thread() noexcept;
	Thread(ThreadHandle hThread, ThreadId id, ProcessId ownerId)
		: Handle(hThread), Id(id), OwnerId(ownerId) { }
	Thread(ThreadHandle hThread)
		: Handle{ hThread }, Id{ GetThreadId(hThread) }, OwnerId(GetProcessIdOfThread(hThread)) { }
	Thread(Thread&& other) noexcept :
		OwnerId(std::exchange(other.OwnerId, 0)),
		Handle(std::exchange(other.Handle, nullptr)),
		Id(std::exchange(other.Id, 0)),
		LastBreakpoint(std::exchange(other.LastBreakpoint, nullptr)),
		Context(std::exchange(other.Context, {})) {}
	Thread& operator=(Thread&& other) noexcept
	{
		OwnerId = std::exchange(other.OwnerId, 0);
		Handle = std::exchange(other.Handle, nullptr);
		Id = std::exchange(other.Id, 0);
		LastBreakpoint = std::exchange(other.LastBreakpoint, nullptr);
		Context = std::exchange(other.Context, {});
		return *this;
	}

	Thread(
		ProcessHandle process,
		ThreadStartRoutine routineFunc,
		ThreadProcessParameter parameter				= nullptr,
		ThreadCreationFlags creationFlags				= CREATE_SUSPENDED
	)		: OwnerId(GetProcessId(process))
	{
		Handle = CreateRemoteThread(
			process, nullptr, 0,
			routineFunc, parameter,
			creationFlags,
			&Id);
	}
	Thread(
		ThreadStartRoutine routineFunc,
		ThreadProcessParameter parameter				= nullptr,
		ThreadCreationFlags creationFlags				= CREATE_SUSPENDED
	)		: OwnerId(GetCurrentProcessId())
	{
		Handle = CreateThread(
			nullptr, 0,
			routineFunc, parameter,
			creationFlags,
			&Id);
	}

	void			EnableSingleStep()
		{
			Context.ContextFlags = CONTEXT_CONTROL;
			auto r = GetThreadContext(Handle, &Context);
			Context.EFlags |= 0x100;
			SetThreadContext(Handle, &Context);
		}
	void			DisableSingleStep()
		{
			Context.ContextFlags = CONTEXT_FULL;
			auto r = GetThreadContext(Handle, &Context);
			Context.EFlags &= 0x100;
			r = SetThreadContext(Handle, &Context);
		}
	CONTEXT&	GetContext(ContextFlags flags)
		{
			Context.ContextFlags = flags;
			auto r = GetThreadContext(Handle, &Context);
			return Context;
		}
	BOOL		SetContext(ContextFlags flags)
		{
			Context.ContextFlags = flags;
			return SetThreadContext(Handle, &Context);
		}
	BOOL		SetContext(CONTEXT& context)
		{
			Context = context;
			return SetThreadContext(Handle, &Context);
		}
	DWORD 	Resume()								{	return ResumeThread(Handle); 	}
	DWORD		Suspend()								{	return SuspendThread(Handle);	}
	BOOL		Terminate(DWORD exitCode)	{	return TerminateThread(Handle, exitCode); }
};
#endif //DEBUGGER_THREAD_HPP