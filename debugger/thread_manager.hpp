#ifndef DEBUGGER_THREAD_MANAGER_HPP
#define DEBUGGER_THREAD_MANAGER_HPP

#include <stdexcept>
#include <string.hpp>

#include "thread.hpp"

/*!
* @autor multfinite
* @brief Thread manager it is just 'smart' container over threads.
* @brief Used by Debugger to manage and count threads.
*/
class ThreadManager final
{
public:
	struct ThreadNotFoundException				: std::runtime_error
	{
		ThreadId	const		TID;
		ThreadNotFoundException(ThreadId tid) : TID(tid), 
			std::runtime_error(Utilities::string_format("Thread [id = %u] not found.", tid)) {}
	};
	struct InvalidThreadOwnerIdException		: std::runtime_error 	
	{
		ProcessId	const		PID;
		ThreadId	const		TID;
		InvalidThreadOwnerIdException(ThreadId tid, ProcessId pid) : TID(tid), PID(pid),
			std::runtime_error(Utilities::string_format("Thread [id = %u] owned by different process [id = %u].", tid, pid)) {}
	};

	std::map<ThreadId, Thread>		Threads;
private:
	ProcessHandle					_process;
	ProcessId							_processId;
public:
	ThreadManager(ThreadManager& other)						= delete;
	ThreadManager& operator=(ThreadManager& other)		= delete;

	~ThreadManager() = default;
	ThreadManager() noexcept = default;
	ThreadManager(ProcessHandle process)
		: _process(process), _processId(GetProcessId(process)) { }
	ThreadManager(ThreadManager&& other) noexcept :
		_process(std::exchange(other._process, nullptr)),
		_processId(std::exchange(other._processId, 0)),
		Threads(std::exchange(other.Threads, {})) { }

	ThreadManager& operator=(ThreadManager&& other) noexcept
	{
		_process = std::exchange(other._process, nullptr);
		_processId = std::exchange(other._processId, 0);
		Threads = std::exchange(other.Threads, {});
		return  *this;
	}
	Thread& operator[](ThreadId id)
	{
		if (auto const it = Threads.find(id); it != Threads.end())
			return it->second;
		throw ThreadNotFoundException{ id };
	};

	Thread& FindOrEmplace(ThreadId id, ThreadHandle handle) noexcept
	{
		if (auto const it = Threads.find(id); it != Threads.end())
			return it->second;
		return Threads.emplace(id, Thread(handle)).first->second;
	}
	Thread& Append(Thread& thread)
	{
		if (thread.OwnerId != _processId)
			throw InvalidThreadOwnerIdException{ thread.Id, thread.OwnerId };
		if (auto const it = Threads.find(thread.Id); it != Threads.end())
			return thread;
		return Threads.emplace(thread.Id, &thread).first->second;
	}
	Thread& Create(
		ThreadStartRoutine				routineFunc,
		ThreadProcessParameter		parameter = nullptr,
		ThreadCreationFlags			creationFlags = CREATE_SUSPENDED
	) {
		ThreadId id;
		ThreadHandle handle = CreateRemoteThread(
			_process, nullptr, 0,
			routineFunc, parameter,
			creationFlags,
			&id);
		return Threads.emplace(id, handle).first->second;
	}
	bool Close(ThreadId id)
	{
		if (auto const it = Threads.find(id); it != Threads.end())
		{
			Thread& threadInfo = it->second;
			Threads.erase(it);
			return true;
		}
		return false;
	}
	bool Remove(Thread& thread)
	{
		if (auto const it = Threads.find(thread.Id); it != Threads.end())
		{
			Thread& threadInfo = it->second;
			Threads.erase(it);
			return true;
		}
		return false;
	}
};

#endif //DEBUGGER_THREAD_MANAGER_HPP