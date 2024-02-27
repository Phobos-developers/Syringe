#ifndef DEBUGGER_TYPEDEFS_HPP
#define DEBUGGER_TYPEDEFS_HPP

//#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
//#undef WIN32_LEAN_AND_MEAN

using ProcessHandle					= HANDLE;
using ProcessId							= DWORD;
using ThreadHandle					= HANDLE;
using ThreadId							= DWORD;
using ContextFlags						= DWORD;
using ThreadStartRoutine			= LPTHREAD_START_ROUTINE;
using ThreadProcessParameter	= LPVOID;
using ThreadCreationFlags			= DWORD;
using Address								= void*;

#endif //DEBUGGER_TYPEDEFS_HPP