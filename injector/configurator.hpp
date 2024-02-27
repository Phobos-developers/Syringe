#ifndef INJECTOR_CONFIGURATOR_HPP
#define INJECTOR_CONFIGURATOR_HPP

#include <debugger.hpp>
#include <portable_executable.hpp>

#include "waiter.hpp"
#include "hook_retriever.hpp"
#include "module_retriever.hpp"
#include "hook_injector.hpp"
#include "context_emplacer.hpp"

namespace Injector
{	
	using namespace Debugger;
	using Breakpoint = DebugLoop::Breakpoint;
	using namespace PECOFF;

	/*!
	* @author multfinite
	* @brief Implements the top behavior of injector. It wraps around debugger events when breakpoint reached.
	* @brief Injection algorithm:
	* @brief 1. Suspend main thread. Create a new thread for injection.
	* @brief 2. Place 'waiter': a simple program which includes breakpoint, which will be trapped by debugger. Used for detecting steps.
	* @brief 3. Wait for kernel32.dll
	* @brief 4. Prepare a program to load all injectable modules: generate, write and execute. Extract all laoded handles from process.
	* @brief 5. Prepare a program to retieve all hook function addresses: generate, write and execute. Extract all data and set it to hooks.
	* @brief 6. Iterate all hooks, check their inejction conditions, checksums, module names and sort it. 
	* @brief 7. Generate for each hooked address a program, which will execute all related hook functions. Then write program and write jumps.
	* @brief 8. Assembly a context of execution (look for ContextEmplacer) and write it into shared memory: 'InjContext-$PID'. It is accessible from injected dlls.
	* @brief 9. Terminate loader thread and resume main thread.
	* @brief NOTE 1: Executable can be protected via ASLR. Injector does not support it (need to create an algorithm which will seek new bases and perform address correction). 
	* @brief NOTE 2: Stack can be protected and then hook invocation to it will cause invalid data inside function.
	*/
	class Configurator final
	{
	public:
		struct InvalidBaseAddressException : exception
		{
			LPVOID Preffered;
			LPVOID Current;
			InvalidBaseAddressException(LPVOID preffered, LPVOID current)	:
				Preffered(preffered),
				Current(current)
			{}
		};
		// 
		struct Kernel32InvalidBaseAddressException : InvalidBaseAddressException
		{
			Kernel32InvalidBaseAddressException(LPVOID preffered, LPVOID current) : InvalidBaseAddressException(preffered, current) {}
		};
		//https://docs.microsoft.com/en-us/cpp/build/reference/dynamicbase-use-address-space-layout-randomization?view=msvc-170
		struct DynamicBaseUnsupportedException : InvalidBaseAddressException
		{
			DynamicBaseUnsupportedException(LPVOID preffered, LPVOID current) : InvalidBaseAddressException(preffered, current) {}
		};
	private:		
		//
		PortableExecutable& _peFile;
		DebugLoop& _debugger;
		Kernel32 _kernel;
		list<Module>& _modules;

		string_view const& _arguments;
		string_view const& _executableName;
		
		//InjectionContext _context;
		//VirtualMemoryHandle& _contextVmh;

		WaiterCode _waiterCode;
		VirtualMemoryHandle& _waiterVmh;
		
		ModuleRetriever* _moduleRetriever;
		HookRetriever* _hookRetriever;
		HookInjector* _hookInjector;

		string _contextSharedMemoryName;
		ContextEmplacer* _contextEmplacer;

		Address _waiterBp;
		Address _moduleRetrieverBp;
		Address _hookRetrieverBp;
		Address _initializerInjectorBp;

		Thread* _loaderThreadInfo;

		VirtualMemoryHandle& _moduleHandle;
		std::vector<VirtualMemoryHandle*> _hookHandles;
		std::vector<VirtualMemoryHandle*> _stringHandles;

		DllInfo* _kernelDll = nullptr;
		VirtualMemoryHandle* _importTable;
	public:
		Configurator(
			PortableExecutable& peFile,
			DebugLoop& debugger, 
			list<Module>& modules,
			string_view const& arguments,
			string_view const& executableName) :
				_peFile(peFile),
				_debugger(debugger),
				_moduleHandle(debugger.Memory.Allocate(sizeof(Module) * modules.size())),
				_modules(modules),
				_arguments(arguments),
				_executableName(executableName),
				_waiterCode(), _waiterVmh(debugger.Memory.Allocate(WaiterCodeSize))
		{
			_waiterVmh.Write(&_waiterCode, WaiterCodeSize);
			_debugger.OnProcessCreated += [this] (DebugLoop& sender) { OnProcessCreated(sender); };
			_debugger.OnAccessViolation += [this](DebugLoop& sender, Thread& thread, Address address) { OnAccessViolation(sender, thread, address); };
			_debugger.OnDllLoaded += [this] (DebugLoop& sender, DllInfo& dll) { OnDllLoaded(sender, dll); };
		};
		~Configurator()
		{
			if(_importTable)
				_debugger.Memory.Free(*_importTable);
			
			for (VirtualMemoryHandle* vmh : _stringHandles)			
				_debugger.Memory.Free(reference_cast(vmh));
			for (VirtualMemoryHandle* vmh : _hookHandles)			
				_debugger.Memory.Free(reference_cast(vmh));
			
			delete _moduleRetriever;
			delete _hookRetriever;
			delete _hookInjector;
		}		
		
	private:		
		void OnProcessCreated(DebugLoop& sender)
		{
			spdlog::info("Process created, configuring...");

			_debugger.MainThread->Suspend();
			
			_loaderThreadInfo = &_debugger.ThreadMgr.Create(
				static_cast<ThreadStartRoutine>(static_cast<Address>(_waiterVmh.Pointer())), 
				nullptr, CREATE_SUSPENDED);

			_waiterBp = _waiterVmh.Pointer(WaiterBreakpointOffset);
			auto& wcbp = _debugger.AddBreakpoint(_waiterBp);
			wcbp.OnReached += [this] (DebugLoop::Breakpoint& bp, DebugLoop& sender, Thread& thread) { OnWaiterBreakpoint(bp, sender, thread); };
			
			_loaderThreadInfo->GetContext(CONTEXT_FULL);
			Address const nextInstruction = _waiterVmh.Pointer();
			_loaderThreadInfo->Context.Eip = reinterpret_cast<DWORD>(nextInstruction);
			_loaderThreadInfo->SetContext(CONTEXT_FULL);
			
			spdlog::info("Process configured, run loader thread and execute injected programs...");
			_loaderThreadInfo->Resume();
		}

		void OnDllLoaded(DebugLoop& sender, DllInfo& dllInfo)
		{
			spdlog::trace("[Debug event] dll \"{0}\" ({1}) loaded at [0x{2:x}], image size: {3} bytes, checksum: 0x{4:X} ({4:d})", 
				dllInfo.FileName, dllInfo.FVI.OriginalFilename, 
				(uint32_t) dllInfo.Handle, dllInfo.ImageSize, dllInfo.Checksum);
			auto dllPath = std::filesystem::path{ dllInfo.FileName };
			auto dllName = dllPath.filename().string();
			if(strcmpi(dllName.c_str(), "kernel32.dll") == 0)
			{
				_kernelDll = &dllInfo;

				_kernel.GetProcAddressFunc = &GetProcAddress;
				_kernel.LoadLibraryFunc = &LoadLibraryA;
				_kernel.FreeLibraryFunc = &FreeLibrary;
				
				_importTable = &_debugger.Memory.Allocate(sizeof(Address) * 3);
				_importTable->Write(&_kernel, sizeof(Kernel32));

				_kernel.GetProcAddressFunc = reinterpret_cast<GetProcAddressFunction>(_importTable->Pointer(sizeof(Address) * 0));
				_kernel.LoadLibraryFunc = reinterpret_cast<LoadLibraryFunction>(_importTable->Pointer(sizeof(Address) * 1));
				_kernel.FreeLibraryFunc = reinterpret_cast<FreeLibraryFunction>(_importTable->Pointer(sizeof(Address) * 2));

				spdlog::trace("::GetProcAddress = 0x{0:x}", (uint32_t) _kernel.GetProcAddressFunc);
				spdlog::trace("::LoadLibraryA = 0x{0:x}", (uint32_t) _kernel.LoadLibraryFunc);
				spdlog::trace("::FreeLibrary = 0x{0:x}", (uint32_t) _kernel.FreeLibraryFunc);
			}
		}
		
		//void OnThreadSingleStep(Debugger& dbg, Thread& thread, Address address)
		void OnWaiterBreakpoint(DebugLoop::Breakpoint& bp, DebugLoop& sender, Thread& thread)
		{
			if(thread.Id != _loaderThreadInfo->Id)
				return;
			if(_kernelDll)
			{
				HMODULE const kernelHandle = GetModuleHandleA("kernel32.dll");
				if(kernelHandle != _kernelDll->Base)
					throw Kernel32InvalidBaseAddressException(kernelHandle, _kernelDll->Base);
				
				InitLL();
			}
			else
			{
				if(_debugger.Dlls.size() > 0)
					throw;
				_loaderThreadInfo->GetContext(CONTEXT_FULL);
				Address const nextInstruction = _waiterVmh.Pointer();
				_loaderThreadInfo->Context.Eip = reinterpret_cast<DWORD>(nextInstruction);			
				_loaderThreadInfo->SetContext(CONTEXT_FULL);
			}
		}

		void InitLL()
		{
			spdlog::info("Prepare module loading program (it invokes LoadLibraryA for a list of modules)...");
			
			_moduleRetriever = new ModuleRetriever { _debugger.Memory, _kernel, _modules };
			_moduleRetrieverBp = static_cast<BYTE*>(_moduleRetriever->breakpoint());
			spdlog::trace("::breakpoint = [0x{0:x}]", (uint32_t) _moduleRetrieverBp);
			auto& mrbp = _debugger.AddBreakpoint(_moduleRetrieverBp);
			mrbp.OnReached += 
				[this] (DebugLoop::Breakpoint& bp, DebugLoop& sender, Thread& thread)
					{	OnLLBreakpoint(bp, sender, thread);	};

			_loaderThreadInfo->GetContext(CONTEXT_FULL);
			Address const nextInstruction = _moduleRetriever->instruction();
			_loaderThreadInfo->Context.Eip = reinterpret_cast<DWORD>(nextInstruction);			
			_loaderThreadInfo->SetContext(CONTEXT_FULL);
			spdlog::info("Run module loading program. (at [0x{0:x}])...", (uint32_t) nextInstruction);
		}
		
		void OnLLBreakpoint(DebugLoop::Breakpoint& bp, DebugLoop& sender, Thread& thread)
		{
			spdlog::info("Module loading program executed.");
			vector<HMODULE> handles;
			handles.resize(_modules.size());
			_moduleRetriever->ModuleHandlesVmh->Read(0, sizeof(HMODULE) * handles.size(), handles.data());

			for (size_t index = 0; index < _modules.size(); ++index)
			{
				Module& mdl = *std::next(_modules.begin(), index);
				mdl.set_handle(handles[index]);
			}

			spdlog::info("Prepare function retrievening program (It invoke GetProcAddress for a list of function names)...");
			_hookRetriever = new HookRetriever { _debugger.Memory, _kernel, _modules };
			_hookRetrieverBp = static_cast<BYTE*>(_hookRetriever->breakpoint());
			spdlog::trace("::breakpoint = [0x{0:x}]", (uint32_t) _hookRetrieverBp);
			auto& hrbp = _debugger.AddBreakpoint(_hookRetrieverBp);
			hrbp.OnReached +=
				[this] (DebugLoop::Breakpoint& bp, DebugLoop& sender, Thread& thread)
					{	OnGPABreakpoint(bp, sender, thread);	};	

			thread.GetContext(CONTEXT_FULL);
			Address const nextInstruction = _hookRetriever->instruction();
			thread.Context.Eip = reinterpret_cast<DWORD>(nextInstruction);
			thread.SetContext(CONTEXT_FULL);
			spdlog::info("Run function retrievening program (at 0x{0:x})...", (uint32_t) nextInstruction);
		}

		//DWORD _eip;
		void OnGPABreakpoint(DebugLoop::Breakpoint& bp, DebugLoop& sender, Thread& thread)
		{
			spdlog::info("Function retrievening program executed.");
			
			vector<InitFunction> initFunctions; initFunctions.resize(_modules.size());
			vector<HookFunction> hookFunctions; hookFunctions.resize(_hookRetriever->TotalHookCount);

			_hookRetriever->InitFunctionsVmh->Read(0, sizeof(InitFunction) * initFunctions.size(), initFunctions.data());
			_hookRetriever->HookFunctionsVmh->Read(0, sizeof(HookFunction) * hookFunctions.size(), hookFunctions.data());

			DWORD prefferedImageBase = _peFile.PEHeader.OptionalHeader.ImageBase;
			DWORD currentImageBase = reinterpret_cast<DWORD>(_debugger.ProcessDebugInfo.lpBaseOfImage);
			DWORD imageBaseOffset = prefferedImageBase - currentImageBase;
			if(imageBaseOffset != 0)
				throw DynamicBaseUnsupportedException(reinterpret_cast<LPVOID>(prefferedImageBase), reinterpret_cast<LPVOID>(currentImageBase));
			
			size_t initf = 0;
			size_t thkIndex = 0;			
			for (size_t index = 0; index < _modules.size(); ++index)
			{
				Module& mdl = *std::next(_modules.begin(), index);
				mdl.InitFunction = initFunctions[index];
				if(mdl.InitFunction)				
					initf++;				

				for (auto& hook : mdl.Hooks)
				{
					hook.Placement = reinterpret_cast<Address>(reinterpret_cast<DWORD>(hook.Placement) + imageBaseOffset);
					
					HookFunction const func =  hookFunctions[thkIndex++];
					hook.Function = func;
				}
			}
			_hookInjector = new HookInjector(_debugger, _modules);

			DWORD processId = _debugger.ProcessInfo.dwProcessId;
			_contextSharedMemoryName = "InjContext-" + std::to_string(processId);
			
			spdlog::info("Inject context into shared memory (\"{}\")...", _contextSharedMemoryName);
			_contextEmplacer = new ContextEmplacer(
				_executableName.data(),
				_arguments,
				_contextSharedMemoryName.data(),
				_debugger.Dlls	);
			spdlog::info("Context injected.");
			
			spdlog::info("Terminate loader thread...");
			thread.Terminate(0);
			spdlog::info("Process configured - resume main thread.");
			_debugger.MainThread->Resume();
		}

		void OnAccessViolation(DebugLoop& dbgLoop, Thread& thread, Address address)
		{
			spdlog::critical("Access Violation at 0x{0:x} in thread {0:d}", (uint32_t) address, thread.Id);
		}
	};
}
#endif //INJECTOR_CONFIGURATOR_HPP