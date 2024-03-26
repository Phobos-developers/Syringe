#include "hook_injector.hpp"

namespace Injector
{
    HookInjector::HookInjector(Debugger::DebugLoop& dbgr, list<Module>& modules)    
            : Memory(dbgr.Memory), Modules(modules)
    {
        auto executableChecksum = CRC32::compute_stream(file_open_binary(dbgr.ExecutablePath));
        for (Module& mdl : modules)
        {
            HMODULE handle = mdl.get_handle();

            if (!handle)
            {
                spdlog::warn("Module \"{0}\" handle is null, skip. -Please sure that it loads correctly.", mdl.FileName);
                continue;
            }
            spdlog::info("Module: \"{0}\" [0x{1:x}] now processing hooks:", mdl.FileName, (uint32_t) handle);
            
            for (auto& hook : mdl.Hooks)
            {
                bool isInExecutable = hook.ModuleName.empty();
                auto hookModuleName = isInExecutable ? "executable" : "\"" + hook.ModuleName + "\"";

                if (!hook.Function)
                {
                    spdlog::warn("::Hook \"{0}\" function not found, skip. -Please, sure that hooks were scanned correctly.", hook.FunctionName);
                    continue;
                }

                auto checksum  = executableChecksum;
                auto placement = hook.Placement;
                if (!isInExecutable)
                {
                    auto inProcessDll = std::find_if(dbgr.Dlls.cbegin(), dbgr.Dlls.cend(), 
                        [&hook, &dbgr](DllMap::value_type pair) -> bool
                        {
                            auto ofnp = std::filesystem::path(pair.second.FVI.Loaded ? pair.second.FVI.OriginalFilename : pair.second.FileName);
                            auto ofn  = ofnp.filename(); // .stem(); no extension
                            auto mfnp = std::filesystem::path(hook.ModuleName);
                            auto mfn  = mfnp.filename(); //.stem();
                            return ofn == mfn;
                        }
                    );
                    if (inProcessDll == dbgr.Dlls.cend())
                    {
                        spdlog::info("::Hook \"{0}\" target module \"{1}\" not found, skip.", 
                            hook.FunctionName,
                            hook.ModuleName
                        ); continue;
                    }

                    hook.ModuleBase = inProcessDll->first;
                    checksum = inProcessDll->second.Checksum;
                }

                bool checksumIsOk = hook.ModuleChecksum == 0 || checksum == hook.ModuleChecksum;
                if (!checksumIsOk)
                {
                    spdlog::info("::Hook \"{0}\": module checksum [0x{1:x}] and required [0x{2:x}] are different, skip.",
                        hook.FunctionName, checksum, hook.ModuleChecksum
                    );
                    continue;
                }

                placement = reinterpret_cast<Address>(
                    reinterpret_cast<DWORD>(placement) + reinterpret_cast<DWORD>(/*isInExecutable ? 0 : */hook.ModuleBase)
                );

                string logAddition, logAddition2;                
                switch (hook.Type)
                {
                    case(HookType::Generic): {}
                    case(HookType::Extended):
                    {
                        spdlog::info("::[0x{2:x}:0x{3:x} = 0x{4:x}] - on \"{1}\" placed hook \"{0}\".",
                            hook.FunctionName, hookModuleName,
                            (uint32_t)hook.ModuleBase, (uint32_t)hook.Placement, (uint32_t)placement
                        );

                        auto pocketIterator = Pockets.find(placement);
                        if (pocketIterator == Pockets.end())
                            pocketIterator = Pockets.emplace(placement, HookPocket()).first;

                        HookPocket& pocket = pocketIterator->second;
                        pocket.Hooks.push_back(&hook);
                        pocket.OverriddenCount =
                            hook.Size > pocket.OverriddenCount ? hook.Size : pocket.OverriddenCount;
                    } break;
                    case(HookType::FacadeByName):
                    { logAddition = "::" + hook.PlacementFunction; }
                    case(HookType::FacadeAtAddress):
                    {
                        auto facadeIterator = Facades.find(placement);
                        if (facadeIterator != Facades.end())
                        {
                            logAddition2 = " - FIRST REDEFINE WILL BE CHOISEN!";
                        }
                        else
                        {
                            facadeIterator = Facades.emplace(placement, Facade()).first;
                            facadeIterator->second.Redefine = &hook;
                        }

                        spdlog::info("::[0x{2:x}:0x{3:x} = 0x{4:x}] - for {1}{5} redefine \"{0}\"{6}.",
                            hook.FunctionName, hookModuleName,
                            (uint32_t)hook.ModuleBase, (uint32_t)hook.Placement, (uint32_t)placement,
                            logAddition, logAddition2
                        );
                    } break;
                    default:
                    {
                        spdlog::warn("::WTF UKNOWN HOOK!? MUST NEVER HAPPEN.");
                    } break;
                }
            }
        }

        size_t programSize = 0;

        spdlog::info("Iterate hook pockets and calculate total program size...");
        for (auto& pair : Pockets)
        {
            HookPocket& pocket = pair.second;
                        
            size_t const overridenCount = pocket.OverriddenCount;
            if (overridenCount < 5)
                pocket.OverriddenCount = 5;

            pocket.OriginalBytes.resize(pocket.OverriddenCount);
            Memory.Read(pair.first, pocket.OriginalBytes.data(), pocket.OriginalBytes.size());
            if (auto rji = is_relative_jump(pocket.OriginalBytes))
                programSize += 4; // byte jump - 2 bytes, int32 jump - 5 (but some 6) bytes. For edge case, when need extend every 1-byte jump to 4 byte-jump need +4 byte to total program size.

            programSize += RegistersBuildCodeSize;
            programSize += HookCallCodeSize * pocket.Hooks.size();
            programSize += RegistersCleanupCodeSize;
            programSize += pocket.OverriddenCount;
            programSize += JumpCodeSize;

            if (overridenCount < 5)
                spdlog::trace("::[0x{0:x}] {1:d} functions, {2:d} overriden bytes (fixed from {3:d})", (uint32_t)pair.first, pair.second.Hooks.size(), pair.second.OverriddenCount, overridenCount);
            else
                spdlog::trace("::[0x{0:x}] {1:d} functions, {2:d} overriden bytes", (uint32_t)pair.first, pair.second.Hooks.size(), pair.second.OverriddenCount);
        }

        NextInstructionsVmh = &Memory.Allocate(sizeof(Address) * Pockets.size());
        ProgramVmh = &Memory.Allocate(programSize);

        spdlog::info("Hook program block: ");
        spdlog::info("::Address = 0x{0:x}", (uint32_t) ProgramVmh->Pointer(0));
        spdlog::info("::Size = {0} (bytes)", ProgramVmh->Size());
        spdlog::info("Next instruction memory block: ");
        spdlog::info("::Address = 0x{0:x}", (uint32_t)NextInstructionsVmh->Pointer(0));
        spdlog::info("::Size = {0} (bytes)", NextInstructionsVmh->Size());

        DWORD refNextInstruction = reinterpret_cast<DWORD>(NextInstructionsVmh->Pointer(0));
        size_t offset = 0;
        
        spdlog::info("Hook program block assembling...");
        for (auto& pair : Pockets)
        {                
            Address const hookAddr = pair.first;
            HookPocket& pocket = pair.second;
            pocket.Offset = offset;

            Address const jumpBase   = reinterpret_cast<BYTE*>(hookAddr) + JumpR32lInstructionLength;
            Address const jumpOffset = ProgramVmh->Pointer(offset);
            
            pocket.HookCallerBlockCode.Offset = relative_offset(jumpBase, jumpOffset);
            Memory.Write(hookAddr, &pocket.HookCallerBlockCode, JumpCodeSize);
            
            pocket.RegistersBuild.HookAddress = hookAddr;
            for (Hook* hook : pocket.Hooks)                
            {
                Address const base = ProgramVmh->Pointer(offset);
                pocket.HookCallBlocks.emplace_back(
                    reinterpret_cast<Address>(refNextInstruction),
                    base,
                    hook->Function,
                    hook->ModuleBase);
                offset += HookCallCodeSize;
            }
            offset = pocket.Offset;

            size_t const hookCallersSize = pocket.HookCallBlocks.size() * HookCallCodeSize;
            size_t const overridenSize = pocket.OriginalBytes.size();
            size_t const jumpBackSize = JumpCodeSize;

            ProgramVmh->Write(&pocket.RegistersBuild, RegistersBuildCodeSize, offset);
            offset += RegistersBuildCodeSize;

            ProgramVmh->Write(pocket.HookCallBlocks.data(), hookCallersSize, offset);
            offset += hookCallersSize;

            ProgramVmh->Write(&pocket.RegistersCleanup, RegistersCleanupCodeSize, offset);
            offset += RegistersCleanupCodeSize;

            if (auto rji = is_relative_jump(pocket.OriginalBytes))
            {
                Address pFrom     = ProgramVmh->Pointer(offset);
                auto    oldOffset = get_relative_offset(pocket.OriginalBytes, rji);
                auto    pTo       = restore_address(hookAddr, oldOffset, rji.Cmd.Command.size());
                try
                {
                    auto newOffset = relative_offset(pFrom, pTo, rji.Cmd.Command.size());
                    set_relative_offset(pocket.OriginalBytes, rji, newOffset);

                    spdlog::info("::{0} rel{1:d} => 0x{2:x}: 0x{3:x}+0x{4:x}:{5:X}h -> 0x{3:x}+0x{6:x}:{7:X}h)",
                        rji.Cmd.Mnemonic, rji.Cmd.Size * 8, (uint32_t) pTo,
                        rji.Cmd.Command.size(),
                        (uint32_t) hookAddr, oldOffset,
                        (uint32_t) pFrom , newOffset
                    );
                }
                catch (const invalid_jump_offset_error& ex)
                {
                    try
                    {
                        auto cmd = find_rel_cmd(rji.Cmd.Mnemonic, 4);
                        std::vector<BYTE> extended; extended.resize(pocket.OriginalBytes.size() - rji.Cmd.Command.size() + cmd.Command.size());
                        memcpy(extended.data(), cmd.Command.data(), cmd.Command.size());
                        memcpy(extended.data() + cmd.Command.size(), pocket.OriginalBytes.data() + rji.Cmd.Command.size(), pocket.OriginalBytes.size() - rji.Cmd.Command.size());
                        auto newOffset = relative_offset(pFrom, pTo, cmd.Command.size());
                        set_relative_offset(extended, rji, newOffset);

                        pocket.OriginalBytes = extended;
                        spdlog::info("::{0} rel{1:d} => 0x{2:x}: 0x{3:x}+0x{4:x}:{5:X}h -> 0x{3:x}+0x{6:x}:{7:X}h) - extended to {0} rel{8:d}",
                            rji.Cmd.Mnemonic, rji.Cmd.Size * 8, (uint32_t) pTo,
                            rji.Cmd.Command.size(),
                            (uint32_t) hookAddr, oldOffset,
                            (uint32_t) pFrom , newOffset,
                            cmd.Size * 8
                        );
                    }
                    catch (...)
                    {
                        spdlog::error("::{0} rel{1:d} => 0x{2:x}: 0x{3:x}+0x{4:x}:{5:X}h -> 0x{3:x}+0x{6:x}:{7:X}h) - no command with huge offset size, SKIP",
                            rji.Cmd.Mnemonic, rji.Cmd.Size * 8, (uint32_t) pTo,
                            rji.Cmd.Command.size(),
                            (uint32_t) hookAddr, oldOffset,
                            (uint32_t) pFrom, ex.Value
                        );
                    }
                }
            }
            ProgramVmh->Write(pocket.OriginalBytes.data(), pocket.OriginalBytes.size(), offset);
            offset += pocket.OriginalBytes.size();

            // Jump back
            Address const jumpBackBase = ProgramVmh->Pointer(offset);
            Address const jumpBackAddress = reinterpret_cast<BYTE*>(hookAddr) + max(JumpR32lInstructionLength, pocket.OverriddenCount);
            pocket.JumpBackCode.Offset = relative_offset(jumpBackBase, jumpBackAddress, JumpR32lInstructionLength);
            
            ProgramVmh->Write(&pocket.JumpBackCode, jumpBackSize, offset);
            offset += jumpBackSize;
            
            refNextInstruction++;
        }

        spdlog::info("Redefines:");
        for (auto& redefine : Facades)
        {
            auto hook = redefine.second.Redefine;
            auto placement = redefine.first;
            Address const jumpBase = reinterpret_cast<BYTE*>(placement) + JumpR32lInstructionLength;
            Address const jumpTo = hook->Function;

            redefine.second.FacadeCallerBlockCode.Offset = relative_offset(jumpBase, jumpTo);
            dbgr.Memory.Write(placement, &redefine.second.FacadeCallerBlockCode, JumpCodeSize);
            spdlog::info("::0x{0:x} --> 0x{1:x} ({2})", 
                placement, jumpTo, hook->FunctionName
            );
        }
    }
    HookInjector::~HookInjector()
    {
        Memory.Free(*NextInstructionsVmh);
        Memory.Free(*ProgramVmh);
    }
}
