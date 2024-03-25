#ifndef INJECTOR_HOOK_INJECTOR_HPP
#define INJECTOR_HOOK_INJECTOR_HPP

#include <portable_executable.hpp>
#include <process_memory.hpp>
#include <debugger.hpp>

#include "framework.hpp"
#include "module.hpp"
#include "misc_code.hpp"
#include "get_function_code.hpp"

namespace Injector
{
    BYTE const RegistersBuildCodeData[] =
    {
        PUSHAD, PUSHFD,              // It creates REGISTERS structure
        PUSH_INTO_STACK(INIT_DWORD), // Push address of hook
        PUSH_ESP,                    // At the top of stack will be REGISTER, and it pushes this* for it
    };
    static constexpr size_t RegistersBuildCodeDataSize = sizeof(RegistersBuildCodeData);

    #pragma pack(push, 1)
    struct RegistersBuildCode
    {
        BYTE Pushad;
        BYTE Pushfd;
        BYTE PUSH_MEM_OpCode;
        Address HookAddress;
        BYTE PUSH_ESP_OpCode;

        RegistersBuildCode()
        {
            memcpy(this, RegistersBuildCodeData, RegistersBuildCodeDataSize);
        }
        RegistersBuildCode(Address hookAddress)
        {
            memcpy(this, RegistersBuildCodeData, RegistersBuildCodeDataSize);

            HookAddress = hookAddress;
        }
    };
    static constexpr size_t RegistersBuildCodeSize = sizeof(RegistersBuildCode);
    #pragma pack(pop)
    static_assert(RegistersBuildCodeSize == RegistersBuildCodeDataSize, "The code and data are not equals");

    BYTE const RegistersCleanupCodeData[] =
    {
        ADD_ESP(0x08), // Remove REGISTERS* from stack
        POPFD, POPAD   // Clear registers content from stack
    };
    static constexpr size_t RegistersCleanupCodeDataSize = sizeof(RegistersCleanupCodeData);

    #pragma pack(push, 1)
    struct RegistersCleanupCode
    {
        BYTE AddEsp[2];
        BYTE AddEsp_Value;
        BYTE Popfd;
        BYTE PopAd;

        RegistersCleanupCode()
        {
            memcpy(this, RegistersCleanupCodeData, RegistersCleanupCodeDataSize);
        }
    };
    static constexpr size_t RegistersCleanupCodeSize = sizeof(RegistersCleanupCode);
    #pragma pack(pop)
    static_assert(RegistersCleanupCodeSize == RegistersCleanupCodeDataSize, "The code and data are not equals");

    BYTE const HookCallCodeData[] =
    {
        CALL_R32(INIT_PTR),                    // Invoke Hook function
        MOV_EAX_TO(INIT_PTR),                  // Save result of hook function, ds:ReturnEIP
        CMP_PTR32_IMM32(INIT_PTR, 0x00),       // Test result for zero (it is address)  | CMP ds:ReturnEIP, 0
        JZ_R8(0x15),                           // Jump the next instruction outse hook caller (there must be placed overriden bytes with jumb back or another hook caller block
        ADD_PTR32_IMM32(INIT_PTR, INIT_DWORD), // Make correction of base for hook module. For executable itself it must be 0. | add dword ptr[ds:ReturnEIP], MODULE BASE (Handle)
        ADD_ESP(0x08),                         // Remove REGISTERS* from stack
        POPFD, POPAD,                          // Clear registers content from stack
        JMP_PTR32(INIT_PTR),                   // Jump to returned address | JMP ds:ReturnEIP
    };
    static constexpr size_t HookCallCodeDataSize = sizeof(HookCallCodeData);
    static constexpr size_t HookCallCodeCallOffset = 8;

    #pragma pack(push, 1)
    struct HookCallCode
    {
        BYTE    CALL_OpCode;
        DWORD   FunctionProcRelativeAddress;
        BYTE    MOV_EAX_OpCode;
        Address RefNextInstruction1;
        BYTE    CMP_ReturnEIP_OpCode_1;
        BYTE    CMP_ReturnEIP_OpCode_2;
        Address RefNextInstruction2;
        BYTE    NULL_VALUE;
        BYTE    JZ_OpCode_1;
        BYTE    JZ_OpCode_2;
        BYTE    ADD_PTR32_IMM32_0[2];
        Address RefNextInstruction3;
        DWORD   ModuleBase;
        BYTE    ADD_ESP_1_OpCode;
        BYTE    ADD_ESP_2_OpCode;
        BYTE    ADD_ESP_3_OpCode;
        BYTE    POP_FD_OpCode;
        BYTE    POP_AD_OpCode;
        BYTE    JMP_ReturnEip_OpCode_1;
        BYTE    JMP_ReturnEip_OpCode_2;
        Address RefNextInstruction4;

        HookCallCode()
        {
            memcpy(this, HookCallCodeData, HookCallCodeDataSize);
        }
        HookCallCode(
            Address refNextInstruction,
            Address base, 
            HookFunction hookFunction,
            Address moduleBase)
        {
            memcpy(this, HookCallCodeData, HookCallCodeDataSize);
            
            ModuleBase          = reinterpret_cast<DWORD>(moduleBase);

            RefNextInstruction1 = refNextInstruction;
            RefNextInstruction2 = refNextInstruction;
            RefNextInstruction3 = refNextInstruction;
            RefNextInstruction4 = refNextInstruction;

            FunctionProcRelativeAddress = relative_offset(
                reinterpret_cast<BYTE*>(base) + HookCallCodeCallOffset + CallR32InstructionLength, 
                static_cast<Address>(hookFunction));
        }
    };
    static constexpr size_t HookCallCodeSize = sizeof(HookCallCode);
    #pragma pack(pop)

    static_assert(HookCallCodeSize == HookCallCodeDataSize, "The code and data are not equals");

    struct HookPocket
    {
        size_t               Offset = 0;
        list<Hook*>          Hooks;
        size_t               OverriddenCount = 0;

        JumpCode             HookCallerBlockCode;
        RegistersBuildCode   RegistersBuild;
        vector<HookCallCode> HookCallBlocks;
        RegistersCleanupCode RegistersCleanup;
        vector<BYTE>         OriginalBytes;
        JumpCode             JumpBackCode;
    };
    
    
    struct Facade
    {
        Hook* Redefine;

        JumpCode             FacadeCallerBlockCode;
    };

    class HookInjector final
    {
    public:
        ProcessMemory&           Memory;
        list<Module>&            Modules;

        VirtualMemoryHandle*     NextInstructionsVmh;
        VirtualMemoryHandle*     ProgramVmh;
        
        map<Address, HookPocket> Pockets;
        map<Address, Facade> Facades;

        HookInjector(Debugger::DebugLoop& dbg, list<Module>& modules);
        ~HookInjector();
    };
}
#endif //INJECTOR_HOOK_INJECTOR_HPP
