#include "hook.hpp"

namespace Injector
{
    inline HookDecl decl(Address address, size_t size, Address functionNamePtr)
    {
        HookDecl h;
        h.Address         = (DWORD) address;
        h.Size            = size;
        h.FunctionNamePtr = (DWORD) functionNamePtr;
        return h;
    }

    Hook::Hook(std::string functionName, Address address, size_t size) 
        : Hook(functionName, decl(address, size, nullptr)) {}
    Hook::Hook(std::string functionName, HookDecl& decl) :
        Type(HookType::Generic),
        FunctionName(functionName),
        Decl(decl)
    {}
    Hook::Hook(std::string functionName, ExtendedHookDecl& decl) :
        Type(HookType::Extended),
        FunctionName(functionName),
        Decl(decl)
    {}
    Hook::Hook(std::string functionName, FunctionReplacement0Decl& decl) :
        Type(HookType::FacadeByName),
        FunctionName(functionName),
        Decl(decl)
    {}
    Hook::Hook(std::string functionName, FunctionReplacement1Decl& decl) :
        Type(HookType::FacadeAtAddress),
        FunctionName(functionName),
        Decl(decl)
    {}
}
