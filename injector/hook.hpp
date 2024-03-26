#ifndef INJECTOR_HOOK_HPP
#define INJECTOR_HOOK_HPP

#include "framework.hpp"

namespace Injector
{
    class Module;
    enum class HookType
    {
        Unknown  = 0,
        /* HookDecl */
        Generic  = 1,
        /* ExtendedHookDecl */
        Extended = 2,
        /* FunctionReplacemen0tDecl */
        FacadeByName = 3,
        /* FunctionReplacement1Decl */
        FacadeAtAddress = 4
    };
    class Hook final
    {
        friend class Module;
    public:
        using Variant = std::variant<HookDecl, ExtendedHookDecl, FunctionReplacement0Decl, FunctionReplacement1Decl>;

        HookType    const Type = HookType::Unknown;
        Variant     const Decl;
        std::string const FunctionName;

        HookFunction Function       { nullptr };
        Address      Placement      { nullptr };
        std::string  PlacementFunction = "";
        Address      ModuleBase     { nullptr };
        std::string  ModuleName     = "";
        unsigned int ModuleChecksum = 0;
        size_t       Size           = 0;
    private:
    public:
        Hook(std::string functionName, Address address, size_t size);
        Hook(std::string functionName, HookDecl& decl);
        Hook(std::string functionName, ExtendedHookDecl& decl);
        Hook(std::string functionName, FunctionReplacement0Decl& decl);
        Hook(std::string functionName, FunctionReplacement1Decl& decl);
    };
}

#endif //INJECTOR_HOOK_HPP
