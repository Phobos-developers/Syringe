#ifndef INJECTOR_ELEMENTS_HPP
#define INJECTOR_ELEMENTS_HPP

namespace Injector
{
    static constexpr const char*  InitializerFunctionName    = "Initialize";
    static constexpr const char*  GenericHooksPESectionName  = ".syhks00";
    static constexpr const char*  HostsPESectionName         = ".syexe00";
    static constexpr const char*  ExtendedHooksPESectionName = ".syhks01";
    static constexpr const char* FunctionReplacementsByNamePESectionName = ".syfrh00";
    static constexpr const char* FunctionReplacementsByAddressPESectionName = ".syfrh01";
    static constexpr const char*  HandshakeFunctionName      = "SyringeHandshake";    
    static constexpr       size_t MaxFilenameLength          = 0x100;
    static constexpr       size_t MaxFunctionNameLength      = 0x100u;
}

#endif // INJECTOR_ELEMENTS_HPP
