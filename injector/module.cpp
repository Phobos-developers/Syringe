#include <crc32.hpp>

#include "module.hpp"

namespace Injector
{
    using PE    = PECOFF::PortableExecutable;
    using CRC32 = Utilities::CRC32;

    void Module::parse_hosts()
    {
        auto& hostsSection = _pe.find_section(HostsPESectionName);
        auto const base    = _pe.PEHeader.OptionalHeader.ImageBase;
        auto const begin   = hostsSection.PointerToRawData;
        auto const end     = begin + hostsSection.SizeOfRawData;
        
        for (auto ptr = begin; ptr < end; ptr += sizeof(HostDecl))
        {
            std::string hostName;
            HostDecl h;
            if (PE::read_bytes(_ifs, ptr, sizeof(HostDecl), &h)    && h.NamePtr &&
                PE::read_cstring(_ifs, PE::virtual_to_raw(h.NamePtr - base, _pe.Sections), hostName))
            { 
                Hosts.emplace_back(hostName, h.Checksum);
            }
        }
    }
    void Module::parse_generic_hooks()
    {
        size_t const declSize = sizeof(HookDecl);

        auto const base       = _pe.PEHeader.OptionalHeader.ImageBase;

        auto&      section    = _pe.find_section(GenericHooksPESectionName);
        auto const begin      = section.PointerToRawData;
        auto const end        = begin + section.SizeOfRawData;

        for (auto ptr = begin; ptr < end; ptr += declSize)
        {
            HookDecl h;
            if (PE::read_bytes(_ifs, ptr, declSize, &h))
            {
                // msvc linker inserts arbitrary padding between variables that come
                // from different translation units
                if (h.FunctionNamePtr)
                {
                    std::string functionName;
                    if (PE::read_cstring(_ifs, PE::virtual_to_raw(h.FunctionNamePtr - base, _pe.Sections), functionName))
                    {
                        Hook& hook     = Hooks.emplace_back(functionName, h);
                        hook.Placement = reinterpret_cast<Address>(h.Address);
                        hook.Size      = h.Size;            
                    }
                }
            }
            else throw construct_error_no_msg(file_read_error);
        }
    }
    void Module::parse_extended_hooks()
    {
        size_t const declSize = sizeof(ExtendedHookDecl);

        auto const base       = _pe.PEHeader.OptionalHeader.ImageBase;

        auto&      section    = _pe.find_section(ExtendedHooksPESectionName);
        auto const begin      = section.PointerToRawData;
        auto const end        = begin + section.SizeOfRawData;

        for (auto ptr = begin; ptr < end; ptr += declSize)
        {
            ExtendedHookDecl h;
            if (PE::read_bytes(_ifs, ptr, declSize, &h))
            {
                // msvc linker inserts arbitrary padding between variables that come
                // from different translation units
                if(h.FunctionNamePtr)
                {
                    std::string functionName;
                    std::string moduleName;
                    if (PE::read_cstring(_ifs, PE::virtual_to_raw(h.FunctionNamePtr - base, _pe.Sections), functionName) &&
                        PE::read_cstring(_ifs, PE::virtual_to_raw(h.ModuleNamePtr - base, _pe.Sections), moduleName))
                    {
                        Hook& hook          = Hooks.emplace_back(functionName, h);
                        hook.Placement      = reinterpret_cast<Address>(h.Address);
                        hook.Size           = h.Size;                
                        hook.ModuleName     = moduleName;
                        hook.ModuleChecksum = h.ModuleChecksum;
                    }
                }
            }
            else throw construct_error_no_msg(file_read_error);
        }
    }
    void Module::parse_function_replacements_type0()
    {
        size_t const declSize = sizeof(FunctionReplacement0Decl);

        auto const base = _pe.PEHeader.OptionalHeader.ImageBase;

        auto& section = _pe.find_section(FunctionReplacementsByAddressPESectionName);

        auto const begin = section.PointerToRawData;
        auto const end = begin + section.SizeOfRawData;

        for (auto ptr = begin; ptr < end; ptr += declSize)
        {
            FunctionReplacement0Decl fr;
            if (PE::read_bytes(_ifs, ptr, declSize, &fr))
            {
                // msvc linker inserts arbitrary padding between variables that come
                // from different translation units
                if (fr.FunctionNamePtr)
                {
                    std::string functionName;
                    std::string moduleName;
                    std::string originalName;
                    if (PE::read_cstring(_ifs, PE::virtual_to_raw(fr.FunctionNamePtr - base, _pe.Sections), functionName) &&
                        PE::read_cstring(_ifs, PE::virtual_to_raw(fr.ModuleNamePtr - base, _pe.Sections), moduleName) &&
                        PE::read_cstring(_ifs, PE::virtual_to_raw(fr.OriginalFunctionNamePtr - base, _pe.Sections), originalName)
                        
                    ) {
                        Hook& hook = Hooks.emplace_back(functionName, fr);
                        hook.PlacementFunction = originalName;
                        hook.Size = 0; // jmp real size is 5
                        hook.ModuleName = moduleName;
                        hook.ModuleChecksum = fr.ModuleChecksum;
                    }
                }
            }
            else throw construct_error_no_msg(file_read_error);
        }
    }
    void Module::parse_function_replacements_type1()
    {
        size_t const declSize = sizeof(FunctionReplacement1Decl);

        auto const base = _pe.PEHeader.OptionalHeader.ImageBase;
      
        auto& section = _pe.find_section(FunctionReplacementsByNamePESectionName);

        auto const begin = section.PointerToRawData;
        auto const end = begin + section.SizeOfRawData;

        for (auto ptr = begin; ptr < end; ptr += declSize)
        {
            FunctionReplacement1Decl fr;
            if (PE::read_bytes(_ifs, ptr, declSize, &fr))
            {
                // msvc linker inserts arbitrary padding between variables that come
                // from different translation units
                if (fr.FunctionNamePtr)
                {
                    std::string functionName;
                    std::string moduleName;
                    if (PE::read_cstring(_ifs, PE::virtual_to_raw(fr.FunctionNamePtr - base, _pe.Sections), functionName) &&
                        PE::read_cstring(_ifs, PE::virtual_to_raw(fr.ModuleNamePtr - base, _pe.Sections), moduleName)
                    ) {
                        Hook& hook = Hooks.emplace_back(functionName, fr);
                        hook.Placement = reinterpret_cast<Address>(fr.Address);
                        hook.Size = 0; // jmp real size is 5
                        hook.ModuleName = moduleName;
                        hook.ModuleChecksum = fr.ModuleChecksum;
                    }
                }
            }
            else throw construct_error_no_msg(file_read_error);
        }
    }
    void Module::parse_inj_file(string_view const& injFileName)
    {
        std::string inj = file_read_text(injFileName.data());
        for (auto& line : string_split(inj, "\n"))
        {
            if (line.front() == ';')
                continue;

            std::string functionName; functionName.reserve(MaxFunctionNameLength);
            size_t      size    = 0;
            Address     address = nullptr;

            if (sscanf_s(line.c_str(), "%p = %[^ \t;,\r\n] , %x", 
                &address, 
                functionName.data(),
                MaxFunctionNameLength, 
                &size) >= 2)
            {
                Hook& hook     = Hooks.emplace_back(functionName, address, size);
                hook.Placement = address;
                hook.Size      = size;
            }
        }
    }

    Module::Module(string_view const& fileName, bool strictFVI)
    {
        parse(fileName, strictFVI);
    }
    void Module::parse(string_view const& fileName, bool strictFVI)
    {
        FileName        = fileName;
        _ifs            = file_open_binary(FileName);
        Checksum        = CRC32::compute_stream(_ifs);
        _pe             = PE(_ifs);
        _injectorHandle = make_unique<HMODULE>(LoadLibrary(FileName.c_str()));
        _handle         = nullptr;

        if (!_injectorHandle.get())
            throw construct_error_args_no_msg(load_library_error, fileName);

        try { FVI.Load(FileName); }
        catch (const Utilities::FileVersionInformation::fvi_load_error&)
        {
            if(strictFVI)
                throw construct_error(file_read_error, "Unable to read FileVersionInformation");
        }

        try { parse_hosts();          } catch(const PE::section_not_found_error&) { };
        try { parse_generic_hooks();  } catch(const PE::section_not_found_error&) { };
        try { parse_extended_hooks(); } catch(const PE::section_not_found_error&) { };
        try { parse_function_replacements_type0(); } catch(const PE::section_not_found_error&) { };
        try { parse_function_replacements_type1(); } catch(const PE::section_not_found_error&) { };
    }
    Module::Module(string_view const& fileName, string_view const& injFileName, bool strictFVI)
    {
        parse(fileName, injFileName, strictFVI);
    }
    void Module::parse(string_view const& fileName, string_view const& injFileName, bool strictFVI)
    {
        FileName        = fileName;
        _ifs            = file_open_binary(FileName);
        Checksum        = CRC32::compute_stream(_ifs);
        _pe             = PE(_ifs);
        _injectorHandle = make_unique<HMODULE>(LoadLibrary(FileName.c_str()));
        _handle         = nullptr;

        if (!_injectorHandle.get())
            throw construct_error_args_no_msg(load_library_error, fileName);

        try { FVI.Load(FileName); }
        catch (const Utilities::FileVersionInformation::fvi_load_error&)
        {
            if (strictFVI)
                throw construct_error(file_read_error, "Unable to read FileVersionInformation");
        }

        try { parse_inj_file(injFileName); } catch(const file_not_found_error&) { throw construct_error_args_no_msg(non_injectable_module_error, fileName, non_injectable_module_error::Type::MissingInj); };
    }

    bool Module::is_host_supported(string_view const& executableFile, unsigned int checksum)
    {
        auto executablePath     = std::filesystem::path(executableFile);
        auto executableFileName = executablePath.stem().string();
    
        auto iter = std::find_if(Hosts.cbegin(), Hosts.cend(), [&executableFileName, &checksum](Host const& item) -> bool
        {
            return executableFileName == item.FileName && (checksum == 0 || checksum == item.Checksum);
        });

        return iter != Hosts.cend();
    }
    bool Module::handshake()
    {
        auto const function = GetFunctionAddress<HandshakeFunction>(*_injectorHandle.get(), HandshakeFunctionName);
        if (function)
        {
            constexpr auto bufferLength = 0x100u;
            vector<char>   buffer(bufferLength + 1); // one more than we tell the dll

            HandshakeInfo   hsInfo;
            HandshakeResult hsResult;

            auto fs = file_open_binary(FileName);

            hsInfo.cbSize       = sizeof(HandshakeInfo);
            hsInfo.num_hooks    = Hooks.size();
            hsInfo.exeFilesize  = file_size(fs);
            hsInfo.checksum     = CRC32::compute_stream(fs);
            hsInfo.exeTimestamp = _pe.PEHeader.FileHeader.TimeDateStamp;
            hsInfo.cchMessage   = static_cast<int>(bufferLength);
            hsInfo.Message      = buffer.data();

            auto const result = function(&hsInfo);

            hsResult.Code = result;
            hsResult.Success = SUCCEEDED(result);

            return hsResult.Success;
        }
        return false;
    }
    bool Module::is_executable_supported(string_view const& executableFile, unsigned int checksum)
    {
        return is_host_supported(executableFile, checksum) || handshake();
    }
}
