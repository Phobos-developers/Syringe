#ifndef INJECTOR_MODULE_HPP
#define INJECTOR_MODULE_HPP

#include <portable_executable.hpp>
#include <handle.win.hpp>
#include <exceptions.win.hpp>
#include <winapi.utilities.hpp>

#include "framework.hpp"
#include "hook.hpp"

namespace Injector
{
    using namespace Utilities;
    using namespace Exceptions;

    struct executable_not_supported_error : public base_error
    {
        std::string const FileName;

        executable_not_supported_error(std::string function, std::string file, int line, std::string_view const& fileName) : base_error("Executable not supported  by " + std::string(fileName), function, file, line), FileName(fileName) {}
        executable_not_supported_error(std::string msg, std::string function, std::string file, int line, std::string_view const& fileName) : base_error(msg, function, file, line), FileName(fileName) { }
    };

    struct file_read_error : public base_error
    {
        file_read_error(std::string function, std::string file, int line) : base_error("File read not possible", function, file, line) {}
        file_read_error(std::string msg, std::string function, std::string file, int line) : base_error(msg, function, file, line) { }
    };
    struct non_injectable_module_error : public base_error
    {
        enum class Type
        {
            MissingHosts = 0,
            MissingInj   = 1
        };

        Type What;
        std::string const FileName;

        non_injectable_module_error(std::string function, std::string file, int line, std::string_view const& fileName, Type what) : base_error("Module (" + std::string(fileName) + ") not injectable", function, file, line), FileName(fileName), What(what) {}
        non_injectable_module_error(std::string msg, std::string function, std::string file, int line, std::string_view const& fileName, Type what) : base_error(msg, function, file, line), FileName(fileName), What(what) { }
    };

    class Module final
    {
    public:
        struct Host
        {
            std::string  const FileName;
            unsigned int const Checksum;

            Host() = default;
            Host(std::string fileName, unsigned int checksum) : FileName(fileName), Checksum(checksum) {}
        };

        string       FileName;
        Utilities::FileVersionInformation FVI;
        unsigned int Checksum;
        list<Hook>   Hooks;
        list<Host>   Hosts;
        // it's idea about Initialize(...) function concept, which invokes before main thread resumed or at moment when it's resumed. Invocation not implemented. Just use hook at top of program.
        InitFunction InitFunction;
    private:
        HMODULE                    _handle;
        unique_ptr<HMODULE>        _injectorHandle;
        std::ifstream              _ifs;
        PECOFF::PortableExecutable _pe;

        void parse_hosts();
        void parse_generic_hooks();
        void parse_extended_hooks();
        void parse_function_replacements_type0();
        void parse_function_replacements_type1();
        void parse_inj_file(string_view const& injFileName);
    public:
        std::istream&                     stream()   { return _ifs; }
        PECOFF::PortableExecutable const& pe() const { return _pe; }

        Module() = default;
        Module(string_view const& fileName);
        Module(string_view const& fileName, string_view const& injFileName);

        void parse(string_view const& fileName);
        void parse(string_view const& fileName, string_view const& injFileName);

        bool is_host_supported(string_view const& executableFile, unsigned int checksum = 0);
        bool is_executable_supported(string_view const& executableFile, unsigned int checksum = 0);
        bool handshake();

        HMODULE get_handle() const { return _handle; }
        void    set_handle(HMODULE value) { _handle = value; }

        HMODULE get_injector_handle() const { return *_injectorHandle.get(); }
        void    set_injector_handle(HMODULE value) { _injectorHandle = make_unique<HMODULE>(value); }
    };
}
#endif //INJECTOR_MODULE_HPP
