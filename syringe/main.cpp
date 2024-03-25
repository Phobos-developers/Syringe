#include <iostream>
#include <string>
#include <string_view>

#define SPDLOG_HEADER_ONLY
#include <spdlog/spdlog.h>

#include <cmd_line_parser.hpp>
#include <debugger.hpp>
#include <configurator.hpp>

using namespace std;
using namespace Injector;
using namespace PECOFF;

int ParseModule(
    Module& mdl, 
    bool forceExecutableValidation,
    bool stopIfModuleInvalid)
{
    try
    {
        mdl.parse(mdl.FileName);
        spdlog::info("::\"{0}\": {1} hooks & {2} hosts found, checksum: 0x{3:x} ({3:d})", mdl.FileName, mdl.Hooks.size(), mdl.Hosts.size(), mdl.Checksum);
        for (auto& host : mdl.Hosts)
            spdlog::trace(":::: 0x{1:x}, \"{0}\"", host.FileName, host.Checksum);
    }
    catch (file_not_found_error const& ex)
    {
        auto msg = Utilities::string_format("File not found: \"%s\".", ex.FileName.c_str());
        spdlog::error("::\"{}\": File not found.", ex.FileName);
        if (stopIfModuleInvalid)
        {
            MessageBoxA(
                nullptr,
                msg.c_str(),
                "Invalid configuration.",
                MB_OK);
            return EXIT_FAILURE;
        }
    }
    catch (non_injectable_module_error const& ex)
    {
        auto msg = Utilities::string_format("Couldn't inject dll: %s.\nThis is not injectable.", ex.FileName.c_str());
        spdlog::error("::\"{}\": not injectable.", ex.FileName);
        if (stopIfModuleInvalid)
        {
            MessageBoxA(
                nullptr,
                msg.c_str(),
                "Invalid configuration.",
                MB_OK);
            return EXIT_FAILURE;
        }
    }
    catch (executable_not_supported_error const& ex)
    {
        auto msg = Utilities::string_format("Couldn't inject dll: %s.\Executable not supported by module.\nYou can disable '-forceExecutableValidation' to skip checking.", ex.FileName.c_str());
        spdlog::error("::\"{}\": executable not supported.", ex.FileName);
        if (stopIfModuleInvalid) 
        {
            MessageBoxA(
                nullptr,
                msg.c_str(),
                "Invalid configuration.",
                MB_OK);
            return EXIT_FAILURE;
        }
    }
    catch (const file_read_error& ex)
    {
        auto msg = Utilities::string_format("File not found/not readable: %s.", mdl.FileName.c_str());
        spdlog::error("::\"{}\": File not found/not readable", mdl.FileName);
        if (stopIfModuleInvalid)
        {
            MessageBoxA(
                nullptr,
                msg.c_str(),
                "Invalid configuration.",
                MB_OK);
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

int ParseModules(
    list<Module>& modules, 
    bool forceExecutableValidation,
    bool processWithEmptyModules,
    bool stopIfModuleInvalid)
{
    if (modules.empty() && !processWithEmptyModules)
    {
        spdlog::error("No modules to inject.");
        MessageBoxA(
            nullptr,
            "No modules to inject.",
            "Invalid configuration.",
            MB_OK);
        return EXIT_FAILURE;
    }
    list<Module*> notAccepted;
    for (auto& mdl : modules)
    {
        auto r = ParseModule(mdl, forceExecutableValidation, stopIfModuleInvalid);
        if (r != EXIT_SUCCESS)
        {
            notAccepted.push_back(&mdl);
            if (stopIfModuleInvalid)
                return r;
        }
    }
    for (auto& mdl : notAccepted)
        modules.remove_if([&](Module& a) -> bool { return a.FileName == mdl->FileName; });
    
    for (auto& mdl : modules)
    {
        spdlog::info("::\"{0}\" - checking for redefines", mdl.FileName);
        for (auto& hook : mdl.Hooks)
        {
            bool isInExecutable = hook.ModuleName.empty();
            auto hookModuleName = isInExecutable ? "executable" : "\"" + hook.ModuleName + "\"";
            if (hook.Type == HookType::FacadeByName)
            {
                auto localDll = isInExecutable ? modules.cbegin() : std::find_if(modules.cbegin(), modules.cend(),
                    [&hook](const Module& m) -> bool
                    {
                        auto ofnp = std::filesystem::path(m.FVI.Loaded ? m.FVI.OriginalFilename : m.FileName);
                        auto ofn = ofnp.filename(); // .stem(); no extension
                        auto mfnp = std::filesystem::path(hook.ModuleName);
                        auto mfn = mfnp.filename(); //.stem();
                        return ofn == mfn;
                    }
                );
                if (localDll == modules.cend())
                {
                    spdlog::warn("::::Redefine {0} for {1}::{2} can not be resolved - target module not found in LOCAL injector list.",
                        hook.FunctionName, hookModuleName, hook.PlacementFunction
                    );
                    break;
                }

                hook.Placement = GetProcAddress(localDll->get_handle(), hook.PlacementFunction.c_str());
                if (!hook.Placement)
                {
                    spdlog::warn("::::Redefine {0} for {1}::{2} can not be resolved - target function not defined in target module.",
                        hook.FunctionName, hookModuleName, hook.PlacementFunction
                    );
                    break;
                }
                spdlog::info("::::Redefine {0} for {1}::{2} = 0x{3:x}.",
                    hook.FunctionName, hookModuleName, hook.PlacementFunction, hook.Placement
                );
            }
            else if (hook.Type != HookType::FacadeAtAddress)
                continue;

            for (auto& m : modules)
            {
                for (auto& h : m.Hooks)
                {
                    auto isRedefine = hook.Type == HookType::FacadeByName || hook.Type == HookType::FacadeAtAddress;
                    if (!isRedefine)
                        continue;
                    if (hook.Placement != h.Placement)
                        continue;
                    auto hModuleName = h.ModuleName.empty() ? "executable" : "\"" + h.ModuleName + "\"";
                    spdlog::warn("::::Redefine conflict between ({0} for {1}::0x{2:x}) and ({3} for {4}::0x{5:x}).",
                        hook.FunctionName, hookModuleName, hook.Placement,
                        h.FunctionName, hModuleName, h.Placement
                    );
                }
            }
        }
    }
    return EXIT_SUCCESS;
}

int Run(std::string_view const arguments)
{
    auto file_logger = spdlog::basic_logger_mt("file-logger", "syringe.log", true);

    spdlog::set_pattern("%v");
    spdlog::set_level(spdlog::level::trace);
    spdlog::set_default_logger(file_logger);

    spdlog::trace("Command line: '{}'", arguments);

    string       executableFile;
    // UPD: the first entry - executable view as module
    list<Module> modules; 
    bool         forceExecutableValidation = false;
    bool         processWithEmptyModules   = true;
    bool         stopIfModuleInvalid       = false;

    unsigned int executableChecksum        = 0;

    try
    {
        ArgumentMap* map = ParseArguments(const_cast<TCHAR*>(arguments.data()));
        if (!map->HasFreeParameters())
        {
            spdlog::error("Executable path not specified. It MUST be first parameter of command line.");
            MessageBoxA(
                nullptr,
                "First argument must be executable file path.",
                "Invalid configuration.",
                MB_OK);
            return EXIT_FAILURE;
        }
        executableFile = map->FreeParameters()->Parameters[0];

        executableChecksum = CRC32::compute_stream(file_open_binary(executableFile));
        spdlog::info("Executable \"{0}\", checksum: 0x{1:x} ({1:d})", executableFile, executableChecksum);

        size_t moduleCount = 0;
        for (size_t i = 0; i < map->Count(); i++)
        {
            auto    arg    = map->At(i);
            if ((string) arg->Prefix == (string) "-forceExecutableValidation")
                forceExecutableValidation = true;
            else if ((string) arg->Prefix == (string)"-requireInjectableModules")
                processWithEmptyModules = false;
            else if ((string) arg->Prefix == (string)"-requireValidConfiguration")
                stopIfModuleInvalid = true;
            else if ((string) arg->Prefix == (string) "-dll")
                moduleCount++;
        }

        if (moduleCount > 0)
        {
            spdlog::info("Modules to inject was directly specified:");

            modules.resize(moduleCount + 1);
            moduleCount = 0;

            std::next(modules.begin(), moduleCount++)->FileName = executableFile;           
            for (size_t i = 0; i < map->Count(); i++)
            {
                auto    arg = map->At(i);
                if ((string) arg->Prefix != (string) "-dll")
                    continue;

                auto fn = arg->Parameters[0];
                std::next(modules.begin(), moduleCount++)->FileName = fn;
            }
        }
        else
        {
            spdlog::info("Modules to inject not specified, scan directory (\"{0}\"):", std::filesystem::current_path().string());

            modules.emplace_back().FileName = executableFile;
            for (const auto& e : std::filesystem::directory_iterator(std::filesystem::current_path()))
            {
                if (!e.is_regular_file())
                    continue;
                if (e.path().has_extension() && e.path().extension().string() == (string)".dll")
                {
                    auto& mdl    = modules.emplace_back();
                    mdl.FileName = e.path().filename().string();
                }
            }
        }        

        for(auto& mdl : modules)
            spdlog::info("::\"{0}\"", mdl.FileName);

        spdlog::info("Parse modules for hosts & hooks");
        auto r = ParseModules(modules, forceExecutableValidation, processWithEmptyModules, stopIfModuleInvalid);
        if (r != EXIT_SUCCESS)
            return r;
    }
    catch (ArgumentMap::StringIsEmptyException& ex)
    {
        MessageBoxA(
            nullptr,
            "Couldn't parse arguments: string is empty.",
            "Invalid configuration.",
            MB_OK);
        return EXIT_FAILURE;
    }    

    PortableExecutable peExecutable { file_open_binary(executableFile) };
    Kernel32 kernel { peExecutable };
    if(!kernel.is_injectable())
    {
        MessageBoxA(
            nullptr, 
            "Import section does not contains KERNEL32.DLL with LOADLIBRARYA, GETPROCADDRESS, FREELIBRARY functions.", 
            "Not injectable.",
            MB_OK);        
        return EXIT_FAILURE;
    }

    spdlog::info("Prepare debugger & process...");
    Debugger::DebugLoop debugger { executableFile, arguments, /* We do not want to lost all applies after debugger detach (by other, real debugger, attaching) */ false };
    spdlog::info("Prepare configurator...");
    Configurator configurator { peExecutable, debugger, /*kernel,*/ modules, arguments, executableFile};
    spdlog::info("Run debugger...");
    debugger.Run();
    spdlog::info("Injector & debugger done.");
    return EXIT_SUCCESS;
}

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(nCmdShow);

    std::string args = lpCmdLine;

    return Run(args);
}
