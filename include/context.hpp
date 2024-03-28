#ifndef INJECTOR_CONTEXT_HPP
#define INJECTOR_CONTEXT_HPP

#include <string>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#undef WIN32_LEAN_AND_MEAN

namespace Injector
{
    template<typename T>
    inline T& reference_cast(T* ptr) { return (T&)*ptr; /* reinterpret_cast<T&>(ptr); */ }

    template<typename T>
    inline T* offset_ptr(void* ptr, size_t offset = 0)
    {
        unsigned char* pointer = static_cast<unsigned char*>(ptr) + offset;
        return reinterpret_cast<T*>(pointer);
    }

    using std::string;

    /*!
    * @author Multfinite Multfinite@gmail.com
    * @brief This class should be used in injected dll to get access to injection context.
    */
    struct InjectionContextHandle
    {
        HANDLE   ShMemHandle;
        BYTE*    ShMemPtr;

        size_t*  DataSize;
        size_t*  ExecutableNameSize;
        char*    ExecutableNameInStruct;
        size_t*  ArgumentsSize;
        char*    ArgumentsInStruct;
        size_t*  NameLength;
        size_t*  ModuleSize;
        HMODULE* Handles;
        char*    Names;

        InjectionContextHandle()
        {
            DWORD  processId           = GetProcessId(GetCurrentProcess());
            string memName             = "InjContext-" + std::to_string(processId);

            ShMemHandle                = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, memName.data());
            ShMemPtr                   = static_cast<BYTE*>(MapViewOfFile(ShMemHandle, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(size_t)));
            size_t const dataSize      = *reinterpret_cast<size_t*>(ShMemPtr);
            UnmapViewOfFile(ShMemPtr);

            ShMemPtr                   = static_cast<BYTE*>(MapViewOfFile(ShMemHandle, FILE_MAP_ALL_ACCESS, 0, 0, dataSize));
            DataSize                   = offset_ptr<size_t>(ShMemPtr, 0);
            ExecutableNameSize         = offset_ptr<size_t>(DataSize, sizeof(size_t));
            ExecutableNameInStruct     = offset_ptr<char>(ExecutableNameSize, sizeof(size_t));
            ArgumentsSize              = offset_ptr<size_t>(ExecutableNameInStruct, *ExecutableNameSize + 1);
            ArgumentsInStruct          = offset_ptr<char>(ArgumentsSize, sizeof(size_t));
            NameLength                 = offset_ptr<size_t>(ArgumentsInStruct, *ArgumentsSize + 1);
            ModuleSize                 = offset_ptr<size_t>(NameLength, sizeof(size_t));
            Handles                    = offset_ptr<HMODULE>(ModuleSize, sizeof(size_t));
            Names                      = offset_ptr<char>(Handles, sizeof(HMODULE) * *ModuleSize);
        }
        ~InjectionContextHandle()
        {
            UnmapViewOfFile(ShMemPtr);
            CloseHandle(ShMemHandle);

            ShMemPtr               = nullptr;
            DataSize               = nullptr;
            ExecutableNameSize     = nullptr;
            ExecutableNameInStruct = nullptr;
            ArgumentsSize          = nullptr;
            ArgumentsInStruct      = nullptr;
            NameLength             = nullptr;
            ModuleSize             = nullptr;
            Handles                = nullptr;
            Names                  = nullptr;
        }
    };
}

#endif //INJECTOR_CONTEXT_HPP
