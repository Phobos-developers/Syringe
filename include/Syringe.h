/*
    SYRINGE.H
    ---------
    Holds macros, structures, classes that are necessary to interact with Syringe correctly.
                                                                                        -pd
    ---------
    It was extended for new injector features like hooks on dynamic linking libraries.
    Also SYR_VER macro removed.
                                                                                        -Multfinite
*/

#ifndef SYRINGE_H
#define SYRINGE_H
#include <windows.h>
#include "declaration.hpp"

class LimitedRegister {
protected:
    DWORD data;

    WORD* wordData() {
        return reinterpret_cast<WORD*>(&this->data);
    }

    BYTE* byteData() {
        return reinterpret_cast<BYTE*>(&this->data);
    }

public:
    WORD Get16() {
        return *this->wordData();
    }

    template<typename T>
    inline T Get() {
        return *reinterpret_cast<T*>(&this->data);
    }

    template<typename T>
    inline void Set(T value) {
        this->data = DWORD(value);
    }

    void Set16(WORD value) {
        *this->wordData() = value;
    }
};

class ExtendedRegister : public LimitedRegister {
public:
    BYTE Get8Hi() {
        return this->byteData()[1];
    }

    BYTE Get8Lo() {
        return this->byteData()[0];
    }

    void Set8Hi(BYTE value) {
        this->byteData()[1] = value;
    }

    void Set8Lo(BYTE value) {
        this->byteData()[0] = value;
    }
};

class StackRegister : public ExtendedRegister {
public:
    template<typename T>
    inline T* lea(int byteOffset) {
        return reinterpret_cast<T*>(static_cast<DWORD>(this->data + static_cast<DWORD>(byteOffset)));
    }

    inline DWORD lea(int byteOffset) {
        return static_cast<DWORD>(this->data + static_cast<DWORD>(byteOffset));
    }

    template<typename T>
    inline T At(int byteOffset) {
        return *reinterpret_cast<T*>(this->data + static_cast<DWORD>(byteOffset));
    }

    template<typename T>
    inline void At(int byteOffset, T value) {
        *reinterpret_cast<T*>(this->data + static_cast<DWORD>(byteOffset)) = value;
    }
};

//Macros to make the following a lot easier
#define REG_SHORTCUTS(reg) \
    inline DWORD reg() \
        { return this->_ ## reg.Get<DWORD>(); } \
    template<typename T> inline T reg() \
        { return this->_ ## reg.Get<T>(); } \
    template<typename T> inline void reg(T value) \
        { this->_ ## reg.Set(value); } \

#define REG_SHORTCUTS_X(r) \
    DWORD r ## X() \
        { return this->_E ## r ## X.Get16(); } \
    void r ## X(WORD value) \
        { this->_E ## r ## X.Set16(value); } \

#define REG_SHORTCUTS_HL(r) \
    DWORD r ## H() \
        { return this->_E ## r ## X.Get8Hi(); } \
    void r ## H(BYTE value) \
        { this->_E ## r ## X.Set8Hi(value); } \
    DWORD r ## L() \
        { return this->_E ## r ## X.Get8Lo(); } \
    void r ## L(BYTE value) \
        { this->_E ## r ## X.Set8Lo(value); } \

#define REG_SHORTCUTS_XHL(r) \
    REG_SHORTCUTS_X(r); \
    REG_SHORTCUTS_HL(r); \

//A pointer to this class is passed as an argument to EXPORT functions
class REGISTERS
{
private:
    DWORD            origin;
    DWORD            flags;

    LimitedRegister  _EDI;
    LimitedRegister  _ESI;
    StackRegister    _EBP;
    StackRegister    _ESP;
    ExtendedRegister _EBX;
    ExtendedRegister _EDX;
    ExtendedRegister _ECX;
    ExtendedRegister _EAX;

public:
    DWORD Origin() {
        return this->origin;
    }

    DWORD EFLAGS() {
        return this->flags;
    }

    void EFLAGS(DWORD value) {
        this->flags = value;
    }

    REG_SHORTCUTS(EAX);
    REG_SHORTCUTS(EBX);
    REG_SHORTCUTS(ECX);
    REG_SHORTCUTS(EDX);
    REG_SHORTCUTS(ESI);
    REG_SHORTCUTS(EDI);
    REG_SHORTCUTS(ESP);
    REG_SHORTCUTS(EBP);

    REG_SHORTCUTS_XHL(A);
    REG_SHORTCUTS_XHL(B);
    REG_SHORTCUTS_XHL(C);
    REG_SHORTCUTS_XHL(D);

    template<typename T>
    inline T lea_Stack(int offset) {
        return reinterpret_cast<T>(this->_ESP.lea(offset));
    }

    template<>
    inline DWORD lea_Stack(int offset) {
        return this->_ESP.lea(offset);
    }

    template<>
    inline int lea_Stack(int offset) {
        return static_cast<int>(this->_ESP.lea(offset));
    }

    template<typename T>
    inline T& ref_Stack(int offset) {
        return *this->lea_Stack<T*>(offset);
    }

    template<typename T>
    inline T Stack(int offset) {
        return this->_ESP.At<T>(offset);
    }

    DWORD Stack32(int offset) {
        return this->_ESP.At<DWORD>(offset);
    }

    WORD Stack16(int offset) {
        return this->_ESP.At<WORD>(offset);
    }

    BYTE Stack8(int offset) {
        return this->_ESP.At<BYTE>(offset);
    }

    template<typename T>
    inline T Base(int offset) {
        return this->_EBP.At<T>(offset);
    }

    template<typename T>
    inline void Stack(int offset, T value) {
        this->_ESP.At(offset, value);
    }

    void Stack16(int offset, WORD value) {
        this->_ESP.At(offset, value);
    }

    void Stack8(int offset, BYTE value) {
        this->_ESP.At(offset, value);
    }

    template<typename T>
    inline void Base(int offset, T value) {
        this->_EBP.At(offset, value);
    }
};

//Use this for DLL export functions
//e.g. EXPORT FunctionName(REGISTERS* R)
#define EXPORT extern "C" __declspec(dllexport) DWORD __cdecl
#define EXPORT_FUNC(name) extern "C" __declspec(dllexport) DWORD __cdecl name (REGISTERS *R)


//Handshake definitions
struct SyringeHandshakeInfo
{
    int          cbSize;
    int          num_hooks;
    unsigned int checksum;
    DWORD        exeFilesize;
    DWORD        exeTimestamp;
    unsigned int exeCRC;
    int          cchMessage;
    char*        Message;
};

#define SYRINGE_HANDSHAKE(pInfo) extern "C" __declspec(dllexport) HRESULT __cdecl SyringeHandshake(SyringeHandshakeInfo* pInfo)

/*
#define DEFINE_INITIALIZER extern "C" __declspec(dllexport) DWORD __cdecl Initialize(Injector::Structures::InjectionContext* pInjectionContext)
*/
namespace SyringeData 
{
    namespace    Hooks {};
    namespace    Hosts {};
    namespace    FunctionReplacements {};
};

#define declhost(exename, checksum) \
namespace SyringeData { namespace Hosts { __declspec(allocate(".syexe00")) HostDecl _hst__ ## exename = { checksum, #exename }; }; };

#define declhook(hook, funcname, size) \
namespace SyringeData { namespace Hooks { __declspec(allocate(".syhks00")) HookDecl _hk__ ## hook ## funcname = { ## hook, ## size, #funcname }; }; };

#define decldllhook(prefix, name, checksum, hook, funcname, size) \
namespace SyringeData { namespace Hooks { __declspec(allocate(".syhks01")) ExtendedHookDecl _hk__ ## prefix ## hook ## funcname = { ## hook, ## size, #funcname, #name, ## checksum }; }; };

#define declarefunctionreplacement0(prefix, name, checksum, targetname, funcname) \
namespace SyringeData { namespace FunctionReplacements { __declspec(allocate(".syfrh00")) FunctionReplacement0Decl _fr0__ ## prefix ## hook ## funcname = { #targetname, #funcname, #name, ## checksum }; }; };

#define declarefunctionreplacement1(prefix, name, checksum, targetaddr, funcname) \
namespace SyringeData { namespace FunctionReplacements { __declspec(allocate(".syfrh01")) FunctionReplacement1Decl _fr1__ ## prefix ## hook ## funcname = { #targetaddr, #funcname, #name, ## checksum }; }; };

// Defines a hook at the specified address with the specified name and saving the specified amount of instruction bytes to be restored if return to the same address is used. In addition to the injgen-declaration, also includes the function opening.
#define DEFINE_HOOK(hook, funcname, size) \
declhook(hook, funcname, size) \
EXPORT_FUNC(funcname)
// Does the same as DEFINE_HOOK but no function opening, use for injgen-declaration when repeating the same hook at multiple addresses.
// CAUTION: funcname must be the same as in DEFINE_HOOK.
#define DEFINE_HOOK_AGAIN(hook, funcname, size) \
declhook(hook, funcname, size)

// Defines a hook at the specified address with the specified name and saving the specified amount of instruction bytes to be restored if return to the same address is used. In addition to the injgen-declaration, also includes the function opening.
// checksum: 0 - any module version, specific value - for module with specific checksum
// name: nullptr - on executable, any string literal "Ares.dll" - for specific module
// prefix - just for split hook on same addresses but on different modules. for example: ares
// DEFINE_HOOK_EX(0x0, "MY_HOOK", 5, kernel32, "kernel32.dll", 0xFFFFFFFF)
#define DEFINE_HOOK_EX(hook, funcname, size, prefix, name, checksum) \
decldllhook(prefix, name, checksum, hook, funcname, size) \
EXPORT_FUNC(funcname)
// Does the same as DEFINE_HOOK_EX but no function opening, use for injgen-declaration when repeating the same hook at multiple addresses.
// CAUTION: funcname must be the same as in DEFINE_HOOK_EX.
#define DEFINE_HOOK_EX_AGAIN(hook, funcname, size, prefix, name, checksum) \
decldllhook(prefix, name, checksum, hook, funcname, size)

// this is only static declaration like DEFINE_HOOK_AGAIN & DEFINE_HOOK_AGAIN_EX and can be in any place of program
// originalname is the function name which will be decorated
#define REDEFINE_FUNCTION(originalname, funcname, prefix, name, checksum) \
declarefunctionreplacement0(prefix, name, checksum, originalname, funcname)

// this is contains function delcaration too
// originalname is the function name which will be decorated
#define REDEFINE_FUNCTION(originalname, funcname, prefix, name, checksum, rettype, ...) \
declarefunctionreplacement0(prefix, name, checksum, originalname, funcname) \
rettype funcname(__VA_ARGS__)

// this is only static declaration like DEFINE_HOOK_AGAIN & DEFINE_HOOK_AGAIN_EX and can be in any place of program
// targetaddr is address which will be decorated
#define REDEFINE_AT(targetaddr, funcname, prefix, name, checksum) \
declarefunctionreplacement1(prefix, name, checksum, targetaddr, funcname)

// this is contains function delcaration too
// targetaddr is address which will be decorated
#define REDEFINE_AT(targetaddr, funcname, prefix, name, checksum, rettype, ...) \
declarefunctionreplacement1(prefix, name, checksum, targetaddr, funcname, rettype, ...) \
rettype funcname(__VA_ARGS__)

#endif
