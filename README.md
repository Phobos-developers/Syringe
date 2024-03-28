# License

- Files in `/include/` folder are made for export and its content are *API headers* as [LGPLv3](LICENSE) decribes.


The original location of this work is [HERE](http://forums.renegadeprojects.com/showthread.php?tid=1160&pid=13088#pid13088).

# Usage

*Injector is synonim of new syringe.*

You can just run injector as `Syringe ${filenameOfExecutable}`. In this case it will scans **current (working) directory (as original syringe does)** for dlls to inject.

Hook order is necessary. You must know that injector put all hooks into lists for each specified addresss of hook. So first processed injectable dll will be placed at beginning of 'hook pocket' and last will be placed at ending. It is really necessary when hook is reached then control flow transfers to hook pocket and some of hooks can move out of 'hook pocket'. **You can control order and list of dlls via `-dll`**.

Dlls that was made for original syringe is supported and all hooks of such dll are `generic hook` which described below.

## Command line

### Define specific dlls to inject and order of injection

Just use this command line argument: `-dll ${filenameOfDll}` as many as you need. Be sure that order of declared dlls with this method is ***Left-to-Right***. If any `-dll ${filenameOfDll}` present then directory scanning is disabled.

## Hook types

See defiitions and macroses at [`Include/Syringe.h`](Include/Syringe.h).

**Recommendation: always use *extended hook* instead of *generic hook* (and do not use `nullptr` case for name for extended hooks) to prevent problems with dynamic module base when basic address is different. Also, it should help with ASLR (need testing).**

### Generic Hook

Common original syringe hook. Can be placed only at executable and there is no any conditions for disable it.

**Macro:** `DEFINE_HOOK` & `DEFINE_HOOK_AGAIN`
**Parameters:**

1. ***Address***
    The address where hook will be placed.
    ***This is absolute address for hook placement: `AbsoluteAddress = ModuleBase + Offset`***.
2. ***Function name***
    Hook related function.
3. ***Overriden bytes (of instrutions)***
    Count of bytes to override at hook placement. Minimal: 5 (injector fix any smaller value). If 'hook pocket' executes all functions and there is no jump out then instruction of this bytes will be executed before jump back.

### Extended Hook

Extended version of generic hook. It is possible place it againts specific DLL and for specific checksum (CRC32) of target module.

**Macro:** `DEFINE_HOOK_EX` & `DEFINE_HOOK_EX_AGAIN`
**Parameters:**

1. ***Address***
    The address where hook will be placed.
    ***This is relative address (offset) for hook placement: `AbsoluteAddress = ModuleBase + Offset`***.
    ***If module specified as `nullptr` then absolute address placement present like generic hook.***
2. ***Function name***
    Hook related function.
3. ***Overriden bytes (of instrutions)***
    Count of bytes to override at hook placement. Minimal: 5 (injector fix any smaller value). If 'hook pocket' executes all functions and there is no jump out then instruction of this bytes will be executed before jump back.
4. **Prefix**
    Just internal identifier to split up hook definitions with same name.
5. **Name**
    Name of target module. If File version info (FVI) present then name of it will be used. If FVI is not present then filename will be used.
    ***`nullptr` is special value which target module is current executable.***
6. **Checksum**
    CRC32 value. Hook will be placed againts module with specific checksum. Can be used for versioning.
    ***`0` is special value which mean any module version.***

### Function redefine (deco hook)

Function redefine or deco hook it is a hook that used to reimplement original function. Injector has two variations of such hook.

**If several function redefinitions present, only one will be selected. And selected one will first declared. It depends on modules (dlls) order.**

#### By Name

***USE THIS VERSION ONLY IF TARGET FUNCTION IS EXPORTED.***

**Macro:** `REDEFINE_FUNCTION`& `REDEFINE_FUNCTION_AGAIN`.
**Parameters:**

1. **Original function name**
    The function to redefine from target module.
    Function must be exported. Injector automatically will seek address of this function and use it.
2. **Function name**
    Hook related function.
3. **Prefix**
    Just internal identifier to split up hook definitions with same name.
4. **Name**
    Name of target module. If File version info (FVI) present then name of it will be used. If FVI is not present then filename will be used.
    ***`nullptr` is special value which target module is current executable.***
5. **Checksum**
    CRC32 value. Hook will be placed againts module with specific checksum. Can be used for versioning.
    ***`0` is special value which mean any module version.***
6. **Return type**
    Return type of function to declare it in-place.
7. **...**
    Variadic arguments of function parameters to declare it in-place.

#### By Address

**Macro:** `REDEFINE_AT`& `REDEFINE_AT_AGAIN`.

1. **Target address**
    The first instruction address of target function.
    The same as `extended hook`.
2. **Function name**
    Hook related function.
3. **Prefix**
    Just internal identifier to split up hook definitions with same name.
4. **Name**
    Name of target module. If File version info (FVI) present then name of it will be used. If FVI is not present then filename will be used.
    ***`nullptr` is special value which target module is current executable.***
5. **Checksum**
    CRC32 value. Hook will be placed againts module with specific checksum. Can be used for versioning.
    ***`0` is special value which mean any module version.***
6. **Return type**
    Return type of function to declare it in-place.
7. **...**
    Variadic arguments of function parameters to declare it in-place.

## Hosts

Original syringe has mechanic for hosts target. It is a list of module names with specific checksums. Syringe and injector check it for each injectable dll.

It can be done with `declhost` macro.

## Notes

### Ares + Phobos

This pair should be run with this order: `-dll Phobos.dll -dll Ares.dll`. **It is necessary**.