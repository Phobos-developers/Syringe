#ifndef INJECTOR_DECLARATION_HPP
#define INJECTOR_DECLARATION_HPP

#ifdef IS_INJECTOR_SOURCE
// disable "structures padded due to alignment specifier"
#pragma warning(push)
#pragma warning(disable : 4324)
struct alignas(16) HookDecl
{
	DWORD			Address;
	size_t			Size;
	DWORD			FunctionNamePtr;
};

struct alignas(32) ExtendedHookDecl
{
	DWORD			Address;
	size_t			Size;
	DWORD			FunctionNamePtr;
	DWORD			ModuleNamePtr;
	unsigned int	ModuleChecksum;
};

struct alignas(16) HostDecl
{
	unsigned int	Checksum;
	DWORD			NamePtr;
};
#pragma warning(pop)
#else
#pragma pack(push, 16)
#pragma warning(push)
#pragma warning( disable : 4324)
__declspec(align(16)) struct HookDecl
{
	unsigned int	Address;
	unsigned int	Size;
	const char*	FunctionNamePtr;
};

__declspec(align(32)) struct ExtendedHookDecl
{
	unsigned int	Address;
	unsigned int	Size;
	const char*	FunctionNamePtr;
	const char*	ModuleNamePtr;
	unsigned int	ModuleChecksum;
};

__declspec(align(16)) struct HostDecl
{
	unsigned int	Checksum;
	const char*	NamePtr;
};
#pragma warning(pop)
#pragma pack(pop)

static_assert(sizeof(HookDecl) == 16);
static_assert(sizeof(ExtendedHookDecl) == 32);
static_assert(sizeof(HostDecl) == 16);

#pragma section(".syhks00", read, write)
#pragma section(".syexe00", read, write)
#pragma section(".syhks01", read, write)
#endif

#endif //INJECTOR_DECLARATION_HPP