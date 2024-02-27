#ifndef INJECTOR_MISC_CODE_HPP
#define INJECTOR_MISC_CODE_HPP

#include "framework.hpp"
#include "asm.hpp"

namespace Injector
{
	static constexpr size_t CallR32InstructionLength		= 5;
	static constexpr size_t JumpR32lInstructionLength	= 5;
	
	BYTE const PrefixCodeData[] =
	{
		PUSH_EAX
	};
	static constexpr size_t PrefixCodeDataSize = sizeof(PrefixCodeData);	
	#pragma pack(push, 1)
	struct PrefixCode
	{
		BYTE arr1[1] { 0 };

		PrefixCode()
		{
			memcpy(this, &PrefixCodeData, PrefixCodeDataSize);
		}
	};
	static constexpr size_t PrefixCodeSize = sizeof(PrefixCode);
	#pragma pack(pop)
	static_assert(PrefixCodeDataSize == PrefixCodeSize, "The code and data are not equals");
		
	BYTE const PostfixCodeData[] =
	{
		POP_EAX,
		DEBUGGER_INTERRUPT_CODE, NOP
	};
	static constexpr size_t PostfixCodeDataSize = sizeof(PostfixCodeData);
	static constexpr size_t PostfixCodeBreakpointOffset = 1;
	#pragma pack(push, 1)
	struct PostfixCode
	{
		BYTE arr1[3] { 0, 0, 0 };

		PostfixCode()
		{
			memcpy(this, &PostfixCodeData, PostfixCodeDataSize);
		}
	};
	static constexpr size_t PostfixCodeSize = sizeof(PostfixCode);
	#pragma pack(pop)
	static_assert(PostfixCodeDataSize == PostfixCodeSize, "The code and data are not equals");

	BYTE const JumpCodeData[] =
	{
		JMP_R32(INIT_PTR)
	};
	static constexpr size_t JumpCodeDataSize = sizeof(JumpCodeData);
	
	#pragma pack(push, 1)
	struct JumpCode
	{
		// 0xE9
		BYTE JumpOpCode;
		// Jump to relative address
		DWORD Offset;
	
		JumpCode()
		{
			memcpy(this, JumpCodeData, JumpCodeDataSize);
		}
		JumpCode(Address base, Address target)
		{
			memcpy(this, JumpCodeData, JumpCodeDataSize);
			Offset = relative_offset(
				reinterpret_cast<BYTE*>(base) + JumpR32lInstructionLength, 
				target);
		}
	};
	static constexpr size_t JumpCodeSize = sizeof(JumpCode);
	#pragma pack(pop)

	static_assert(JumpCodeSize == JumpCodeDataSize, "The code and data are not equals");
	
	BYTE const CallCodeData[] =
	{
		CALL_R32(INIT_PTR)
	};
	static constexpr size_t CallCodeDataSize = sizeof(CallCodeData);
	
	#pragma pack(push, 1)
	struct CallCode
	{
		// 0xE8
		BYTE CallOpCode;
		// Call function at relative offset.
		DWORD Offset;
	
		CallCode()
		{
			memcpy(this, CallCodeData, CallCodeDataSize);
		}
		CallCode(Address base, FARPROC func)
		{
			memcpy(this, CallCodeData, CallCodeDataSize);
			Offset = relative_offset(
				reinterpret_cast<BYTE*>(base) + JumpR32lInstructionLength, 
				func);
		}
	};
	static constexpr size_t CallCodeSize = sizeof(CallCode);
	#pragma pack(pop)

	static_assert(CallCodeSize == CallCodeDataSize, "The code and data are not equals");
}
#endif //INJECTOR_MISC_CODE_HPP