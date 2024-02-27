#ifndef INJECTOR_ASM_HPP
#define INJECTOR_ASM_HPP

#include "framework.hpp"

static constexpr size_t MaxLibraryNameLength		= 0x100u;
static constexpr size_t MaxProcNameLength			= 0x100u;

static size_t constexpr CallR32InstructionLength	= 5;

#define INT3 0xCC
// trap to debugger interrupt opcode. (INT3)
#define DEBUGGER_INTERRUPT_CODE INT3
// no operation code
#define NOP 0x90
// marker for placeholder
#define INIT 0
// Pointer 32 bit placeholder
#define INIT_PTR INIT, INIT, INIT, INIT
// uint32 placeholdfer
#define INIT_DWORD INIT, INIT, INIT, INIT

#define MASK8 0xFF
#define MASK32 0xFF, 0xFF, 0xFF, 0xFF

#define JO_R8(rel8)				0x70, rel8
#define JNO_R8(rel8)				0x71, rel8
#define JB_R8(rel8)				0x72, rel8
#define JNB_R8(rel8)				0x73, rel8
#define JZ_R8(rel8)				0x74, rel8
#define JNZ_R8(rel8)				0x75, rel8
#define JBE_R8(rel8)				0x76, rel8
#define JNBE_R8(rel8)			0x77, rel8
#define JS_R8(rel8)				0x78, rel8
#define JNS_R8(rel8)				0x79, rel8
#define JP_R8(rel8)				0x7A, rel8
#define JNP_R8(rel8)				0x7B, rel8
#define JL_R8(rel8)				0x7C, rel8
#define JNL_R8(rel8)				0x7D, rel8
#define JNG_R8(rel8)				0x7E, rel8
#define JG_R8(rel8)				0x7F, rel8
#define JCXZ(rel8)					0xE3, rel8
#define LOOPNZ(rel8)				0xE0, rel8
#define LOOPZ(rel8)				0xE1, rel8
#define LOOP(rel8)					0xE2, rel8
#define CALL_R32(rel32)		0xE8, rel32
#define JMP_R32(rel32)			0xE9, rel32
#define JMPF_R32(rel32)		0xEA, rel32
#define	JMP_R8(rel8)				0xEB, rel8
#define JO_R32(rel32)			0x0F, 0x80, rel32
#define JNO_R32(rel32)			0x0F, 0x81, rel32
#define JB_R32(rel32)			0x0F, 0x82, rel32
#define JNB_R32(rel32)			0x0F, 0x83, rel32
#define JZ_R32(rel32)			0x0F, 0x84, rel32
#define JNZ_R32(rel32)			0x0F, 0x85, rel32
#define JBE_R32(rel32)			0x0F, 0x86, rel32
#define JNBE_R32(rel32)		0x0F, 0x87, rel32
#define JS_R32(rel32)			0x0F, 0x88, rel32
#define JNS_R32(rel32)			0x0F, 0x89, rel32
#define JP_R32(rel32)			0x0F, 0x8A, rel32
#define JNP_R32(rel32)			0x0F, 0x8B, rel32
#define JL_R32(rel32)			0x0F, 0x8C, rel32
#define JNL_R32(rel32)			0x0F, 0x8D, rel32
#define JNG_R32(rel32)			0x0F, 0x8E, rel32
#define JG_R32(rel32)			0x0F, 0x8F, rel32

#define PUSH_EAX					0x50
#define POP_EAX					0x58
#define PUSH_ECX					0x51
#define POP_ECX					0x59
#define PUSH_EDX					0x52
#define POP_EDX					0x5A
#define PUSHAD					0x60
#define POPAD						0x61
#define PUSHFD						0x9C
#define POPFD						0x9D
#define PUSH_ESP					0x54
#define ADD_ESP(imm8)		0x83, 0xC4, imm8 
#define PUSH_INTO_STACK(imm32) 0x68, imm32
#define ADD_PTR32_IMM32(ptr32, imm32) 0x81, 0x05, ptr32, imm32
#define MOV_EAX_TO(ptr32)	0xA3, ptr32
#define MOV_TO_EAX(ptr32)	0XB8, ptr32
#define TEST_EAX_EAX			0x85, 0xC0

#define JMP_PTR32(ptr32)		0xFF, 0x25, ptr32
#define CALL_PTR32(ptr32)	0xFF, 0x15, ptr32

#define CALL_EAX					0xFF, 0xD0
#define CMP_PTR32_IMM32(ptr32, imm32) 0x83, 0x3D, ptr32, imm32

struct invalid_jump_offset_error : std::runtime_error
{
	int64_t	const Value;
	size_t	const Size;
	invalid_jump_offset_error(int64_t value) : std::runtime_error("JUMP/CALL offset is invalid"), Value(value), Size(sizeof(int32_t)) {}
	invalid_jump_offset_error(int64_t value, size_t size) : std::runtime_error("JUMP/CALL offset is invalid"), Value(value), Size(size) {}
};

inline int32_t __fastcall relative_offset(Address pFrom, Address pTo, size_t cmdSize = 0)
{
	auto const offset		= reinterpret_cast<int64_t>(pTo) - (reinterpret_cast<int64_t>(pFrom) + (int64_t) cmdSize);
	if (offset <= INT32_MAX && offset >= INT32_MIN)
		return offset;
	throw invalid_jump_offset_error{ offset };
}

inline Address __fastcall restore_address(Address pFrom, int32_t offset, size_t cmdSize = 0)
{
	int32_t const pTo	= reinterpret_cast<int32_t>(pFrom) + offset + cmdSize;
	return reinterpret_cast<Address>(pTo);
}

// newOffset = (oldOffset + pOld) - pNew
inline int32_t __fastcall correct_relative_offset(int32_t oldOffset, Address pOld, Address pNew)
{
	int64_t		diff = reinterpret_cast<int64_t>(pOld) - reinterpret_cast<int64_t>(pNew);
	int64_t		offset = oldOffset + diff;
	if (offset <= INT32_MAX && offset >= INT32_MIN)
		return offset;
	throw invalid_jump_offset_error{ offset };
}

struct _rel_cmd
{
	std::string					Mnemonic;
	std::vector<BYTE>		Command;
	
	size_t						Size;
	size_t						OffsetStart;

	_rel_cmd(std::string mnemonic, size_t size, size_t offsetStart, std::vector<BYTE> command) 
		: Mnemonic(mnemonic), Size(size), OffsetStart(offsetStart), Command(command)
	{}
	_rel_cmd() = default;
};
struct relative_jump_info
{
	bool				IsRelativeJump;
	// Offset in bytes from command start to jump command offset 
	size_t			Offset;
	_rel_cmd		Cmd;

	relative_jump_info() : IsRelativeJump(false) {}
	relative_jump_info(_rel_cmd cmd, size_t offset) : IsRelativeJump(true), Offset(offset), Cmd(cmd) {}

	bool operator!()	const		{ return !IsRelativeJump; }
	operator bool()	const		{ return IsRelativeJump; }
};

inline std::vector<_rel_cmd> get_eip_affected_instruction_with_relative_offset()
{
	return std::vector<_rel_cmd>
	{
		{ "JCXZ"		, 2, 1		, { JCXZ(MASK8)				}	},
		{ "LOOPNZ"	, 2, 1		, { LOOPNZ(MASK8)			}	},
		{ "LOOPZ"		, 2, 1		, { LOOPZ(MASK8)				}	},
		{ "LOOP"		, 2, 1		, { LOOP(MASK8)				}	},

		{ "JO"			, 2, 1		, { JO_R8(MASK8)				}	},
		{ "JNO"			, 2, 1		, { JNO_R8(MASK8)			}	},
		{ "JB"			, 2, 1		, { JB_R8(MASK8)				}	},
		{ "JNB"			, 2, 1		, { JNB_R8(MASK8)			}	},
		{ "JZ"			, 2, 1		, { JZ_R8(MASK8)				}	},
		{ "JNZ"			, 2, 1		, { JNZ_R8(MASK8)			}	},
		{ "JBE"			, 2, 1		, { JBE_R8(MASK8)			}	},
		{ "JNBE"		, 2, 1		, { JNBE_R8(MASK8)			}	},
		{ "JS"			, 2, 1		, { JS_R8(MASK8)				}	},
		{ "JNS"			, 2, 1		, { JNS_R8(MASK8)			}	},
		{ "JP"			, 2, 1		, { JP_R8(MASK8)				}	},
		{ "JNP"			, 2, 1		, { JNP_R8(MASK8)			}	},
		{ "JL"			, 2, 1		, { JL_R8(MASK8)				}	},
		{ "JNL"			, 2, 1		, { JNL_R8(MASK8)			}	},
		{ "JNG"			, 2, 1		, { JNG_R8(MASK8)			}	},
		{ "JG"			, 2, 1		, { JG_R8(MASK8)				}	},
		{ "JMP"			, 2, 1		, { JMP_R8(MASK8)			}	},

		{ "JO"			, 4, 2		, { JO_R32(MASK32)			}	},
		{ "JNO"			, 4, 2		, { JNO_R32(MASK32)		}	},
		{ "JB"			, 4, 2		, { JB_R32(MASK32)			}	},
		{ "JNB"			, 4, 2		, { JNB_R32(MASK32)		}	},
		{ "JZ"			, 4, 2		, { JZ_R32(MASK32)			}	},
		{ "JNZ"			, 4, 2		, { JNZ_R32(MASK32)		}	},
		{ "JBE"			, 4, 2		, { JBE_R32(MASK32)			}	},
		{ "JNBE"		, 4, 2		, { JNBE_R32(MASK32)		}	},
		{ "JS"			, 4, 2		, { JS_R32(MASK32)			}	},
		{ "JNS"			, 4, 2		, { JNS_R32(MASK32)		}	},
		{ "JP"			, 4, 2		, { JP_R32(MASK32)			}	},
		{ "JNP"			, 4, 2		, { JNP_R32(MASK32)			}	},
		{ "JL"			, 4, 2		, { JL_R32(MASK32)			}	},
		{ "JNL"			, 4, 2		, { JNL_R32(MASK32)			}	},
		{ "JNG"			, 4, 2		, { JNG_R32(MASK32)		}	},
		{ "JG"			, 4, 2		, { JG_R32(MASK32)			}	},
		{ "JMP"			, 4, 1		, { JMP_R32(MASK32)		}	},

		{ "CALL"		, 4, 1		, { CALL_R32(MASK32)		}	},
	};
}

inline _rel_cmd find_rel_cmd(std::string mnemonic, size_t size)
{
	auto instructions = get_eip_affected_instruction_with_relative_offset();
	auto iter = std::find_if(instructions.cbegin(), instructions.cend(), [&mnemonic, &size](const _rel_cmd& item) -> bool
	{
		return item.Mnemonic == mnemonic && item.Size == size;
	});
	if (iter == instructions.cend())
		throw;
	return *iter;
}

inline relative_jump_info is_relative_jump(std::vector<BYTE> command)
{
	for (auto& instruction : get_eip_affected_instruction_with_relative_offset())
	{
		if (instruction.Command.empty())								continue;
		if (command.size() < instruction.Command.size())		continue;
		bool ok = true;
		for (size_t i = 0; i < instruction.OffsetStart; i++)
		{
			auto	a	= instruction.Command.at(i);
			auto	b	= command.at(i);
			ok			= a == b;
			if (!ok)	break;
		}
		if (ok)
			return relative_jump_info(instruction, 1);
	}
	return relative_jump_info{};
}

template<typename T>
inline T _get_relative_offset(std::vector<BYTE> command, size_t offset)
{
	T value = 0;
	memcpy(&value, command.data() + offset, sizeof(T));
	return value;
}
inline int32_t get_relative_offset(std::vector<BYTE> command, relative_jump_info& rji)
{
	switch (rji.Cmd.Size)
	{
		case(1):		return _get_relative_offset<int8_t>(command, rji.Offset);
		case(2):		return _get_relative_offset<int16_t>(command, rji.Offset);
		case(4):		return _get_relative_offset<int32_t>(command, rji.Offset);
		default:			throw;
	}
}

inline void set_relative_offset(std::vector<BYTE>& command, relative_jump_info& rji, int32_t value)
{
	switch (rji.Cmd.Size)
	{
		case(1):
		{
			if (value <= INT8_MAX && value >= INT8_MIN)
				memcpy(command.data() + rji.Offset, &value, sizeof(int8_t));
			else throw invalid_jump_offset_error { value, rji.Cmd.Size };
		} break;
		case(2):
		{
			if (value <= INT16_MAX && value >= INT16_MIN)
				memcpy(command.data() + rji.Offset, &value, sizeof(int16_t));
			else throw invalid_jump_offset_error { value, rji.Cmd.Size };
		} break;
		case(4):
		{
			if (value <= INT32_MAX && value >= INT32_MIN)
				memcpy(command.data() + rji.Offset, &value, sizeof(int32_t));
			else throw invalid_jump_offset_error { value, rji.Cmd.Size };
		} break;
		default: throw;
	}
}

#endif //INJECTOR_ASM_HPP