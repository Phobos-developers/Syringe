#ifndef INJECTOR_WAITER_HPP
#define INJECTOR_WIATER_HPP

#include <macro.hpp>

#include "framework.hpp"
#include "asm.hpp"

namespace Injector
{
	static constexpr size_t WaiterBreakpointOffset = 2;
	
	BYTE const WaiterCodeData[] =
	{
		NOP,
		NOP,
		DEBUGGER_INTERRUPT_CODE, NOP
	};
	static constexpr size_t WaiterCodeDataSize = sizeof(WaiterCodeData);	
	#pragma pack(push, 1)
	struct WaiterCode
	{
		BYTE arr1[4] { 0, 0, 0, 0 };

		WaiterCode()
		{
			memcpy(this, &WaiterCodeData, WaiterCodeDataSize);
		}
	};
	static constexpr size_t WaiterCodeSize = sizeof(WaiterCode);
	#pragma pack(pop)
	static_assert(WaiterCodeDataSize == WaiterCodeSize, "The code and data are not equals");
}

#endif //INJECTOR_WIATER_HPP
