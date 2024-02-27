#include "debugger.hpp"

namespace Debugger
{
	DebugLoop::Breakpoint::Breakpoint(Address address) :
		OnReached(this)
	{
		Addr = address;
		OpCode = 0;
		IsWritten = false;
	}
	DebugLoop::Breakpoint::Breakpoint() noexcept :
		OnReached(this)
	{}
	DebugLoop::Breakpoint::~Breakpoint() = default;

	DebugLoop::Breakpoint::Breakpoint(DebugLoop::Breakpoint&& other) noexcept :
		OnReached(std::exchange(other.OnReached, { nullptr })),
		Addr(std::exchange(other.Addr, nullptr)),
		OpCode(std::exchange(other.OpCode, 0)),
		IsWritten(std::exchange(other.IsWritten, false))
	{}
	DebugLoop::Breakpoint& DebugLoop::Breakpoint::operator=(DebugLoop::Breakpoint&& other) noexcept
	{
		OnReached = std::exchange(other.OnReached, { nullptr });
		Addr = std::exchange(Addr, nullptr);
		OpCode = std::exchange(OpCode, 0);
		IsWritten = std::exchange(other.IsWritten, false);
		return *this;
	}
}