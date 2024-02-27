#ifndef INJECTOR_FRAMEWORK_HPP
#define INJECTOR_FRAMEWORK_HPP

#include <handle.hpp>
#include <macro.hpp>
#include <events.hpp>
#include <string.hpp>
#include <portable_executable.hpp>

#include <utility>
#include <exception>
#include <string_view>
#include <string>
#include <filesystem>
#include <list>
#include <map>
#include <vector>
#include <memory>
#include <variant>

//#define FMT_HEADER_ONLY
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>

#define IS_INJECTOR_SOURCE
#include <elements.hpp>
#include <declaration.hpp>
#include "typedefs.hpp"

namespace Injector
{
	using std::exception;
	using std::string;
	using std::string_view;
	using std::map;
	using std::list;
	using std::vector;

	using std::unique_ptr;
	using std::make_unique;
}

template<typename TFunction>
inline TFunction GetFunctionAddress(HMODULE handle, std::string_view const& name)
{
	return reinterpret_cast<TFunction>(GetProcAddress(handle, name.data()));
}


#endif //INJECTOR_FRAMEWORK_HPP