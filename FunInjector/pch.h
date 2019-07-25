// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#include "FunInjectorAPI.h"

// WINAPI
#include <Windows.h>

// Debugging functions
#include <DbgHelp.h>

// Detours: https://github.com/Microsoft/Detours
#include "../Dependencies/Detours/include/detours.h"

// Logger
#include <plog/Log.h>
#include <plog/Appenders/ColorConsoleAppender.h>

// Strings
#include <string>
#include <string_view>

//WIL
#include <wil/resource.h>

// Basic types
#include <vector>
#include <unordered_map>
#include <type_traits>
#include <optional>
#include <functional>
#include <variant>
#include <filesystem>
#include <array>
#include <memory>

#include "ByteBuffer.h"

#endif //PCH_H
