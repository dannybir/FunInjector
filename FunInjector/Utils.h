#pragma once

#include "pch.h"

namespace FunInjector::Utils
{
	template <typename Func, typename ... FuncArgs>
	bool PerformWinApiCall(const std::string_view FuncName, Func&& FuncPtr, FuncArgs&& ... Args)
	{
		using RetType = std::invoke_result_t< Func, FuncArgs ... >;

		// Call the function
		auto Result = std::invoke(FuncPtr, Args...);

		// I am pessimistic :)
		bool InvokeSuccess = false;

		// if constexpr means here that compiled code would either have the first or second code in the final assembly result
		// is_same_v does compile time type comparison
		if constexpr (std::is_same_v< RetType, HRESULT >)
		{
			InvokeSuccess = Result == 0;
		}
		else if constexpr (std::is_same_v< RetType, HANDLE>)
		{
			InvokeSuccess = Result != nullptr && Result != INVALID_HANDLE_VALUE;
		}
		else if constexpr (std::is_same_v< RetType, BOOL> || std::is_same_v< RetType, DWORD> ||
			std::is_same_v< RetType, DWORD64>)
		{
			InvokeSuccess = Result > 0;
		}
		else
		{
			static_assert(false, "Supplied function has a non-supported return type");
		}

		if (!InvokeSuccess)
		{
			LOG_ERROR << FuncName << L" failed, Error= " << GetLastError();
		}

		return InvokeSuccess;
	}
}

