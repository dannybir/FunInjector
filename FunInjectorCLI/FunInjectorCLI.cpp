// FunInjectorCLI.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>

// Command line options parser
#include <cxxopts.hpp>

// The CLI will direct use the API by linking to it statically
// I,e it will have the funinjector in its import table
#include "../FunInjector/FunInjectorAPI.h"

#include <filesystem>

// Logger
#include <plog/Log.h>
#include <plog/Appenders/ColorConsoleAppender.h>

#include <Windows.h>
#include "../FunInjector/ExceptionHandler.h"

int main(int argc, char* argv[])
{
	HANDLE_EXCEPTION_BEGIN;

	static plog::ColorConsoleAppender<plog::TxtFormatter> ColorConsoleLogger;
	plog::init(plog::debug, &ColorConsoleLogger);

	cxxopts::Options options(argv[0], " - FunInjectorCLI command line options");
    
	options.add_options("Basic")
		("f,fhook", "A flag to signify we would like to use function hook injection")
		("help", "Shows detailed information on all the commands");

	options.add_options("General")
		("d,dllpath", "The path to the Dll you would like to inject", cxxopts::value<std::string>())
		("p,pid", "The PID of the target process", cxxopts::value<DWORD>())
		("h,dhandle", "A handle value for the target process, must be duplicated to the CLI process externally", cxxopts::value<DWORD>());

	options.add_options("Function Hook Injection")
		("m,tmodule", "The name of the module the target function resides in", cxxopts::value<std::string>())
		("t,tfunction", "The name of the function we would like to hook", cxxopts::value<std::string>());

	auto ParseResult = options.parse(argc, argv);
	if (ParseResult.count("help") > 0)
	{
		std::cout << options.help({ "Basic", "General", "Function Hook Injection" }) << std::endl;
		return 0;
	}

	std::filesystem::path DllPath;
	if (ParseResult.count("dllpath") > 0)
	{
		DllPath = ParseResult["dllpath"].as<std::string>();
	}

	if (DllPath.empty())
	{
		LOG_ERROR << L"Failed to supply a dll path, won't be able to inject, returning 1";
		return 1;
	}

	DWORD TargetPid = 0;
	if (ParseResult.count("pid") > 0)
	{
		TargetPid = ParseResult["pid"].as<DWORD>();
	}

	DWORD TargetHandle = 0;
	if (ParseResult.count("dhandle") > 0)
	{
		TargetHandle = ParseResult["dhandle"].as<DWORD>();
	}

	if (TargetPid == 0 && TargetHandle == 0)
	{
		LOG_ERROR << L"Did not supply a target process pid or handle, won't be able to inject, returning 2";
		return 2;
	}

	if (ParseResult.count("fhook") > 0)
	{
		std::string ModuleName;
		if (ParseResult.count("tmodule") > 0)
		{
			ModuleName = ParseResult["tmodule"].as<std::string>();
		}
		else
		{
			LOG_ERROR << L"Did not supply a module name to inject using a function hook injection, returning 3";
			return 3;
		}

		std::string FunctionName;
		if (ParseResult.count("tfunction") > 0)
		{
			FunctionName = ParseResult["tfunction"].as<std::string>();
		}
		else
		{
			LOG_ERROR << L"Did not supply a function name to inject using a function hook injection, returning 4";
			return 4;
		}

		FunInjector::InjectionParameters Params;

		auto DllPathStr = DllPath.wstring();
		std::copy_n(DllPathStr.begin(), DllPathStr.size(), Params.DllPath.begin());
		std::copy_n(FunctionName.begin(), FunctionName.size(), Params.TargetFunctionName.begin());
		std::copy_n(ModuleName.begin(), ModuleName.size(), Params.TargetModuleName.begin());

		Params.ProcessHandle = reinterpret_cast<HANDLE>(TargetHandle);
		Params.ProcessId = TargetPid;
		Params.InjectionType = FunInjector::EInjectionType::RemoteFunction;

		if (InjectDllUsingStructure(Params) != 0)
		{
			LOG_ERROR << "Injection of dll: " << DllPath.string() << ", to process with pid: " << TargetPid
				<< ", or handle: " << TargetHandle << " has failed! Returning status 3";
			return 5;
		}

		LOG_DEBUG << "Injection of dll: " << DllPath.string() << ", to process with pid: " << TargetPid
			<< ", or handle: " << TargetHandle << " was succeseful, returning 0";

		return 0;
	}


	HANDLE_EXCEPTION_END_RET(-10);
}