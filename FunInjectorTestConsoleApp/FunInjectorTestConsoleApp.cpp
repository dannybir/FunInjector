// FunInjectorTestConsoleApp.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "../FunInjector/FunInjectorAPI.h"
#include <Windows.h>
#include <tlhelp32.h>

int main()
{
	DWORD ProcessId = 0;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		do
		{
			std::wstring ProcessName(entry.szExeFile);
			if (ProcessName == L"flux.exe")
			{
				ProcessId = entry.th32ProcessID;
				break;
			}

		} while (Process32Next(snapshot, &entry) == TRUE);
	}

	CloseHandle(snapshot);

	
	FunInjector::InjectionParameters Params;

	auto DllPath = std::wstring(L"C:\\Users\\DB\\Source\\Repos\\FunInjector\\FunInjector\\Debug\\TESTDLL.dll");
	std::copy_n( DllPath.begin(), DllPath.size(), Params.DllPath.begin());

	auto FunctionName = std::string("CreateFileW");
	std::copy_n(FunctionName.begin(), FunctionName.size(), Params.TargetFunctionName.begin());

	auto ModuleName = std::string("kernelbase");
	std::copy_n(ModuleName.begin(), ModuleName.size(), Params.TargetModuleName.begin());
	
	Params.ProcessId = ProcessId;
	Params.InjectionType = FunInjector::EInjectionType::RemoteFunction;

	InjectDllUsingStructure(Params);
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
