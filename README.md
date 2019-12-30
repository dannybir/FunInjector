# FunInjector

A neat library to inject evil DLL's into processes. 
Written with C++17, therefore compilation is supported on Visual Studio 2017 and 2019.

Currently supports only one injection method. The method is to use an auto-removeable hook on some function in the target process and to inject some assembly code to an empty area in memory. Once the process runs the "victim" function, the assembly code will run, loading the DLL.

Plan is to add more injection methods, at some points.
Another plan is to have a nice command line application to inject DLL's into processes.

Tested with an automatic tester, passed about 500,000 sucesseful injections to 32 and 64bit processes.


How to use:
1. Clone code.
2. Open solution in VS2017 or 2019.
3. Build FunInjector.
4. Use the InjectDllUsingStructure or InjectWithFunctionHook of the DLL in your project to inject DLL's.

