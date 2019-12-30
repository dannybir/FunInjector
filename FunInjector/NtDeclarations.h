#pragma once

#include <Windows.h>
#include <stdint.h>

namespace FunInjector
{
	typedef struct _UNICODE_STRING64 
	{
		USHORT Length;
		USHORT MaximumLength;
		DWORD64 Buffer;
	} UNICODE_STRING64;

	typedef struct LIST_ENTRY64 {
		DWORD64 Flink;
		DWORD64 Blink;
	} LIST_ENTRY64;

	typedef struct _LDR_DATA_TABLE_ENTRY64 {
		LIST_ENTRY64 InLoadOrderLinks;
		LIST_ENTRY64 InMemoryOrderModuleList;
		LIST_ENTRY64 InInitializationOrderModuleList;
		DWORD64 DllBase;
		DWORD64 EntryPoint;
		ULONGLONG SizeOfImage;
		UNICODE_STRING64 FullDllName;
		UNICODE_STRING64 BaseDllName;
		ULONG Flags;
		USHORT LoadCount;
		USHORT TlsIndex;
		LIST_ENTRY64 HashLinks;
		ULONGLONG TimeDateStamp;
	} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

	//	 +0x000 Length           : Uint4B
	//	+ 0x004 Initialized : UChar
	//	+ 0x008 SsHandle : Ptr64 Void
	//	+ 0x010 InLoadOrderModuleList : _LIST_ENTRY
	//	+ 0x020 InMemoryOrderModuleList : _LIST_ENTRY
	//	+ 0x030 InInitializationOrderModuleList : _LIST_ENTRY
	//	+ 0x040 EntryInProgress : Ptr64 Void
	//	+ 0x048 ShutdownInProgress : UChar
	//	+ 0x050 ShutdownThreadId : Ptr64 Void

	typedef struct _PEB_LDR_DATA64 {
		UINT Length;
		UCHAR Initialized;
		DWORD64 SsHandle;
		LIST_ENTRY64 InLoadOrderModuleList;
		LIST_ENTRY64 InMemoryOrderModuleList;
		// Rest is cutoff, its not needed for now
	} PEB_LDR_DATA64, *PPEB_LDR_DATA64;

	typedef struct _RTL_USER_PROCESS_PARAMETERS64 {
		UCHAR			  Reserved1[32];
		DWORD64           Reserved2[10];
		UNICODE_STRING64  ImagePathName;
		UNICODE_STRING64  CommandLine;
	} RTL_USER_PROCESS_PARAMETERS64, *PRTL_USER_PROCESS_PARAMETERS64;

	typedef struct _PEB64 {
		BYTE							Reserved1[2];
		BYTE							BeingDebugged;
		BYTE							Reserved2[1];
		DWORD64                         Reserved3[2];
		DWORD64							Ldr;
		PRTL_USER_PROCESS_PARAMETERS64  ProcessParameters;
// We don't care about the rest
	} PEB64, *PPEB64;

	typedef struct _PROCESS_BASIC_INFORMATION64 {
		PVOID Reserved1[2];
		DWORD64 PebBaseAddress;
		PVOID Reserved2[4];
		ULONG_PTR UniqueProcessId[2];
		PVOID Reserved3[2];
	} PROCESS_BASIC_INFORMATION64;

	typedef enum _PROCESSINFOCLASS {
		ProcessBasicInformation
		// We don't need the others
	} PROCESSINFOCLASS;

	using NtQueryInformationProcessDecl = NTSTATUS(NTAPI *)(
		IN  HANDLE ProcessHandle,
		IN  PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN  ULONG ProcessInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);

	// NtWow64ReadVirtualMemory64Decl
	using NtWow64ReadVirtualMemory64Decl = NTSTATUS(NTAPI *)(
		IN HANDLE ProcessHandle,
		IN DWORD64 BaseAddress,
		OUT PVOID Buffer,
		IN ULONG64 Size,
		PDWORD64 NumberOfBytesRead);

	// NtWow64WriteVirtualMemory64Decl
	using NtWow64WriteVirtualMemory64Decl = NTSTATUS(NTAPI *)(
		IN HANDLE ProcessHandle,
		IN DWORD64 BaseAddress,
		OUT PVOID Buffer,
		IN ULONG64 Size,
		PDWORD64 NumberOfBytesWritten);

	// NtWow64AllocateVirtualMemory64
	using NtWow64AllocateVirtualMemory64Decl = NTSTATUS(NTAPI *)(
		IN  HANDLE   ProcessHandle,
		IN  PULONG64 BaseAddress,
		IN  ULONG64  ZeroBits,
		IN  PULONG64 Size,
		IN  ULONG    AllocationType,
		IN  ULONG    Protection
		);

	// NtWow64QueryVirtualMemory64
	using NtWow64QueryVirtualMemory64 = NTSTATUS(NTAPI *)(
		IN HANDLE   ProcessHandle,
		IN ULONG64  BaseAddress,
		IN DWORD    MemoryInformationClass,
		OUT PVOID   Buffer,
		IN ULONG64  Length,
		OUT PULONG  ResultLength OPTIONAL
		);
}