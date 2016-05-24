#pragma once
///
/// LoadLibraryList is a convenient shorthand on windows to load many
/// functions from a specific DLL into a struct with function pointers.
///
/// Define a struct like this:
/// \code
/// struct Kernel32_t {
///	    HANDLE (__stdcall *CreateToolhelp32Snapshot)(DWORD Flags, DWORD NotUsedZero);
///     BOOL   (__stdcall *Thread32First)(HANDLE ToolHelp, PTHREADENTRY32 ThreadEntry);
///    	BOOL   (__stdcall *Thread32Next)(HANDLE ToolHelp, PTHREADENTRY32 ThreadEntry);
///    	HANDLE (__stdcall *OpenThread)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
/// } Kernel32;
/// \endcode
/// And a loading string like:
/// \code
/// const char *Kernel32Names = "kernel32.dll\0CreateToolhelp32Snapshot\0Thread32First\0Thread32Next\0OpenThread\0";
/// \endcode
///
/// Note that the substrings are nul seperated and the whole thing is terminated by an additional nul character.
/// The first subpart is the name of the dll to load.
///
/// Use it like:
/// \code
/// Kernel32_t k32 = { };
/// if (!LoadLibraryList((void**)&k32, Kernel32Names))
///     return false;
/// \endcode
/// At this point, all function pointers in k32 are populated.
///
bool __cdecl LoadLibraryList(void **proc, const char *dll, HMODULE module = 0);
