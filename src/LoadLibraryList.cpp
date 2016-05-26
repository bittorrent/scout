#include <windows.h>
//#include "StdAfxCore.h"
#include "LoadLibraryList.h"

// Helper function needed to load a lib
bool __cdecl LoadLibraryList(void **proc, const char *dll, HMODULE module)
{
	bool retVal = true;
	HMODULE lib = module;
	void *p;

	if (lib) goto load_procs;

	while (*dll) {
		lib = LoadLibraryA(dll);
		if (lib == NULL) {
			DWORD err = GetLastError();
			retVal = false;
			break;
		}
		while (true) {
			while(*dll++);
load_procs:
			if (!*dll)
				break;
			p = (void *) GetProcAddress(lib, dll);
			if (p == NULL)
				retVal = false;
			*proc++ = p;
		}
		dll++;
	}
	return retVal;
}

