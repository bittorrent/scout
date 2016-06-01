/*
Copyright 2016 BitTorrent Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

