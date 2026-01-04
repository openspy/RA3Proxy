#include <Windows.h>
#include <d3d9.h>
#include <stdio.h>
typedef IDirect3D9*(__stdcall* D3D9_CREATE_FUNC) (UINT SDKVersion);

#pragma data_seg (".d3d9_shared")
HINSTANCE           gl_hOriginalDll;
HINSTANCE           gl_hThisInstance;
#pragma data_seg ()

void LoadOriginalDll(void);
void perform_ra3_patches();

IDirect3D9* __stdcall Direct3DCreate9(UINT SDKVersion) {
	if (!gl_hOriginalDll) LoadOriginalDll();


	D3D9_CREATE_FUNC funcAddress_Direct3DCreate9 = (D3D9_CREATE_FUNC)GetProcAddress(gl_hOriginalDll, "Direct3DCreate9");


	//char dumb_msg[1024];
	//sprintf_s(dumb_msg, sizeof(dumb_msg), "func pointer is: %p, thread: %d\n", funcAddress_Direct3DCreate9, GetCurrentThreadId());
	//MessageBoxA(NULL, dumb_msg, "Injected", MB_OK);

	if (!funcAddress_Direct3DCreate9)
	{
		OutputDebugString("PROXYDLL: Pointer to original DirectInput8Create function not received ERROR ****\r\n");
		::ExitProcess(0); // exit the hard way
	}

	static bool patches_done = false;
	if (!patches_done) {
		patches_done = true;
		perform_ra3_patches();
	}

	return funcAddress_Direct3DCreate9(SDKVersion);
}

void LoadOriginalDll(void)
{
	char buffer[MAX_PATH];

	// Getting path to system dir and to d3d8.dll
	::GetSystemDirectory(buffer, MAX_PATH);

	// Append dll name
	strcat_s(buffer, sizeof(buffer), "\\d3d9.dll");

	// try to load the system's d3d9.dll, if pointer empty
	if (!gl_hOriginalDll) gl_hOriginalDll = ::LoadLibrary(buffer);
	// Debug
	if (!gl_hOriginalDll)
	{
		OutputDebugString("PROXYDLL: Original d3d9.dinput8 not loaded ERROR ****\r\n");
		::ExitProcess(0); // exit the hard way
	}
}