#include <Windows.h>
#include <stdio.h>
#include "dll.h"

// once injected, this DLL prints out the window text of the process it is injected into

char g_text[128] = { '\0' };

BOOL CALLBACK isMyWindow (HWND handle, LPARAM procId) {
	if (!handle) {return false;}
	DWORD tmpId;
	DWORD threadId;
	char ob[128];
	threadId = GetWindowThreadProcessId(handle, &tmpId);
	if (procId == tmpId) {
		sprintf(ob,"target: %d, found: %d\n",procId,tmpId);
		OutputDebugStringA( ob );
		if (GetWindowTextA(handle, g_text, 127) == 0) {
			OutputDebugStringA("couldnt get window text\n");
		} else {
			OutputDebugStringA(g_text);
		}
	}
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	if ((ul_reason_for_call == DLL_PROCESS_ATTACH) ){
		MessageBeep(MB_OK);
		OutputDebugStringA("ive been injected!\n");
		DWORD PID = GetCurrentProcessId();
		EnumWindows(&isMyWindow, PID);
	}
	return TRUE;
}