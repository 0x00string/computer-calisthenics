#include <Windows.h>
#include <stdio.h>

void usage(void){
	printf("usage: simpleinjector C:\\\\path\\\\to\\\\dll\\\\to\\\\inject <target process id> <1/0 unload library after exec? default 1 (yes)>\n");
	exit(1);
}

int main (int argc, char **argv) {
	DWORD PID;
	HANDLE hThread;
	char szLibPath[128];
	strncpy(szLibPath,"C:\\Users\\user\\Desktop\\projects\\debugwindowtitledll\\debugwindowtitledll\\Release\\debugwindowtitledll.dll",110);
	void* pLibRemote = 0;
	DWORD hLibModule = 0;
	HMODULE hKernel32 = GetModuleHandleA("Kernel32");
	HINSTANCE hInst = GetModuleHandle(NULL);
	int killswitch = 1;
	int tmp = 0;

	if (!argv[2]) {
		usage();
	} else {
		tmp = atoi(argv[2]);
		PID = (DWORD)tmp;
	}

	if (GetCurrentProcessId() == PID) {
		usage();
	}

	if (atoi(argv[3]) == 0) {
		killswitch = 0;
	}

	printf("OpenProcess()\n");
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, PID);
	if (hProcess == NULL) {
		printf("OpenProcess() failed\n");
		exit(1);
	}

	printf("VirutalAllocEx()\n");
	pLibRemote = VirtualAllocEx(hProcess, NULL, 111, MEM_COMMIT, PAGE_READWRITE);
	if (pLibRemote == NULL) {
		printf("VirtualAllocEx() failed\n");
		exit(1);
	}

	SIZE_T dwNumBytesTransferred;

	printf("WriteProcessMemory()\n");
	if (WriteProcessMemory(hProcess, pLibRemote, &szLibPath, 110, &dwNumBytesTransferred) == 0) {
		printf("%s\n","something went wrong during WriteProcessMemory()");
	}

	printf("transferred %d bytes\n",dwNumBytesTransferred);

	printf("CreateRemoteThread()\n");
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) GetProcAddress(hKernel32,"LoadLibraryA"), pLibRemote, 0, NULL);
	if (hThread == NULL) {
		printf("CreateRemoteThread() LoadLibrary failed\n");
		CloseHandle(hProcess);
		exit(1);
	}

	WaitForSingleObject(hThread, INFINITE);

	GetExitCodeThread(hThread, &hLibModule);

	CloseHandle(hThread);

	printf("remote thread LoadLibrary() exit code: %d\n",hLibModule);

	if (hLibModule == NULL) {
		printf("CreateRemoteThread(GetLastError())\n");
		hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) GetProcAddress(hKernel32,"GetLastError"), NULL, 0, NULL);
		if (hThread == NULL) {
			printf("CreateRemoteThread() LoadLibrary failed\n");
			CloseHandle(hProcess);
			exit(1);
		}

		WaitForSingleObject(hThread, INFINITE);
		GetExitCodeThread(hThread, &hLibModule);
		CloseHandle(hThread);
		printf("remote thread GetLastError() exit code: %d\n",hLibModule);
	}

	printf("VirtualFreeEx()\n");
	tmp = VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
	if (tmp == 0) {
		printf("VirtualFreeEx failed, but we carry on. error code: %#08x\n",GetLastError());
	}

	if (killswitch > 0) {
		printf("killing self\n");
		CloseHandle(hProcess);
		exit(0);
	}

	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) GetProcAddress(hKernel32,"FreeLibrary"), (void*)hLibModule, 0, NULL);
	if (hThread == NULL) {
		printf("CreateRemoteThread() FreeLibrary failed");
		CloseHandle(hProcess);
		exit(1);
	}
	
	WaitForSingleObject(hThread, INFINITE);

	GetExitCodeThread(hThread, &hLibModule);
	printf("remote thread FreeLibrary() exit code: %d\n",hLibModule);

	CloseHandle(hProcess);

	exit(0);
}