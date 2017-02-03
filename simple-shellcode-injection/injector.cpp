#include <Windows.h>
#include <stdio.h>

int injection(void) {
	return 1337;
}

static void dummyFunction(void){}

int main(int argc, char**argv){
	int pid_arg;
	DWORD PID;
	DWORD *pCodeRemote;
	HANDLE hThread = NULL;
	DWORD dwThreadId = 0;
	DWORD dwNumBytesTransferred = 0;
	int remoteThreadReturnValue = 0;

	if (!argv[0]){
		printf("%s\n","no pid provided");
		exit(1);
	} else {
		pid_arg = atoi(argv[1]);
		PID = (DWORD)pid_arg;
	}
	// dont run with needles
	if (GetCurrentProcessId() == PID) {
		printf("%s\n","You're trying to inject the injector, dummy.");
		exit(1);
	}
	//get a handle on the target process
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, PID);
	if (hProcess == NULL) {
		printf("%s\n","something went wrong with OpenProcess()");
		exit(1);
	}
	// calculate size of injection
	int injectionSize = ((LPBYTE) dummyFunction - (LPBYTE) injection);
	// alloc space in target process for injection
	pCodeRemote = (PDWORD) VirtualAllocEx(hProcess, 0, injectionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pCodeRemote == NULL) {
		printf("%s\n","something went wrong during VirtualAllocEx()");
		exit(1);
	}
	// inject!
	if (WriteProcessMemory(hProcess, pCodeRemote, &injection, injectionSize, &dwNumBytesTransferred) == 0) {
		printf("%s\n","something went wrong during WriteProcessMemory()");
	}
	// create thread of injection in target process
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) pCodeRemote, NULL, 0, &dwThreadId);
	if (hThread == NULL) {
		printf("%s\n","something went wrong during CreateRemoteThread()");
		exit(1);
	}
	WaitForSingleObject(hThread, INFINITE);
	// once its finished, free it and get its ret value
	VirtualFreeEx(hProcess, pCodeRemote, 0, MEM_RELEASE);
	GetExitCodeThread(hThread, (PDWORD) &remoteThreadReturnValue);
	printf("injection return value: %d",remoteThreadReturnValue);

	exit(0);
}