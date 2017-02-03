#include <Windows.h>
#include <stdio.h>

void usage(void){
	printf("usage: simpleinjector <target process id> <1/0 unload library after exec? default 1 (yes)>\n");
	exit(1);
}

int main (int argc, char **argv) {
	DWORD PID;
	HANDLE hThread;
	char szLibPath[128];
	strncpy(szLibPath,"C:\\\\path\\\\to\\\\dll\\\\to\\\\inject.dll",34);// lol yeah
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


	// here we'll prepare the stuff to use ntcreatethreadex instead of createremotethread
	// check out this place, its rad: http://undocumented.ntinternals.net/

	struct NtCreateThreadExBuffer {
	ULONG Size;
	ULONG Unknown1;
	ULONG Unknown2;
	PULONG Unknown3;
	ULONG Unknown4;
	ULONG Unknown5;
	ULONG Unknown6;
	PULONG Unknown7;
	ULONG Unknown8;
	}; 

	typedef NTSTATUS (WINAPI *LPFUN_NtCreateThreadEx) (
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended,
	IN ULONG StackZeroBits,
	IN ULONG SizeOfStackCommit,
	IN ULONG SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
	);

	HMODULE modNtDll = GetModuleHandleA("ntdll.dll");
	if (!modNtDll) {
		printf("\ncouldnt get ntdll: %.8x\n",GetLastError());
		exit(1);
	}

	LPFUN_NtCreateThreadEx funNtCreateThreadEx = (LPFUN_NtCreateThreadEx) GetProcAddress(modNtDll, "NtCreateThreadEx");

	if (!funNtCreateThreadEx) {
		printf("\ncouldnt get NtCreateThreadEx: %.8x\n",GetLastError());
	}

	NtCreateThreadExBuffer ntbuffer;

	memset (&ntbuffer, 0, sizeof(NtCreateThreadExBuffer));

	DWORD temp1 = 0;
	DWORD temp2 = 0;

	ntbuffer.Size = sizeof(NtCreateThreadExBuffer);
	ntbuffer.Unknown1 = 0x10003;
	ntbuffer.Unknown2 = 0x8;
	ntbuffer.Unknown3 = &temp2;
	ntbuffer.Unknown4 = 0;
	ntbuffer.Unknown5 = 0x10004;
	ntbuffer.Unknown6 = 4;
	ntbuffer.Unknown7 = &temp1;
	ntbuffer.Unknown8 = 0;

	//get a handle on the target
	printf("OpenProcess()\n");
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, PID);
	if (hProcess == NULL) {
		printf("OpenProcess() failed\n");
		exit(1);
	}

	// alloc space in the target space
	printf("VirutalAllocEx()\n");
	pLibRemote = VirtualAllocEx(hProcess, NULL, 111, MEM_COMMIT, PAGE_READWRITE);
	if (pLibRemote == NULL) {
		printf("VirtualAllocEx() failed\n");
		exit(1);
	}

	SIZE_T dwNumBytesTransferred;

	//write to target memory
	printf("WriteProcessMemory()\n");
	if (WriteProcessMemory(hProcess, pLibRemote, &szLibPath, 110, &dwNumBytesTransferred) == 0) {
		printf("%s\n","something went wrong during WriteProcessMemory()");
	}

	printf("transferred %d bytes\n",dwNumBytesTransferred);

	// now we can use funNtCreateThreadEx in place of CreateRemoteThread
	printf("NtCreateThreadEx()\n");
	NTSTATUS status = funNtCreateThreadEx(&hThread,0x1FFFFF,NULL,hProcess,(LPTHREAD_START_ROUTINE) GetProcAddress(hKernel32,"LoadLibraryA"), pLibRemote, FALSE, NULL, NULL, NULL, &ntbuffer);

	if (hThread == NULL) {
		printf("NtCreateThreadEx didnt work: %.8x\n",GetLastError());
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


	printf("NtCreateThreadEx()\n");
	NTSTATUS status2 = funNtCreateThreadEx(&hThread,0x1FFFFF,NULL,hProcess,(LPTHREAD_START_ROUTINE) GetProcAddress(hKernel32,"FreeLibrary"), (void*)hLibModule, FALSE, NULL, NULL, NULL, &ntbuffer);
	if (hThread == NULL) {
		printf("so, NtCreateThreadEx didnt work: %.8x\n",GetLastError());
		CloseHandle(hProcess);
		exit(1);
	}
	
	WaitForSingleObject(hThread, INFINITE);

	GetExitCodeThread(hThread, &hLibModule);
	printf("remote thread FreeLibrary() exit code: %d\n",hLibModule);

	CloseHandle(hProcess);

	exit(0);
}