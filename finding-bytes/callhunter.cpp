#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <conio.h>

/*
This is a stupid program that reads its own memory and prints out when it finds what looks like a call instruction
*/

int findMe(int b){
	int a = 1;
	int c = a + b;
	return c;
}

void main() {
	HMODULE modhandle = GetModuleHandle(NULL);
	DWORD baseAddr = (DWORD)modhandle;
	printf("base address: %#08x\n",baseAddr);
	HANDLE procHandle = GetCurrentProcess();
	DWORD *mainPtr = (DWORD *)main;
	SIZE_T *bytesRead = 0;
	unsigned char buf[4];
	int end = 0;
	int i = 0;
	unsigned int rpmrv;
	while (end != 1) {
		rpmrv = ReadProcessMemory(procHandle, mainPtr + i, buf, 1, bytesRead);
		if (rpmrv == 0) {
			printf("ReadProcessMemory() failed, dog!\n");
			_getch();
			break;
		} else {
			printf("byte read at %#08x: %#x\n", mainPtr + i, buf[0]);
			if (buf[0] == 232 || buf[0] == 255) {
				printf("call found at %#08x, exiting!\n", mainPtr + i);
				end = 1;
			}
		}
		i++;
	}
	_getch();
	exit(0);
}