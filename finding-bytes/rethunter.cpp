#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <conio.h>

/*
This is a stupid program that reads its own memory and prints out when it finds what looks like a ret instruction
*/

int findMe(int b){
	int a = 1;
	int c = a + b;
	return c;
}

void main() {
	HANDLE thisProcHandle = GetCurrentProcess();
	DWORD *findMeptr = (DWORD *)findMe;
	SIZE_T *bytesRead = 0;
	unsigned char buf[4];
	int found = 0;
	int i = 0;
	unsigned int rpmrv;
	while (found != 1){
		rpmrv = ReadProcessMemory(thisProcHandle, findMeptr + i, buf, 1, bytesRead);
		if (rpmrv == 0) {
			printf("ReadProcessMemory() failed, dog!\n");
			_getch();
			exit(1);
		} else {
			printf("byte read at %#08x: %#x\n", findMeptr + i, buf[0]);
			if (buf[0] == 195) {
				printf("ret found at %#08x, exiting!\n", findMeptr + i);
				found = 1;
			}
		}
		i++;
	}
	_getch();
	int whyaYouMakeaMeDoThatHuh = findMe(i);
	printf("%d\n",whyaYouMakeaMeDoThatHuh);
	exit(0);
}