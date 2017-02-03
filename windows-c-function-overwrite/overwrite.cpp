#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <conio.h>

    // mark the beginning of printfFunctionB
void printfFunctionB(void){
	printf("%s\n", "B");
}
    // mark the end by creating a do-nothing function stub
void printfFunctionBStub(void){}

    // Beginning of printfFunction
void printfFunction(void){
	printf("%s\n", "A");
}
    // mark the end
void printfFunctionStub(){}

int main(){
	DWORD dwPrintFunctionSize = 0, dwOldProtect;//variables to hold function sizes and memory permissions
	DWORD *fA = NULL, *fB = NULL, *fPrintF = NULL, *fAB = NULL;// memory addresses
	DWORD thispid = GetCurrentProcessId();//process id
	char shellcode[27];// a shellcode buffer, we end up not using it here, we copy a function to this instead.
    // = "\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc";
    // = "\x55\x8b\xec\x68\xec\x20\x40\x00\x68\xf0\x20\x40\x00\xff\x15\xa4\x20\x40\x00\x83\xc4\x08\x5d\xc3";
	HANDLE thisProcHandle = GetCurrentProcess();//get a handle on ourselves.
	SIZE_T* bytesRead = 0;
	SIZE_T* bytesWritten = 0;

	// get function addresses
	fA = (DWORD *)&printfFunction;
	printf("fA pointer: %p\n",fA);
	fB = (DWORD *)&printfFunctionStub;
	printf("fB pointer: %p\n",fB);
	fPrintF = (DWORD *)&printf;
	printf("__imp_printf XREF pointer: %p\n",fPrintF);
	fAB = (DWORD *)&printfFunctionB;
	printf("fAB pointer: %p\n",fAB);

	// calculate function size... or i guess we just hardcoded it.
	dwPrintFunctionSize = 0x25;//(fB - fA);//0x16; //(fB - fA);
	
	// prints: A,B
	printfFunction();
	printfFunctionB();
	
	// set RWX on the region of memory containing printfFunction()
	unsigned int vprv = VirtualProtect(fA, dwPrintFunctionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	if (vprv!=0) { 
		printf("Memory successfully set to RWX.\n"); 
		printf("PID: %d\n", thispid); 
		printf("Base address of module: 0x%8x\n", fA); 
		printf("End address of meaning: 0x%8x\n", fB); 
		printf("Old protection:         0x%8x\n", &dwOldProtect); 
		printf("New protection:         0x%8x\n", PAGE_EXECUTE_READWRITE); 
		printf("Length in bytes:        0x%8x\n", dwPrintFunctionSize); 
		printf("Return value from VirtualProtect: %d\n", vprv); 
	} else { 
		printf("No joy...\n"); 
		printf("PID: %d\n", thispid); 
		printf("Base address of module: 0x%8x\n", fA); 
		printf("End address of meaning: 0x%8x\n", fB); 
		printf("Old protection:         0x%8x\n", &dwOldProtect); 
		printf("New protection:         0x%8x\n", PAGE_EXECUTE_READWRITE); 
		printf("Length in bytes:        0x%8x\n", dwPrintFunctionSize); 
		printf("Return value from VirtualProtect: %d\n", vprv); 
	}
	
    // read the memory from printfFunctionB() to char shellcode[]
	unsigned int rpmrv = ReadProcessMemory(thisProcHandle, fAB, shellcode, 25, bytesRead);

	if (&bytesRead == 0) {
		printf("%s %d\n","ReadProcessMemory() failed, dog!: ", rpmrv);
		_getch();
		exit(1);
	} else {
		printf("$s %d\n","ReadProcessMemory() return value: ",rpmrv);
	}
	int i;
	for (i = 0; i < sizeof(shellcode); i++) {
		printf("%#x",shellcode[i]);
	}
	printf("\n");

    // overwrite printfFunction() with printfFunctionB()
	unsigned int wpmrv = WriteProcessMemory(thisProcHandle, fA, shellcode, sizeof(shellcode), bytesWritten);
		
	if (wpmrv == 0) {
		printf("%s %d\n","overwriting failed, dog!: ", wpmrv);
		_getch();
		exit(1);
	} else {
		printf("%s %d\n","WriteProcessMemory return value: ",wpmrv);
	}
	
	// restore vm protect
	//VirtualProtect(fA, dwPrintFunctionSize, dwOldProtect, NULL);
	// meh

    // print out: B,B
	printfFunction();
	printfFunctionB();

	_getch();
	exit(0);
}