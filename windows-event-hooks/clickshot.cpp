#define _WIN32_WINNT 0x0400
#pragma comment( lib, "user32.lib" )
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <time.h>

/*
A friend of mine asked me to write a program that would take a screenshot 
every time he clicked the left mouse button so he could quickly create 
screenshots for creating software instructions for new employees.

I decided to google windows hooks and write a program that would hook the mouse click event
then perform some action every time it was detected. I later also googled windows screenshot
api examples, then just copypasta'd one that looked good since that was the least interesting part.

This is that program.
*/

HHOOK hMouseHook;

__declspec(dllexport) LRESULT CALLBACK KeyboardEvent (int nCode, WPARAM wParam, LPARAM lParam) {
	MOUSEHOOKSTRUCT * pMouseStruct = (MOUSEHOOKSTRUCT *) lParam;
	if (pMouseStruct != NULL) {
		if (wParam == WM_LBUTTONDOWN) {
			printf("Mouse clicked at: X=%d, Y=%d\n",pMouseStruct->pt.x,pMouseStruct->pt.y);
			//YOLO!
            /*
            This is screenshot saving code from some forum post or stackexchange question.
            I didn't feel like writing this part, so, lol, copypasta
            */
			char* filename = "C:\\Users\\user\\Desktop\\ss.bmp";
			keybd_event(VK_SNAPSHOT, 0x45, KEYEVENTF_EXTENDEDKEY, 0);
        	keybd_event(VK_SNAPSHOT, 0x45, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0);
        	HBITMAP h;
        	
        	OpenClipboard(NULL);
        	h = (HBITMAP)GetClipboardData(CF_BITMAP);
        	CloseClipboard();
        	HDC hdc = NULL;
        	FILE* fp = NULL;
        	LPVOID pBuf = NULL;
        	BITMAPINFO bmpInfo;
        	BITMAPFILEHEADER bmpFileHeader;
        	do
        	{ 
        		hdc=GetDC(NULL);
        		ZeroMemory(&bmpInfo,sizeof(BITMAPINFO));
        		bmpInfo.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);
        		GetDIBits(hdc,h,0,0,NULL,&bmpInfo,DIB_RGB_COLORS); 
        		if(bmpInfo.bmiHeader.biSizeImage<=0) {
        			bmpInfo.bmiHeader.biSizeImage=bmpInfo.bmiHeader.biWidth*abs(bmpInfo.bmiHeader.biHeight)*(bmpInfo.bmiHeader.biBitCount+7)/8;
        		}
        		if((pBuf = malloc(bmpInfo.bmiHeader.biSizeImage))==NULL) {
        			MessageBoxA( NULL, "Unable to Allocate Bitmap Memory", "Error", MB_OK|MB_ICONERROR);
        			break;
        		} 
        		bmpInfo.bmiHeader.biCompression=BI_RGB;
        		GetDIBits(hdc,h,0,bmpInfo.bmiHeader.biHeight,pBuf, &bmpInfo, DIB_RGB_COLORS);
        		if((fp = fopen(filename,"wb"))==NULL) {
        			MessageBoxA( NULL, "Unable to Create Bitmap File", "Error", MB_OK|MB_ICONERROR);
        			break;
        		} 
        		bmpFileHeader.bfReserved1=0;
        		bmpFileHeader.bfReserved2=0;
        		bmpFileHeader.bfSize=sizeof(BITMAPFILEHEADER)+sizeof(BITMAPINFOHEADER)+bmpInfo.bmiHeader.biSizeImage;
        		bmpFileHeader.bfType='MB';
        		bmpFileHeader.bfOffBits=sizeof(BITMAPFILEHEADER)+sizeof(BITMAPINFOHEADER); 
        		fwrite(&bmpFileHeader,sizeof(BITMAPFILEHEADER),1,fp);
        		fwrite(&bmpInfo.bmiHeader,sizeof(BITMAPINFOHEADER),1,fp);
        		fwrite(pBuf,bmpInfo.bmiHeader.biSizeImage,1,fp); 
        	} while(false); 
        	if(hdc)ReleaseDC(NULL,hdc); 
        	if(pBuf) free(pBuf); 
        	if(fp)fclose(fp);
		}
	}
	return CallNextHookEx(hMouseHook, nCode, wParam, lParam);
}

void MessageLoop() {
	MSG message;
	while (GetMessage(&message,NULL,0,0)) {
		TranslateMessage(&message);
		DispatchMessage(&message);
	}
}

DWORD WINAPI MyMouseLogger(LPVOID lParam) {
	HINSTANCE hInstance = GetModuleHandle(NULL);
	if (!hInstance) hInstance = LoadLibrary((LPCWSTR) lParam);
	if (!hInstance) return 1;

	hMouseHook = SetWindowsHookEx(WH_MOUSE_LL, (HOOKPROC) KeyboardEvent, hInstance,NULL);
	MessageLoop();
	UnhookWindowsHookEx(hMouseHook);
	return 0;
}

int main(int argc, char** argv) {
	HANDLE hThread;
	DWORD dwThread;

	hThread = CreateThread(NULL,NULL,(LPTHREAD_START_ROUTINE) MyMouseLogger, (LPVOID) argv[0], NULL, &dwThread);
	if (hThread) {
		return WaitForSingleObject(hThread, INFINITE);
	} else {
		return 1;
	}
}