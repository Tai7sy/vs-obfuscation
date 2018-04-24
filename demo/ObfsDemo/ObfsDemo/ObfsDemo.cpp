// ObfsDemo.cpp: 定义控制台应用程序的入口点。
//


#include <stdio.h>
#include <windows.h>
#include "../../../obfuscation.h"

int main() {
    printf("I'am the main");
    IFN(LoadLibraryA)(XorString("user32.dll"));
    // 方式1
    IFN(MessageBoxA)(0, XorString("World!"), XorString("Hello"), MB_OK);
    // 方式2
    IFN_DLL(XorStringW(L"user32.dll"), MessageBoxA)(0, XorString("World!"), XorString("Hello"), MB_OK);
    // IFN(MessageBoxW)(0, XorStringW(L"World!"), XorStringW(L"Hello"), MB_OK);
    return 0;
}
