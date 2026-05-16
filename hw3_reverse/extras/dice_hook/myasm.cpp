// myasm.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// myasm.cpp
#include <windows.h>
#include <iostream>

__declspec(naked) void myasm()
{
    __asm {
        push ebp
        mov ebp, esp
        push edi
        mov eax, 0x1058
        push eax
        push edx
        mov eax, [ebp + 0xC]
        cmp eax, 0
        jz custom_return
        mov edx, [eax]
        cmp edx, 0x31425148
        jnz custom_return
        mov edx, [eax + 4]
        cmp edx, 0x594A3545
        jnz custom_return
        mov edx, [eax + 8]
        cmp dl, 0x49
        jnz custom_return
        cmp dh, 0x36
        jnz custom_return
        mov[ebp + 0x8], 7
        custom_return:
        pop edx
            pop eax
    }
}

int main() {
    std::cout << "Calling myasm (does nothing visible)..." << std::endl;
    myasm();
    std::cout << "Done." << std::endl;
    return 0;
}
// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
