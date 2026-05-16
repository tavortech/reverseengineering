myasm.cpp: created visual studio file for making asm code and creating exe with it.
(instead of looking for opcodes online like a monkey)
myasm.exe: (created from cpp)
the exe was later used to copy bytes from into the cff explorer
(by opening in ida-> looking for our created function->copying bytes until the end of
the function->adding in our dice.exe the jmp to our address. we got the jmp command 
from code above and just calculated the difference to jmp to where we wanted)