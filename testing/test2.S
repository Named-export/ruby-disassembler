BITS 32

section .text

add eax,0x11223344
add dword [eax], 0x11223344
add dword [ecx], 0x11223344
add dword [edx], 0x11223344
add dword [ebx], 0x11223344
add dword [esi], 0x11223344
add dword [edi], 0x11223344
add dword [0x11223344], 0x55667788 

add dword [eax+0x08],0x11223344

add dword [eax+0x11223344],0x55667788 
add dword [ecx+0x11223344],0x55667788 
add dword [edx+0x11223344],0x55667788 
add dword [ebx+0x11223344],0x55667788 
add dword [esi+0x11223344],0x55667788 

add eax,0x11223344 
add ecx,0x11223344
add edx,0x11223344
add ebx,0x11223344
add esi,0x11223344
add edi,0x11223344


add [eax],eax
add [eax],ecx
add [eax],edx
add [eax],ebx
add [eax],esi
add [eax],edi

add eax,[eax]
add ecx,[eax]
add edx,[eax]
add ebx,[eax]
add esi,[eax]
add edi,[eax]

add [0x12345678], eax

add [eax+0x78],eax 
add [edi+0x78],ecx 

add [eax+0x12345678], eax
add [edi+0x12345678], ecx

add esp, ebx
add eax, esi
add ebp, esi