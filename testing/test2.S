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

add eax,[eax+0x78]
add ecx, [edi+0x78]

add [eax+0x12345678], eax
add [edi+0x12345678], ecx

add esp, ebx
add eax, esi
add ebp, esi

add eax, [0x12345678]
add ecx, [0x23455678]

add eax, [eax+0x12345678]
add ecx, [edx+0x34567890]

add esi, edi
nop
nop
nop


and eax,0x12345678 
and dword [eax],0x12345678 
and dword [ecx],0x12345678 

and dword [eax+0x12],0x12345678
and dword [ecx+0x12],0x12345678

and dword [eax+0x34567812],0x34567812
and eax,0x12345678 
AND [EAX], EAX
and [edi], edi
and [eax+0x78],eax 
and esi, ebx
and [eax+0x12345678],ecx
and [eax+0x12345678], eax
and [edi+0x12345678], ecx

not dword[eax]
not dword[ecx]
not dword[0x12345678]
not dword[edx+0x78]
not dword[eax+0x12345678]
not dword[edx+0x12345678]
not eax
not ecx
not edx
bswap eax
bswap ecx
bswap edi
bswap edi
bswap esi

or eax, 0x12345678
or dword [eax], 0x11223344
or dword [ecx], 0x11223344
or dword [edx], 0x11223344
or dword [ebx], 0x11223344
or dword [esi], 0x11223344
or dword [edi], 0x11223344
or dword [0x11223344], 0x55667788 
or dword [eax+0x08],0x11223344
or dword [eax+0x11223344],0x55667788 
or dword [ecx+0x11223344],0x55667788 
or dword [edx+0x11223344],0x55667788 
or dword [ebx+0x11223344],0x55667788 
or dword [esi+0x11223344],0x55667788 
or eax,0x11223344 
or ecx,0x11223344
or edx,0x11223344
or ebx,0x11223344
or esi,0x11223344
or edi,0x11223344
or [eax],eax
or [eax],ecx
or [eax],edx
or [eax],ebx
or [eax],esi
or [eax],edi
or eax,[eax]
or ecx,[eax]
or edx,[eax]
or ebx,[eax]
or esi,[eax]
or edi,[eax]
or [0x12345678], eax
or [eax+0x78],eax 
or [edi+0x78],ecx 
or eax,[eax+0x78]
or ecx, [edi+0x78]
or [eax+0x12345678], eax
or [edi+0x12345678], ecx
or esp, ebx
or eax, esi
or ebp, esi
or eax, [0x12345678]
or ecx, [0x23455678]
or eax, [eax+0x12345678]
or ecx, [edx+0x34567890]
or esi, edi

pop dword[eax]
pop dword[edi]
pop dword[eax+0x78]
pop dword[eax+0x12345678]
pop dword[0x12345678]
pop eax
pop ecx
pop ebp
pop esp