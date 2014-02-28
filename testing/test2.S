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

cmp eax,0x11223344
cmp dword [eax], 0x11223344
cmp dword [ecx], 0x11223344
cmp dword [edx], 0x11223344
cmp dword [ebx], 0x11223344
cmp dword [esi], 0x11223344
cmp dword [edi], 0x11223344
cmp dword [0x11223344], 0x55667788 

cmp dword [eax+0x08],0x11223344

cmp dword [eax+0x11223344],0x55667788 
cmp dword [ecx+0x11223344],0x55667788 
cmp dword [edx+0x11223344],0x55667788 
cmp dword [ebx+0x11223344],0x55667788 
cmp dword [esi+0x11223344],0x55667788 

cmp eax,0x11223344 
cmp ecx,0x11223344
cmp edx,0x11223344
cmp ebx,0x11223344
cmp esi,0x11223344
cmp edi,0x11223344


cmp [eax],eax
cmp [eax],ecx
cmp [eax],edx
cmp [eax],ebx
cmp [eax],esi
cmp [eax],edi

cmp eax,[eax]
cmp ecx,[eax]
cmp edx,[eax]
cmp ebx,[eax]
cmp esi,[eax]
cmp edi,[eax]

cmp [0x12345678], eax

cmp [eax+0x78],eax 
cmp [edi+0x78],ecx 

cmp eax,[eax+0x78]
cmp ecx, [edi+0x78]

cmp [eax+0x12345678], eax
cmp [edi+0x12345678], ecx

cmp esp, ebx
cmp eax, esi
cmp ebp, esi

cmp eax, [0x12345678]
cmp ecx, [0x23455678]

cmp eax, [eax+0x12345678]
cmp ecx, [edx+0x34567890]

cmp esi, edi


popcnt edi, dword [edi]
popcnt eax, dword [eax]
popcnt eax, [0x12455678]
popcnt eax, dword [eax+0x78]
popcnt eax,DWORD[eax+0x12345678]
popcnt eax, eax
add eax, eax

dec dword[eax]
dec dword[ecx]
dec dword[0x12345678]
dec dword[edx+0x78]
dec dword[eax+0x12345678]
dec dword[edx+0x12345678]
dec eax
dec ecx
dec edx

push dword[eax]
push dword[ecx]
push dword[0x12345678]
push dword[edx+0x78]
push dword[eax+0x12345678]
push dword[edx+0x12345678]
push eax
push ecx
push edx
push 0x12345678

idiv dword[eax]
idiv dword[ecx]
idiv dword[0x12345678]
idiv dword[edx+0x78]
idiv dword[eax+0x12345678]
idiv dword[edx+0x12345678]
idiv eax
idiv ecx
idiv edx

imul dword[eax]
imul dword[ecx]
imul dword[0x12345678]
imul dword[edx+0x78]
imul dword[eax+0x12345678]
imul dword[edx+0x12345678]
imul eax
imul ecx
imul edx
imul edi, dword [edi]
imul eax, dword [eax]
imul eax, [0x12455678]
imul eax, dword [eax+0x78]
imul eax,DWORD[eax+0x12345678]
imul eax, eax
imul eax,[0x21345678],0x11345678
imul edx,[ecx],0x21345678 
imul ebx,[edx+0x78],0x12345678
imul eax,[eax+0x12345678],0x34456789
imul esp,edi,0x12345678
retf 0x3254
retf

inc dword[eax]
inc dword[ecx]
inc dword[0x12345678]
inc dword[edx+0x78]
inc dword[eax+0x12345678]
inc dword[edx+0x12345678]
inc eax
inc ecx
inc edx

retn 0x3254
retn