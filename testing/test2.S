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

call poop 
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
call label_2

push ecx

label_2:
pop ecx
jmp 0x01000000 
jmp [eax]
jmp [eax+0x12345678]
jmp eax
jz 0x00000006
poop:
shl dword[eax], 0x1
shl dword [eax+0x78],0x1  
shl dword [eax+0x12345678],0x1 
shl dword eax, 0x1
jz mub
mub:
pop ecx
push ecx
push ecx
push ecx	
jz poop
jnz 0x5
jnz poop
jnz 0xd0ffffff
sar dword[eax], 0x1
sar dword [eax+0x78],0x1  
sar dword [eax+0x12345678],0x1 
sar dword eax, 0x1

lea eax, [eax]
lea eax, [ecx]
lea eax, [0x12345678]
lea eax, [edx+0x78]
lea eax, [eax+0x12345678]
lea eax, [edx+0x12345678]
lea edi,  [edi]
lea eax,  [eax]
lea eax, [0x12455678]
lea eax,  [eax+0x78]
lea eax,[eax+0x12345678]
lea eax,[0x21345678]
lea edx,[ecx]
lea ebx,[edx+0x78]
lea eax,[eax+0x12345678]

sbb eax,0x11223344
sbb dword [eax], 0x11223344
sbb dword [ecx], 0x11223344
sbb dword [edx], 0x11223344
sbb dword [ebx], 0x11223344
sbb dword [esi], 0x11223344
sbb dword [edi], 0x11223344
sbb dword [0x11223344], 0x55667788 
sbb dword [eax+0x08],0x11223344
sbb dword [eax+0x11223344],0x55667788 
sbb dword [ecx+0x11223344],0x55667788 
sbb dword [edx+0x11223344],0x55667788 
sbb dword [ebx+0x11223344],0x55667788 
sbb dword [esi+0x11223344],0x55667788 
sbb eax,0x11223344 
sbb ecx,0x11223344
sbb edx,0x11223344
sbb ebx,0x11223344
sbb esi,0x11223344
sbb edi,0x11223344
sbb [eax],eax
sbb [eax],ecx
sbb [eax],edx
sbb [eax],ebx
sbb [eax],esi
sbb [eax],edi
sbb eax,[eax]
sbb ecx,[eax]
sbb edx,[eax]
sbb ebx,[eax]
sbb esi,[eax]
sbb edi,[eax]
sbb [0x12345678], eax
sbb [eax+0x78],eax 
sbb [edi+0x78],ecx 
sbb eax,[eax+0x78]
sbb ecx, [edi+0x78]
sbb [eax+0x12345678], eax
sbb [edi+0x12345678], ecx
sbb esp, ebx
sbb eax, esi
sbb ebp, esi
sbb eax, [0x12345678]
sbb ecx, [0x23455678]
sbb eax, [eax+0x12345678]
sbb ecx, [edx+0x34567890]
sbb esi, edi

mov eax,0x11223344
mov dword [eax], 0x11223344
mov dword [ecx], 0x11223344
mov dword [edx], 0x11223344
mov dword [ebx], 0x11223344
mov dword [esi], 0x11223344
mov dword [edi], 0x11223344
mov dword [0x11223344], 0x55667788 
mov dword [eax+0x08],0x11223344
mov dword [eax+0x11223344],0x55667788 
mov dword [ecx+0x11223344],0x55667788 
mov dword [edx+0x11223344],0x55667788 
mov dword [ebx+0x11223344],0x55667788 
mov dword [esi+0x11223344],0x55667788 
mov eax,0x11223344 
mov ecx,0x11223344
mov edx,0x11223344
mov ebx,0x11223344
mov esi,0x11223344
mov edi,0x11223344
mov [eax],eax
mov [eax],ecx
mov [eax],edx
mov [eax],ebx
mov [eax],esi
mov [eax],edi
mov eax,[eax]
mov ecx,[eax]
mov edx,[eax]
mov ebx,[eax]
mov esi,[eax]
mov edi,[eax]
mov [eax+0x78],eax 
mov [edi+0x78],ecx 
mov eax,[eax+0x78]
mov ecx, [edi+0x78]
mov [eax+0x12345678], eax
mov [edi+0x12345678], ecx
mov esp, ebx
mov eax, esi
mov ebp, esi
mov ecx, [0x23455678]
mov eax, [eax+0x12345678]
mov ecx, [edx+0x34567890]
mov esi, edi
movsb
movsd

shr dword[eax], 0x1
shr dword [eax+0x78],0x1  
shr dword [eax+0x12345678],0x1 
shr dword eax, 0x1

movzx ecx, ax

test eax, 0x12345678
test dword[eax],0x12345678 
test dword[ecx], 0x12345678
test dword[0x12345678], 0x12345678
test dword[edx+0x78], 0x12345678
test dword[eax+0x12345678], 0x12345678
test dword[edx+0x12345678], 0x12345678
test ecx, 0x12345678
test [eax],eax
test [eax],ecx
test [eax],edx
test [eax],ebx
test [eax],esi
test [eax],edi
test eax,[eax]
test ecx,[eax]
test edx,[eax]
test ebx,[eax]
test esi,[eax]
test edi,[eax]
test [0x12345678], eax
test [eax+0x78],eax 
test [edi+0x78],ecx 
test eax,[eax+0x78]
test ecx, [edi+0x78]
test [eax+0x12345678], eax
test [edi+0x12345678], ecx

mul dword[eax]
mul dword[ecx]
mul dword[0x12345678]
mul dword[edx+0x78]
mul dword[eax+0x12345678]
mul dword[edx+0x12345678]
mul eax
mul ecx
mul edx

xor eax,0x11223344 
xor ecx,0x11223344
xor edx,0x11223344
xor ebx,0x11223344
xor esi,0x11223344
xor edi,0x11223344
xor eax,0x11223344
xor dword [eax], 0x11223344
xor dword [ecx], 0x11223344
xor dword [edx], 0x11223344
xor dword [ebx], 0x11223344
xor dword [esi], 0x11223344
xor dword [edi], 0x11223344
xor dword [0x11223344], 0x55667788 
xor dword [eax+0x08],0x11223344
xor dword [eax+0x11223344],0x55667788 
xor dword [ecx+0x11223344],0x55667788 
xor dword [edx+0x11223344],0x55667788 
xor dword [ebx+0x11223344],0x55667788 
xor dword [esi+0x11223344],0x55667788 
xor eax,0x11223344 
xor ecx,0x11223344
xor edx,0x11223344
xor ebx,0x11223344
xor esi,0x11223344
xor edi,0x11223344
xor [eax],eax
xor [eax],ecx
xor [eax],edx
xor [eax],ebx
xor [eax],esi
xor [eax],edi
xor eax,[eax]
xor ecx,[eax]
xor edx,[eax]
xor ebx,[eax]
xor esi,[eax]
xor edi,[eax]
xor [0x12345678], eax
xor [eax+0x78],eax 
xor [edi+0x78],ecx 
xor eax,[eax+0x78]
xor ecx, [edi+0x78]
xor [eax+0x12345678], eax
xor [edi+0x12345678], ecx
xor esp, ebx
xor eax, esi
xor ebp, esi
xor eax, [0x12345678]
xor ecx, [0x23455678]
xor eax, [eax+0x12345678]
xor ecx, [edx+0x34567890]
xor esi, edi

neg dword[eax]
neg dword[ecx]
neg dword[0x12345678]
neg dword[edx+0x78]
neg dword[eax+0x12345678]
neg dword[edx+0x12345678]
neg eax
neg ecx
neg edx

or dword [eax], 0x78
or DWORD [eax],0x1
or DWORD [eax],0xffffff80
or DWORD [0x34567805],0xffffff81
or DWORD [eax+0x5],0xffffff88
or DWORD [eax+0x5],0x78 
or DWORD [eax+0x12345678],0xffffff88
or DWORD [eax+0x12345678],0x78
or eax,0x78
or eax,0xffffff88

and dword [eax], 0x78
and DWORD [eax],0x1
and DWORD [eax],0xffffff80
and DWORD [0x34567805],0xffffff81
and DWORD [eax+0x5],0xffffff88
and DWORD [eax+0x5],0x78 
and DWORD [eax+0x12345678],0xffffff88
and DWORD [eax+0x12345678],0x78
and eax,0x78
and eax,0xffffff88

add dword [eax], 0x78
add DWORD [eax],0x1
add DWORD [eax],0xffffff80
add DWORD [0x34567805],0xffffff81
add DWORD [eax+0x5],0xffffff88
add DWORD [eax+0x5],0x78 
add DWORD [eax+0x12345678],0xffffff88
add DWORD [eax+0x12345678],0x78
add eax,0x78
add eax,0xffffff88