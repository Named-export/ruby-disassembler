BITS 32

section .text

xor eax,eax
mov  eax,edx  
mov  [eax],edx  
mov  [eax+0x12345678],edx  
mov  eax,0x12345678   
mov  eax,  [0x12345678]
mov  dword[eax + 0x1234567],  0x12345678
mov  dword[  eax  ],  0x12345678
mov  dword[  0x12345678  ],  0x12345678

add  eax,edx  
add  [eax],edx  
add  [eax+0x12345678],edx  
add  eax,0x12345678   
add  eax,  [0x12345678]
add  dword[eax + 0x1234567],  0x12345678
add  dword[  eax  ],  0x12345678
add  dword[  0x12345678  ],  0x12345678

and  eax,edx  
and  [eax],edx  
and  [eax+0x12345678],edx  
and  eax,0x12345678   
and  eax,  [0x12345678]
and  dword[eax + 0x1234567],  0x12345678
and  dword[  eax  ],  0x12345678
and  dword[  0x12345678  ],  0x12345678

not ecx
not dword[eax]

bswap eax

or  eax,edx  
or  [eax],edx  
or  [eax+0x12345678],edx  
or  eax,0x12345678   
or  eax,  [0x12345678]
or  dword[eax + 0x1234567],  0x12345678
or  dword[  eax  ],  0x12345678
or  dword[  0x12345678  ],  0x12345678

cmp  eax,edx  
cmp  [eax],edx  
cmp  [eax+0x12345678],edx  
cmp  eax,0x12345678   
cmp  eax,  [0x12345678]
cmp  dword[eax + 0x1234567],  0x12345678
cmp  dword[  eax  ],  0x12345678
cmp  dword[  0x12345678  ],  0x12345678

popcnt  eax,edx  
dec eax
dec ecx
idiv eax
idiv ecx
imul eax 
