; aes128 used by the legacy tls layer
%define AES2_RK_BYTES 176

section .data align=16
aes2_sbox:
 db 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76
 db 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0
 db 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15
 db 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75
 db 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84
 db 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf
 db 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8
 db 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2
 db 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73
 db 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb
 db 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79
 db 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08
 db 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a
 db 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e
 db 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf
 db 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
aes2_rcon db 1,2,4,8,16,32,64,128,0x1b,0x36

section .bss align=16
aes2_rk resb AES2_RK_BYTES
aes2_state resb 16
aes2_tmp resb 16

section .text

aes2_set_key:
 push rbx
 push rsi
 push rdi
 mov rsi,rcx
 lea rcx,[rel aes2_rk]
 mov rdx,rsi
 mov r8d,16
 sub rsp,32
 call mem_copy_x64
 add rsp,32
 mov edi,16
 xor ebx,ebx
.expand:
 cmp edi,AES2_RK_BYTES
 jae .done
 lea r10,[rel aes2_rk]
 lea r11,[rel aes2_tmp]
 mov al,[r10+rdi-4]
 mov [r11],al
 mov al,[r10+rdi-3]
 mov [r11+1],al
 mov al,[r10+rdi-2]
 mov [r11+2],al
 mov al,[r10+rdi-1]
 mov [r11+3],al
 mov eax,edi
 and eax,15
 jnz .gen
 movzx eax,byte [r11]
 movzx edx,byte [r11+1]
 movzx ecx,byte [r11+2]
 movzx r8d,byte [r11+3]
 mov [r11],dl
 mov [r11+1],cl
 mov [r11+2],r8b
 mov [r11+3],al
 lea r9,[rel aes2_sbox]
 xor ecx,ecx
.sub:
 movzx eax,byte [r11+rcx]
 mov al,[r9+rax]
 mov [r11+rcx],al
 inc ecx
 cmp ecx,4
 jb .sub
 lea r9,[rel aes2_rcon]
 mov al,[r9+rbx]
 xor [r11],al
 inc ebx
.gen:
 xor ecx,ecx
.g:
 mov eax,edi
 sub eax,16
 mov al,[r10+rax]
 xor al,[r11+rcx]
 mov [r10+rdi],al
 inc edi
 inc ecx
 cmp ecx,4
 jb .g
 jmp .expand
.done:
 pop rdi
 pop rsi
 pop rbx
 ret

aes2_xtime:
 mov r8b,al
 shl al,1
 test r8b,0x80
 jz .d
 xor al,0x1b
.d:
 ret

aes2_add_key:
 mov eax,ecx
 shl eax,4
 lea r10,[rel aes2_rk]
 add r10,rax
 lea r11,[rel aes2_state]
 xor ecx,ecx
.l:
 cmp ecx,16
 jae .d
 mov al,[r10+rcx]
 xor [r11+rcx],al
 inc ecx
 jmp .l
.d:
 ret

aes2_sub:
 lea r10,[rel aes2_state]
 lea r11,[rel aes2_sbox]
 xor ecx,ecx
.l:
 cmp ecx,16
 jae .d
 movzx eax,byte [r10+rcx]
 mov al,[r11+rax]
 mov [r10+rcx],al
 inc ecx
 jmp .l
.d:
 ret

aes2_shift:
 lea rcx,[rel aes2_tmp]
 lea rdx,[rel aes2_state]
 mov r8d,16
 sub rsp,40
 call mem_copy_x64
 add rsp,40
 lea r10,[rel aes2_state]
 lea r11,[rel aes2_tmp]
 mov al,[r11+0]
 mov [r10+0],al
 mov al,[r11+4]
 mov [r10+4],al
 mov al,[r11+8]
 mov [r10+8],al
 mov al,[r11+12]
 mov [r10+12],al
 mov al,[r11+5]
 mov [r10+1],al
 mov al,[r11+9]
 mov [r10+5],al
 mov al,[r11+13]
 mov [r10+9],al
 mov al,[r11+1]
 mov [r10+13],al
 mov al,[r11+10]
 mov [r10+2],al
 mov al,[r11+14]
 mov [r10+6],al
 mov al,[r11+2]
 mov [r10+10],al
 mov al,[r11+6]
 mov [r10+14],al
 mov al,[r11+15]
 mov [r10+3],al
 mov al,[r11+3]
 mov [r10+7],al
 mov al,[r11+7]
 mov [r10+11],al
 mov al,[r11+11]
 mov [r10+15],al
 ret

aes2_mix_col:
 push rbx
 mov rbx,rcx
 lea r10,[rel aes2_tmp]
 mov eax,[rbx]
 mov [r10],eax

 mov dl,[r10]
 xor dl,[r10+1]
 xor dl,[r10+2]
 xor dl,[r10+3]

 mov al,[r10]
 xor al,[r10+1]
 sub rsp,32
 call aes2_xtime
 add rsp,32
 xor al,[r10]
 xor al,dl
 mov [rbx],al

 mov al,[r10+1]
 xor al,[r10+2]
 sub rsp,32
 call aes2_xtime
 add rsp,32
 xor al,[r10+1]
 xor al,dl
 mov [rbx+1],al

 mov al,[r10+2]
 xor al,[r10+3]
 sub rsp,32
 call aes2_xtime
 add rsp,32
 xor al,[r10+2]
 xor al,dl
 mov [rbx+2],al

 mov al,[r10+3]
 xor al,[r10]
 sub rsp,32
 call aes2_xtime
 add rsp,32
 xor al,[r10+3]
 xor al,dl
 mov [rbx+3],al

 pop rbx
 ret

aes2_mix:
 push rbx
 lea rbx,[rel aes2_state]
 xor ecx,ecx
.l:
 cmp ecx,4
 jae .d
 push rcx
 mov rcx,rbx
 sub rsp,40
 call aes2_mix_col
 add rsp,40
 pop rcx
 add rbx,4
 inc ecx
 jmp .l
.d:
 pop rbx
 ret

aes2_encrypt:
 push rbx
 push rsi
 mov rbx,rcx
 mov rsi,rdx
 lea rcx,[rel aes2_state]
 mov rdx,rbx
 mov r8d,16
 sub rsp,40
 call mem_copy_x64
 add rsp,40
 xor ecx,ecx
 sub rsp,40
 call aes2_add_key
 add rsp,40
 mov ebx,1
.r:
 cmp ebx,10
 jae .last
 sub rsp,40
 call aes2_sub
 add rsp,40
 sub rsp,40
 call aes2_shift
 add rsp,40
 sub rsp,40
 call aes2_mix
 add rsp,40
 mov ecx,ebx
 sub rsp,40
 call aes2_add_key
 add rsp,40
 inc ebx
 jmp .r
.last:
 sub rsp,40
 call aes2_sub
 add rsp,40
 sub rsp,40
 call aes2_shift
 add rsp,40
 mov ecx,10
 sub rsp,40
 call aes2_add_key
 add rsp,40
 mov rcx,rsi
 lea rdx,[rel aes2_state]
 mov r8d,16
 sub rsp,40
 call mem_copy_x64
 add rsp,40
 pop rsi
 pop rbx
 ret
