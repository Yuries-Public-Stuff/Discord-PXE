; aes128 gcm for the legacy tls layer
section .bss align=16
g2_h resb 16
g2_y resb 16
g2_v resb 16
g2_z resb 16
g2_j0 resb 16
g2_ctr resb 16
g2_stream resb 16
g2_block resb 16
g2_mask resb 16
g2_lenblk resb 16
g2_outptr resq 1
g2_tagptr resq 1
g2_cryptout resq 1
section .text
g2_xor16:
 xor r8d,r8d
.l: cmp r8d,16
 jae .d
 mov al,[rdx+r8]
 xor [rcx+r8],al
 inc r8d
 jmp .l
.d: ret
g2_shift:
 lea r10,[rel g2_v]
 mov r9b,[r10+15]
 and r9b,1
 xor edx,edx
 xor ecx,ecx
.l:
 cmp ecx,16
 jae .red
 movzx eax,byte [r10+rcx]
 mov r8d,eax
 and r8d,1
 shr al,1
 test dl,dl
 jz .s
 or al,80h
.s: mov [r10+rcx],al
 mov dl,r8b
 inc ecx
 jmp .l
.red:
 test r9b,r9b
 jz .d
 xor byte [r10],0E1h
.d: ret
g2_mul:
 push rbx
 push rsi
 push rdi
 push r12
 mov rsi,rcx
 mov [rel g2_outptr],rdx
 lea rcx,[rel g2_z]
 xor edx,edx
 mov r8d,16
 sub rsp,40
 call mem_set_x64
 add rsp,40
 lea rcx,[rel g2_v]
 lea rdx,[rel g2_h]
 mov r8d,16
 sub rsp,40
 call mem_copy_x64
 add rsp,40
 xor edi,edi
.b:
 cmp edi,16
 jae .fin
 mov bl,[rsi+rdi]
 mov r12d,8
.bit:
 test bl,80h
 jz .sh
 lea rcx,[rel g2_z]
 lea rdx,[rel g2_v]
 sub rsp,40
 call g2_xor16
 add rsp,40
.sh:
 sub rsp,40
 call g2_shift
 add rsp,40
 shl bl,1
 dec r12d
 jnz .bit
 inc edi
 jmp .b
.fin:
 mov rcx,[rel g2_outptr]
 lea rdx,[rel g2_z]
 mov r8d,16
 sub rsp,40
 call mem_copy_x64
 add rsp,40
 pop r12
 pop rdi
 pop rsi
 pop rbx
 ret
g2_ghash_block:
 push rcx
 lea rcx,[rel g2_y]
 mov rdx,[rsp]
 sub rsp,32
 call g2_xor16
 add rsp,32
 lea rcx,[rel g2_y]
 mov rdx,rcx
 sub rsp,32
 call g2_mul
 add rsp,32
 add rsp,8
 ret
g2_ghash_bytes:
 push rbx
 push rsi
 push rdi
 mov rsi,rcx
 mov rbx,rdx
.l:
 test rbx,rbx
 jz .d
 lea rcx,[rel g2_block]
 xor edx,edx
 mov r8d,16
 sub rsp,32
 call mem_set_x64
 add rsp,32
 mov rdi,rbx
 cmp rdi,16
 jbe .n
 mov edi,16
.n:
 lea rcx,[rel g2_block]
 mov rdx,rsi
 mov r8,rdi
 sub rsp,32
 call mem_copy_x64
 add rsp,32
 lea rcx,[rel g2_block]
 sub rsp,32
 call g2_ghash_block
 add rsp,32
 add rsi,rdi
 sub rbx,rdi
 jmp .l
.d:
 pop rdi
 pop rsi
 pop rbx
 ret
g2_inc32:
 lea r10,[rel g2_ctr]
 mov ecx,15
.l: inc byte [r10+rcx]
 jnz .d
 dec ecx
 cmp ecx,11
 ja .l
.d: ret
g2_store_bits:
 mov qword [rcx],0
 mov eax,edx
 shl rax,3
 bswap rax
 mov [rcx],rax
 ret
g2_init:
 push rbx
 mov rbx,rdx
 sub rsp,40
 call aes2_set_key
 add rsp,40
 lea rcx,[rel g2_block]
 xor edx,edx
 mov r8d,16
 sub rsp,40
 call mem_set_x64
 add rsp,40
 lea rcx,[rel g2_block]
 lea rdx,[rel g2_h]
 sub rsp,40
 call aes2_encrypt
 add rsp,40
 lea rcx,[rel g2_j0]
 mov rdx,rbx
 mov r8d,12
 sub rsp,40
 call mem_copy_x64
 add rsp,40
 mov dword [rel g2_j0+12],01000000h
 lea rcx,[rel g2_ctr]
 lea rdx,[rel g2_j0]
 mov r8d,16
 sub rsp,40
 call mem_copy_x64
 add rsp,40
 lea rcx,[rel g2_j0]
 lea rdx,[rel g2_mask]
 sub rsp,40
 call aes2_encrypt
 add rsp,40
 pop rbx
 ret
g2_ctrcrypt:
 push rbx
 push rsi
 push rdi
 mov rsi,rcx
 mov rdi,rdx
 mov rbx,r8
.l:
 test rbx,rbx
 jz .d
 sub rsp,32
 call g2_inc32
 add rsp,32
 lea rcx,[rel g2_ctr]
 lea rdx,[rel g2_stream]
 sub rsp,32
 call aes2_encrypt
 add rsp,32
 mov rcx,rbx
 cmp rcx,16
 jbe .n
 mov ecx,16
.n:
 xor r8d,r8d
.x:
 cmp r8,rcx
 jae .next
 mov al,[rsi+r8]
 lea r10,[rel g2_stream]
 xor al,[r10+r8]
 mov [rdi+r8],al
 inc r8
 jmp .x
.next:
 add rsi,rcx
 add rdi,rcx
 sub rbx,rcx
 jmp .l
.d:
 pop rdi
 pop rsi
 pop rbx
 ret
g2_tag:
 push rbx
 push rsi
 push rdi
 push r12
 mov r12,rcx
 mov rbx,rdx
 mov rsi,r8
 mov rdi,r9
 mov rax,[rsp+72]
 mov [rel g2_tagptr],rax
 lea rcx,[rel g2_y]
 xor edx,edx
 mov r8d,16
 sub rsp,40
 call mem_set_x64
 add rsp,40
 mov rcx,r12
 mov rdx,rbx
 sub rsp,40
 call g2_ghash_bytes
 add rsp,40
 mov rcx,rsi
 mov rdx,rdi
 sub rsp,40
 call g2_ghash_bytes
 add rsp,40
 lea rcx,[rel g2_lenblk]
 xor edx,edx
 mov r8d,16
 sub rsp,40
 call mem_set_x64
 add rsp,40
 lea rcx,[rel g2_lenblk]
 mov edx,ebx
 sub rsp,40
 call g2_store_bits
 add rsp,40
 lea rcx,[rel g2_lenblk+8]
 mov edx,edi
 sub rsp,40
 call g2_store_bits
 add rsp,40
 lea rcx,[rel g2_lenblk]
 sub rsp,40
 call g2_ghash_block
 add rsp,40
 mov r11,[rel g2_tagptr]
 lea r10,[rel g2_y]
 lea r9,[rel g2_mask]
 xor ecx,ecx
.l:
 cmp ecx,16
 jae .d
 mov al,[r10+rcx]
 xor al,[r9+rcx]
 mov [r11+rcx],al
 inc ecx
 jmp .l
.d:
 pop r12
 pop rdi
 pop rsi
 pop rbx
 ret
aes2_gcm_encrypt:
 push rbx
 push rsi
 push rdi
 push r12
 push r13
 push r14
 push r15
 mov r12,rcx
 mov r13,rdx
 mov r14,r8
 mov r15,r9
 mov rsi,[rsp+96]
 mov ebx,[rsp+104]
 mov rdi,[rsp+112]
 mov rax,[rsp+120]
 mov [rel g2_tagptr],rax
 mov rcx,r12
 mov rdx,r13
 sub rsp,32
 call g2_init
 add rsp,32
 mov rcx,rsi
 mov rdx,rdi
 mov r8d,ebx
 sub rsp,32
 call g2_ctrcrypt
 add rsp,32
 mov rcx,r14
 mov rdx,r15
 mov r8,rdi
 mov r9d,ebx
 sub rsp,48
 mov rax,[rel g2_tagptr]
 mov [rsp+32],rax
 call g2_tag
 add rsp,48
 xor eax,eax
 pop r15
 pop r14
 pop r13
 pop r12
 pop rdi
 pop rsi
 pop rbx
 ret
aes2_gcm_decrypt:
 push rbx
 push rsi
 push rdi
 push r12
 push r13
 push r14
 push r15
 mov r12,rcx
 mov r13,rdx
 mov r14,r8
 mov r15,r9
 mov rsi,[rsp+96]
 mov ebx,[rsp+104]
 mov rdi,[rsp+112]
 mov rax,[rsp+120]
 mov [rel g2_cryptout],rax
 mov rcx,r12
 mov rdx,r13
 sub rsp,32
 call g2_init
 add rsp,32
 mov rcx,r14
 mov rdx,r15
 mov r8,rsi
 mov r9d,ebx
 sub rsp,48
 lea rax,[rel g2_block]
 mov [rsp+32],rax
 call g2_tag
 add rsp,48
 lea rcx,[rel g2_block]
 mov rdx,rdi
 mov r8d,16
 sub rsp,32
 call mem_equal_x64
 add rsp,32
 test eax,eax
 jz .bad
 mov rcx,r12
 mov rdx,r13
 sub rsp,32
 call g2_init
 add rsp,32
 mov rcx,rsi
 mov rdx,[rel g2_cryptout]
 mov r8d,ebx
 sub rsp,32
 call g2_ctrcrypt
 add rsp,32
 xor eax,eax
 jmp .d
.bad:
 mov rax,EFI_DEVICE_ERROR
.d:
 pop r15
 pop r14
 pop r13
 pop r12
 pop rdi
 pop rsi
 pop rbx
 ret