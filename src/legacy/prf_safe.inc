; tls 1.2 prf wrapper
%define TLS2_PRF_SEED_MAX 256
section .bss align=16
prf2_seed resb TLS2_PRF_SEED_MAX
prf2_seed_len resd 1
prf2_out_len resd 1
prf2_a resb 32
prf2_block resb 32
prf2_input resb TLS2_PRF_SEED_MAX+32
section .text
; rcx secret, rdx secret len, r8 label, r9 label len stack +40 seed, +48 seed len, +56
; out, +64 out len
tls12_prf2_sha256_x64:
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
 mov eax,[rsp+120]
 mov [rel prf2_out_len],eax
 mov eax,r15d
 add eax,ebx
 cmp eax,TLS2_PRF_SEED_MAX
 ja .bad
 mov [rel prf2_seed_len],eax
 lea rcx,[rel prf2_seed]
 mov rdx,r14
 mov r8,r15
 sub rsp,32
 call mem_copy_x64
 add rsp,32
 lea rcx,[rel prf2_seed]
 add rcx,r15
 mov rdx,rsi
 mov r8d,ebx
 sub rsp,32
 call mem_copy_x64
 add rsp,32
 mov rcx,r12
 mov rdx,r13
 lea r8,[rel prf2_seed]
 mov r9d,[rel prf2_seed_len]
 sub rsp,48
 lea rax,[rel prf2_a]
 mov [rsp+32],rax
 call hmac_sha256_x64
 add rsp,48
 mov ebx,[rel prf2_out_len]
.loop:
 test ebx,ebx
 jz .ok
 lea rcx,[rel prf2_input]
 lea rdx,[rel prf2_a]
 mov r8d,32
 sub rsp,32
 call mem_copy_x64
 add rsp,32
 lea rcx,[rel prf2_input+32]
 lea rdx,[rel prf2_seed]
 mov r8d,[rel prf2_seed_len]
 sub rsp,32
 call mem_copy_x64
 add rsp,32
 mov rcx,r12
 mov rdx,r13
 lea r8,[rel prf2_input]
 mov r9d,[rel prf2_seed_len]
 add r9d,32
 sub rsp,48
 lea rax,[rel prf2_block]
 mov [rsp+32],rax
 call hmac_sha256_x64
 add rsp,48
 mov ecx,ebx
 cmp ecx,32
 jbe .count
 mov ecx,32
.count:
 mov esi,ecx
 mov rcx,rdi
 lea rdx,[rel prf2_block]
 mov r8d,esi
 sub rsp,32
 call mem_copy_x64
 add rsp,32
 add rdi,rsi
 sub ebx,esi
 mov rcx,r12
 mov rdx,r13
 lea r8,[rel prf2_a]
 mov r9d,32
 sub rsp,48
 lea rax,[rel prf2_block]
 mov [rsp+32],rax
 call hmac_sha256_x64
 add rsp,48
 lea rcx,[rel prf2_a]
 lea rdx,[rel prf2_block]
 mov r8d,32
 sub rsp,32
 call mem_copy_x64
 add rsp,32
 jmp .loop
.ok:
 xor eax,eax
 jmp .done
.bad:
 mov rax,EFI_INVALID_PARAMETER
.done:
 pop r15
 pop r14
 pop r13
 pop r12
 pop rdi
 pop rsi
 pop rbx
 ret
