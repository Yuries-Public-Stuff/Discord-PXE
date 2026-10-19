; rsa sha256 verify for the legacy tls certificate path
%define RSA_MAX_LIMBS 128
%define RSA_MAX_BYTES 512
section .bss align=16
rsa_modulus_x64 resd RSA_MAX_LIMBS
rsa_base_x64 resd RSA_MAX_LIMBS
rsa_result_x64 resd RSA_MAX_LIMBS
rsa_mul_acc_x64 resd RSA_MAX_LIMBS
rsa_mul_temp_x64 resd RSA_MAX_LIMBS
rsa_add_tmp_x64 resd RSA_MAX_LIMBS
rsa_em_x64 resb RSA_MAX_BYTES
rsa_modulus_bytes_x64 resd 1
rsa_modulus_limbs_x64 resd 1
rsa_multiplier_word_x64 resd 1
section .data align=16
rsa_sha256_di_prefix_x64:
 db 0x30,0x31,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
rsa_sha256_di_prefix_len_x64 equ $-rsa_sha256_di_prefix_x64
section .text
rsa_zero_limbs_x64:
 xor eax,eax
 xor r8d,r8d
.loop: cmp r8d,edx
 jae .done
 mov [rcx+r8*4],eax
 inc r8d
 jmp .loop
.done: ret
rsa_copy_limbs_x64:
 xor r9d,r9d
.loop: cmp r9d,r8d
 jae .done
 mov eax,[rdx+r9*4]
 mov [rcx+r9*4],eax
 inc r9d
 jmp .loop
.done: ret
rsa_ge_x64:
 test r8d,r8d
 jz .yes
 mov r9d,r8d
 dec r9d
.loop: mov eax,[rcx+r9*4]
 cmp eax,[rdx+r9*4]
 ja .yes
 jb .no
 test r9d,r9d
 jz .yes
 dec r9d
 jmp .loop
.yes: mov eax,1
 ret
.no: xor eax,eax
 ret
rsa_sub2_x64:
 mov r10,rcx
 mov r11,rdx
 mov rax,r8
 mov ecx,r9d
 test ecx,ecx
 jz .done
 clc
.loop: mov edx,[r11]
 sbb edx,[rax]
 mov [r10],edx
 lea r11,[r11+4]
 lea rax,[rax+4]
 lea r10,[r10+4]
 loop .loop
.done: ret
rsa_mod_add_x64:
 push rbx
 push rsi
 push rdi
 push r12
 mov r12,rcx
 mov rsi,rdx
 mov rbx,r8
 mov edi,r9d
 lea r10,[rel rsa_add_tmp_x64]
 mov ecx,edi
 test ecx,ecx
 jz .copy
 clc
.add: mov eax,[rsi]
 adc eax,[rbx]
 mov [r10],eax
 lea rsi,[rsi+4]
 lea rbx,[rbx+4]
 lea r10,[r10+4]
 loop .add
 sbb ebx,ebx
 test ebx,ebx
 jnz .subtract
 lea rcx,[rel rsa_add_tmp_x64]
 lea rdx,[rel rsa_modulus_x64]
 mov r8d,edi
 sub rsp,40
 call rsa_ge_x64
 add rsp,40
 test eax,eax
 jz .copy
.subtract:
 lea rcx,[rel rsa_add_tmp_x64]
 mov rdx,rcx
 lea r8,[rel rsa_modulus_x64]
 mov r9d,edi
 sub rsp,40
 call rsa_sub2_x64
 add rsp,40
.copy:
 mov rcx,r12
 lea rdx,[rel rsa_add_tmp_x64]
 mov r8d,edi
 sub rsp,40
 call rsa_copy_limbs_x64
 add rsp,40
 pop r12
 pop rdi
 pop rsi
 pop rbx
 ret
rsa_mod_mul_x64:
 push rbx
 push rsi
 push rdi
 push r12
 push r13
 mov r12,rcx
 mov r13,rdx
 mov rsi,r8
 mov edi,r9d
 lea rcx,[rel rsa_mul_acc_x64]
 mov edx,edi
 sub rsp,32
 call rsa_zero_limbs_x64
 add rsp,32
 lea rcx,[rel rsa_mul_temp_x64]
 mov rdx,r13
 mov r8d,edi
 sub rsp,32
 call rsa_copy_limbs_x64
 add rsp,32
 xor ebx,ebx
.limb: cmp ebx,edi
 jae .finish
 mov eax,[rsi+rbx*4]
 mov [rel rsa_multiplier_word_x64],eax
 mov r13d,32
.bit: test dword [rel rsa_multiplier_word_x64],1
 jz .double
 lea rcx,[rel rsa_mul_acc_x64]
 mov rdx,rcx
 lea r8,[rel rsa_mul_temp_x64]
 mov r9d,edi
 sub rsp,32
 call rsa_mod_add_x64
 add rsp,32
.double:
 lea rcx,[rel rsa_mul_temp_x64]
 mov rdx,rcx
 mov r8,rcx
 mov r9d,edi
 sub rsp,32
 call rsa_mod_add_x64
 add rsp,32
 shr dword [rel rsa_multiplier_word_x64],1
 dec r13d
 jnz .bit
 inc ebx
 jmp .limb
.finish:
 mov rcx,r12
 lea rdx,[rel rsa_mul_acc_x64]
 mov r8d,edi
 sub rsp,32
 call rsa_copy_limbs_x64
 add rsp,32
 pop r13
 pop r12
 pop rdi
 pop rsi
 pop rbx
 ret
rsa_import_be_x64:
 push rbx
 push rsi
 push rdi
 mov rdi,rcx
 mov rsi,rdx
 mov ebx,r9d
 mov edx,r8d
 sub rsp,32
 call rsa_zero_limbs_x64
 add rsp,32
 mov eax,r8d
 shl eax,2
 cmp ebx,eax
 jbe .count
 mov ebx,eax
.count: xor ecx,ecx
.copy: cmp ecx,ebx
 jae .done
 mov eax,ebx
 dec eax
 sub eax,ecx
 mov dl,[rsi+rcx]
 mov [rdi+rax],dl
 inc ecx
 jmp .copy
.done: pop rdi
 pop rsi
 pop rbx
 ret
rsa_export_be_x64:
 xor r9d,r9d
.loop: cmp r9d,r8d
 jae .done
 mov eax,r8d
 dec eax
 sub eax,r9d
 mov al,[rdx+rax]
 mov [rcx+r9],al
 inc r9d
 jmp .loop
.done: ret
rsa_public_65537_x64:
 push rbx
 mov rdx,rcx
 lea rcx,[rel rsa_base_x64]
 mov r8d,[rel rsa_modulus_limbs_x64]
 sub rsp,40
 call rsa_copy_limbs_x64
 add rsp,40
 lea rcx,[rel rsa_result_x64]
 lea rdx,[rel rsa_base_x64]
 mov r8d,[rel rsa_modulus_limbs_x64]
 sub rsp,40
 call rsa_copy_limbs_x64
 add rsp,40
 mov ebx,16
.square:
 lea rcx,[rel rsa_result_x64]
 mov rdx,rcx
 mov r8,rcx
 mov r9d,[rel rsa_modulus_limbs_x64]
 sub rsp,40
 call rsa_mod_mul_x64
 add rsp,40
 dec ebx
 jnz .square
 lea rcx,[rel rsa_result_x64]
 mov rdx,rcx
 lea r8,[rel rsa_base_x64]
 mov r9d,[rel rsa_modulus_limbs_x64]
 sub rsp,40
 call rsa_mod_mul_x64
 add rsp,40
 pop rbx
 ret
rsa_verify_pkcs1_sha256_x64:
 push rbx
 push rsi
 push rdi
 push r12
 mov r12,r8
 cmp edx,[rel rsa_modulus_bytes_x64]
 jne .fail
 mov rsi,rcx
 mov ebx,edx
 lea rcx,[rel rsa_base_x64]
 mov rdx,rsi
 mov r8d,[rel rsa_modulus_limbs_x64]
 mov r9d,ebx
 sub rsp,40
 call rsa_import_be_x64
 add rsp,40
 lea rcx,[rel rsa_base_x64]
 lea rdx,[rel rsa_modulus_x64]
 mov r8d,[rel rsa_modulus_limbs_x64]
 sub rsp,40
 call rsa_ge_x64
 add rsp,40
 test eax,eax
 jnz .fail
 lea rcx,[rel rsa_base_x64]
 sub rsp,40
 call rsa_public_65537_x64
 add rsp,40
 lea rcx,[rel rsa_em_x64]
 lea rdx,[rel rsa_result_x64]
 mov r8d,[rel rsa_modulus_bytes_x64]
 sub rsp,40
 call rsa_export_be_x64
 add rsp,40
 lea rsi,[rel rsa_em_x64]
 cmp byte [rsi],0
 jne .fail
 cmp byte [rsi+1],1
 jne .fail
 mov eax,[rel rsa_modulus_bytes_x64]
 sub eax,rsa_sha256_di_prefix_len_x64+35
 cmp eax,8
 jb .fail
 mov ecx,eax
 mov ebx,2
.ff: cmp byte [rsi+rbx],0xFF
 jne .fail
 inc ebx
 dec ecx
 jnz .ff
 cmp byte [rsi+rbx],0
 jne .fail
 inc ebx
 lea rdi,[rel rsa_sha256_di_prefix_x64]
 xor ecx,ecx
.prefix: cmp ecx,rsa_sha256_di_prefix_len_x64
 jae .digest
 mov al,[rsi+rbx]
 cmp al,[rdi+rcx]
 jne .fail
 inc ebx
 inc ecx
 jmp .prefix
.digest: xor ecx,ecx
.dloop: cmp ecx,32
 jae .ok
 mov al,[rsi+rbx]
 cmp al,[r12+rcx]
 jne .fail
 inc ebx
 inc ecx
 jmp .dloop
.ok: xor eax,eax
 jmp .done
.fail: mov rax,EFI_DEVICE_ERROR
.done: pop r12
 pop rdi
 pop rsi
 pop rbx
 ret
