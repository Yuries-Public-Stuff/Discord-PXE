; x25519 key exchange for the legacy tls layer
%define FE_BYTES 32
section .data align=16
x25519_p_x64: dd 0xFFFFFFED,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0x7FFFFFFF

x25519_inv_exp_x64: dd 0xFFFFFFEB,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0x7FFFFFFF

x25519_a24_x64: dd 121665,0,0,0,0,0,0,0

x25519_base_u_x64: db 9
 times 31 db 0
section .bss align=16
x25519_reduce_tmp_x64 resd 8
x25519_sub_addend_x64 resd 8
x25519_mul_acc_x64 resd 8
x25519_mul_temp_x64 resd 8
x25519_mul_candidate_x64 resd 8
x25519_inv_result_x64 resd 8
x25519_inv_base_x64 resd 8
x25519_scalar_x64 resb 32
x25519_x1_x64 resd 8
x25519_x2_x64 resd 8
x25519_z2_x64 resd 8
x25519_x3_x64 resd 8
x25519_z3_x64 resd 8
x25519_a_x64 resd 8
x25519_aa_x64 resd 8
x25519_b_x64 resd 8
x25519_bb_x64 resd 8
x25519_e_x64 resd 8
x25519_c_x64 resd 8
x25519_d_x64 resd 8
x25519_da_x64 resd 8
x25519_cb_x64 resd 8
x25519_tmp1_x64 resd 8
x25519_tmp2_x64 resd 8
x25519_inv_z_x64 resd 8
section .text
fe_copy_x64:
 mov r8d,FE_BYTES
 jmp mem_copy_x64
fe_zero_x64:
 xor edx,edx
 mov r8d,FE_BYTES
 jmp mem_set_x64
fe_one_x64:
 push rcx
 sub rsp,32
 call fe_zero_x64
 add rsp,32
 pop rcx
 mov dword [rcx],1
 ret
fe_normalize_x64:
 push rbx
 push rsi
 push rdi
 mov rsi,rcx
 lea rdi,[rel x25519_reduce_tmp_x64]
 mov eax,[rsi]
 sub eax,0xFFFFFFED
 mov [rdi],eax
 mov eax,[rsi+4]
 sbb eax,0xFFFFFFFF
 mov [rdi+4],eax
 mov eax,[rsi+8]
 sbb eax,0xFFFFFFFF
 mov [rdi+8],eax
 mov eax,[rsi+12]
 sbb eax,0xFFFFFFFF
 mov [rdi+12],eax
 mov eax,[rsi+16]
 sbb eax,0xFFFFFFFF
 mov [rdi+16],eax
 mov eax,[rsi+20]
 sbb eax,0xFFFFFFFF
 mov [rdi+20],eax
 mov eax,[rsi+24]
 sbb eax,0xFFFFFFFF
 mov [rdi+24],eax
 mov eax,[rsi+28]
 sbb eax,0x7FFFFFFF
 mov [rdi+28],eax
 sbb ebx,ebx
 mov edx,ebx
 not edx
 xor ecx,ecx
.sel: mov eax,[rsi+rcx*4]
 and eax,ebx
 mov r8d,[rdi+rcx*4]
 and r8d,edx
 or eax,r8d
 mov [rsi+rcx*4],eax
 inc ecx
 cmp ecx,8
 jb .sel
 pop rdi
 pop rsi
 pop rbx
 ret
fe_add_x64:
 push rbx
 push rsi
 push rdi
 mov rdi,rcx
 mov rsi,rdx
 mov rbx,r8
 mov eax,[rsi]
 add eax,[rbx]
 mov [rdi],eax
 mov eax,[rsi+4]
 adc eax,[rbx+4]
 mov [rdi+4],eax
 mov eax,[rsi+8]
 adc eax,[rbx+8]
 mov [rdi+8],eax
 mov eax,[rsi+12]
 adc eax,[rbx+12]
 mov [rdi+12],eax
 mov eax,[rsi+16]
 adc eax,[rbx+16]
 mov [rdi+16],eax
 mov eax,[rsi+20]
 adc eax,[rbx+20]
 mov [rdi+20],eax
 mov eax,[rsi+24]
 adc eax,[rbx+24]
 mov [rdi+24],eax
 mov eax,[rsi+28]
 adc eax,[rbx+28]
 mov [rdi+28],eax
 mov rcx,rdi
 sub rsp,32
 call fe_normalize_x64
 add rsp,32
 pop rdi
 pop rsi
 pop rbx
 ret
fe_sub_x64:
 push rbx
 push rsi
 push rdi
 push r12
 mov rdi,rcx
 mov rsi,rdx
 mov rbx,r8
 mov eax,[rsi]
 sub eax,[rbx]
 mov [rdi],eax
 mov eax,[rsi+4]
 sbb eax,[rbx+4]
 mov [rdi+4],eax
 mov eax,[rsi+8]
 sbb eax,[rbx+8]
 mov [rdi+8],eax
 mov eax,[rsi+12]
 sbb eax,[rbx+12]
 mov [rdi+12],eax
 mov eax,[rsi+16]
 sbb eax,[rbx+16]
 mov [rdi+16],eax
 mov eax,[rsi+20]
 sbb eax,[rbx+20]
 mov [rdi+20],eax
 mov eax,[rsi+24]
 sbb eax,[rbx+24]
 mov [rdi+24],eax
 mov eax,[rsi+28]
 sbb eax,[rbx+28]
 mov [rdi+28],eax
 sbb r12d,r12d
 lea r10,[rel x25519_p_x64]
 lea r11,[rel x25519_sub_addend_x64]
 xor ecx,ecx
.mask: mov eax,[r10+rcx*4]
 and eax,r12d
 mov [r11+rcx*4],eax
 inc ecx
 cmp ecx,8
 jb .mask
 mov eax,[rdi]
 add eax,[r11]
 mov [rdi],eax
 mov eax,[rdi+4]
 adc eax,[r11+4]
 mov [rdi+4],eax
 mov eax,[rdi+8]
 adc eax,[r11+8]
 mov [rdi+8],eax
 mov eax,[rdi+12]
 adc eax,[r11+12]
 mov [rdi+12],eax
 mov eax,[rdi+16]
 adc eax,[r11+16]
 mov [rdi+16],eax
 mov eax,[rdi+20]
 adc eax,[r11+20]
 mov [rdi+20],eax
 mov eax,[rdi+24]
 adc eax,[r11+24]
 mov [rdi+24],eax
 mov eax,[rdi+28]
 adc eax,[r11+28]
 mov [rdi+28],eax
 pop r12
 pop rdi
 pop rsi
 pop rbx
 ret
fe_mul2_x64:
 push rbx
 push rsi
 push rdi
 push r12
 push r13
 mov r12,rcx
 mov rsi,rdx
 mov r13,r8
 lea rcx,[rel x25519_mul_acc_x64]
 sub rsp,32
 call fe_zero_x64
 add rsp,32
 lea rcx,[rel x25519_mul_temp_x64]
 mov rdx,rsi
 sub rsp,32
 call fe_copy_x64
 add rsp,32
 xor edi,edi
.bit: cmp edi,255
 jae .finish
 lea rcx,[rel x25519_mul_candidate_x64]
 lea rdx,[rel x25519_mul_acc_x64]
 lea r8,[rel x25519_mul_temp_x64]
 sub rsp,32
 call fe_add_x64
 add rsp,32
 mov eax,edi
 mov edx,eax
 shr eax,5
 and edx,31
 bt dword [r13+rax*4],edx
 sbb ebx,ebx
 lea r10,[rel x25519_mul_candidate_x64]
 lea r11,[rel x25519_mul_acc_x64]
 xor ecx,ecx
.sel: mov eax,[r10+rcx*4]
 xor eax,[r11+rcx*4]
 and eax,ebx
 xor [r11+rcx*4],eax
 inc ecx
 cmp ecx,8
 jb .sel
 lea rcx,[rel x25519_mul_temp_x64]
 mov rdx,rcx
 mov r8,rcx
 sub rsp,32
 call fe_add_x64
 add rsp,32
 inc edi
 jmp .bit
.finish:
 mov rcx,r12
 lea rdx,[rel x25519_mul_acc_x64]
 sub rsp,32
 call fe_copy_x64
 add rsp,32
 pop r13
 pop r12
 pop rdi
 pop rsi
 pop rbx
 ret
fe_square_x64:
 mov r8,rdx
 jmp fe_mul2_x64
fe_invert_x64:
 push rbx
 push rsi
 push r12
 mov r12,rcx
 mov rsi,rdx
 lea rcx,[rel x25519_inv_result_x64]
 sub rsp,40
 call fe_one_x64
 add rsp,40
 lea rcx,[rel x25519_inv_base_x64]
 mov rdx,rsi
 sub rsp,40
 call fe_copy_x64
 add rsp,40
 mov ebx,254
.loop:
 lea rcx,[rel x25519_inv_result_x64]
 mov rdx,rcx
 sub rsp,40
 call fe_square_x64
 add rsp,40
 mov eax,ebx
 mov edx,eax
 shr eax,5
 and edx,31
 lea r10,[rel x25519_inv_exp_x64]
 bt dword [r10+rax*4],edx
 jnc .skip
 lea rcx,[rel x25519_inv_result_x64]
 mov rdx,rcx
 lea r8,[rel x25519_inv_base_x64]
 sub rsp,40
 call fe_mul2_x64
 add rsp,40
.skip: dec ebx
 jns .loop
 mov rcx,r12
 lea rdx,[rel x25519_inv_result_x64]
 sub rsp,40
 call fe_copy_x64
 add rsp,40
 pop r12
 pop rsi
 pop rbx
 ret
fe_cswap_x64:
 mov eax,ecx
 neg eax
 mov r9d,eax
 xor ecx,ecx
.loop: mov eax,[rdx+rcx*4]
 xor eax,[r8+rcx*4]
 and eax,r9d
 xor [rdx+rcx*4],eax
 xor [r8+rcx*4],eax
 inc ecx
 cmp ecx,8
 jb .loop
 ret
fe_from_bytes_x64:
 push rcx
 sub rsp,32
 call fe_copy_x64
 add rsp,32
 pop rcx
 and dword [rcx+28],0x7FFFFFFF
 sub rsp,40
 call fe_normalize_x64
 add rsp,40
 ret
fe_to_bytes_x64:
; keep both pointers because normalize uses rcx as a loop counter
 push rbx
 push rsi
 mov rbx,rcx
 mov rsi,rdx
 mov rcx,rsi
 sub rsp,40
 call fe_normalize_x64
 add rsp,40
 mov rcx,rbx
 mov rdx,rsi
 sub rsp,40
 call fe_copy_x64
 add rsp,40
 pop rsi
 pop rbx
 ret
x25519_bytes_all_zero_x64:
 xor edx,edx
 xor r8d,r8d
.loop: cmp r8d,32
 jae .done
 movzx eax,byte [rcx+r8]
 or edx,eax
 inc r8d
 jmp .loop
.done: xor eax,eax
 test edx,edx
 setz al
 ret
x25519_x64:
 push rbx
 push rsi
 push rdi
 push r12
 push r13
 push r14
 mov r12,rcx
 mov r13,rdx
 mov r14,r8
 lea rcx,[rel x25519_scalar_x64]
 mov rdx,r13
 mov r8d,32
 sub rsp,40
 call mem_copy_x64
 add rsp,40
 and byte [rel x25519_scalar_x64],248
 and byte [rel x25519_scalar_x64+31],127
 or byte [rel x25519_scalar_x64+31],64
 lea rcx,[rel x25519_x1_x64]
 mov rdx,r14
 sub rsp,40
 call fe_from_bytes_x64
 add rsp,40
 lea rcx,[rel x25519_x2_x64]
 sub rsp,40
 call fe_one_x64
 add rsp,40
 lea rcx,[rel x25519_z2_x64]
 sub rsp,40
 call fe_zero_x64
 add rsp,40
 lea rcx,[rel x25519_x3_x64]
 lea rdx,[rel x25519_x1_x64]
 sub rsp,40
 call fe_copy_x64
 add rsp,40
 lea rcx,[rel x25519_z3_x64]
 sub rsp,40
 call fe_one_x64
 add rsp,40
 xor esi,esi
 mov ebx,254
.ladder:
 mov eax,ebx
 mov edx,eax
 shr eax,5
 and edx,31
 lea r10,[rel x25519_scalar_x64]
 bt dword [r10+rax*4],edx
 sbb edi,edi
 and edi,1
 xor esi,edi
 mov ecx,esi
 lea rdx,[rel x25519_x2_x64]
 lea r8,[rel x25519_x3_x64]
 sub rsp,40
 call fe_cswap_x64
 add rsp,40
 mov ecx,esi
 lea rdx,[rel x25519_z2_x64]
 lea r8,[rel x25519_z3_x64]
 sub rsp,40
 call fe_cswap_x64
 add rsp,40
 mov esi,edi
 lea rcx,[rel x25519_a_x64]
 lea rdx,[rel x25519_x2_x64]
 lea r8,[rel x25519_z2_x64]
 sub rsp,40
 call fe_add_x64
 add rsp,40
 lea rcx,[rel x25519_aa_x64]
 lea rdx,[rel x25519_a_x64]
 sub rsp,40
 call fe_square_x64
 add rsp,40
 lea rcx,[rel x25519_b_x64]
 lea rdx,[rel x25519_x2_x64]
 lea r8,[rel x25519_z2_x64]
 sub rsp,40
 call fe_sub_x64
 add rsp,40
 lea rcx,[rel x25519_bb_x64]
 lea rdx,[rel x25519_b_x64]
 sub rsp,40
 call fe_square_x64
 add rsp,40
 lea rcx,[rel x25519_e_x64]
 lea rdx,[rel x25519_aa_x64]
 lea r8,[rel x25519_bb_x64]
 sub rsp,40
 call fe_sub_x64
 add rsp,40
 lea rcx,[rel x25519_c_x64]
 lea rdx,[rel x25519_x3_x64]
 lea r8,[rel x25519_z3_x64]
 sub rsp,40
 call fe_add_x64
 add rsp,40
 lea rcx,[rel x25519_d_x64]
 lea rdx,[rel x25519_x3_x64]
 lea r8,[rel x25519_z3_x64]
 sub rsp,40
 call fe_sub_x64
 add rsp,40
 lea rcx,[rel x25519_da_x64]
 lea rdx,[rel x25519_d_x64]
 lea r8,[rel x25519_a_x64]
 sub rsp,40
 call fe_mul2_x64
 add rsp,40
 lea rcx,[rel x25519_cb_x64]
 lea rdx,[rel x25519_c_x64]
 lea r8,[rel x25519_b_x64]
 sub rsp,40
 call fe_mul2_x64
 add rsp,40
 lea rcx,[rel x25519_tmp1_x64]
 lea rdx,[rel x25519_da_x64]
 lea r8,[rel x25519_cb_x64]
 sub rsp,40
 call fe_add_x64
 add rsp,40
 lea rcx,[rel x25519_x3_x64]
 lea rdx,[rel x25519_tmp1_x64]
 sub rsp,40
 call fe_square_x64
 add rsp,40
 lea rcx,[rel x25519_tmp1_x64]
 lea rdx,[rel x25519_da_x64]
 lea r8,[rel x25519_cb_x64]
 sub rsp,40
 call fe_sub_x64
 add rsp,40
 lea rcx,[rel x25519_tmp2_x64]
 lea rdx,[rel x25519_tmp1_x64]
 sub rsp,40
 call fe_square_x64
 add rsp,40
 lea rcx,[rel x25519_z3_x64]
 lea rdx,[rel x25519_x1_x64]
 lea r8,[rel x25519_tmp2_x64]
 sub rsp,40
 call fe_mul2_x64
 add rsp,40
 lea rcx,[rel x25519_x2_x64]
 lea rdx,[rel x25519_aa_x64]
 lea r8,[rel x25519_bb_x64]
 sub rsp,40
 call fe_mul2_x64
 add rsp,40
 lea rcx,[rel x25519_tmp1_x64]
 lea rdx,[rel x25519_a24_x64]
 lea r8,[rel x25519_e_x64]
 sub rsp,40
 call fe_mul2_x64
 add rsp,40
 lea rcx,[rel x25519_tmp1_x64]
 lea rdx,[rel x25519_aa_x64]
 lea r8,[rel x25519_tmp1_x64]
 sub rsp,40
 call fe_add_x64
 add rsp,40
 lea rcx,[rel x25519_z2_x64]
 lea rdx,[rel x25519_e_x64]
 lea r8,[rel x25519_tmp1_x64]
 sub rsp,40
 call fe_mul2_x64
 add rsp,40
 dec ebx
 jns .ladder
 mov ecx,esi
 lea rdx,[rel x25519_x2_x64]
 lea r8,[rel x25519_x3_x64]
 sub rsp,40
 call fe_cswap_x64
 add rsp,40
 mov ecx,esi
 lea rdx,[rel x25519_z2_x64]
 lea r8,[rel x25519_z3_x64]
 sub rsp,40
 call fe_cswap_x64
 add rsp,40
 lea rcx,[rel x25519_inv_z_x64]
 lea rdx,[rel x25519_z2_x64]
 sub rsp,40
 call fe_invert_x64
 add rsp,40
 lea rcx,[rel x25519_tmp1_x64]
 lea rdx,[rel x25519_x2_x64]
 lea r8,[rel x25519_inv_z_x64]
 sub rsp,40
 call fe_mul2_x64
 add rsp,40
 mov rcx,r12
 lea rdx,[rel x25519_tmp1_x64]
 sub rsp,40
 call fe_to_bytes_x64
 add rsp,40
 pop r14
 pop r13
 pop r12
 pop rdi
 pop rsi
 pop rbx
 ret
x25519_public_from_private_x64:
 lea r8,[rel x25519_base_u_x64]
 jmp x25519_x64
