; hmac sha256 and tls 1.2 prf

%define TLS_PRF_SEED_MAX 256

section .bss align=16
hmac_ipad_x64       resb 64
hmac_opad_x64       resb 64
hmac_key_hash_x64   resb 32
hmac_inner_hash_x64 resb 32
hmac_inner_ctx_x64  resb SHA256_CTX_SIZE
hmac_outer_ctx_x64  resb SHA256_CTX_SIZE
hmac_saved_out      resq 1

tls_prf_seed_x64      resb TLS_PRF_SEED_MAX
tls_prf_seed_len_x64  resd 1
tls_prf_a_x64         resb 32
tls_prf_block_x64     resb 32
tls_prf_input_x64     resb TLS_PRF_SEED_MAX + 32

section .text
hmac_sha256_x64:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    mov r12, rcx
    mov r13, rdx
    mov rsi, r8
    mov rdi, r9
    mov rax, [rsp + 80]
    mov [rel hmac_saved_out], rax
    lea rcx, [rel hmac_ipad_x64]
    xor edx, edx
    mov r8d, 64
    sub rsp, 40
    call mem_set_x64
    add rsp, 40
    lea rcx, [rel hmac_opad_x64]
    xor edx, edx
    mov r8d, 64
    sub rsp, 40
    call mem_set_x64
    add rsp, 40
    cmp r13, 64
    jbe .key_ready
    mov rcx, r12
    mov rdx, r13
    lea r8, [rel hmac_key_hash_x64]
    sub rsp, 40
    call sha256_hash3_x64
    add rsp, 40
    lea r12, [rel hmac_key_hash_x64]
    mov r13d, 32
.key_ready:
    lea rcx, [rel hmac_ipad_x64]
    mov rdx, r12
    mov r8, r13
    sub rsp, 40
    call mem_copy_x64
    add rsp, 40
    lea rcx, [rel hmac_opad_x64]
    mov rdx, r12
    mov r8, r13
    sub rsp, 40
    call mem_copy_x64
    add rsp, 40
    xor ecx, ecx
    lea r10, [rel hmac_ipad_x64]
    lea r11, [rel hmac_opad_x64]
.pad:
    cmp ecx, 64
    jae .inner
    xor byte [r10+rcx], 0x36
    xor byte [r11+rcx], 0x5C
    inc ecx
    jmp .pad
.inner:
    lea rcx, [rel hmac_inner_ctx_x64]
    sub rsp, 40
    call sha256_init_x64
    add rsp, 40
    lea rcx, [rel hmac_inner_ctx_x64]
    lea rdx, [rel hmac_ipad_x64]
    mov r8d, 64
    sub rsp, 40
    call sha256_update_x64
    add rsp, 40
    lea rcx, [rel hmac_inner_ctx_x64]
    mov rdx, rsi
    mov r8, rdi
    sub rsp, 40
    call sha256_update_x64
    add rsp, 40
    lea rcx, [rel hmac_inner_ctx_x64]
    lea rdx, [rel hmac_inner_hash_x64]
    sub rsp, 40
    call sha256_final_x64
    add rsp, 40
    lea rcx, [rel hmac_outer_ctx_x64]
    sub rsp, 40
    call sha256_init_x64
    add rsp, 40
    lea rcx, [rel hmac_outer_ctx_x64]
    lea rdx, [rel hmac_opad_x64]
    mov r8d, 64
    sub rsp, 40
    call sha256_update_x64
    add rsp, 40
    lea rcx, [rel hmac_outer_ctx_x64]
    lea rdx, [rel hmac_inner_hash_x64]
    mov r8d, 32
    sub rsp, 40
    call sha256_update_x64
    add rsp, 40
    lea rcx, [rel hmac_outer_ctx_x64]
    mov rdx, [rel hmac_saved_out]
    sub rsp, 40
    call sha256_final_x64
    add rsp, 40
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

tls12_prf_sha256_x64:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    mov r15, r9
    mov rsi, [rsp + 96]
    mov eax, [rsp + 104]
    mov rdi, [rsp + 112]
    mov ebx, [rsp + 120]
    mov edx, r15d
    add edx, eax
    cmp edx, TLS_PRF_SEED_MAX
    ja .bad
    mov [rel tls_prf_seed_len_x64], edx
    lea rcx, [rel tls_prf_seed_x64]
    mov rdx, r14
    mov r8, r15
    sub rsp, 32
    call mem_copy_x64
    add rsp, 32
    lea rcx, [rel tls_prf_seed_x64]
    add rcx, r15
    mov rdx, rsi
    mov r8d, eax
    sub rsp, 32
    call mem_copy_x64
    add rsp, 32
    mov rcx, r12
    mov rdx, r13
    lea r8, [rel tls_prf_seed_x64]
    mov r9d, [rel tls_prf_seed_len_x64]
    sub rsp, 48
    lea rax, [rel tls_prf_a_x64]
    mov [rsp+32], rax
    call hmac_sha256_x64
    add rsp, 48
.loop:
    test ebx, ebx
    jz .success
    lea rcx, [rel tls_prf_input_x64]
    lea rdx, [rel tls_prf_a_x64]
    mov r8d, 32
    sub rsp, 32
    call mem_copy_x64
    add rsp, 32
    lea rcx, [rel tls_prf_input_x64 + 32]
    lea rdx, [rel tls_prf_seed_x64]
    mov r8d, [rel tls_prf_seed_len_x64]
    sub rsp, 32
    call mem_copy_x64
    add rsp, 32
    mov rcx, r12
    mov rdx, r13
    lea r8, [rel tls_prf_input_x64]
    mov r9d, [rel tls_prf_seed_len_x64]
    add r9d, 32
    sub rsp, 48
    lea rax, [rel tls_prf_block_x64]
    mov [rsp+32], rax
    call hmac_sha256_x64
    add rsp, 48
    mov ecx, ebx
    cmp ecx, 32
    jbe .copy_count
    mov ecx, 32
.copy_count:
    mov esi, ecx
    mov rcx, rdi
    lea rdx, [rel tls_prf_block_x64]
    mov r8d, esi
    sub rsp, 32
    call mem_copy_x64
    add rsp, 32
    add rdi, rsi
    sub ebx, esi
    mov rcx, r12
    mov rdx, r13
    lea r8, [rel tls_prf_a_x64]
    mov r9d, 32
    sub rsp, 48
    lea rax, [rel tls_prf_block_x64]
    mov [rsp+32], rax
    call hmac_sha256_x64
    add rsp, 48
    lea rcx, [rel tls_prf_a_x64]
    lea rdx, [rel tls_prf_block_x64]
    mov r8d, 32
    sub rsp, 32
    call mem_copy_x64
    add rsp, 32
    jmp .loop
.success:
    xor eax, eax
    jmp .done
.bad:
    mov rax, EFI_INVALID_PARAMETER
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
