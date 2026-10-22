; sha256 used by tls and certificate checks kept scalar so it works on basically any x64
; cpu we can boot

BITS 64

%define SHA256_CTX_H          0
%define SHA256_CTX_TOTAL      32
%define SHA256_CTX_BUFFER_LEN 40
%define SHA256_CTX_BUFFER     44
%define SHA256_CTX_SIZE       108

align 16
sha256_k_x64:
    dd 0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5
    dd 0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5
    dd 0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3
    dd 0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174
    dd 0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC
    dd 0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA
    dd 0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7
    dd 0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967
    dd 0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13
    dd 0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85
    dd 0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3
    dd 0xD192E819,0xD6990624,0xF40E3585,0x106AA070
    dd 0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5
    dd 0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3
    dd 0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208
    dd 0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2

align 16
sha256_w_x64     times 64 dd 0
sha256_work_x64  times 8 dd 0
sha256_ctx_x64   times SHA256_CTX_SIZE db 0

sha256_init_x64:
    mov dword [rcx+0],  0x6A09E667
    mov dword [rcx+4],  0xBB67AE85
    mov dword [rcx+8],  0x3C6EF372
    mov dword [rcx+12], 0xA54FF53A
    mov dword [rcx+16], 0x510E527F
    mov dword [rcx+20], 0x9B05688C
    mov dword [rcx+24], 0x1F83D9AB
    mov dword [rcx+28], 0x5BE0CD19
    mov qword [rcx+SHA256_CTX_TOTAL], 0
    mov dword [rcx+SHA256_CTX_BUFFER_LEN], 0
    ret

sha256_transform_x64:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    mov r12, rcx
    mov rsi, rdx
    lea rdi, [rel sha256_w_x64]
    xor ecx, ecx
.load:
    cmp ecx, 16
    jae .expand
    movzx eax, byte [rsi]
    shl eax, 24
    movzx edx, byte [rsi+1]
    shl edx, 16
    or eax, edx
    movzx edx, byte [rsi+2]
    shl edx, 8
    or eax, edx
    movzx edx, byte [rsi+3]
    or eax, edx
    mov [rdi+rcx*4], eax
    add rsi, 4
    inc ecx
    jmp .load
.expand:
    cmp ecx, 64
    jae .init_work
    mov eax, [rdi+rcx*4-60]
    mov edx, eax
    ror eax, 7
    ror edx, 18
    xor eax, edx
    mov edx, [rdi+rcx*4-60]
    shr edx, 3
    xor eax, edx
    mov ebx, eax
    mov eax, [rdi+rcx*4-8]
    mov edx, eax
    ror eax, 17
    ror edx, 19
    xor eax, edx
    mov edx, [rdi+rcx*4-8]
    shr edx, 10
    xor eax, edx
    add eax, ebx
    add eax, [rdi+rcx*4-64]
    add eax, [rdi+rcx*4-28]
    mov [rdi+rcx*4], eax
    inc ecx
    jmp .expand
.init_work:
    lea r13, [rel sha256_work_x64]
    xor ecx, ecx
.copy_h:
    cmp ecx, 8
    jae .rounds
    mov eax, [r12+rcx*4]
    mov [r13+rcx*4], eax
    inc ecx
    jmp .copy_h
.rounds:
    xor ecx, ecx
.round:
    cmp ecx, 64
    jae .finish
    mov eax, [r13+16]
    mov edx, eax
    ror eax, 6
    ror edx, 11
    xor eax, edx
    mov edx, [r13+16]
    ror edx, 25
    xor eax, edx
    mov ebx, eax
    mov eax, [r13+16]
    and eax, [r13+20]
    mov edx, [r13+16]
    not edx
    and edx, [r13+24]
    xor eax, edx
    add ebx, eax
    add ebx, [r13+28]
    lea rsi, [rel sha256_k_x64]
    add ebx, [rsi+rcx*4]
    add ebx, [rdi+rcx*4]
    mov eax, [r13]
    mov edx, eax
    ror eax, 2
    ror edx, 13
    xor eax, edx
    mov edx, [r13]
    ror edx, 22
    xor eax, edx
    mov esi, eax
    mov eax, [r13]
    and eax, [r13+4]
    mov edx, [r13]
    and edx, [r13+8]
    xor eax, edx
    mov edx, [r13+4]
    and edx, [r13+8]
    xor eax, edx
    add esi, eax
    mov eax, [r13+24]
    mov [r13+28], eax
    mov eax, [r13+20]
    mov [r13+24], eax
    mov eax, [r13+16]
    mov [r13+20], eax
    mov eax, [r13+12]
    add eax, ebx
    mov [r13+16], eax
    mov eax, [r13+8]
    mov [r13+12], eax
    mov eax, [r13+4]
    mov [r13+8], eax
    mov eax, [r13]
    mov [r13+4], eax
    lea eax, [rbx+rsi]
    mov [r13], eax
    inc ecx
    jmp .round
.finish:
    xor ecx, ecx
.add:
    cmp ecx, 8
    jae .done
    mov eax, [r13+rcx*4]
    add [r12+rcx*4], eax
    inc ecx
    jmp .add
.done:
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

sha256_update_x64:
    push rbx
    push rsi
    push rdi
    push r12
    mov rdi, rcx
    mov rsi, rdx
    mov rbx, r8
    add qword [rdi+SHA256_CTX_TOTAL], rbx
.copy_loop:
    test rbx, rbx
    jz .done
    mov ecx, [rdi+SHA256_CTX_BUFFER_LEN]
    mov eax, 64
    sub eax, ecx
    mov r12d, eax
    cmp rbx, r12
    jae .chunk
    mov r12, rbx
.chunk:
    lea rcx, [rdi+SHA256_CTX_BUFFER]
    mov eax, [rdi+SHA256_CTX_BUFFER_LEN]
    add rcx, rax
    mov rdx, rsi
    mov r8, r12
    call mem_copy_x64
    add rsi, r12
    sub rbx, r12
    add [rdi+SHA256_CTX_BUFFER_LEN], r12d
    cmp dword [rdi+SHA256_CTX_BUFFER_LEN], 64
    jne .copy_loop
    mov rcx, rdi
    lea rdx, [rdi+SHA256_CTX_BUFFER]
    call sha256_transform_x64
    mov dword [rdi+SHA256_CTX_BUFFER_LEN], 0
    jmp .copy_loop
.done:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

sha256_final_x64:
    push rbx
    push rsi
    push rdi
    mov rdi, rcx
    mov rsi, rdx
    mov ecx, [rdi+SHA256_CTX_BUFFER_LEN]
    lea rbx, [rdi+SHA256_CTX_BUFFER]
    mov byte [rbx+rcx], 0x80
    inc ecx
    cmp ecx, 56
    jbe .pad56
.pad64:
    cmp ecx, 64
    jae .first
    mov byte [rbx+rcx], 0
    inc ecx
    jmp .pad64
.first:
    mov rcx, rdi
    mov rdx, rbx
    call sha256_transform_x64
    xor ecx, ecx
.pad56:
    cmp ecx, 56
    jae .length
    mov byte [rbx+rcx], 0
    inc ecx
    jmp .pad56
.length:
    mov rax, [rdi+SHA256_CTX_TOTAL]
    shl rax, 3
    mov rdx, rax
    bswap rdx
    mov [rbx+56], rdx
    mov rcx, rdi
    mov rdx, rbx
    call sha256_transform_x64
    xor ecx, ecx
.output:
    cmp ecx, 8
    jae .done
    mov eax, [rdi+rcx*4]
    bswap eax
    mov [rsi+rcx*4], eax
    inc ecx
    jmp .output
.done:
    pop rdi
    pop rsi
    pop rbx
    ret

sha256_hash3_x64:
    push rbx
    push rsi
    push rdi
    mov rbx, rcx
    mov rsi, rdx
    mov rdi, r8
    lea rcx, [rel sha256_ctx_x64]
    call sha256_init_x64
    lea rcx, [rel sha256_ctx_x64]
    mov rdx, rbx
    mov r8, rsi
    call sha256_update_x64
    lea rcx, [rel sha256_ctx_x64]
    mov rdx, rdi
    call sha256_final_x64
    pop rdi
    pop rsi
    pop rbx
    ret
