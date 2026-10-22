; per-shard transport buffers and rfc6455 frame builder actual tcp/tls send/receive
; contexts will plug into these buffers later.

BITS 64

%define SHARD_RX_CAP    65536
%define SHARD_TX_CAP     8192

%if SHARD_TX_CAP < 4096
    %error "shard TX buffer too small for Gateway frames"
%endif

; rcx=shard ctx, rax=0 success.
legacy_shard_transport_alloc64:
    push rbx
    mov rbx, rcx
    test rbx, rbx
    jz .bad

    cmp qword [rbx + SHARD_OFF_RX_BUF], 0
    jne .rx_done
    mov ecx, SHARD_RX_CAP / 4096
    call alloc_pages64
    test rax, rax
    jnz .rx_got
    mov ecx, SHARD_RX_CAP / 4096
    call alloc_high_pages64
.rx_got:
    test rax, rax
    jz .bad
    mov [rbx + SHARD_OFF_RX_BUF], rax
.rx_done:

    cmp qword [rbx + SHARD_OFF_TX_BUF], 0
    jne .tx_done
    mov ecx, SHARD_TX_CAP / 4096
    call alloc_pages64
    test rax, rax
    jnz .tx_got
    mov ecx, SHARD_TX_CAP / 4096
    call alloc_high_pages64
.tx_got:
    test rax, rax
    jz .bad
    mov [rbx + SHARD_OFF_TX_BUF], rax
.tx_done:

    mov dword [rbx + SHARD_OFF_RX_LEN], 0
    mov dword [rbx + SHARD_OFF_TX_LEN], 0
    xor eax, eax
    pop rbx
    ret
.bad:
    mov eax, 1
    pop rbx
    ret

; rcx=shard ctx, rdx=bytes, r8d=len. appends decrypted application bytes to the shard's
; receive buffer.
legacy_shard_rx_append64:
    push rbx
    push r12
    push r13
    mov rbx, rcx
    mov r12, rdx
    mov r13d, r8d
    test rbx, rbx
    jz .bad_noctx
    test r12, r12
    jz .bad
    test r13d, r13d
    jz .ok

    cmp qword [rbx + SHARD_OFF_RX_BUF], 0
    jne .have
    mov rcx, rbx
    call legacy_shard_transport_alloc64
    test eax, eax
    jnz .bad
.have:
    mov eax, [rbx + SHARD_OFF_RX_LEN]
    mov edx, SHARD_RX_CAP
    sub edx, eax
    cmp r8d, edx
    ja .bad

    mov rdi, [rbx + SHARD_OFF_RX_BUF]
    add rdi, rax
    mov rsi, r12
    mov ecx, r8d
    rep movsb
    add [rbx + SHARD_OFF_RX_LEN], r8d
.ok:
    xor eax, eax
    jmp .out
.bad:
    mov dword [rbx + SHARD_OFF_LAST_ERROR], 1
.bad_noctx:
    mov eax, 1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx, edx=byte count consumed from front.
legacy_shard_rx_consume64:
    push rbx
    mov rbx, rcx
    test rbx, rbx
    jz .bad
    mov eax, [rbx + SHARD_OFF_RX_LEN]
    cmp edx, eax
    ja .bad
    je .clear

    sub eax, edx
    mov r8d, eax
    mov rsi, [rbx + SHARD_OFF_RX_BUF]
    add rsi, rdx
    mov rdi, [rbx + SHARD_OFF_RX_BUF]
    mov ecx, r8d
    rep movsb
    mov [rbx + SHARD_OFF_RX_LEN], r8d
    xor eax, eax
    pop rbx
    ret
.clear:
    mov dword [rbx + SHARD_OFF_RX_LEN], 0
    xor eax, eax
    pop rbx
    ret
.bad:
    mov eax, 1
    pop rbx
    ret

; rcx=shard ctx, rdx=payload, r8d=payload len, r9d=opcode. rax=masked client frame
; pointer, edx=wire length. zero pointer on failure.
legacy_shard_ws_frame64:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov rbx, rcx
    mov r12, rdx
    mov r13d, r8d
    mov r14d, r9d

    test rbx, rbx
    jz .bad
    test r12, r12
    jz .bad
    cmp r13d, 4096
    ja .bad
    cmp r14d, 0x0F
    ja .bad

    cmp qword [rbx + SHARD_OFF_TX_BUF], 0
    jne .have_tx
    mov rcx, rbx
    call legacy_shard_transport_alloc64
    test eax, eax
    jnz .bad
.have_tx:
    mov rdi, [rbx + SHARD_OFF_TX_BUF]
    mov al, r14b
    or al, 0x80
    mov [rdi], al

    cmp r13d, 125
    ja .len16
    mov eax, r13d
    or al, 0x80
    mov [rdi+1], al
    lea r15, [rdi+2]
    lea r10, [rdi+6]
    mov r11d, 6
    jmp .mask
.len16:
    cmp r13d, 65535
    ja .bad
    mov byte [rdi+1], 0xFE
    mov eax, r13d
    mov [rdi+3], al
    shr eax, 8
    mov [rdi+2], al
    lea r15, [rdi+4]
    lea r10, [rdi+8]
    mov r11d, 8
.mask:
    mov rcx, r15
    mov edx, 4
    call rng_safe_get
    test eax, eax
    jnz .bad

   ; rng_safe_get is a normal call and may use volatile registers. rebuild all frame pointers
   ; and the header length from the payload length afterward.
    mov rdi, [rbx + SHARD_OFF_TX_BUF]
    cmp r13d, 125
    ja .post_len16
    lea r15, [rdi+2]
    lea r10, [rdi+6]
    mov r11d, 6
    jmp .post_ptrs
.post_len16:
    lea r15, [rdi+4]
    lea r10, [rdi+8]
    mov r11d, 8
.post_ptrs:
    mov eax, r13d
    add eax, r11d
    cmp eax, SHARD_TX_CAP
    ja .bad
    mov [rbx + SHARD_OFF_TX_LEN], eax

    xor ecx, ecx
.copy:
    cmp ecx, r13d
    jae .check
    mov al, [r12+rcx]
    mov edx, ecx
    and edx, 3
    xor al, [r15+rdx]
    mov [r10+rcx], al
    inc ecx
    jmp .copy

.check:
    xor ecx, ecx
.check_loop:
    cmp ecx, r13d
    jae .ok
    mov al, [r10+rcx]
    mov edx, ecx
    and edx, 3
    xor al, [r15+rdx]
    cmp al, [r12+rcx]
    jne .bad
    inc ecx
    jmp .check_loop

.ok:
    mov rax, [rbx + SHARD_OFF_TX_BUF]
    mov edx, [rbx + SHARD_OFF_TX_LEN]
    jmp .out
.bad:
    test rbx, rbx
    jz .bad_ret
    mov dword [rbx + SHARD_OFF_LAST_ERROR], 2
.bad_ret:
    xor eax, eax
    xor edx, edx
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx. prepare all non-tcp/tls resources needed before connecting.
legacy_shard_transport_prepare64:
    push rbx
    mov rbx, rcx
    call legacy_shard_transport_alloc64
    test eax, eax
    jnz .bad
    mov rcx, rbx
    call legacy_shard_ws_build_request64
    test eax, eax
    jnz .bad
    xor eax, eax
    pop rbx
    ret
.bad:
    mov eax, 1
    pop rbx
    ret
