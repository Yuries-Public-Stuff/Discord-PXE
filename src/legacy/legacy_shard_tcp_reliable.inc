; per-shard reliable tcp transmit queue. keeps tls records until the peer cumulatively
; acks them so many shard sessions can share one nic without treating an occasional dropped frame

BITS 64

%define STCP_REL_SLOTS        8
%define STCP_REL_DATA      1200
%define STCP_REL_RETRY_MS   750
%define STCP_REL_MAX_RETRIES  8

%define SREL_USED       0
%define SREL_RETRIES    4
%define SREL_SEQ        8
%define SREL_END       12
%define SREL_LEN       16
%define SREL_DEADLINE  24
%define SREL_DATA      32
%define SREL_SLOT_SIZE (SREL_DATA + STCP_REL_DATA)
%define SREL_BYTES     (STCP_REL_SLOTS * SREL_SLOT_SIZE)
%define SREL_PAGES     ((SREL_BYTES + 4095) / 4096)

%define STCP_REL_PTR       88
%define STCP_REL_NEXT      96
%define STCP_RETRANSMITS  104
%define STCP_ACKED        112

; rcx=shard ctx, rax=reliable queue base or zero.
legacy_shard_tcp_rel_alloc64:
    push rbx
    mov rbx, rcx
    test rbx, rbx
    jz .bad
    mov r11, [rbx + SHARD_OFF_TCP_CTX]
    test r11, r11
    jz .bad
    mov rax, [r11 + STCP_REL_PTR]
    test rax, rax
    jnz .done

    mov ecx, SREL_PAGES
    call alloc_pages64
    test rax, rax
    jnz .got
    mov ecx, SREL_PAGES
    call alloc_high_pages64
.got:
    test rax, rax
    jz .bad
    mov r11, [rbx + SHARD_OFF_TCP_CTX]
    mov [r11 + STCP_REL_PTR], rax
    push rax
    mov rdi, rax
    xor eax, eax
    mov ecx, (SREL_PAGES * 4096) / 8
    rep stosq
    pop rax
.done:
    pop rbx
    ret
.bad:
    xor eax, eax
    pop rbx
    ret

; rcx=shard ctx, rax=free slot or zero.
legacy_shard_tcp_rel_find_free64:
    push rbx
    push r12
    mov rbx, rcx
    mov rcx, rbx
    call legacy_shard_tcp_rel_alloc64
    test rax, rax
    jz .none
    mov r12, rax
    mov r11, [rbx + SHARD_OFF_TCP_CTX]
    mov edx, [r11 + STCP_REL_NEXT]
    xor ecx, ecx
.loop:
    cmp ecx, STCP_REL_SLOTS
    jae .none
    mov eax, edx
    imul rax, SREL_SLOT_SIZE
    add rax, r12
    cmp dword [rax + SREL_USED], 0
    je .found
    inc edx
    and edx, STCP_REL_SLOTS-1
    inc ecx
    jmp .loop
.found:
    mov ecx, edx
    inc ecx
    and ecx, STCP_REL_SLOTS-1
    mov [r11 + STCP_REL_NEXT], ecx
    pop r12
    pop rbx
    ret
.none:
    xor eax, eax
    pop r12
    pop rbx
    ret

; rcx=slot
legacy_shard_tcp_rel_deadline64:
    mov r8, rcx
    mov rax, [rel tsc_cycles_per_ms]
    test rax, rax
    jz .fallback
    imul rax, STCP_REL_RETRY_MS
    mov r9, rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    add rax, r9
    mov [r8 + SREL_DEADLINE], rax
    ret
.fallback:
    mov qword [r8 + SREL_DEADLINE], 0
    ret

; rcx=shard ctx, rdx=bytes, r8d=len.
legacy_shard_tcp_send64:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rcx
    mov r12, rdx
    mov r13d, r8d
    cmp r13d, STCP_REL_DATA
    ja .full

    mov r11, [rbx + SHARD_OFF_TCP_CTX]
    test r11, r11
    jz .not_ready
    cmp dword [r11 + STCP_STATE], SHARD_TCP_UP
    jne .not_ready

    mov rcx, rbx
    call legacy_shard_tcp_rel_find_free64
    test rax, rax
    jz .full
    mov r14, rax

    mov r11, [rbx + SHARD_OFF_TCP_CTX]
    mov eax, [r11 + STCP_LOCAL_SEQ]
    mov [r14 + SREL_SEQ], eax
    mov edx, r13d
    add eax, edx
    mov [r14 + SREL_END], eax
    mov [r14 + SREL_LEN], r13d
    mov dword [r14 + SREL_RETRIES], 0
    lea rdi, [r14 + SREL_DATA]
    mov rsi, r12
    mov ecx, r13d
    rep movsb

    mov rcx, rbx
    mov rdx, r12
    mov r8d, r13d
    call legacy_shard_tcp_send64_raw
    test eax, eax
    jnz .out

    mov dword [r14 + SREL_USED], 1
    mov rcx, r14
    call legacy_shard_tcp_rel_deadline64
    xor eax, eax
    jmp .out
.full:
    mov eax, LEGACY_STATUS_NO_MEMORY
    jmp .out
.not_ready:
    mov eax, LEGACY_STATUS_NOT_READY
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx, edx=cumulative ack.
legacy_shard_tcp_rel_ack64:
    push rbx
    push r12
    push r13
    mov rbx, rcx
    mov r13d, edx
    mov r11, [rbx + SHARD_OFF_TCP_CTX]
    test r11, r11
    jz .done
    mov r12, [r11 + STCP_REL_PTR]
    test r12, r12
    jz .done
    mov ecx, STCP_REL_SLOTS
.loop:
    cmp dword [r12 + SREL_USED], 1
    jne .next
    mov eax, r13d
    sub eax, [r12 + SREL_END]
    test eax, 0x80000000
    jnz .next
    mov dword [r12 + SREL_USED], 0
    inc qword [r11 + STCP_ACKED]
.next:
    add r12, SREL_SLOT_SIZE
    dec ecx
    jnz .loop
.done:
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx. retransmit due records at their original sequence number.
legacy_shard_tcp_rel_tick64:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rcx
    mov r11, [rbx + SHARD_OFF_TCP_CTX]
    test r11, r11
    jz .done
    cmp dword [r11 + STCP_STATE], SHARD_TCP_UP
    jne .done
    mov r12, [r11 + STCP_REL_PTR]
    test r12, r12
    jz .done
    mov r13d, STCP_REL_SLOTS
.loop:
    cmp dword [r12 + SREL_USED], 1
    jne .next
    mov r8, [r12 + SREL_DEADLINE]
    test r8, r8
    jz .retry
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, r8
    jb .next
.retry:
    cmp dword [r12 + SREL_RETRIES], STCP_REL_MAX_RETRIES
    jae .fail

    mov r11, [rbx + SHARD_OFF_TCP_CTX]
    mov r14d, [r11 + STCP_LOCAL_SEQ]
    mov eax, [r12 + SREL_SEQ]
    mov [r11 + STCP_LOCAL_SEQ], eax

    mov rcx, rbx
    lea rdx, [r12 + SREL_DATA]
    mov r8d, [r12 + SREL_LEN]
    mov r9d, 0x18
    call legacy_shard_tcp_send_segment64

    mov r11, [rbx + SHARD_OFF_TCP_CTX]
    mov [r11 + STCP_LOCAL_SEQ], r14d
    test eax, eax
    jnz .next
    inc dword [r12 + SREL_RETRIES]
    inc qword [r11 + STCP_RETRANSMITS]
    mov rcx, r12
    call legacy_shard_tcp_rel_deadline64
.next:
    add r12, SREL_SLOT_SIZE
    dec r13d
    jnz .loop
    jmp .done
.fail:
    mov r11, [rbx + SHARD_OFF_TCP_CTX]
    mov dword [r11 + STCP_STATE], SHARD_TCP_FAILED
    mov dword [rbx + SHARD_OFF_STATE], SHARD_STATE_BACKOFF
    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_stcp_rel_fail]
    call serial_puts64
.done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

msg_stcp_rel_fail db 'TCP data stayed unacked; shard stopped',13,10,0
