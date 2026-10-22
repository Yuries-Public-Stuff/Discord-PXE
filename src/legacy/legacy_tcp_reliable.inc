; keep sent tcp data until the other side actually acks it tls can send a few records fast
; without losing one to a random dropped packet

BITS 64

%ifndef LEGACY_STATUS_NO_MEMORY
%define LEGACY_STATUS_NO_MEMORY 2
%endif
%ifndef LEGACY_STATUS_NOT_READY
%define LEGACY_STATUS_NOT_READY 3
%endif

%define TCP_RELIABLE_SLOTS 16
%define TCP_RELIABLE_DATA  1200
%define TCP_RELIABLE_RETRY_MS 750
%define TCP_RELIABLE_MAX_RETRIES 8
%define TCP_REL_USED      0
%define TCP_REL_RETRIES   4
%define TCP_REL_SEQ       8
%define TCP_REL_END      12
%define TCP_REL_LEN      16
%define TCP_REL_DEADLINE 24
%define TCP_REL_DATA_OFF 32
%define TCP_REL_SLOT_SIZE (TCP_REL_DATA_OFF + TCP_RELIABLE_DATA)

legacy_tcp_reliable_init64:
    lea rdi, [rel tcp_rel_slots]
    xor eax, eax
    mov ecx, (TCP_RELIABLE_SLOTS * TCP_REL_SLOT_SIZE + 7) / 8
    rep stosq
    mov dword [rel tcp_rel_next], 0
    mov qword [rel tcp_rel_retransmits], 0
    mov qword [rel tcp_rel_acked], 0
    ret

; rcx bytes, edx len
legacy_tcp_send64:
    push rbx
    push r12
    push r13
    mov r12, rcx
    mov r13d, edx
    cmp r13d, TCP_RELIABLE_DATA
    ja .full
    cmp dword [rel legacy_tcp_state], LEGACY_TCP_UP
    jne .not_ready

    call legacy_tcp_rel_find_free64
    test rax, rax
    jz .full
    mov rbx, rax
    mov eax, [rel legacy_tcp_local_seq]
    mov [rbx+TCP_REL_SEQ], eax
    mov edx, r13d
    add eax, edx
    mov [rbx+TCP_REL_END], eax
    mov [rbx+TCP_REL_LEN], r13d
    mov dword [rbx+TCP_REL_RETRIES], 0
    lea rdi, [rbx+TCP_REL_DATA_OFF]
    mov rsi, r12
    mov ecx, r13d
    rep movsb

    mov rcx, r12
    mov edx, r13d
    call legacy_tcp_send64_raw
    test eax, eax
    jnz .out
    mov dword [rbx+TCP_REL_USED], 1
    mov rcx, rbx
    call legacy_tcp_rel_set_deadline64
    xor eax, eax
.out:
    pop r13
    pop r12
    pop rbx
    ret
.full:
    mov eax, LEGACY_STATUS_NO_MEMORY
    jmp .out
.not_ready:
    mov eax, LEGACY_STATUS_NOT_READY
    jmp .out

legacy_tcp_rel_find_free64:
    mov edx, [rel tcp_rel_next]
    xor ecx, ecx
.loop:
    cmp ecx, TCP_RELIABLE_SLOTS
    jae .none
    mov eax, edx
    imul rax, TCP_REL_SLOT_SIZE
    lea r8, [rel tcp_rel_slots]
    add rax, r8
    cmp dword [rax+TCP_REL_USED], 0
    je .found
    inc edx
    and edx, TCP_RELIABLE_SLOTS-1
    inc ecx
    jmp .loop
.found:
    mov ecx, edx
    inc ecx
    and ecx, TCP_RELIABLE_SLOTS-1
    mov [rel tcp_rel_next], ecx
    ret
.none:
    xor eax, eax
    ret

; rcx slot
legacy_tcp_rel_set_deadline64:
    mov r8, rcx
    mov rax, [rel tsc_cycles_per_ms]
    test rax, rax
    jz .fallback
    imul rax, TCP_RELIABLE_RETRY_MS
    mov r9, rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    add rax, r9
    mov [r8+TCP_REL_DEADLINE], rax
    ret
.fallback:
    mov qword [r8+TCP_REL_DEADLINE], 0
    ret

; ack is cumulative, clear anything fully below it
legacy_tcp_rel_ack64:
    push rbx
    push r12
    mov r10d, ecx
    lea rbx, [rel tcp_rel_slots]
    mov r12d, TCP_RELIABLE_SLOTS
.loop:
    cmp dword [rbx+TCP_REL_USED], 1
    jne .next
    mov eax, r10d
    sub eax, [rbx+TCP_REL_END]
    test eax, 0x80000000
    jnz .next
    mov dword [rbx+TCP_REL_USED], 0
    inc qword [rel tcp_rel_acked]
.next:
    add rbx, TCP_REL_SLOT_SIZE
    dec r12d
    jnz .loop
    pop r12
    pop rbx
    ret

; raw receive validates the packet before we trust its ack number
legacy_tcp_rx64:
    push rbx
    push r12
    push r13
    push r14
    mov r12, rcx
    mov r13d, edx
    mov r14d, r8d
    mov rbx, [rel legacy_tcp_bad]
    call legacy_tcp_rx64_raw

    cmp dword [rel legacy_tcp_state], LEGACY_TCP_UP
    jne .done
    cmp r13d, 20
    jb .done
    cmp r14d, [rel legacy_gateway_ip]
    jne .done
    cmp rbx, [rel legacy_tcp_bad]
    jne .done
    mov rcx, r12
    call legacy_tcp_load_be16
    cmp eax, LEGACY_TCP_REMOTE_PORT
    jne .done
    lea rcx, [r12+2]
    call legacy_tcp_load_be16
    cmp eax, LEGACY_TCP_LOCAL_PORT
    jne .done
    test byte [r12+13], 0x10
    jz .done
    lea rcx, [r12+8]
    call legacy_tcp_load_be32
    mov ecx, eax
    call legacy_tcp_rel_ack64
.done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

legacy_tcp_tick64:
    call legacy_tcp_tick64_raw
    cmp dword [rel legacy_tcp_state], LEGACY_TCP_UP
    jne .done
    call legacy_tcp_rel_tick64
.done:
    ret

legacy_tcp_rel_tick64:
    push rbx
    push r12
    push r13
    lea rbx, [rel tcp_rel_slots]
    mov r12d, TCP_RELIABLE_SLOTS
.loop:
    cmp dword [rbx+TCP_REL_USED], 1
    jne .next
    mov r8, [rbx+TCP_REL_DEADLINE]
    test r8, r8
    jz .retry
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, r8
    jb .next
.retry:
    cmp dword [rbx+TCP_REL_RETRIES], TCP_RELIABLE_MAX_RETRIES
    jae .fail

   ; resend at the old sequence then put the live sequence back
    mov r13d, [rel legacy_tcp_local_seq]
    mov eax, [rbx+TCP_REL_SEQ]
    mov [rel legacy_tcp_local_seq], eax
    lea rcx, [rbx+TCP_REL_DATA_OFF]
    mov edx, [rbx+TCP_REL_LEN]
    mov r8d, 0x18
    call legacy_tcp_send_segment64
    mov [rel legacy_tcp_local_seq], r13d
    test eax, eax
    jnz .next
    inc dword [rbx+TCP_REL_RETRIES]
    inc qword [rel tcp_rel_retransmits]
    mov rcx, rbx
    call legacy_tcp_rel_set_deadline64
.next:
    add rbx, TCP_REL_SLOT_SIZE
    dec r12d
    jnz .loop
    jmp .done
.fail:
    mov dword [rel legacy_tcp_state], LEGACY_TCP_FAILED
    lea rsi, [rel msg_tcp_rel_fail]
    call serial_puts64
.done:
    pop r13
    pop r12
    pop rbx
    ret

align 16
tcp_rel_slots times (TCP_RELIABLE_SLOTS * TCP_REL_SLOT_SIZE) db 0
tcp_rel_next dd 0
tcp_rel_retransmits dq 0
tcp_rel_acked dq 0

msg_tcp_rel_fail db '[TCP] data stayed unacked, connection stopped',13,10,0
