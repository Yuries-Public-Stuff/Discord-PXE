; shard connection lifecycle / reconnect controller keeps a failed shard isolated, waits a
; bounded backoff, then rebuilds only that shard's tcp/tls/websocket/discord state.

BITS 64

%define SHARD_RECONNECT_BACKOFF_MS 5000

; rcx=shard ctx.
legacy_shard_schedule_backoff64:
    push rbx
    mov rbx, rcx
    test rbx, rbx
    jz .done
    mov dword [rbx + SHARD_OFF_STATE], SHARD_STATE_BACKOFF
    inc qword [rbx + SHARD_OFF_RECONNECTS]

    mov rax, [rel tsc_cycles_per_ms]
    test rax, rax
    jz .no_tsc
    imul rax, SHARD_RECONNECT_BACKOFF_MS
    mov r8, rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    add rax, r8
    mov [rbx + SHARD_OFF_RECONNECT_DEADLINE], rax
    jmp .log
.no_tsc:
    mov qword [rbx + SHARD_OFF_RECONNECT_DEADLINE], 0
.log:
    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_shard_backoff_err]
    call serial_puts64
    mov eax, [rbx + SHARD_OFF_LAST_ERROR]
    call serial_hex32_64
    lea rsi, [rel msg_shard_backoff_tcp]
    call serial_puts64
    mov r10, [rbx + SHARD_OFF_TCP_CTX]
    test r10, r10
    jz .tcp_zero
    mov eax, [r10 + STCP_STATE]
    jmp .tcp_done
.tcp_zero:
    xor eax, eax
.tcp_done:
    call serial_hex32_64
    lea rsi, [rel msg_shard_backoff_tls]
    call serial_puts64
    mov r10, [rbx + SHARD_OFF_TLS_CTX]
    test r10, r10
    jz .tls_zero
    mov eax, [r10 + STLS_STATE]
    jmp .tls_done
.tls_zero:
    xor eax, eax
.tls_done:
    call serial_hex32_64
    lea rsi, [rel msg_shard_backoff]
    call serial_puts64
.done:
    pop rbx
    ret

; rcx=shard ctx.
legacy_shard_connection_reset64:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rcx
    test rbx, rbx
    jz .bad_noctx

   ; preserve the last gateway sequence only when a valid resumable session survives this
   ; transport reset.
    mov r14d, [rbx + SHARD_OFF_SEQUENCE]
    mov r15d, [rbx + SHARD_OFF_FLAGS]

   ; reset the shard tcp page but retain/re-zero its separately allocated reliable retransmit
   ; queue so reconnects do not leak pages.
    mov r12, [rbx + SHARD_OFF_TCP_CTX]
    test r12, r12
    jz .tls
    mov r13, [r12 + STCP_REL_PTR]
    mov rdi, r12
    xor eax, eax
    mov ecx, 4096/8
    rep stosq
    mov [r12 + STCP_REL_PTR], r13
    mov eax, [rbx + SHARD_OFF_ID]
    and eax, SHARD_TCP_PORT_MASK
    add eax, SHARD_TCP_PORT_BASE
    mov [r12 + STCP_LOCAL_PORT], eax
    mov dword [r12 + STCP_STATE], SHARD_TCP_IDLE
    test r13, r13
    jz .tls
    mov rdi, r13
    xor eax, eax
    mov ecx, (SREL_PAGES * 4096) / 8
    rep stosq

.tls:
    mov rcx, rbx
    call legacy_shard_tls_reset64
    test eax, eax
    jnz .bad

   ; fresh websocket nonce/accept state for the next authenticated connection.
    mov r12, [rbx + SHARD_OFF_WS_CTX]
    test r12, r12
    jz .discord
    mov rdi, r12
    xor eax, eax
    mov ecx, 4096/8
    rep stosq

.discord:
    mov r12, [rbx + SHARD_OFF_DISCORD_CTX]
    test r12, r12
    jz .buffers
    mov rdi, r12
    xor eax, eax
    mov ecx, SHARD_DISCORD_BYTES / 8
    rep stosq

.buffers:
    mov dword [rbx + SHARD_OFF_RX_LEN], 0
    mov dword [rbx + SHARD_OFF_TX_LEN], 0
    mov dword [rbx + SHARD_OFF_HEARTBEAT_MS], 0
    mov qword [rbx + SHARD_OFF_HEARTBEAT_DEADLINE], 0
    mov dword [rbx + SHARD_OFF_HEARTBEAT_MISSES], 0
    mov qword [rbx + SHARD_OFF_RECONNECT_DEADLINE], 0
    mov dword [rbx + SHARD_OFF_FLAGS], 0
    mov dword [rbx + SHARD_OFF_LAST_ERROR], 0
    mov dword [rbx + SHARD_OFF_STATE], SHARD_STATE_ASSIGNED

    mov r12, [rbx + SHARD_OFF_SESSION_PTR]
    test r12, r12
    jz .no_resume
    cmp dword [r12 + SSES_VALID], 1
    jne .no_resume
    test r15d, SHARD_FLAG_SEQ_VALID
    jz .no_resume
    mov [rbx + SHARD_OFF_SEQUENCE], r14d
    or dword [rbx + SHARD_OFF_FLAGS], SHARD_FLAG_SEQ_VALID
    jmp .resume_done
.no_resume:
    mov dword [rbx + SHARD_OFF_SEQUENCE], 0xFFFFFFFF
.resume_done:

   ; rebuild the private websocket request and rebind private tcp -> tls.
    mov rcx, rbx
    call legacy_shard_ws_build_request64
    test eax, eax
    jnz .bad
    mov rcx, rbx
    call legacy_shard_tls_bind_tcp64
    test eax, eax
    jnz .bad

    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_shard_retry]
    call serial_puts64
    xor eax, eax
    jmp .out

.bad:
    mov dword [rbx + SHARD_OFF_LAST_ERROR], 10
.bad_noctx:
    mov eax, 1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx, eax=1 if backoff deadline has elapsed.
legacy_shard_backoff_due64:
    mov r8, [rcx + SHARD_OFF_RECONNECT_DEADLINE]
    test r8, r8
    jz .yes
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, r8
    jae .yes
    xor eax, eax
    ret
.yes:
    mov eax, 1
    ret

; rcx=shard ctx. detect private transport failure/backoff for one shard. keeping this as a
; one-context primitive lets the main scheduler reuse the same shard pointer for lifecycle, tcp, tls
legacy_shard_lifecycle_tick64:
    push rbx
    mov rbx, rcx
    test rbx, rbx
    jz .done

    cmp dword [rbx + SHARD_OFF_STATE], SHARD_STATE_FATAL
    je .done
    cmp dword [rbx + SHARD_OFF_STATE], SHARD_STATE_BACKOFF
    je .backoff

    mov r10, [rbx + SHARD_OFF_TCP_CTX]
    test r10, r10
    jz .tls_check
    cmp dword [r10 + STCP_STATE], SHARD_TCP_FAILED
    je .schedule
.tls_check:
    mov r10, [rbx + SHARD_OFF_TLS_CTX]
    test r10, r10
    jz .done
    cmp dword [r10 + STLS_STATE], LEGACY_TLS_FAILED
    je .schedule
    jmp .done

.schedule:
    mov rcx, rbx
    call legacy_shard_schedule_backoff64
    jmp .done

.backoff:
   ; a zero deadline means the failure site marked backoff directly.
    cmp qword [rbx + SHARD_OFF_RECONNECT_DEADLINE], 0
    jne .check_due
    mov rcx, rbx
    call legacy_shard_schedule_backoff64
    jmp .done
.check_due:
    mov rcx, rbx
    call legacy_shard_backoff_due64
    test eax, eax
    jz .done
    mov rcx, rbx
    call legacy_shard_connection_reset64
    test eax, eax
    jz .done
    mov rcx, rbx
    call legacy_shard_schedule_backoff64
.done:
    pop rbx
    ret

; compatibility wrapper for callers that still want a full lifecycle sweep.
legacy_shard_lifecycle_tick_all64:
    cmp dword [rel shard_initialized], 1
    jne .done
    cmp dword [rel shard_network_enabled], 1
    jne .done
    push rbx
    xor ebx, ebx
.loop:
    cmp ebx, [rel shard_active_count]
    jae .out
    mov ecx, ebx
    call legacy_shards_get_ctx64
    test rax, rax
    jz .out
    mov rcx, rax
    call legacy_shard_lifecycle_tick64
    inc ebx
    jmp .loop
.out:
    pop rbx
.done:
    ret

msg_shard_backoff_err db 'connection failed err=0x',0
msg_shard_backoff_tcp db ' tcp=0x',0
msg_shard_backoff_tls db ' tls=0x',0
msg_shard_backoff db '; backing off 5s',13,10,0
msg_shard_retry   db 'connection state reset; retrying',13,10,0
