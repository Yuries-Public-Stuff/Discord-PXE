; per-shard discord http/websocket/gateway state. each shard owns its own parser/fragment
; workspace and uses its private tls transport. no singleton gateway state is touched.

BITS 64

%define SHARD_DISCORD_PAGES 17
%define SHARD_DISCORD_BYTES (SHARD_DISCORD_PAGES * 4096)
%define SDIS_FRAG_LEN        0
%define SDIS_FRAG_ACTIVE     4
%define SDIS_FRAG_OPCODE     8
%define SDIS_CLOSE_CODE     12
%define SDIS_EVENTS         16
%define SDIS_READY_COUNT    24
%define SDIS_IDENTIFY_LEN   32
%define SDIS_JSON           64
%define SDIS_JSON_CAP     2048
%define SDIS_FRAG         4096
%define SDIS_FRAG_CAP    65536

%if (SDIS_FRAG + SDIS_FRAG_CAP) > SHARD_DISCORD_BYTES
    %error "shard Discord workspace exceeds allocated pages"
%endif

%define SHARD_SESSION_ID_CAP 128
%define SHARD_RESUME_URL_CAP 256
%define SSES_VALID          0
%define SSES_ID_LEN         4
%define SSES_URL_LEN        8
%define SSES_ID            16
%define SSES_URL          160

; rcx=shard ctx, rax=discord workspace or zero.
legacy_shard_discord_alloc64:
    push rbx
    mov rbx, rcx
    test rbx, rbx
    jz .bad
    mov rax, [rbx + SHARD_OFF_DISCORD_CTX]
    test rax, rax
    jnz .done

    mov ecx, SHARD_DISCORD_PAGES
    call alloc_pages64
    test rax, rax
    jnz .got
    mov ecx, SHARD_DISCORD_PAGES
    call alloc_high_pages64
.got:
    test rax, rax
    jz .bad
    mov [rbx + SHARD_OFF_DISCORD_CTX], rax
    push rax
    mov rdi, rax
    xor eax, eax
    mov ecx, SHARD_DISCORD_BYTES / 8
    rep stosq
    pop rax
.done:
    pop rbx
    ret
.bad:
    xor eax, eax
    pop rbx
    ret

; rcx=shard ctx, rax=persistent session workspace or zero.
legacy_shard_session_alloc64:
    push rbx
    mov rbx, rcx
    test rbx, rbx
    jz .bad
    mov rax, [rbx + SHARD_OFF_SESSION_PTR]
    test rax, rax
    jnz .done
    mov ecx, 1
    call alloc_pages64
    test rax, rax
    jnz .got
    mov ecx, 1
    call alloc_high_pages64
.got:
    test rax, rax
    jz .bad
    mov [rbx + SHARD_OFF_SESSION_PTR], rax
    push rax
    mov rdi, rax
    xor eax, eax
    mov ecx, 4096/8
    rep stosq
    pop rax
.done:
    pop rbx
    ret
.bad:
    xor eax, eax
    pop rbx
    ret

; rcx=src, rdx=end, r8=dst, r9d=cap. eax=len or 0xffffffff.
legacy_shard_json_copy_string64:
    push rbx
    xor eax, eax
.loop:
    cmp rcx, rdx
    jae .bad
    mov bl, [rcx]
    cmp bl, '"'
    je .done
    cmp bl, '\'
    je .bad
    cmp bl, 0x20
    jb .bad
    cmp eax, r9d
    jae .bad
    mov [r8+rax], bl
    inc eax
    inc rcx
    jmp .loop
.done:
    cmp eax, r9d
    jae .bad
    mov byte [r8+rax], 0
    pop rbx
    ret
.bad:
    mov eax, 0xFFFFFFFF
    pop rbx
    ret

; rcx=ctx, rdx=ready payload, r8d=len.
legacy_shard_session_store_ready64:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rcx
    mov r12, rdx
    mov r13d, r8d
    lea r14, [r12+r13]

    mov rcx, rbx
    call legacy_shard_session_alloc64
    test rax, rax
    jz .bad
    mov r11, rax

    mov rcx, r12
    mov edx, r13d
    lea r8, [rel sdis_session_key]
    mov r9d, sdis_session_key_len
    call legacy_dgw_find64
    test rax, rax
    jz .bad
    lea rcx, [rax+sdis_session_key_len]
    mov rdx, r14
    mov r11, [rbx + SHARD_OFF_SESSION_PTR]
    lea r8, [r11 + SSES_ID]
    mov r9d, SHARD_SESSION_ID_CAP-1
    call legacy_shard_json_copy_string64
    cmp eax, 0xFFFFFFFF
    je .bad
    test eax, eax
    jz .bad
    mov r11, [rbx + SHARD_OFF_SESSION_PTR]
    mov [r11 + SSES_ID_LEN], eax

   ; save resume_gateway_url for the future controller/dns-aware reconnect path. resume
   ; currently uses the already-resolved gateway endpoint.
    mov rcx, r12
    mov edx, r13d
    lea r8, [rel sdis_resume_url_key]
    mov r9d, sdis_resume_url_key_len
    call legacy_dgw_find64
    test rax, rax
    jz .valid
    lea rcx, [rax+sdis_resume_url_key_len]
    mov rdx, r14
    mov r11, [rbx + SHARD_OFF_SESSION_PTR]
    lea r8, [r11 + SSES_URL]
    mov r9d, SHARD_RESUME_URL_CAP-1
    call legacy_shard_json_copy_string64
    cmp eax, 0xFFFFFFFF
    je .valid
    mov r11, [rbx + SHARD_OFF_SESSION_PTR]
    mov [r11 + SSES_URL_LEN], eax
.valid:
    mov r11, [rbx + SHARD_OFF_SESSION_PTR]
    mov dword [r11 + SSES_VALID], 1
    xor eax, eax
    jmp .out
.bad:
    mov eax, 1
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rcx=ctx, eax=1 when a resumable session and sequence exist.
legacy_shard_session_can_resume64:
    test rcx, rcx
    jz .no
    test dword [rcx + SHARD_OFF_FLAGS], SHARD_FLAG_SEQ_VALID
    jz .no
    mov rax, [rcx + SHARD_OFF_SESSION_PTR]
    test rax, rax
    jz .no
    cmp dword [rax + SSES_VALID], 1
    jne .no
    cmp dword [rax + SSES_ID_LEN], 0
    je .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; rcx=ctx.
legacy_shard_session_invalidate64:
    test rcx, rcx
    jz .done
    mov rax, [rcx + SHARD_OFF_SESSION_PTR]
    test rax, rax
    jz .flags
    mov dword [rax + SSES_VALID], 0
    mov dword [rax + SSES_ID_LEN], 0
    mov dword [rax + SSES_URL_LEN], 0
.flags:
    and dword [rcx + SHARD_OFF_FLAGS], ~(SHARD_FLAG_SEQ_VALID | SHARD_FLAG_RESUMING)
    mov dword [rcx + SHARD_OFF_SEQUENCE], 0xFFFFFFFF
.done:
    ret

; rcx=ctx, rdx=dst, r8d=cap. eax=len or 0xffffffff.
legacy_shard_build_resume64:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r15, rcx
    mov rdi, rdx
    mov r12d, r8d
    xor r13d, r13d

    mov rcx, r15
    call legacy_shard_session_can_resume64
    test eax, eax
    jz .bad
    mov rbx, [r15 + SHARD_OFF_SESSION_PTR]

    lea rcx, [rel sdis_resume_a]
    call legacy_shard_ident_append_z64
    test eax, eax
    jnz .bad
    lea rcx, [rel legacy_token]
    mov edx, [rel legacy_token_len]
    call legacy_shard_ident_append_bytes64
    test eax, eax
    jnz .bad
    lea rcx, [rel sdis_resume_b]
    call legacy_shard_ident_append_z64
    test eax, eax
    jnz .bad
    lea rcx, [rbx + SSES_ID]
    mov edx, [rbx + SSES_ID_LEN]
    call legacy_shard_ident_append_bytes64
    test eax, eax
    jnz .bad
    lea rcx, [rel sdis_resume_c]
    call legacy_shard_ident_append_z64
    test eax, eax
    jnz .bad
    mov eax, [r15 + SHARD_OFF_SEQUENCE]
    call legacy_shard_ident_append_u32_64
    test eax, eax
    jnz .bad
    lea rcx, [rel sdis_resume_d]
    call legacy_shard_ident_append_z64
    test eax, eax
    jnz .bad
    mov eax, r13d
    jmp .out
.bad:
    mov eax, 0xFFFFFFFF
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rcx=ctx.
legacy_shard_discord_send_resume64:
    push rbx
    push r12
    mov rbx, rcx
    mov rcx, rbx
    call legacy_shard_discord_alloc64
    test rax, rax
    jz .bad
    mov r12, rax
    mov rcx, rbx
    lea rdx, [r12 + SDIS_JSON]
    mov r8d, SDIS_JSON_CAP
    call legacy_shard_build_resume64
    cmp eax, 0xFFFFFFFF
    je .bad
    mov rcx, rbx
    lea rdx, [r12 + SDIS_JSON]
    mov r8d, eax
    mov r9d, 1
    call legacy_shard_discord_ws_send64
    test eax, eax
    jnz .bad
    or dword [rbx + SHARD_OFF_FLAGS], SHARD_FLAG_RESUMING
    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_sdis_resume]
    call serial_puts64
    xor eax, eax
    jmp .out
.bad:
    mov eax, 1
.out:
    pop r12
    pop rbx
    ret

; rcx=ctx, rdx=payload, r8d=len, r9d=opcode.
legacy_shard_discord_ws_send64:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rcx
    mov r12, rdx
    mov r13d, r8d
    mov r14d, r9d

    mov rcx, rbx
    mov rdx, r12
    mov r8d, r13d
    mov r9d, r14d
    call legacy_shard_ws_frame64
    test rax, rax
    jz .bad
    mov r12, rax
    mov r13d, edx

    mov rcx, rbx
    mov rdx, r12
    mov r8d, r13d
    call legacy_shard_tls_send_app64
    jmp .out
.bad:
    mov eax, 1
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rcx=ctx.
legacy_shard_discord_send_identify64:
    push rbx
    push r12
    mov rbx, rcx
    test dword [rbx + SHARD_OFF_FLAGS], SHARD_FLAG_IDENTIFIED
    jnz .ok

    mov rcx, rbx
    call legacy_shard_discord_alloc64
    test rax, rax
    jz .bad
    mov r12, rax

    mov rcx, rbx
    lea rdx, [r12 + SDIS_JSON]
    mov r8d, SDIS_JSON_CAP
    call legacy_shard_build_identify64
    cmp eax, 0xFFFFFFFF
    je .bad
    mov [r12 + SDIS_IDENTIFY_LEN], eax

    mov rcx, rbx
    lea rdx, [r12 + SDIS_JSON]
    mov r8d, eax
    mov r9d, 1
    call legacy_shard_discord_ws_send64
    test eax, eax
    jnz .bad

    or dword [rbx + SHARD_OFF_FLAGS], SHARD_FLAG_IDENTIFIED
    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_sdis_ident]
    call serial_puts64
.ok:
    xor eax, eax
    pop r12
    pop rbx
    ret
.bad:
    mov dword [rbx + SHARD_OFF_LAST_ERROR], 5
    mov eax, 1
    pop r12
    pop rbx
    ret

; rcx=ctx. build one opcode 1 heartbeat with this shard's sequence.
legacy_shard_discord_send_heartbeat64:
    push rbx
    push r12
    push r13
    mov rbx, rcx
    mov rcx, rbx
    call legacy_shard_discord_alloc64
    test rax, rax
    jz .bad
    mov r12, rax
    lea rdi, [r12 + SDIS_JSON]
    lea rsi, [rel sdis_hb_a]
    mov ecx, sdis_hb_a_len
    rep movsb
    mov r13d, sdis_hb_a_len

    test dword [rbx + SHARD_OFF_FLAGS], SHARD_FLAG_SEQ_VALID
    jz .null
    mov ecx, [rbx + SHARD_OFF_SEQUENCE]
    call legacy_dgw_u32_text64
    mov rsi, rax
    mov ecx, edx
    add r13d, edx
    cmp r13d, SDIS_JSON_CAP-1
    ja .bad
    rep movsb
    jmp .close
.null:
    lea rsi, [rel sdis_null]
    mov ecx, 4
    add r13d, 4
    rep movsb
.close:
    mov byte [rdi], '}'
    inc r13d

    mov rcx, rbx
    lea rdx, [r12 + SDIS_JSON]
    mov r8d, r13d
    mov r9d, 1
    call legacy_shard_discord_ws_send64
    test eax, eax
    jnz .bad
    mov rcx, rbx
    call legacy_shard_gateway_note_heartbeat64
    xor eax, eax
    jmp .out
.bad:
    mov dword [rbx + SHARD_OFF_LAST_ERROR], 6
    mov eax, 1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; rcx=ctx, rdx=gateway text payload, r8d=len.
legacy_shard_discord_gateway_text64:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rcx
    mov r12, rdx
    mov r13d, r8d
    lea r14, [r12+r13]

   ; capture sequence when present.
    mov rcx, r12
    mov edx, r13d
    lea r8, [rel dgw_seq_key]
    mov r9d, dgw_seq_key_len
    call legacy_dgw_find64
    test rax, rax
    jz .opcode
    lea rcx, [rax+dgw_seq_key_len]
    mov rdx, r14
    call legacy_dgw_uint64
    jc .opcode
    mov edx, eax
    mov rcx, rbx
    call legacy_shard_gateway_set_sequence64

.opcode:
    mov rcx, r12
    mov edx, r13d
    call legacy_dgw_opcode64
    jc .bad
    cmp eax, 10
    je .hello
    cmp eax, 11
    je .ack
    cmp eax, 1
    je .heartbeat_now
    cmp eax, 7
    je .reconnect
    cmp eax, 9
    je .invalid
    cmp eax, 0
    je .dispatch
    jmp .ok

.dispatch:
   ; fan every gateway dispatch through the poc listener table first. listeners are
   ; read/parse-only today; outbound account-token transport is hard-disabled in legacy_bot_poc_outbound64.
    mov rcx, rbx
    mov rdx, r12
    mov r8d, r13d
    call legacy_bot_event_dispatch64

    mov rcx, r12
    mov edx, r13d
    lea r8, [rel sdis_resumed_event]
    mov r9d, sdis_resumed_event_len
    call legacy_dgw_find64
    test rax, rax
    jnz .resumed

    mov rcx, r12
    mov edx, r13d
    lea r8, [rel dgw_ready_event]
    mov r9d, dgw_ready_event_len
    call legacy_dgw_find64
    test rax, rax
    jz .event_done

    mov rcx, rbx
    mov rdx, r12
    mov r8d, r13d
    call legacy_shard_session_store_ready64
    test eax, eax
    jnz .bad
    mov rcx, rbx
    call legacy_shard_gateway_mark_ready64
    mov r11, [rbx + SHARD_OFF_DISCORD_CTX]
    test r11, r11
    jz .ready_log
    inc qword [r11 + SDIS_READY_COUNT]
.ready_log:
    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_sdis_ready]
    call serial_puts64
    jmp .event_done
.resumed:
    and dword [rbx + SHARD_OFF_FLAGS], ~SHARD_FLAG_RESUMING
    mov rcx, rbx
    call legacy_shard_gateway_mark_ready64
    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_sdis_resumed]
    call serial_puts64
.event_done:
    mov r11, [rbx + SHARD_OFF_DISCORD_CTX]
    test r11, r11
    jz .ok
    inc qword [r11 + SDIS_EVENTS]
    jmp .ok

.hello:
    mov rcx, r12
    mov edx, r13d
    lea r8, [rel dgw_hbi]
    mov r9d, dgw_hbi_len
    call legacy_dgw_find64
    test rax, rax
    jz .bad
    lea rcx, [rax+dgw_hbi_len]
    mov rdx, r14
    call legacy_dgw_uint64
    jc .bad
    test eax, eax
    jz .bad
    mov edx, eax
    mov rcx, rbx
    call legacy_shard_gateway_set_hello64
    test eax, eax
    jnz .bad

    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_sdis_hello]
    call serial_puts64
    mov eax, [rbx + SHARD_OFF_HEARTBEAT_MS]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64

   ; resume is intentionally disabled on this hardware path for now. fresh identify is proven
   ; across all local shards; the cached resume payload is currently rejected by discord with
    and dword [rbx + SHARD_OFF_FLAGS], ~(SHARD_FLAG_IDENTIFIED | SHARD_FLAG_RESUMING)
    or dword [rbx + SHARD_OFF_FLAGS], SHARD_FLAG_IDENTIFY_PENDING

   ; a separate scheduler enforces discord's max_concurrency buckets instead of blasting
   ; every reconnecting shard at once.
.schedule_hb:
    mov rcx, rbx
    call legacy_shard_gateway_schedule_first_heartbeat64
    test eax, eax
    jnz .bad
    jmp .ok

.ack:
    mov rcx, rbx
    call legacy_shard_gateway_note_ack64
    cmp dword [rel serial_live_enabled], 1
    jne .ok
    call legacy_shell_input_busy64
    test eax, eax
    jnz .ok
    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_sdis_ack]
    call serial_puts64
    jmp .ok

.heartbeat_now:
    mov rcx, rbx
    call legacy_shard_discord_send_heartbeat64
    test eax, eax
    jnz .bad
    jmp .ok

.reconnect:
    mov dword [rbx + SHARD_OFF_STATE], SHARD_STATE_BACKOFF
    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_sdis_reconnect]
    call serial_puts64
    jmp .ok
.invalid:
   ; opcode 9 carries a boolean telling us whether the saved session can still be resumed.
   ; preserve the session/sequence only when discord explicitly says true; otherwise force the next
    mov rcx, r12
    mov edx, r13d
    lea r8, [rel sdis_invalid_true]
    mov r9d, sdis_invalid_true_len
    call legacy_dgw_find64
    test rax, rax
    jnz .invalid_resumable
    mov rcx, rbx
    call legacy_shard_session_invalidate64
    jmp .invalid_backoff
.invalid_resumable:
    or dword [rbx + SHARD_OFF_FLAGS], SHARD_FLAG_RESUMING
.invalid_backoff:
    mov dword [rbx + SHARD_OFF_STATE], SHARD_STATE_BACKOFF
    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_sdis_invalid]
    call serial_puts64
    jmp .ok

.bad:
    mov dword [rbx + SHARD_OFF_LAST_ERROR], 7
    mov eax, 1
    jmp .out
.ok:
    xor eax, eax
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rcx=ctx. parse/verify http 101 and this shard's exact ws accept.
legacy_shard_discord_http_parse64:
    push rbx
    push r12
    push r13
    mov rbx, rcx
    mov r13d, [rbx + SHARD_OFF_RX_LEN]
    cmp r13d, 16
    jb .wait
    mov r12, [rbx + SHARD_OFF_RX_BUF]
    test r12, r12
    jz .bad

    cmp byte [r12+0], 'H'
    jne .bad
    cmp byte [r12+1], 'T'
    jne .bad
    cmp byte [r12+2], 'T'
    jne .bad
    cmp byte [r12+3], 'P'
    jne .bad
    cmp byte [r12+4], '/'
    jne .bad

    xor r10d, r10d
.status_space:
    cmp r10d, r13d
    jae .wait
    cmp byte [r12+r10], ' '
    je .status
    inc r10d
    jmp .status_space
.status:
    lea eax, [r10d+4]
    cmp eax, r13d
    ja .wait
    cmp byte [r12+r10+1], '1'
    jne .bad
    cmp byte [r12+r10+2], '0'
    jne .bad
    cmp byte [r12+r10+3], '1'
    jne .bad

    xor r10d, r10d
.scan:
    lea eax, [r10d+4]
    cmp eax, r13d
    ja .wait
    cmp byte [r12+r10], 13
    jne .next
    cmp byte [r12+r10+1], 10
    jne .next
    cmp byte [r12+r10+2], 13
    jne .next
    cmp byte [r12+r10+3], 10
    jne .next

    lea r13d, [r10d+4]
    mov rcx, rbx
    mov rdx, r12
    mov r8d, r13d
    call legacy_shard_ws_validate_accept64
    test eax, eax
    jz .bad

    mov rcx, rbx
    mov edx, r13d
    call legacy_shard_rx_consume64
    or dword [rbx + SHARD_OFF_FLAGS], SHARD_FLAG_WS_OPEN
    and dword [rbx + SHARD_OFF_FLAGS], ~SHARD_FLAG_WS_HTTP

    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_sdis_ws_open]
    call serial_puts64
    xor eax, eax
    jmp .out
.next:
    inc r10d
    jmp .scan
.wait:
    mov eax, 2
    jmp .out
.bad:
    mov dword [rbx + SHARD_OFF_LAST_ERROR], 8
    mov eax, 1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; rcx=ctx, rdx=payload, r8d=len.
legacy_shard_discord_frag_append64:
    push rbx
    push r12
    push r13
    mov rbx, rcx
    mov r12, rdx
    mov r13d, r8d
    mov r11, [rbx + SHARD_OFF_DISCORD_CTX]
    test r11, r11
    jz .bad
    mov eax, [r11 + SDIS_FRAG_LEN]
    mov edx, SDIS_FRAG_CAP
    sub edx, eax
    cmp r13d, edx
    ja .bad
    lea rdi, [r11 + SDIS_FRAG]
    add rdi, rax
    mov rsi, r12
    mov ecx, r13d
    rep movsb
    add [r11 + SDIS_FRAG_LEN], r13d
    xor eax, eax
    jmp .out
.bad:
    mov eax, 1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; rcx=ctx, eax=reason code. print enough raw frame state to diagnose immediate
; post-upgrade failures on hardware without a debugger.
legacy_shard_discord_ws_fail_diag64:
    push rbx
    push r12
    push r13
    mov rbx, rcx
    mov r13d, eax
    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_sdis_ws_bad]
    call serial_puts64
    mov eax, r13d
    call serial_hex32_64
    lea rsi, [rel msg_sdis_ws_rxlen]
    call serial_puts64
    mov eax, [rbx + SHARD_OFF_RX_LEN]
    call serial_hex32_64
    mov r12, [rbx + SHARD_OFF_RX_BUF]
    test r12, r12
    jz .line
    lea rsi, [rel msg_sdis_ws_bytes]
    call serial_puts64
    xor r13d, r13d
.bytes:
    cmp r13d, 8
    jae .line
    cmp r13d, [rbx + SHARD_OFF_RX_LEN]
    jae .line
    movzx eax, byte [r12+r13]
    call serial_hex32_64
    mov al, ' '
    call serial_putc64_al
    inc r13d
    jmp .bytes
.line:
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    pop r13
    pop r12
    pop rbx
    ret

; rcx=ctx. parse complete server websocket frames from the shard rx buffer.
legacy_shard_discord_ws_parse64:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rcx

.loop:
    mov r13d, [rbx + SHARD_OFF_RX_LEN]
    cmp r13d, 2
    jb .ok
    mov r12, [rbx + SHARD_OFF_RX_BUF]
    test r12, r12
    jz .bad

    movzx r14d, byte [r12]
    mov r15d, r14d
    and r15d, 0x0F
    and r14d, 0x80

    movzx eax, byte [r12+1]
    test eax, 0x80
    jnz .bad_masked
    and eax, 0x7F
    cmp eax, 126
    je .len16
    cmp eax, 127
    je .len64
    mov r10d, eax
    mov r11d, 2
    jmp .have_len
.len16:
    cmp r13d, 4
    jb .ok
    movzx r10d, byte [r12+2]
    shl r10d, 8
    movzx eax, byte [r12+3]
    or r10d, eax
    mov r11d, 4
    jmp .have_len
.len64:
    cmp r13d, 10
    jb .ok
    cmp dword [r12+2], 0
    jne .bad_len64
    movzx r10d, byte [r12+6]
    shl r10d, 24
    movzx eax, byte [r12+7]
    shl eax, 16
    or r10d, eax
    movzx eax, byte [r12+8]
    shl eax, 8
    or r10d, eax
    movzx eax, byte [r12+9]
    or r10d, eax
    mov r11d, 10
.have_len:
    mov eax, r11d
    add eax, r10d
    cmp eax, SHARD_RX_CAP
    ja .bad_oversize
    cmp r13d, eax
    jb .ok
    mov r13d, eax

    cmp r15d, 8
    jae .control
    cmp r15d, 1
    je .text
    cmp r15d, 0
    je .continuation
    jmp .bad_opcode

.control:
    test r14d, r14d
    jz .bad_control
    cmp r10d, 125
    ja .bad_control
    cmp r15d, 8
    je .close
    cmp r15d, 9
    je .ping
    cmp r15d, 10
    je .consume
    jmp .bad_control

.text:
    mov rdx, r12
    add rdx, r11
    mov r11, [rbx + SHARD_OFF_DISCORD_CTX]
    test r11, r11
    jz .bad
    cmp dword [r11 + SDIS_FRAG_ACTIVE], 0
    jne .bad
    test r14d, r14d
    jnz .text_whole
    mov dword [r11 + SDIS_FRAG_ACTIVE], 1
    mov dword [r11 + SDIS_FRAG_OPCODE], 1
    mov dword [r11 + SDIS_FRAG_LEN], 0
    mov rcx, rbx
    mov r8d, r10d
    call legacy_shard_discord_frag_append64
    test eax, eax
    jnz .bad
    jmp .consume
.text_whole:
    mov rcx, rbx
    mov r8d, r10d
    call legacy_shard_discord_gateway_text64
    test eax, eax
    jnz .bad
    jmp .consume

.continuation:
    mov r11, [rbx + SHARD_OFF_DISCORD_CTX]
    test r11, r11
    jz .bad
    cmp dword [r11 + SDIS_FRAG_ACTIVE], 1
    jne .bad
   ; r11 is the workspace pointer here, so recompute the frame header length instead of
   ; reusing the earlier volatile header-length register.
    mov rdx, r12
    movzx eax, byte [r12+1]
    and eax, 0x7F
    cmp eax, 126
    je .cont_h4
    cmp eax, 127
    je .cont_h10
    add rdx, 2
    jmp .cont_ptr
.cont_h4:
    add rdx, 4
    jmp .cont_ptr
.cont_h10:
    add rdx, 10
.cont_ptr:
    mov rcx, rbx
    mov r8d, r10d
    call legacy_shard_discord_frag_append64
    test eax, eax
    jnz .bad
    test r14d, r14d
    jz .consume

    mov r11, [rbx + SHARD_OFF_DISCORD_CTX]
    cmp dword [r11 + SDIS_FRAG_OPCODE], 1
    jne .frag_done
    mov rcx, rbx
    lea rdx, [r11 + SDIS_FRAG]
    mov r8d, [r11 + SDIS_FRAG_LEN]
    call legacy_shard_discord_gateway_text64
    test eax, eax
    jnz .bad
.frag_done:
    mov r11, [rbx + SHARD_OFF_DISCORD_CTX]
    mov dword [r11 + SDIS_FRAG_ACTIVE], 0
    mov dword [r11 + SDIS_FRAG_LEN], 0
    jmp .consume

.ping:
    mov rdx, r12
   ; recompute header length for control payload.
    movzx eax, byte [r12+1]
    and eax, 0x7F
    cmp eax, 126
    je .ping_h4
    cmp eax, 127
    je .ping_h10
    add rdx, 2
    jmp .ping_ptr
.ping_h4:
    add rdx, 4
    jmp .ping_ptr
.ping_h10:
    add rdx, 10
.ping_ptr:
    mov rcx, rbx
    mov r8d, r10d
    mov r9d, 10
    call legacy_shard_discord_ws_send64
    test eax, eax
    jnz .bad
    jmp .consume

.close:
    mov r11, [rbx + SHARD_OFF_DISCORD_CTX]
    test r11, r11
    jz .bad
    mov dword [r11 + SDIS_CLOSE_CODE], 0
    cmp r10d, 2
    jb .closed
   ; locate payload and decode network-order close code.
    mov rdx, r12
    movzx eax, byte [r12+1]
    and eax, 0x7F
    cmp eax, 126
    je .close_h4
    cmp eax, 127
    je .close_h10
    add rdx, 2
    jmp .close_ptr
.close_h4:
    add rdx, 4
    jmp .close_ptr
.close_h10:
    add rdx, 10
.close_ptr:
    movzx eax, byte [rdx]
    shl eax, 8
    movzx ecx, byte [rdx+1]
    or eax, ecx
    mov [r11 + SDIS_CLOSE_CODE], eax
.closed:
    mov r11, [rbx + SHARD_OFF_DISCORD_CTX]
    mov eax, [r11 + SDIS_CLOSE_CODE]

   ; session-invalidating close codes must force a fresh identify.
    cmp eax, 4007
    je .close_invalidate
    cmp eax, 4009
    je .close_invalidate

   ; payload/auth/shard configuration errors will not heal by reconnecting in a loop.
    cmp eax, 4002
    je .close_fatal
    cmp eax, 4003
    je .close_fatal
    cmp eax, 4004
    je .close_fatal
    cmp eax, 4005
    je .close_fatal
    cmp eax, 4010
    je .close_fatal
    cmp eax, 4011
    je .close_fatal
    cmp eax, 4012
    je .close_fatal
    cmp eax, 4013
    je .close_fatal
    cmp eax, 4014
    je .close_fatal

    mov dword [rbx + SHARD_OFF_STATE], SHARD_STATE_BACKOFF
    jmp .close_log

.close_invalidate:
    mov rcx, rbx
    call legacy_shard_session_invalidate64
    mov dword [rbx + SHARD_OFF_STATE], SHARD_STATE_BACKOFF
    jmp .close_log

.close_fatal:
    mov dword [rbx + SHARD_OFF_STATE], SHARD_STATE_FATAL
    mov dword [rbx + SHARD_OFF_LAST_ERROR], 11

.close_log:
    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_sdis_close]
    call serial_puts64
    mov r11, [rbx + SHARD_OFF_DISCORD_CTX]
    mov eax, [r11 + SDIS_CLOSE_CODE]
    call serial_hex32_64
    cmp dword [rbx + SHARD_OFF_STATE], SHARD_STATE_FATAL
    jne .close_line
    lea rsi, [rel msg_sdis_close_fatal]
    call serial_puts64
    mov r11, [rbx + SHARD_OFF_DISCORD_CTX]
    mov eax, [r11 + SDIS_CLOSE_CODE]
    cmp eax, 4002
    jne .fatal_4003
    lea rsi, [rel msg_sdis_4002]
    call serial_puts64
    jmp .consume
.fatal_4003:
    cmp eax, 4003
    jne .fatal_4004
    lea rsi, [rel msg_sdis_4003]
    call serial_puts64
    jmp .consume
.fatal_4004:
    cmp eax, 4004
    jne .fatal_4005
    lea rsi, [rel msg_sdis_4004]
    call serial_puts64
    jmp .consume
.fatal_4005:
    cmp eax, 4005
    jne .consume
    lea rsi, [rel msg_sdis_4005]
    call serial_puts64
    jmp .consume
.close_line:
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    jmp .consume

.consume:
    mov rcx, rbx
    mov edx, r13d
    call legacy_shard_rx_consume64
    jmp .loop

.bad_masked:
    mov eax, 1
    jmp .bad_diag
.bad_len64:
    mov eax, 2
    jmp .bad_diag
.bad_oversize:
    mov eax, 3
    jmp .bad_diag
.bad_opcode:
    mov eax, 4
    jmp .bad_diag
.bad_control:
    mov eax, 5
    jmp .bad_diag
.bad_diag:
    mov rcx, rbx
    call legacy_shard_discord_ws_fail_diag64
.bad:
    mov dword [rbx + SHARD_OFF_LAST_ERROR], 9
    mov dword [rbx + SHARD_OFF_STATE], SHARD_STATE_BACKOFF
    mov eax, 1
    jmp .out
.ok:
    xor eax, eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rcx=ctx. parse authenticated app bytes as http until upgrade, then ws.
legacy_shard_discord_parse64:
    push rbx
    mov rbx, rcx
    test dword [rbx + SHARD_OFF_FLAGS], SHARD_FLAG_WS_OPEN
    jnz .ws
    test dword [rbx + SHARD_OFF_FLAGS], SHARD_FLAG_WS_HTTP
    jz .done
    mov rcx, rbx
    call legacy_shard_discord_http_parse64
    cmp eax, 1
    je .bad
    test dword [rbx + SHARD_OFF_FLAGS], SHARD_FLAG_WS_OPEN
    jz .done
.ws:
    mov rcx, rbx
    call legacy_shard_discord_ws_parse64
    test eax, eax
    jnz .bad
.done:
    xor eax, eax
    pop rbx
    ret
.bad:
    mov eax, 1
    pop rbx
    ret

%define SHARD_IDENTIFY_WINDOW_MS 5500
%define SHARD_HEARTBEAT_MISS_LIMIT 5

; one local identify wave. each discord concurrency bucket is used at most once in a 5.5
; second window. the controller will eventually arbitrate the same buckets across nodes
legacy_shard_discord_identify_tick64:
    cmp dword [rel shard_initialized], 1
    jne .done
    cmp dword [rel shard_network_enabled], 1
    jne .done

    mov rax, [rel tsc_cycles_per_ms]
    test rax, rax
    jz .done

    mov r8, [rel shard_identify_wave_deadline]
    test r8, r8
    jz .wave
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, r8
    jb .done

.wave:
    push rdi
    push r15
   ; clear bucket-use marks for this wave.
    lea rdi, [rel shard_identify_bucket_used]
    xor eax, eax
    mov ecx, 1024/8
    rep stosq

    mov r15d, [rel shard_identify_concurrency]
    test r15d, r15d
    jnz .cap
    mov r15d, 1
.cap:
    cmp r15d, LEGACY_SHARD_MAX
    jbe .scan_start
    mov r15d, LEGACY_SHARD_MAX

.scan_start:
    push rbx
    push r12
    push r13
    push r14
    xor ebx, ebx
    xor r14d, r14d
.scan:
    cmp ebx, [rel shard_active_count]
    jae .set_deadline
    cmp r14d, r15d
    jae .set_deadline

    mov ecx, ebx
    call legacy_shards_get_ctx64
    test rax, rax
    jz .set_deadline
    mov r12, rax

    test dword [r12 + SHARD_OFF_FLAGS], SHARD_FLAG_IDENTIFY_PENDING
    jz .next
    test dword [r12 + SHARD_OFF_FLAGS], SHARD_FLAG_IDENTIFIED
    jnz .clear_pending

    mov r13d, [r12 + SHARD_OFF_IDENTIFY_BUCKET]
    cmp r13d, 1024
    jae .next
    lea r10, [rel shard_identify_bucket_used]
    cmp byte [r10+r13], 0
    jne .next

    mov rcx, r12
    call legacy_shard_discord_send_identify64
    test eax, eax
    jnz .next
    lea r10, [rel shard_identify_bucket_used]
    mov byte [r10+r13], 1
    and dword [r12 + SHARD_OFF_FLAGS], ~SHARD_FLAG_IDENTIFY_PENDING
    inc r14d
    jmp .next

.clear_pending:
    and dword [r12 + SHARD_OFF_FLAGS], ~SHARD_FLAG_IDENTIFY_PENDING
.next:
    inc ebx
    jmp .scan

.set_deadline:
    mov rax, [rel tsc_cycles_per_ms]
    imul rax, SHARD_IDENTIFY_WINDOW_MS
    mov r8, rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    add rax, r8
    mov [rel shard_identify_wave_deadline], rax

    pop r14
    pop r13
    pop r12
    pop rbx
    pop r15
    pop rdi
.done:
    ret

; rcx=shard ctx. run heartbeat maintenance for one live gateway shard.
legacy_shard_discord_tick64:
    push rbx
    mov rbx, rcx
    test rbx, rbx
    jz .done
    test dword [rbx + SHARD_OFF_FLAGS], SHARD_FLAG_IDENTIFIED
    jz .done
    cmp dword [rbx + SHARD_OFF_STATE], SHARD_STATE_BACKOFF
    je .done
    mov rcx, rbx
    call legacy_shard_gateway_heartbeat_due64
    test eax, eax
    jz .done

    test dword [rbx + SHARD_OFF_FLAGS], SHARD_FLAG_AWAITING_ACK
    jz .send
    inc dword [rbx + SHARD_OFF_HEARTBEAT_MISSES]
    cmp dword [rbx + SHARD_OFF_HEARTBEAT_MISSES], SHARD_HEARTBEAT_MISS_LIMIT
    jb .late
    mov dword [rbx + SHARD_OFF_STATE], SHARD_STATE_BACKOFF
    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_sdis_hb_dead]
    call serial_puts64
    jmp .done
.late:
    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_sdis_hb_late]
    call serial_puts64
.send:
    mov rcx, rbx
    call legacy_shard_discord_send_heartbeat64
.done:
    pop rbx
    ret

; full sweep wrapper retained for diagnostics/compatibility.
legacy_shard_discord_tick_all64:
    call legacy_shard_discord_identify_tick64
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
    call legacy_shard_discord_tick64
    inc ebx
    jmp .loop
.out:
    pop rbx
.done:
    ret

sdis_hb_a db '{"op":1,"d":'
sdis_hb_a_len equ $-sdis_hb_a
sdis_null db 'null'

msg_sdis_ident     db 'Gateway Identify sent',13,10,0
msg_sdis_hello     db 'Gateway Hello heartbeat-ms=0x',0
msg_sdis_ack       db 'heartbeat ACK',13,10,0
msg_sdis_hb_late   db 'heartbeat ACK late; keepalive continues',13,10,0
msg_sdis_hb_dead   db 'heartbeat ACK missing repeatedly; reconnecting shard',13,10,0
msg_sdis_ready     db 'READY, shard online',13,10,0
msg_sdis_reconnect db 'Gateway requested reconnect',13,10,0
msg_sdis_invalid   db 'Gateway invalid session',13,10,0
msg_sdis_ws_open   db 'HTTP 101 + WebSocket accept verified',13,10,0
msg_sdis_ws_bad    db 'WebSocket parser failure reason=0x',0
msg_sdis_ws_rxlen  db ' rxlen=0x',0
msg_sdis_ws_bytes  db ' first8=',0
msg_sdis_close     db 'WebSocket close code=0x',0
msg_sdis_close_fatal db ' fatal; shard disabled',13,10,0
msg_sdis_4002      db '[SHARD] close 4002: Gateway could not decode this shard Identify payload',13,10,0
msg_sdis_4003      db '[SHARD] close 4003: shard sent traffic before authentication',13,10,0
msg_sdis_4004      db '[SHARD] close 4004: bot token authentication failed',13,10,0
msg_sdis_4005      db '[SHARD] close 4005: shard sent Identify more than once',13,10,0


sdis_session_key db '"session_id":"'
sdis_session_key_len equ $-sdis_session_key
sdis_resume_url_key db '"resume_gateway_url":"'
sdis_resume_url_key_len equ $-sdis_resume_url_key
sdis_resumed_event db '"t":"RESUMED"'
sdis_resumed_event_len equ $-sdis_resumed_event
sdis_invalid_true db '"d":true'
sdis_invalid_true_len equ $-sdis_invalid_true
sdis_resume_a db '{"op":6,"d":{"token":"',0
sdis_resume_b db '","session_id":"',0
sdis_resume_c db '","seq":',0
sdis_resume_d db '}}',0
msg_sdis_resume db 'Gateway Resume sent',13,10,0
msg_sdis_resumed db 'RESUMED, shard session restored',13,10,0
