; discord gateway v10 messages after websocket opens keeps the token private and only
; sends masked client frames

BITS 64

%define DGW_FRAME_CAP 8192
%define DGW_JSON_CAP  4096

legacy_discord_gateway_init64:
    mov dword [rel dgw_identified], 0
    mov dword [rel dgw_ready], 0
    mov dword [rel dgw_seq_valid], 0
    mov dword [rel dgw_awaiting_ack], 0
    mov dword [rel dgw_heartbeat_misses], 0
    mov qword [rel dgw_heartbeat_deadline], 0
    mov qword [rel dgw_heartbeats_sent], 0
    mov qword [rel dgw_heartbeat_acks], 0
    ret

; rcx hay, edx hay len, r8 needle, r9d needle len
legacy_dgw_find64:
    push rbx
    push rsi
    push rdi
    push r12
    mov rsi, rcx
    mov ebx, edx
    mov rdi, r8
    test r9d, r9d
    jz .hit0
    cmp ebx, r9d
    jb .no
    sub ebx, r9d
    xor edx, edx
.outer:
    cmp edx, ebx
    ja .no
    lea r12, [rsi+rdx]
    xor ecx, ecx
.inner:
    cmp ecx, r9d
    jae .hit
    mov al, [r12+rcx]
    cmp al, [rdi+rcx]
    jne .next
    inc ecx
    jmp .inner
.next:
    inc edx
    jmp .outer
.hit:
    lea rax, [rsi+rdx]
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
.hit0:
    mov rax, rsi
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
.no:
    xor eax, eax
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; rcx points near a json number and rdx is the end
legacy_dgw_uint64:
    xor eax, eax
    xor r8d, r8d
.skip:
    cmp rcx, rdx
    jae .bad
    mov r9b, [rcx]
    cmp r9b, ' '
    je .skip_one
    cmp r9b, ':'
    je .skip_one
    cmp r9b, 9
    je .skip_one
    cmp r9b, 13
    je .skip_one
    cmp r9b, 10
    je .skip_one
    jne .digits
.skip_one:
    inc rcx
    jmp .skip
.digits:
    cmp rcx, rdx
    jae .finish
    mov r9b, [rcx]
    cmp r9b, '0'
    jb .finish
    cmp r9b, '9'
    ja .finish
    imul eax, eax, 10
    movzx r10d, r9b
    sub r10d, '0'
    add eax, r10d
    inc rcx
    inc r8d
    cmp r8d, 10
    jbe .digits
.bad:
    stc
    ret
.finish:
    test r8d, r8d
    jz .bad
    clc
    ret

; parse the numeric gateway opcode instead of matching formatting-sensitive strings such
; as '"op":10'. discord is free to insert whitespace around ':'. rcx payload, edx len -> eax opcode
legacy_dgw_opcode64:
    push rbx
    push r12
    mov r12, rcx
    mov ebx, edx
    mov rcx, r12
    mov edx, ebx
    lea r8, [rel dgw_op_key]
    mov r9d, dgw_op_key_len
    call legacy_dgw_find64
    test rax, rax
    jz .bad
    lea rcx, [rax+dgw_op_key_len]
    lea rdx, [r12+rbx]
    call legacy_dgw_uint64
    jc .bad
    clc
    pop r12
    pop rbx
    ret
.bad:
    xor eax, eax
    stc
    pop r12
    pop rbx
    ret

; rcx payload, edx len, r8d opcode generic rfc6455 client frame sender.
legacy_dgw_ws_send64:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rcx
    mov r13d, edx
    mov r14d, r8d

    cmp r13d, DGW_JSON_CAP
    ja .bad
    mov rax, [rel discord_transport_send]
    test rax, rax
    jz .bad

    cmp r14d, 8
    jb .data_frame
    cmp r13d, 125
    ja .bad
.data_frame:
    lea rbx, [rel dgw_frame]
    mov al, r14b
    or al, 0x80
    mov [rbx+0], al

    cmp r13d, 125
    ja .extended16
    mov eax, r13d
    or al, 0x80
    mov [rbx+1], al
    mov r15d, 6
    lea rcx, [rbx+2]
    jmp .mask_key

.extended16:
    mov byte [rbx+1], 0xFE
    mov eax, r13d
    mov [rbx+3], al
    shr eax, 8
    mov [rbx+2], al
    mov r15d, 8
    lea rcx, [rbx+4]

.mask_key:
    mov edx, 4
    call rng_safe_get
    test eax, eax
    jnz .bad
    cmp r15d, 6
    jne .ptr_extended
    lea r11, [rbx+2]
    lea rdi, [rbx+6]
    jmp .ptr_ready
.ptr_extended:
    lea r11, [rbx+4]
    lea rdi, [rbx+8]
.ptr_ready:
    mov eax, r13d
    add eax, r15d
    cmp eax, DGW_FRAME_CAP
    ja .bad
    xor ecx, ecx
.mask_copy:
    cmp ecx, r13d
    jae .selfcheck
    mov al, [r12+rcx]
    mov edx, ecx
    and edx, 3
    xor al, [r11+rdx]
    mov [rdi+rcx], al
    inc ecx
    jmp .mask_copy

; prove the complete masked payload decodes byte-for-byte to the source before it enters
; tls. this catches any websocket header/mask regression locally.
.selfcheck:
    xor ecx, ecx
.check_loop:
    cmp ecx, r13d
    jae .send
    mov al, [rdi+rcx]
    mov edx, ecx
    and edx, 3
    xor al, [r11+rdx]
    cmp al, [r12+rcx]
    jne .bad
    inc ecx
    jmp .check_loop

.send:
    mov rax, [rel discord_transport_send]
    lea rcx, [rel dgw_frame]
    mov edx, r13d
    add edx, r15d
    mov r8, [rel discord_transport_arg]
    sub rsp, 32
    call rax
    add rsp, 32
    jmp .out
.bad:
    mov eax, LEGACY_STATUS_DEVICE
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

legacy_dgw_append64:
.loop:
    mov al, [rcx]
    test al, al
    jz .done
    cmp r8d, r9d
    jae .bad
    mov [rdi+r8], al
    inc rcx
    inc r8d
    jmp .loop
.done:
    mov eax, r8d
    ret
.bad:
    mov eax, 0xFFFFFFFF
    ret

; build.ps1 creates and parses the exact identify json at build time. send those exact
; bytes here so runtime token concatenation cannot corrupt the payload.
legacy_discord_send_identify64:
    cmp dword [rel legacy_config_ready], 1
    jne .bad
    cmp dword [rel dgw_identified], 1
    je .ok
%ifdef LEGACY_HAVE_LOCAL_SECRETS
    lea rcx, [rel legacy_embedded_identify]
    mov edx, legacy_embedded_identify_len
    mov r8d, 1
    call legacy_dgw_ws_send64
    test eax, eax
    jnz .send_fail
%else
    jmp .bad
%endif
    mov dword [rel dgw_identified], 1
    mov dword [rel discord_base_state], DISCORD_BASE_IDENTIFIED
    lea rsi, [rel msg_dgw_ident]
    call serial_puts64
.ok:
    xor eax, eax
    ret
.send_fail:
    lea rsi, [rel msg_dgw_ident_fail]
    call serial_puts64
.bad:
    mov eax, LEGACY_STATUS_DEVICE
    ret

legacy_dgw_u32_text64:
    push rdi
    lea rdi, [rel dgw_num+15]
    mov byte [rdi], 0
    mov eax, ecx
    xor edx, edx
    test eax, eax
    jnz .loop
    dec rdi
    mov byte [rdi], '0'
    mov edx, 1
    mov rax, rdi
    pop rdi
    ret
.loop:
    xor edx, edx
    mov r8d, 10
    div r8d
    add dl, '0'
    dec rdi
    mov [rdi], dl
    inc dword [rel dgw_num_len]
    test eax, eax
    jnz .loop
    mov edx, [rel dgw_num_len]
    mov dword [rel dgw_num_len], 0
    mov rax, rdi
    pop rdi
    ret

legacy_discord_send_heartbeat64:
    lea rdi, [rel dgw_json]
    lea rsi, [rel dgw_hb_a]
    mov ecx, dgw_hb_a_len
    rep movsb
    cmp dword [rel dgw_seq_valid], 1
    jne .null
    mov ecx, [rel discord_sequence]
    call legacy_dgw_u32_text64
    mov rsi, rax
    mov ecx, edx
    rep movsb
    jmp .close
.null:
    lea rsi, [rel dgw_null]
    mov ecx, 4
    rep movsb
.close:
    mov byte [rdi], '}'
    inc rdi
    mov rax, rdi
    lea rdx, [rel dgw_json]
    sub rax, rdx
    mov edx, eax
    lea rcx, [rel dgw_json]
    mov r8d, 1
    call legacy_dgw_ws_send64
    test eax, eax
    jnz .bad
    mov dword [rel dgw_awaiting_ack], 1
    inc qword [rel dgw_heartbeats_sent]
    call legacy_dgw_schedule_heartbeat64
    xor eax, eax
    ret
.bad:
    mov eax, LEGACY_STATUS_DEVICE
    ret

legacy_dgw_schedule_heartbeat64:
    mov eax, [rel discord_heartbeat_ms]
    test eax, eax
    jz .none
    mov rcx, [rel tsc_cycles_per_ms]
    test rcx, rcx
    jz .none
    imul rax, rcx
    mov r8, rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    add rax, r8
    mov [rel dgw_heartbeat_deadline], rax
.none:
    ret

legacy_discord_gateway_text64:
    push rbx
    push r12
    mov r12, rcx
    mov ebx, edx
    lea rdx, [r12+rbx]
    mov [rel dgw_json_end], rdx

    mov rcx, r12
    mov edx, ebx
    lea r8, [rel dgw_seq_key]
    mov r9d, dgw_seq_key_len
    call legacy_dgw_find64
    test rax, rax
    jz .op
    lea rcx, [rax+dgw_seq_key_len]
    mov rdx, [rel dgw_json_end]
    call legacy_dgw_uint64
    jc .op
    mov [rel discord_sequence], eax
    mov dword [rel dgw_seq_valid], 1
.op:
    mov rcx, r12
    mov edx, ebx
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
    jmp .done
.dispatch:
    mov rcx, r12
    mov edx, ebx
    lea r8, [rel dgw_ready_event]
    mov r9d, dgw_ready_event_len
    call legacy_dgw_find64
    test rax, rax
    jnz .ready
    jmp .done
.hello:
    mov rcx, r12
    mov edx, ebx
    lea r8, [rel dgw_hbi]
    mov r9d, dgw_hbi_len
    call legacy_dgw_find64
    test rax, rax
    jz .bad
    lea rcx, [rax+dgw_hbi_len]
    mov rdx, [rel dgw_json_end]
    call legacy_dgw_uint64
    jc .bad
    test eax, eax
    jz .bad
    mov [rel discord_heartbeat_ms], eax
    mov dword [rel discord_base_state], DISCORD_BASE_HELLO
    lea rsi, [rel msg_dgw_hello]
    call serial_puts64
    mov eax, [rel discord_heartbeat_ms]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    call legacy_discord_send_identify64
    test eax, eax
    jnz .bad
    call legacy_dgw_schedule_heartbeat64
    jmp .done
.ack:
    mov dword [rel dgw_awaiting_ack], 0
    mov dword [rel dgw_heartbeat_misses], 0
    inc qword [rel dgw_heartbeat_acks]
    cmp dword [rel serial_live_enabled], 1
    jne .done
    call legacy_shell_input_busy64
    test eax, eax
    jnz .done
    lea rsi, [rel msg_dgw_ack]
    call serial_puts64
    jmp .done
.heartbeat_now:
    call legacy_discord_send_heartbeat64
    test eax, eax
    jnz .bad
    jmp .done
.ready:
    mov dword [rel dgw_ready], 1
    mov dword [rel discord_base_state], DISCORD_BASE_READY
    lea rsi, [rel msg_dgw_ready]
    call serial_puts64
    jmp .done
.reconnect:
    mov dword [rel discord_base_state], DISCORD_BASE_FAILED
    lea rsi, [rel msg_dgw_reconnect]
    call serial_puts64
    jmp .done
.invalid:
    mov dword [rel discord_base_state], DISCORD_BASE_FAILED
    lea rsi, [rel msg_dgw_invalid]
    call serial_puts64
    jmp .done
.bad:
    mov dword [rel discord_base_state], DISCORD_BASE_FAILED
    lea rsi, [rel msg_dgw_bad]
    call serial_puts64
.done:
    pop r12
    pop rbx
    ret

legacy_discord_gateway_pong64:
    mov r8d, 10
    call legacy_dgw_ws_send64
    ret

; keep sending at discord's heartbeat interval even if one ack is delayed or dropped. the
; old code permanently killed the gateway on a single missed ack, which made
legacy_discord_gateway_tick64:
    cmp dword [rel discord_base_state], DISCORD_BASE_FAILED
    je .done
    cmp dword [rel dgw_identified], 1
    jne .done
    mov rax, [rel dgw_heartbeat_deadline]
    test rax, rax
    jz .done
    mov r8, rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, r8
    jb .done

    cmp dword [rel dgw_awaiting_ack], 1
    jne .send
    inc dword [rel dgw_heartbeat_misses]
    lea rsi, [rel msg_dgw_ack_late]
    call serial_puts64

.send:
    call legacy_discord_send_heartbeat64
    test eax, eax
    jz .done
    lea rsi, [rel msg_dgw_hb_send_fail]
    call serial_puts64
.done:
    ret

align 16
dgw_frame times DGW_FRAME_CAP db 0
dgw_json  times DGW_JSON_CAP db 0
dgw_num   times 16 db 0
dgw_num_len dd 0
dgw_identified dd 0
dgw_ready dd 0
dgw_seq_valid dd 0
dgw_awaiting_ack dd 0
dgw_heartbeat_misses dd 0
dgw_heartbeat_deadline dq 0
dgw_heartbeats_sent dq 0
dgw_heartbeat_acks dq 0
dgw_json_end dq 0

dgw_hb_a db '{"op":1,"d":'
dgw_hb_a_len equ $-dgw_hb_a
dgw_null db 'null'
dgw_op_key db '"op"'
dgw_op_key_len equ $-dgw_op_key
dgw_hbi db '"heartbeat_interval"'
dgw_hbi_len equ $-dgw_hbi
dgw_seq_key db '"s"'
dgw_seq_key_len equ $-dgw_seq_key
dgw_ready_event db '"t":"READY"'
dgw_ready_event_len equ $-dgw_ready_event

msg_dgw_hello      db '[DISCORD] hello heartbeat-ms=0x',0
msg_dgw_ident      db '[DISCORD] identify sent, token hidden',13,10,0
msg_dgw_ident_fail db '[DISCORD] identify transport send failed',13,10,0
msg_dgw_ready      db '[DISCORD] READY, bot online',13,10,0
msg_dgw_ack        db '[DISCORD] heartbeat ACK',13,10,0
msg_dgw_ack_late   db '[DISCORD] heartbeat ACK late/missed; keepalive continues',13,10,0
msg_dgw_hb_send_fail db '[DISCORD] heartbeat transport send failed',13,10,0
msg_dgw_ack_miss   db '[DISCORD] heartbeat ack missed, gateway stopped',13,10,0
msg_dgw_reconnect  db '[DISCORD] gateway requested reconnect',13,10,0
msg_dgw_invalid    db '[DISCORD] invalid session',13,10,0
msg_dgw_bad        db '[DISCORD] gateway message invalid',13,10,0