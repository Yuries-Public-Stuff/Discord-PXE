; discord websocket state without tying it to firmware tls only gives us encrypted
; transport and decrypted bytes

BITS 64

%define DISCORD_BASE_DOWN       0
%define DISCORD_BASE_TLS_WAIT   1
%define DISCORD_BASE_WS_HTTP    2
%define DISCORD_BASE_WS_OPEN    3
%define DISCORD_BASE_HELLO      4
%define DISCORD_BASE_IDENTIFIED 5
%define DISCORD_BASE_READY      6
%define DISCORD_BASE_FAILED     7

%define DISCORD_RX_CAP   65536
%define DISCORD_TX_CAP    4096
%define DISCORD_FRAG_CAP 65536

legacy_discord_init64:
    mov dword [rel discord_base_state], DISCORD_BASE_DOWN
    mov dword [rel discord_rx_len], 0
    mov dword [rel discord_tx_len], 0
    mov dword [rel discord_heartbeat_ms], 0
    mov dword [rel discord_sequence], 0xFFFFFFFF
    mov dword [rel discord_frame_total], 0
    mov dword [rel discord_frag_len], 0
    mov dword [rel discord_close_code], 0
    mov byte [rel discord_frag_active], 0
    mov byte [rel discord_frag_opcode], 0
    mov qword [rel discord_transport_send], 0
    mov qword [rel discord_transport_arg], 0
    call legacy_ws_init64
    call legacy_discord_gateway_init64

    mov ecx, (DISCORD_RX_CAP + 4095) / 4096
    call alloc_pages64
    test rax, rax
    jnz .rx_ok
    mov ecx, (DISCORD_RX_CAP + 4095) / 4096
    call alloc_high_pages64
.rx_ok:
    mov [rel discord_rx_buf], rax
    test rax, rax
    jz .fail

    mov ecx, (DISCORD_TX_CAP + 4095) / 4096
    call alloc_pages64
    test rax, rax
    jnz .tx_ok
    mov ecx, (DISCORD_TX_CAP + 4095) / 4096
    call alloc_high_pages64
.tx_ok:
    mov [rel discord_tx_buf], rax
    test rax, rax
    jz .fail

    mov ecx, (DISCORD_FRAG_CAP + 4095) / 4096
    call alloc_pages64
    test rax, rax
    jnz .frag_ok
    mov ecx, (DISCORD_FRAG_CAP + 4095) / 4096
    call alloc_high_pages64
.frag_ok:
    mov [rel discord_frag_buf], rax
    test rax, rax
    jz .fail

    mov dword [rel discord_base_state], DISCORD_BASE_TLS_WAIT
    lea rsi, [rel msg_discord_base_ready]
    call serial_puts64
    ret
.fail:
    mov dword [rel discord_base_state], DISCORD_BASE_FAILED
    lea rsi, [rel msg_discord_base_fail]
    call serial_puts64
    ret

; tls sets this once encrypted app writes are available
legacy_discord_set_transport64:
    mov [rel discord_transport_send], rcx
    mov [rel discord_transport_arg], rdx
    ret

; tls calls this with decrypted bytes
legacy_discord_rx64:
    test edx, edx
    jz .done
    mov eax, [rel discord_rx_len]
    mov r9d, DISCORD_RX_CAP
    sub r9d, eax
    cmp edx, r9d
    ja .overflow
    mov rdi, [rel discord_rx_buf]
    add rdi, rax
    mov rsi, rcx
    mov r10d, edx
    mov ecx, edx
    rep movsb
    add [rel discord_rx_len], r10d
    add qword [rel discord_rx_total], r10
    call legacy_discord_parse64
.done:
    ret
.overflow:
    mov dword [rel discord_base_state], DISCORD_BASE_FAILED
    inc qword [rel discord_rx_overflow]
    lea rsi, [rel msg_discord_rx_full]
    call serial_puts64
    ret

legacy_discord_parse64:
    mov eax, [rel discord_base_state]
    cmp eax, DISCORD_BASE_WS_HTTP
    je .http
    cmp eax, DISCORD_BASE_WS_OPEN
    jb .done
    call legacy_discord_ws_parse64
    ret
.http:
    call legacy_discord_http_parse64
.done:
    ret

; require http 101 and the exact accept value we calculated
legacy_discord_http_parse64:
    mov ecx, [rel discord_rx_len]
    cmp ecx, 16
    jb .done
    mov rsi, [rel discord_rx_buf]

    cmp byte [rsi+0], 'H'
    jne .bad
    cmp byte [rsi+1], 'T'
    jne .bad
    cmp byte [rsi+2], 'T'
    jne .bad
    cmp byte [rsi+3], 'P'
    jne .bad
    cmp byte [rsi+4], '/'
    jne .bad

    xor edx, edx
.status_space:
    cmp edx, ecx
    jae .done
    cmp byte [rsi+rdx], ' '
    je .status
    inc edx
    jmp .status_space
.status:
    lea eax, [rdx+4]
    cmp eax, ecx
    ja .done
    cmp byte [rsi+rdx+1], '1'
    jne .bad
    cmp byte [rsi+rdx+2], '0'
    jne .bad
    cmp byte [rsi+rdx+3], '1'
    jne .bad

    xor edx, edx
.scan:
    lea eax, [rdx+4]
    cmp eax, ecx
    ja .done
    cmp byte [rsi+rdx+0], 13
    jne .next
    cmp byte [rsi+rdx+1], 10
    jne .next
    cmp byte [rsi+rdx+2], 13
    jne .next
    cmp byte [rsi+rdx+3], 10
    jne .next

    lea r9d, [rdx+4]
    mov rcx, [rel discord_rx_buf]
    mov edx, r9d
    call legacy_ws_validate_accept64
    test eax, eax
    jz .accept_bad

    mov eax, r9d
    call legacy_discord_consume_bytes64
    mov dword [rel discord_base_state], DISCORD_BASE_WS_OPEN
    lea rsi, [rel msg_discord_ws_open]
    call serial_puts64
    cmp dword [rel discord_rx_len], 0
    je .done
    call legacy_discord_ws_parse64
    ret
.next:
    inc edx
    jmp .scan
.accept_bad:
    lea rsi, [rel msg_discord_accept_bad]
    call serial_puts64
.bad:
    mov dword [rel discord_base_state], DISCORD_BASE_FAILED
    lea rsi, [rel msg_discord_http_bad]
    call serial_puts64
.done:
    ret

; server frames are never masked, client frames always are
legacy_discord_ws_parse64:
.loop:
    mov ecx, [rel discord_rx_len]
    cmp ecx, 2
    jb .done
    mov rsi, [rel discord_rx_buf]

    mov al, [rsi]
    mov [rel discord_frame_fin], al
    and byte [rel discord_frame_fin], 0x80
    mov al, [rsi]
    and al, 0x0F
    mov [rel discord_last_opcode], al

    movzx eax, byte [rsi+1]
    test eax, 0x80
    jnz .bad
    and eax, 0x7F
    cmp eax, 126
    je .len16
    cmp eax, 127
    je .len64
    mov edx, eax
    mov r8d, 2
    jmp .have_len
.len16:
    cmp ecx, 4
    jb .done
    movzx edx, byte [rsi+2]
    shl edx, 8
    movzx eax, byte [rsi+3]
    or edx, eax
    mov r8d, 4
    jmp .have_len
.len64:
    cmp ecx, 10
    jb .done
    cmp dword [rsi+2], 0
    jne .too_big
    movzx edx, byte [rsi+6]
    shl edx, 24
    movzx eax, byte [rsi+7]
    shl eax, 16
    or edx, eax
    movzx eax, byte [rsi+8]
    shl eax, 8
    or edx, eax
    movzx eax, byte [rsi+9]
    or edx, eax
    mov r8d, 10
.have_len:
    mov eax, r8d
    add eax, edx
    cmp eax, DISCORD_RX_CAP
    ja .too_big
    cmp ecx, eax
    jb .done
    mov [rel discord_frame_total], eax
    mov [rel discord_frame_payload], edx
    mov [rel discord_frame_header], r8d

    movzx eax, byte [rel discord_last_opcode]
    cmp eax, 8
    jae .control
    cmp eax, 1
    je .text
    cmp eax, 0
    je .continue
    jmp .bad
.control:
    cmp byte [rel discord_frame_fin], 0
    je .bad
    cmp edx, 125
    ja .bad
    cmp eax, 8
    je .close
    cmp eax, 9
    je .ping
    cmp eax, 10
    je .consume
    jmp .bad
.text:
    cmp byte [rel discord_frag_active], 0
    jne .bad
    cmp byte [rel discord_frame_fin], 0
    jne .text_whole
    mov byte [rel discord_frag_active], 1
    mov byte [rel discord_frag_opcode], 1
    mov dword [rel discord_frag_len], 0
    call legacy_discord_append_fragment64
    test eax, eax
    jnz .too_big
    jmp .consume
.text_whole:
    inc qword [rel discord_text_frames]
    mov r11d, [rel discord_frame_header]
    mov r10d, [rel discord_frame_payload]
    lea rcx, [rsi+r11]
    mov edx, r10d
    call legacy_discord_gateway_text64
    jmp .consume
.continue:
    cmp byte [rel discord_frag_active], 1
    jne .bad
    call legacy_discord_append_fragment64
    test eax, eax
    jnz .too_big
    cmp byte [rel discord_frame_fin], 0
    je .consume
    cmp byte [rel discord_frag_opcode], 1
    jne .bad
    inc qword [rel discord_text_frames]
    mov rcx, [rel discord_frag_buf]
    mov edx, [rel discord_frag_len]
    call legacy_discord_gateway_text64
    mov byte [rel discord_frag_active], 0
    mov byte [rel discord_frag_opcode], 0
    mov dword [rel discord_frag_len], 0
    jmp .consume
.ping:
    inc qword [rel discord_ping_frames]
    mov r11d, [rel discord_frame_header]
    mov r10d, [rel discord_frame_payload]
    lea rcx, [rsi+r11]
    mov edx, r10d
    call legacy_discord_gateway_pong64
    test eax, eax
    jnz .bad
    jmp .consume
.close:
   ; preserve the exact discord gateway close code. this is the difference between a bad
   ; token, malformed identify, bad intents, and reconnects.
    xor eax, eax
    mov r10d, [rel discord_frame_payload]
    cmp r10d, 2
    jb .close_code_ready
    mov r11d, [rel discord_frame_header]
    movzx eax, byte [rsi+r11]
    shl eax, 8
    movzx ecx, byte [rsi+r11+1]
    or eax, ecx
.close_code_ready:
    mov [rel discord_close_code], eax
    mov dword [rel discord_base_state], DISCORD_BASE_FAILED
    lea rsi, [rel msg_discord_close_code]
    call serial_puts64
    mov eax, [rel discord_close_code]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64

    mov eax, [rel discord_close_code]
    cmp eax, 4002
    je .close_decode
    cmp eax, 4003
    je .close_not_auth
    cmp eax, 4004
    je .close_auth
    cmp eax, 4005
    je .close_already
    cmp eax, 4010
    je .close_shard
    cmp eax, 4011
    je .close_sharding
    cmp eax, 4012
    je .close_version
    cmp eax, 4013
    je .close_intents
    cmp eax, 4014
    je .close_disallowed
    lea rsi, [rel msg_discord_close]
    call serial_puts64
    jmp .consume
.close_decode:
    lea rsi, [rel msg_discord_close_decode]
    call serial_puts64
    jmp .consume
.close_not_auth:
    lea rsi, [rel msg_discord_close_not_auth]
    call serial_puts64
    jmp .consume
.close_auth:
    lea rsi, [rel msg_discord_close_auth]
    call serial_puts64
    jmp .consume
.close_already:
    lea rsi, [rel msg_discord_close_already]
    call serial_puts64
    jmp .consume
.close_shard:
    lea rsi, [rel msg_discord_close_shard]
    call serial_puts64
    jmp .consume
.close_sharding:
    lea rsi, [rel msg_discord_close_sharding]
    call serial_puts64
    jmp .consume
.close_version:
    lea rsi, [rel msg_discord_close_version]
    call serial_puts64
    jmp .consume
.close_intents:
    lea rsi, [rel msg_discord_close_intents]
    call serial_puts64
    jmp .consume
.close_disallowed:
    lea rsi, [rel msg_discord_close_disallowed]
    call serial_puts64
.consume:
    mov eax, [rel discord_frame_total]
    call legacy_discord_consume_bytes64
    cmp dword [rel discord_rx_len], 0
    je .done
    cmp dword [rel discord_base_state], DISCORD_BASE_FAILED
    je .done
    jmp .loop
.too_big:
    mov dword [rel discord_base_state], DISCORD_BASE_FAILED
    lea rsi, [rel msg_discord_frame_big]
    call serial_puts64
    ret
.bad:
    mov dword [rel discord_base_state], DISCORD_BASE_FAILED
    lea rsi, [rel msg_discord_frame_bad]
    call serial_puts64
.done:
    ret

; append this frame payload to the current fragmented message
legacy_discord_append_fragment64:
    mov eax, [rel discord_frag_len]
    mov edx, [rel discord_frame_payload]
    mov r9d, DISCORD_FRAG_CAP
    sub r9d, eax
    cmp edx, r9d
    ja .bad
    mov rdi, [rel discord_frag_buf]
    add rdi, rax
    mov rsi, [rel discord_rx_buf]
    mov ecx, [rel discord_frame_header]
    add rsi, rcx
    mov ecx, edx
    rep movsb
    add [rel discord_frag_len], edx
    xor eax, eax
    ret
.bad:
    mov eax, 1
    ret

; eax bytes are removed from the front of the shared receive buffer
legacy_discord_consume_bytes64:
    mov edx, [rel discord_rx_len]
    cmp eax, edx
    jae .empty
    sub edx, eax
    mov rsi, [rel discord_rx_buf]
    add rsi, rax
    mov rdi, [rel discord_rx_buf]
    mov ecx, edx
    rep movsb
    mov [rel discord_rx_len], edx
    ret
.empty:
    mov dword [rel discord_rx_len], 0
    ret

; tls calls this after its handshake is authenticated
legacy_discord_tls_ready64:
    cmp dword [rel legacy_config_ready], 1
    jne .config_missing
    mov dword [rel discord_base_state], DISCORD_BASE_WS_HTTP
    lea rsi, [rel msg_discord_tls_ready]
    call serial_puts64
    call legacy_ws_start64
    test eax, eax
    jnz .fail
    ret
.config_missing:
    lea rsi, [rel msg_discord_no_config]
    call serial_puts64
.fail:
    mov dword [rel discord_base_state], DISCORD_BASE_FAILED
    ret

legacy_discord_tick64:
    jmp legacy_discord_gateway_tick64

align 16
discord_base_state    dd 0
discord_heartbeat_ms  dd 0
discord_sequence      dd 0
discord_rx_len        dd 0
discord_tx_len        dd 0
discord_frame_total   dd 0
discord_frame_payload dd 0
discord_frame_header  dd 0
discord_frag_len      dd 0
discord_close_code    dd 0
discord_last_opcode   db 0
discord_frame_fin     db 0
discord_frag_active   db 0
discord_frag_opcode   db 0
align 8
discord_rx_buf         dq 0
discord_tx_buf         dq 0
discord_frag_buf       dq 0
discord_transport_send dq 0
discord_transport_arg  dq 0
discord_rx_total       dq 0
discord_rx_overflow    dq 0
discord_text_frames    dq 0
discord_ping_frames    dq 0

msg_discord_base_ready       db '[DISCORD] runtime base ready, waiting on tls',13,10,0
msg_discord_base_fail        db '[ERROR] discord buffers could not be allocated',13,10,0
msg_discord_tls_ready        db '[DISCORD] authenticated tls ready, starting websocket',13,10,0
msg_discord_ws_open          db '[DISCORD] http 101 + websocket accept verified',13,10,0
msg_discord_rx_full          db '[ERROR] discord receive buffer full',13,10,0
msg_discord_close_code       db '[DISCORD] websocket close code=0x',0
msg_discord_close            db '[DISCORD] websocket close received',13,10,0
msg_discord_close_decode     db '[DISCORD] close 4002: gateway could not decode Identify payload',13,10,0
msg_discord_close_not_auth   db '[DISCORD] close 4003: gateway says client was not authenticated',13,10,0
msg_discord_close_auth       db '[DISCORD] close 4004: authentication failed - check bot token',13,10,0
msg_discord_close_already    db '[DISCORD] close 4005: connection was already authenticated',13,10,0
msg_discord_close_shard      db '[DISCORD] close 4010: invalid shard',13,10,0
msg_discord_close_sharding   db '[DISCORD] close 4011: sharding required',13,10,0
msg_discord_close_version    db '[DISCORD] close 4012: invalid gateway version',13,10,0
msg_discord_close_intents    db '[DISCORD] close 4013: invalid intents',13,10,0
msg_discord_close_disallowed db '[DISCORD] close 4014: disallowed intents',13,10,0
msg_discord_http_bad         db '[ERROR] discord websocket upgrade was not valid http 101',13,10,0
msg_discord_accept_bad       db '[ERROR] websocket accept value did not match',13,10,0
msg_discord_frame_big        db '[ERROR] discord websocket frame too large',13,10,0
msg_discord_frame_bad        db '[ERROR] discord websocket frame invalid',13,10,0
msg_discord_no_config        db '[ERROR] discord config is not ready',13,10,0
