; authenticated tls 1.2 over the legacy tcp client keeps the old proven c02f path but
; talks to our pxe network stack

BITS 64

%define LEGACY_TLS_IDLE          0
%define LEGACY_TLS_HELLO_SENT    1
%define LEGACY_TLS_SERVER_FLIGHT 2
%define LEGACY_TLS_WAIT_FINISH   3
%define LEGACY_TLS_UP            4
%define LEGACY_TLS_FAILED        5

%define LEGACY_TLS_WIRE_CAP      32768
%define LEGACY_TLS_HS_CAP        32768
%define LEGACY_TLS_TRANSCRIPT_CAP 65536
%define LEGACY_TLS_RECORD_CAP    17408
%define LEGACY_TLS_PLAIN_CAP     16384
%define LEGACY_TLS_SEND_MAX      1100

legacy_tls_init64:
    mov dword [rel legacy_tls_state], LEGACY_TLS_IDLE
    mov dword [rel legacy_tls_wire_len], 0
    mov dword [rel legacy_tls_hs_len], 0
    mov dword [rel legacy_tls_transcript_len], 0
    mov dword [rel legacy_tls_write_on], 0
    mov dword [rel legacy_tls_read_on], 0
    mov dword [rel legacy_tls_wseq_hi], 0
    mov dword [rel legacy_tls_wseq_lo], 0
    mov dword [rel legacy_tls_rseq_hi], 0
    mov dword [rel legacy_tls_rseq_lo], 0
    mov dword [rel legacy_tls_ems], 0
    mov dword [rel legacy_tls_server_sig_len], 0
    mov dword [rel legacy_tls_server_ec_len], 0

    call legacy_x509_init64
    call legacy_ws_init64
    lea rcx, [rel legacy_tls_tcp_rx64]
    xor edx, edx
    call legacy_tcp_set_rx64
    lea rsi, [rel msg_tls_ready]
    call serial_puts64
    ret

legacy_tls_fail64:
    cmp dword [rel legacy_tls_state], LEGACY_TLS_FAILED
    je .done
    mov dword [rel legacy_tls_state], LEGACY_TLS_FAILED
    lea rsi, [rel msg_tls_fail]
    call serial_puts64
.done:
    mov eax, LEGACY_STATUS_DEVICE
    ret

legacy_tls_tick64:
    cmp dword [rel legacy_tls_state], LEGACY_TLS_FAILED
    je .done
    cmp dword [rel legacy_tls_state], LEGACY_TLS_UP
    je .done
    cmp dword [rel legacy_config_ready], 1
    jne .done
    cmp dword [rel legacy_tcp_state], LEGACY_TCP_UP
    je .tcp_up
    cmp dword [rel legacy_tcp_state], LEGACY_TCP_FAILED
    jne .done
    call legacy_tls_fail64
    ret
.tcp_up:
    cmp dword [rel legacy_tls_state], LEGACY_TLS_IDLE
    jne .done
    call legacy_tls_send_hello64
.done:
    ret

; tcp gives us bytes in any size so keep them until a whole tls record exists
legacy_tls_tcp_rx64:
    test edx, edx
    jz .done
    mov eax, [rel legacy_tls_wire_len]
    mov r9d, LEGACY_TLS_WIRE_CAP
    sub r9d, eax
    cmp edx, r9d
    ja .bad
    lea rdi, [rel legacy_tls_wire]
    add rdi, rax
    mov rsi, rcx
    mov r10d, edx
    mov ecx, edx
    rep movsb
    add [rel legacy_tls_wire_len], r10d
    add qword [rel legacy_tls_rx_bytes], r10
    call legacy_tls_parse_records64
.done:
    ret
.bad:
    call legacy_tls_fail64
    ret

legacy_tls_shift_wire64:
    mov edx, [rel legacy_tls_wire_len]
    cmp eax, edx
    jae .empty
    sub edx, eax
    lea rsi, [rel legacy_tls_wire]
    add rsi, rax
    lea rdi, [rel legacy_tls_wire]
    mov ecx, edx
    rep movsb
    mov [rel legacy_tls_wire_len], edx
    ret
.empty:
    mov dword [rel legacy_tls_wire_len], 0
    ret

legacy_tls_shift_hs64:
    mov edx, [rel legacy_tls_hs_len]
    cmp eax, edx
    jae .empty
    sub edx, eax
    lea rsi, [rel legacy_tls_hs]
    add rsi, rax
    lea rdi, [rel legacy_tls_hs]
    mov ecx, edx
    rep movsb
    mov [rel legacy_tls_hs_len], edx
    ret
.empty:
    mov dword [rel legacy_tls_hs_len], 0
    ret

; rcx data, edx len
legacy_tls_transcript_add64:
    mov eax, [rel legacy_tls_transcript_len]
    mov r9d, LEGACY_TLS_TRANSCRIPT_CAP
    sub r9d, eax
    cmp edx, r9d
    ja .bad
    lea rdi, [rel legacy_tls_transcript]
    add rdi, rax
    mov rsi, rcx
    mov r10d, edx
    mov ecx, edx
    rep movsb
    add [rel legacy_tls_transcript_len], r10d
    xor eax, eax
    ret
.bad:
    mov eax, LEGACY_STATUS_NO_MEMORY
    ret

legacy_tls_parse_records64:
.loop:
    mov ecx, [rel legacy_tls_wire_len]
    cmp ecx, 5
    jb .done
    lea rsi, [rel legacy_tls_wire]
    movzx eax, byte [rsi+3]
    shl eax, 8
    movzx edx, byte [rsi+4]
    or eax, edx
    cmp eax, LEGACY_TLS_RECORD_CAP-5
    ja .bad
    mov r10d, eax
    add eax, 5
    cmp ecx, eax
    jb .done

    movzx ebx, byte [rsi]
    cmp byte [rsi+1], 3
    jne .bad
    cmp byte [rsi+2], 3
    je .dispatch
    cmp byte [rsi+2], 1
    jne .bad
.dispatch:
    lea rdx, [rsi+5]
    mov ecx, ebx
    mov r8d, r10d
    call legacy_tls_record64
    test eax, eax
    jnz .bad
    mov eax, r10d
    add eax, 5
    call legacy_tls_shift_wire64
    jmp .loop
.bad:
    call legacy_tls_fail64
.done:
    ret

; ecx type, rdx payload, r8d payload len
legacy_tls_record64:
    push rbx
    push r12
    mov ebx, ecx
    mov r12, rdx
    mov r10d, r8d

    cmp dword [rel legacy_tls_read_on], 1
    je .encrypted
    cmp ebx, 22
    je .handshake
    cmp ebx, 20
    je .ccs
    cmp ebx, 21
    je .alert
    xor eax, eax
    jmp .out
.handshake:
    mov eax, [rel legacy_tls_hs_len]
    mov ecx, LEGACY_TLS_HS_CAP
    sub ecx, eax
    cmp r10d, ecx
    ja .fail
    lea rdi, [rel legacy_tls_hs]
    add rdi, rax
    mov rsi, r12
    mov ecx, r10d
    rep movsb
    add [rel legacy_tls_hs_len], r10d
    call legacy_tls_process_hs64
    xor eax, eax
    jmp .out
.ccs:
    cmp r10d, 1
    jne .fail
    cmp byte [r12], 1
    jne .fail
    mov dword [rel legacy_tls_read_on], 1
    mov dword [rel legacy_tls_rseq_hi], 0
    mov dword [rel legacy_tls_rseq_lo], 0
    xor eax, eax
    jmp .out
.alert:
    lea rsi, [rel msg_tls_alert]
    call serial_puts64
    jmp .fail
.encrypted:
    mov ecx, ebx
    mov rdx, r12
    mov r8d, r10d
    call legacy_tls_decrypt_record64
    test rax, rax
    jz .fail
    mov r12, rax
    mov r10d, edx
    cmp ebx, 22
    je .encrypted_hs
    cmp ebx, 23
    je .app
    cmp ebx, 21
    je .fail
    xor eax, eax
    jmp .out
.encrypted_hs:
    cmp dword [rel legacy_tls_state], LEGACY_TLS_WAIT_FINISH
    jne .fail
    mov rcx, r12
    mov edx, r10d
    call legacy_tls_verify_server_finished64
    jmp .out
.app:
    cmp dword [rel legacy_tls_state], LEGACY_TLS_UP
    jne .fail
    mov rcx, r12
    mov edx, r10d
    xor r8d, r8d
    call legacy_discord_rx64
    xor eax, eax
    jmp .out
.fail:
    mov eax, LEGACY_STATUS_DEVICE
.out:
    pop r12
    pop rbx
    ret

legacy_tls_process_hs64:
.loop:
    mov eax, [rel legacy_tls_hs_len]
    cmp eax, 4
    jb .done
    lea rsi, [rel legacy_tls_hs]
    movzx ebx, byte [rsi+1]
    shl ebx, 16
    movzx eax, byte [rsi+2]
    shl eax, 8
    or ebx, eax
    movzx eax, byte [rsi+3]
    or ebx, eax
    add ebx, 4
    cmp ebx, [rel legacy_tls_hs_len]
    ja .done

    mov rcx, rsi
    mov edx, ebx
    call legacy_tls_transcript_add64
    test eax, eax
    jnz .fail

    movzx eax, byte [rsi]
    lea rcx, [rsi+4]
    mov edx, ebx
    sub edx, 4
    cmp eax, 2
    je .server_hello
    cmp eax, 11
    je .certificate
    cmp eax, 12
    je .server_kex
    cmp eax, 14
    je .server_done
    jmp .consume
.server_hello:
    call legacy_tls_server_hello64
    test eax, eax
    jnz .fail
    jmp .consume
.certificate:
    call legacy_x509_load_leaf64
    test eax, eax
    jnz .fail
    jmp .consume
.server_kex:
    call legacy_tls_server_kex64
    test eax, eax
    jnz .fail
    jmp .consume
.server_done:
    call legacy_tls_auth_kex64
    test eax, eax
    jnz .fail
    call legacy_tls_keys_and_finish64
    test eax, eax
    jnz .fail
.consume:
    mov eax, ebx
    call legacy_tls_shift_hs64
    jmp .loop
.fail:
    call legacy_tls_fail64
.done:
    ret

; server must select tls1.2 and ecdhe-rsa-aes128-gcm-sha256
legacy_tls_server_hello64:
    push rbx
    mov rsi, rcx
    mov ebx, edx
    cmp ebx, 38
    jb .bad
    cmp byte [rsi], 3
    jne .bad
    cmp byte [rsi+1], 3
    jne .bad
    lea rdi, [rel legacy_tls_server_random]
    lea rsi, [rsi+2]
    mov ecx, 32
    rep movsb
    sub rsi, 34
    movzx eax, byte [rsi+34]
    mov r10d, 35
    add r10d, eax
    add r10d, 3
    cmp r10d, ebx
    ja .bad
    lea r11, [rsi+35]
    add r11, rax
    cmp byte [r11], 0xC0
    jne .bad
    cmp byte [r11+1], 0x2F
    jne .bad
    cmp byte [r11+2], 0
    jne .bad

    mov dword [rel legacy_tls_ems], 0
    lea r10, [r11+3]
    lea r11, [rsi+rbx]
    cmp r10, r11
    je .ok
    lea rax, [r10+2]
    cmp rax, r11
    ja .bad
    movzx ecx, byte [r10]
    shl ecx, 8
    mov cl, [r10+1]
    add r10, 2
    lea rax, [r10+rcx]
    cmp rax, r11
    ja .bad
    mov r11, rax
.ext:
    cmp r10, r11
    jae .ok
    lea rax, [r10+4]
    cmp rax, r11
    ja .bad
    movzx eax, byte [r10]
    shl eax, 8
    mov al, [r10+1]
    movzx edx, byte [r10+2]
    shl edx, 8
    mov dl, [r10+3]
    lea r9, [r10+4]
    add r9, rdx
    cmp r9, r11
    ja .bad
    cmp eax, 0x17
    jne .next
    test edx, edx
    jnz .bad
    mov dword [rel legacy_tls_ems], 1
.next:
    mov r10, r9
    jmp .ext
.ok:
    mov dword [rel legacy_tls_state], LEGACY_TLS_SERVER_FLIGHT
    lea rsi, [rel msg_tls_server_hello]
    call serial_puts64
    xor eax, eax
    pop rbx
    ret
.bad:
    mov eax, LEGACY_STATUS_UNSUPPORTED
    pop rbx
    ret

; save x25519 params and the rsa signature for later authentication
legacy_tls_server_kex64:
    push rbx
    mov rsi, rcx
    mov ebx, edx
    cmp ebx, 40
    jb .bad
    cmp byte [rsi], 3
    jne .bad
    cmp byte [rsi+1], 0
    jne .bad
    cmp byte [rsi+2], 0x1D
    jne .bad
    cmp byte [rsi+3], 32
    jne .bad
    lea rdi, [rel legacy_tls_server_ec]
    lea rsi, [rsi+4]
    mov ecx, 32
    rep movsb
    mov dword [rel legacy_tls_server_ec_len], 32
    sub rsi, 36
    lea rdi, [rel legacy_tls_kex_params]
    mov ecx, 36
    rep movsb
    mov dword [rel legacy_tls_kex_params_len], 36
    sub rsi, 36
    cmp byte [rsi+36], 4
    jne .bad
    cmp byte [rsi+37], 1
    jne .bad
    movzx eax, byte [rsi+38]
    shl eax, 8
    mov al, [rsi+39]
    cmp eax, RSA_MAX_BYTES
    ja .bad
    mov r10d, eax
    add eax, 40
    cmp eax, ebx
    ja .bad
    mov [rel legacy_tls_server_sig_len], r10d
    lea rdi, [rel legacy_tls_server_sig]
    lea rsi, [rsi+40]
    mov ecx, r10d
    rep movsb
    lea rsi, [rel msg_tls_kex]
    call serial_puts64
    xor eax, eax
    pop rbx
    ret
.bad:
    mov eax, LEGACY_STATUS_UNSUPPORTED
    pop rbx
    ret

legacy_tls_auth_kex64:
    cmp dword [rel legacy_leaf_key_ready], 1
    jne .bad
    cmp dword [rel legacy_tls_server_ec_len], 32
    jne .bad
    cmp dword [rel legacy_tls_server_sig_len], 0
    je .bad

    lea rcx, [rel legacy_tls_signed]
    lea rdx, [rel legacy_tls_client_random]
    mov r8d, 32
    call mem_copy_x64
    lea rcx, [rel legacy_tls_signed+32]
    lea rdx, [rel legacy_tls_server_random]
    mov r8d, 32
    call mem_copy_x64
    lea rcx, [rel legacy_tls_signed+64]
    lea rdx, [rel legacy_tls_kex_params]
    mov r8d, [rel legacy_tls_kex_params_len]
    call mem_copy_x64

    lea rcx, [rel legacy_tls_signed]
    mov edx, [rel legacy_tls_kex_params_len]
    add edx, 64
    lea r8, [rel legacy_tls_auth_hash]
    call sha256_hash3_x64
    lea rcx, [rel legacy_tls_server_sig]
    mov edx, [rel legacy_tls_server_sig_len]
    lea r8, [rel legacy_tls_auth_hash]
    call rsa_verify_pkcs1_sha256_x64
    test eax, eax
    jnz .bad
    lea rsi, [rel msg_tls_auth]
    call serial_puts64
    xor eax, eax
    ret
.bad:
    mov eax, LEGACY_STATUS_DEVICE
    ret

; rcx out, edx high, r8d low
legacy_tls_store_seq64:
    mov eax, edx
    bswap eax
    mov [rcx], eax
    mov eax, r8d
    bswap eax
    mov [rcx+4], eax
    ret

legacy_tls_inc_wseq64:
    inc dword [rel legacy_tls_wseq_lo]
    jnz .done
    inc dword [rel legacy_tls_wseq_hi]
.done:
    ret

legacy_tls_inc_rseq64:
    inc dword [rel legacy_tls_rseq_lo]
    jnz .done
    inc dword [rel legacy_tls_rseq_hi]
.done:
    ret

; ecx type, rdx data, r8d len
legacy_tls_plain_record64:
    cmp r8d, LEGACY_TLS_SEND_MAX
    ja .bad
    mov r11d, ecx
    lea r10, [rel legacy_tls_record]
    mov [r10], r11b
    mov byte [r10+1], 3
    mov byte [r10+2], 3
    mov eax, r8d
    xchg al, ah
    mov [r10+3], ax
    lea rdi, [r10+5]
    mov rsi, rdx
    mov ecx, r8d
    rep movsb
    lea rcx, [rel legacy_tls_record]
    mov edx, r8d
    add edx, 5
    call legacy_tcp_send64
    ret
.bad:
    mov eax, LEGACY_STATUS_BUFFER
    ret

; ecx type and edx plain length
legacy_tls_write_meta64:
    push rbx
    mov ebx, ecx
    mov r10d, edx
    lea rcx, [rel legacy_tls_aad]
    mov edx, [rel legacy_tls_wseq_hi]
    mov r8d, [rel legacy_tls_wseq_lo]
    call legacy_tls_store_seq64
    mov [rel legacy_tls_aad+8], bl
    mov byte [rel legacy_tls_aad+9], 3
    mov byte [rel legacy_tls_aad+10], 3
    mov eax, r10d
    xchg al, ah
    mov [rel legacy_tls_aad+11], ax
    mov eax, [rel legacy_tls_client_iv]
    mov [rel legacy_tls_nonce], eax
    lea rcx, [rel legacy_tls_nonce+4]
    mov edx, [rel legacy_tls_wseq_hi]
    mov r8d, [rel legacy_tls_wseq_lo]
    call legacy_tls_store_seq64
    pop rbx
    ret

; ecx type, edx plain length and r8 explicit nonce bytes
legacy_tls_read_meta64:
    push rbx
    mov ebx, ecx
    mov r10d, edx
    mov r11, r8
    lea rcx, [rel legacy_tls_aad]
    mov edx, [rel legacy_tls_rseq_hi]
    mov r8d, [rel legacy_tls_rseq_lo]
    call legacy_tls_store_seq64
    mov [rel legacy_tls_aad+8], bl
    mov byte [rel legacy_tls_aad+9], 3
    mov byte [rel legacy_tls_aad+10], 3
    mov eax, r10d
    xchg al, ah
    mov [rel legacy_tls_aad+11], ax
    mov eax, [rel legacy_tls_server_iv]
    mov [rel legacy_tls_nonce], eax
    lea rdi, [rel legacy_tls_nonce+4]
    mov rsi, r11
    mov ecx, 8
    rep movsb
    pop rbx
    ret

; ecx type, rdx plaintext, r8d len
legacy_tls_encrypted_record64:
    push rbx
    push r12
    push r13
    mov ebx, ecx
    mov r12, rdx
    mov r13d, r8d
    cmp dword [rel legacy_tls_write_on], 1
    jne .not_ready
    cmp r13d, LEGACY_TLS_SEND_MAX
    ja .bad

    mov ecx, ebx
    mov edx, r13d
    call legacy_tls_write_meta64
    lea rcx, [rel legacy_tls_client_key]
    lea rdx, [rel legacy_tls_nonce]
    lea r8, [rel legacy_tls_aad]
    mov r9d, 13
    sub rsp, 64
    mov [rsp+32], r12
    mov [rsp+40], r13
    lea rax, [rel legacy_tls_cipher]
    mov [rsp+48], rax
    lea rax, [rel legacy_tls_tag]
    mov [rsp+56], rax
    call aes2_gcm_encrypt
    add rsp, 64
    test eax, eax
    jnz .out

    lea r10, [rel legacy_tls_record]
    mov [r10], bl
    mov byte [r10+1], 3
    mov byte [r10+2], 3
    mov eax, r13d
    add eax, 24
    xchg al, ah
    mov [r10+3], ax
    lea rcx, [r10+5]
    mov edx, [rel legacy_tls_wseq_hi]
    mov r8d, [rel legacy_tls_wseq_lo]
    call legacy_tls_store_seq64
    lea rdi, [r10+13]
    lea rsi, [rel legacy_tls_cipher]
    mov ecx, r13d
    rep movsb
    lea rsi, [rel legacy_tls_tag]
    mov ecx, 16
    rep movsb
    lea rcx, [rel legacy_tls_record]
    mov edx, r13d
    add edx, 29
    call legacy_tcp_send64
    test eax, eax
    jnz .out
    call legacy_tls_inc_wseq64
    add qword [rel legacy_tls_tx_bytes], r13
.out:
    pop r13
    pop r12
    pop rbx
    ret
.not_ready:
    mov eax, LEGACY_STATUS_NOT_READY
    jmp .out
.bad:
    mov eax, LEGACY_STATUS_BUFFER
    jmp .out

; ecx type, rdx encrypted payload, r8d payload length rax plaintext pointer or zero, edx
; plaintext length
legacy_tls_decrypt_record64:
    push rbx
    push r12
    push r13
    mov ebx, ecx
    mov r12, rdx
    mov r13d, r8d
    cmp r13d, 24
    jb .bad
    sub r13d, 24
    cmp r13d, LEGACY_TLS_PLAIN_CAP
    ja .bad
    mov ecx, ebx
    mov edx, r13d
    mov r8, r12
    call legacy_tls_read_meta64
    lea rcx, [rel legacy_tls_server_key]
    lea rdx, [rel legacy_tls_nonce]
    lea r8, [rel legacy_tls_aad]
    mov r9d, 13
    sub rsp, 64
    lea rax, [r12+8]
    mov [rsp+32], rax
    mov [rsp+40], r13
    lea rax, [r12+8+r13]
    mov [rsp+48], rax
    lea rax, [rel legacy_tls_plain]
    mov [rsp+56], rax
    call aes2_gcm_decrypt
    add rsp, 64
    test eax, eax
    jnz .bad
    call legacy_tls_inc_rseq64
    lea rax, [rel legacy_tls_plain]
    mov edx, r13d
    pop r13
    pop r12
    pop rbx
    ret
.bad:
    xor eax, eax
    xor edx, edx
    pop r13
    pop r12
    pop rbx
    ret

legacy_tls_send_hello64:
    cmp dword [rel rng_ready], 1
    jne .bad
    lea rcx, [rel legacy_tls_client_random]
    mov edx, 32
    call rng_safe_get
    test eax, eax
    jnz .bad

    lea r10, [rel legacy_tls_hello]
    mov byte [r10], 22
    mov byte [r10+1], 3
    mov byte [r10+2], 1
    mov word [r10+3], 0
    mov byte [r10+5], 1
    mov byte [r10+6], 0
    mov byte [r10+7], 0
    mov byte [r10+8], 0
    lea r8, [r10+9]
    mov byte [r8], 3
    mov byte [r8+1], 3
    add r8, 2
    lea r9, [rel legacy_tls_client_random]
    mov ecx, 32
.random:
    mov al, [r9]
    mov [r8], al
    inc r9
    inc r8
    dec ecx
    jnz .random

    mov byte [r8], 0
    inc r8
    mov byte [r8], 0
    mov byte [r8+1], 2
    mov byte [r8+2], 0xC0
    mov byte [r8+3], 0x2F
    add r8, 4
    mov byte [r8], 1
    mov byte [r8+1], 0
    add r8, 2

    mov r11, r8
    add r8, 2
    mov r9, r8

   ; sni keeps discord on the right certificate
    mov byte [r8], 0
    mov byte [r8+1], 0
    mov byte [r8+2], 0
    mov byte [r8+3], tls_host_len+5
    mov byte [r8+4], 0
    mov byte [r8+5], tls_host_len+3
    mov byte [r8+6], 0
    mov byte [r8+7], 0
    mov byte [r8+8], tls_host_len
    add r8, 9
    lea rdx, [rel tls_host]
    mov ecx, tls_host_len
.sni:
    mov al, [rdx]
    mov [r8], al
    inc rdx
    inc r8
    dec ecx
    jnz .sni

   ; only x25519 so the parser has one key exchange path
    mov byte [r8], 0
    mov byte [r8+1], 0x0A
    mov byte [r8+2], 0
    mov byte [r8+3], 4
    mov byte [r8+4], 0
    mov byte [r8+5], 2
    mov byte [r8+6], 0
    mov byte [r8+7], 0x1D
    add r8, 8

    mov byte [r8], 0
    mov byte [r8+1], 0x0B
    mov byte [r8+2], 0
    mov byte [r8+3], 2
    mov byte [r8+4], 1
    mov byte [r8+5], 0
    add r8, 6

   ; only rsa sha256 for the signed server key exchange
    mov byte [r8], 0
    mov byte [r8+1], 0x0D
    mov byte [r8+2], 0
    mov byte [r8+3], 4
    mov byte [r8+4], 0
    mov byte [r8+5], 2
    mov byte [r8+6], 4
    mov byte [r8+7], 1
    add r8, 8

   ; request extended master secret and safe renegotiation
    mov byte [r8], 0
    mov byte [r8+1], 0x17
    mov word [r8+2], 0
    add r8, 4
    mov byte [r8], 0xFF
    mov byte [r8+1], 1
    mov byte [r8+2], 0
    mov byte [r8+3], 1
    mov byte [r8+4], 0
    add r8, 5

    mov rax, r8
    sub rax, r9
    mov edx, eax
    mov [r11+1], dl
    shr edx, 8
    mov [r11], dl

    mov rax, r8
    lea rdx, [r10+9]
    sub rax, rdx
    mov edx, eax
    mov [r10+8], dl
    shr edx, 8
    mov [r10+7], dl
    shr edx, 8
    mov [r10+6], dl

    mov rax, r8
    lea rdx, [r10+5]
    sub rax, rdx
    mov edx, eax
    mov [r10+4], dl
    shr edx, 8
    mov [r10+3], dl

    mov rax, r8
    sub rax, r10
    mov [rel legacy_tls_hello_len], eax
    lea rcx, [r10+5]
    mov edx, eax
    sub edx, 5
    call legacy_tls_transcript_add64
    test eax, eax
    jnz .bad
    lea rcx, [rel legacy_tls_hello]
    mov edx, [rel legacy_tls_hello_len]
    call legacy_tcp_send64
    test eax, eax
    jnz .bad
    mov dword [rel legacy_tls_state], LEGACY_TLS_HELLO_SENT
    lea rsi, [rel msg_tls_hello]
    call serial_puts64
    xor eax, eax
    ret
.bad:
    call legacy_tls_fail64
    ret

legacy_tls_keys_and_finish64:
    lea rcx, [rel legacy_tls_private]
    mov edx, 32
    call rng_safe_get
    test eax, eax
    jnz .bad
    lea rcx, [rel legacy_tls_public]
    lea rdx, [rel legacy_tls_private]
    call x25519_public_from_private_x64
    lea rcx, [rel legacy_tls_shared]
    lea rdx, [rel legacy_tls_private]
    lea r8, [rel legacy_tls_server_ec]
    call x25519_x64
    lea rcx, [rel legacy_tls_shared]
    call x25519_bytes_all_zero_x64
    test eax, eax
    jnz .bad

   ; client key exchange joins the transcript before keys are calculated
    lea r10, [rel legacy_tls_kex_msg]
    mov byte [r10], 16
    mov byte [r10+1], 0
    mov byte [r10+2], 0
    mov byte [r10+3], 33
    mov byte [r10+4], 32
    lea rcx, [r10+5]
    lea rdx, [rel legacy_tls_public]
    mov r8d, 32
    call mem_copy_x64
    lea rcx, [rel legacy_tls_kex_msg]
    mov edx, 37
    call legacy_tls_transcript_add64
    test eax, eax
    jnz .bad
    mov ecx, 22
    lea rdx, [rel legacy_tls_kex_msg]
    mov r8d, 37
    call legacy_tls_plain_record64
    test eax, eax
    jnz .bad

    cmp dword [rel legacy_tls_ems], 1
    jne .classic
    lea rcx, [rel legacy_tls_transcript]
    mov edx, [rel legacy_tls_transcript_len]
    lea r8, [rel legacy_tls_hash]
    call sha256_hash3_x64
    lea rcx, [rel legacy_tls_shared]
    mov edx, 32
    lea r8, [rel label_ext_master]
    mov r9d, label_ext_master_len
    sub rsp, 72
    lea rax, [rel legacy_tls_hash]
    mov [rsp+32], rax
    mov qword [rsp+40], 32
    lea rax, [rel legacy_tls_master]
    mov [rsp+48], rax
    mov qword [rsp+56], 48
    call tls12_prf2_sha256_x64
    add rsp, 72
    test eax, eax
    jnz .bad
    jmp .keyblock
.classic:
    lea rcx, [rel legacy_tls_seed]
    lea rdx, [rel legacy_tls_client_random]
    mov r8d, 32
    call mem_copy_x64
    lea rcx, [rel legacy_tls_seed+32]
    lea rdx, [rel legacy_tls_server_random]
    mov r8d, 32
    call mem_copy_x64
    lea rcx, [rel legacy_tls_shared]
    mov edx, 32
    lea r8, [rel label_master]
    mov r9d, label_master_len
    sub rsp, 72
    lea rax, [rel legacy_tls_seed]
    mov [rsp+32], rax
    mov qword [rsp+40], 64
    lea rax, [rel legacy_tls_master]
    mov [rsp+48], rax
    mov qword [rsp+56], 48
    call tls12_prf2_sha256_x64
    add rsp, 72
    test eax, eax
    jnz .bad
.keyblock:
    lea rcx, [rel legacy_tls_seed]
    lea rdx, [rel legacy_tls_server_random]
    mov r8d, 32
    call mem_copy_x64
    lea rcx, [rel legacy_tls_seed+32]
    lea rdx, [rel legacy_tls_client_random]
    mov r8d, 32
    call mem_copy_x64
    lea rcx, [rel legacy_tls_master]
    mov edx, 48
    lea r8, [rel label_keys]
    mov r9d, label_keys_len
    sub rsp, 72
    lea rax, [rel legacy_tls_seed]
    mov [rsp+32], rax
    mov qword [rsp+40], 64
    lea rax, [rel legacy_tls_keyblock]
    mov [rsp+48], rax
    mov qword [rsp+56], 40
    call tls12_prf2_sha256_x64
    add rsp, 72
    test eax, eax
    jnz .bad

    lea rcx, [rel legacy_tls_client_key]
    lea rdx, [rel legacy_tls_keyblock]
    mov r8d, 16
    call mem_copy_x64
    lea rcx, [rel legacy_tls_server_key]
    lea rdx, [rel legacy_tls_keyblock+16]
    mov r8d, 16
    call mem_copy_x64
    mov eax, [rel legacy_tls_keyblock+32]
    mov [rel legacy_tls_client_iv], eax
    mov eax, [rel legacy_tls_keyblock+36]
    mov [rel legacy_tls_server_iv], eax

    mov byte [rel legacy_tls_plain], 1
    mov ecx, 20
    lea rdx, [rel legacy_tls_plain]
    mov r8d, 1
    call legacy_tls_plain_record64
    test eax, eax
    jnz .bad
    mov dword [rel legacy_tls_wseq_hi], 0
    mov dword [rel legacy_tls_wseq_lo], 0
    mov dword [rel legacy_tls_write_on], 1

    lea rcx, [rel legacy_tls_transcript]
    mov edx, [rel legacy_tls_transcript_len]
    lea r8, [rel legacy_tls_hash]
    call sha256_hash3_x64
    lea rcx, [rel legacy_tls_master]
    mov edx, 48
    lea r8, [rel label_client_finished]
    mov r9d, label_client_finished_len
    sub rsp, 72
    lea rax, [rel legacy_tls_hash]
    mov [rsp+32], rax
    mov qword [rsp+40], 32
    lea rax, [rel legacy_tls_verify]
    mov [rsp+48], rax
    mov qword [rsp+56], 12
    call tls12_prf2_sha256_x64
    add rsp, 72
    test eax, eax
    jnz .bad

    lea r10, [rel legacy_tls_finished]
    mov byte [r10], 20
    mov byte [r10+1], 0
    mov byte [r10+2], 0
    mov byte [r10+3], 12
    lea rcx, [r10+4]
    lea rdx, [rel legacy_tls_verify]
    mov r8d, 12
    call mem_copy_x64
    lea rcx, [rel legacy_tls_finished]
    mov edx, 16
    call legacy_tls_transcript_add64
    test eax, eax
    jnz .bad
    mov ecx, 22
    lea rdx, [rel legacy_tls_finished]
    mov r8d, 16
    call legacy_tls_encrypted_record64
    test eax, eax
    jnz .bad
    mov dword [rel legacy_tls_state], LEGACY_TLS_WAIT_FINISH
    lea rsi, [rel msg_tls_finish_sent]
    call serial_puts64
    xor eax, eax
    ret
.bad:
    call legacy_tls_fail64
    ret

legacy_tls_verify_server_finished64:
    push rbx
    mov rsi, rcx
    mov ebx, edx
    cmp ebx, 16
    jne .bad
    cmp byte [rsi], 20
    jne .bad
    cmp byte [rsi+1], 0
    jne .bad
    cmp byte [rsi+2], 0
    jne .bad
    cmp byte [rsi+3], 12
    jne .bad
    lea rcx, [rel legacy_tls_transcript]
    mov edx, [rel legacy_tls_transcript_len]
    lea r8, [rel legacy_tls_hash]
    call sha256_hash3_x64
    lea rcx, [rel legacy_tls_master]
    mov edx, 48
    lea r8, [rel label_server_finished]
    mov r9d, label_server_finished_len
    sub rsp, 72
    lea rax, [rel legacy_tls_hash]
    mov [rsp+32], rax
    mov qword [rsp+40], 32
    lea rax, [rel legacy_tls_verify]
    mov [rsp+48], rax
    mov qword [rsp+56], 12
    call tls12_prf2_sha256_x64
    add rsp, 72
    test eax, eax
    jnz .bad
    lea rcx, [rsi+4]
    lea rdx, [rel legacy_tls_verify]
    mov r8d, 12
    call mem_equal_x64
    test eax, eax
    jz .bad
    mov rcx, rsi
    mov edx, 16
    call legacy_tls_transcript_add64
    test eax, eax
    jnz .bad

    mov dword [rel legacy_tls_state], LEGACY_TLS_UP
    lea rcx, [rel legacy_tls_send_app64]
    xor edx, edx
    call legacy_discord_set_transport64
    call legacy_discord_tls_ready64
    call legacy_ws_start64
    test eax, eax
    jnz .bad
    lea rsi, [rel msg_tls_up]
    call serial_puts64
    xor eax, eax
    pop rbx
    ret
.bad:
    call legacy_tls_fail64
    pop rbx
    ret

; rcx bytes, edx len, r8 ignored
legacy_tls_send_app64:
    cmp dword [rel legacy_tls_state], LEGACY_TLS_UP
    jne .not_ready
    mov r8d, edx
    mov rdx, rcx
    mov ecx, 23
    call legacy_tls_encrypted_record64
    ret
.not_ready:
    mov eax, LEGACY_STATUS_NOT_READY
    ret

align 16
legacy_tls_wire       times LEGACY_TLS_WIRE_CAP db 0
legacy_tls_hs         times LEGACY_TLS_HS_CAP db 0
legacy_tls_transcript times LEGACY_TLS_TRANSCRIPT_CAP db 0
legacy_tls_record     times LEGACY_TLS_RECORD_CAP db 0
legacy_tls_plain      times LEGACY_TLS_PLAIN_CAP db 0
legacy_tls_cipher     times LEGACY_TLS_PLAIN_CAP db 0
legacy_tls_hello      times 512 db 0
legacy_tls_client_random times 32 db 0
legacy_tls_server_random times 32 db 0
legacy_tls_server_ec  times 32 db 0
legacy_tls_kex_params times 64 db 0
legacy_tls_server_sig times RSA_MAX_BYTES db 0
legacy_tls_auth_hash  times 32 db 0
legacy_tls_signed     times 160 db 0
legacy_tls_private    times 32 db 0
legacy_tls_public     times 32 db 0
legacy_tls_shared     times 32 db 0
legacy_tls_master     times 48 db 0
legacy_tls_keyblock   times 40 db 0
legacy_tls_client_key times 16 db 0
legacy_tls_server_key times 16 db 0
legacy_tls_client_iv  times 4 db 0
legacy_tls_server_iv  times 4 db 0
legacy_tls_seed       times 64 db 0
legacy_tls_hash       times 32 db 0
legacy_tls_verify     times 12 db 0
legacy_tls_finished   times 16 db 0
legacy_tls_kex_msg    times 37 db 0
legacy_tls_tag        times 16 db 0
legacy_tls_nonce      times 12 db 0
legacy_tls_aad        times 13 db 0

legacy_tls_state             dd 0
legacy_tls_wire_len          dd 0
legacy_tls_hs_len            dd 0
legacy_tls_transcript_len    dd 0
legacy_tls_hello_len         dd 0
legacy_tls_ems               dd 0
legacy_tls_server_ec_len     dd 0
legacy_tls_kex_params_len    dd 0
legacy_tls_server_sig_len    dd 0
legacy_tls_write_on          dd 0
legacy_tls_read_on           dd 0
legacy_tls_wseq_hi           dd 0
legacy_tls_wseq_lo           dd 0
legacy_tls_rseq_hi           dd 0
legacy_tls_rseq_lo           dd 0
legacy_tls_rx_bytes          dq 0
legacy_tls_tx_bytes          dq 0

tls_host db 'gateway.discord.gg'
tls_host_len equ $-tls_host
label_ext_master db 'extended master secret'
label_ext_master_len equ $-label_ext_master
label_master db 'master secret'
label_master_len equ $-label_master
label_keys db 'key expansion'
label_keys_len equ $-label_keys
label_client_finished db 'client finished'
label_client_finished_len equ $-label_client_finished
label_server_finished db 'server finished'
label_server_finished_len equ $-label_server_finished

msg_tls_ready       db '[TLS] tls1.2 runtime ready',13,10,0
msg_tls_hello       db '[TLS] client hello sent',13,10,0
msg_tls_server_hello db '[TLS] server chose tls1.2 c02f',13,10,0
msg_tls_kex         db '[TLS] signed x25519 server key received',13,10,0
msg_tls_auth        db '[TLS] pinned certificate + rsa signature verified',13,10,0
msg_tls_finish_sent db '[TLS] client keys + finished sent',13,10,0
msg_tls_up          db '[TLS] authenticated tls established',13,10,0
msg_tls_alert       db '[TLS] peer sent an alert',13,10,0
msg_tls_fail        db '[TLS] failed closed, shell and network stay alive',13,10,0
