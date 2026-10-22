; direct tls stream fixes and diagnostics no generated/python patching belongs in this
; path

BITS 64

%include "legacy_tls_keyflight_fix.inc"

%define TLS_PATCH_TRACE_LIMIT 16

legacy_tls_patch_init64:
    mov dword [rel tls_patch_rx_trace_count], 0
    mov dword [rel tls_patch_record_trace_count], 0
    mov dword [rel tls_patch_wait_trace_once], 0
    lea rcx, [rel legacy_tls_tcp_rx_patched64]
    xor edx, edx
    call legacy_tcp_set_rx64
    ret

; tcp callback: preserve the chunk length in r12 instead of caller-saved temps
legacy_tls_tcp_rx_patched64:
    push rbx
    push r12
    mov r12d, edx
    test r12d, r12d
    jz .done

    mov eax, [rel legacy_tls_wire_len]
    mov r9d, LEGACY_TLS_WIRE_CAP
    sub r9d, eax
    cmp r12d, r9d
    ja .bad

    lea rdi, [rel legacy_tls_wire]
    add rdi, rax
    mov rsi, rcx
    mov ecx, r12d
    rep movsb
    add [rel legacy_tls_wire_len], r12d
    add qword [rel legacy_tls_rx_bytes], r12

    cmp dword [rel tls_patch_rx_trace_count], TLS_PATCH_TRACE_LIMIT
    jae .parse
    inc dword [rel tls_patch_rx_trace_count]
    lea rsi, [rel msg_tlsrx_chunk]
    call serial_puts64
    mov eax, r12d
    call serial_hex32_64
    lea rsi, [rel msg_tlsrx_wire]
    call serial_puts64
    mov eax, [rel legacy_tls_wire_len]
    call serial_hex32_64
    lea rsi, [rel msg_tlsrx_hs]
    call serial_puts64
    mov eax, [rel legacy_tls_hs_len]
    call serial_hex32_64
    lea rsi, [rel msg_tlsrx_state]
    call serial_puts64
    mov eax, [rel legacy_tls_state]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64

.parse:
    call legacy_tls_parse_records_patched64
    jmp .done
.bad:
    call legacy_tls_fail64
.done:
    pop r12
    pop rbx
    ret

; parse complete records only. r12 keeps payload length and r13 keeps total length
legacy_tls_parse_records_patched64:
    push rbx
    push r12
    push r13
.loop:
    mov ecx, [rel legacy_tls_wire_len]
    cmp ecx, 5
    jb .done
    lea rsi, [rel legacy_tls_wire]

    movzx r12d, byte [rsi+3]
    shl r12d, 8
    movzx eax, byte [rsi+4]
    or r12d, eax
    cmp r12d, LEGACY_TLS_RECORD_CAP-5
    ja .bad

    mov r13d, r12d
    add r13d, 5
    cmp ecx, r13d
    jb .done

    cmp byte [rsi+1], 3
    jne .bad
    cmp byte [rsi+2], 3
    je .dispatch
    cmp byte [rsi+2], 1
    jne .bad

.dispatch:
    cmp dword [rel tls_patch_record_trace_count], TLS_PATCH_TRACE_LIMIT
    jae .call
    inc dword [rel tls_patch_record_trace_count]
    lea rsi, [rel msg_tlsrec_type]
    call serial_puts64
    lea rbx, [rel legacy_tls_wire]
    movzx eax, byte [rbx]
    call serial_hex32_64
    lea rsi, [rel msg_tlsrec_len]
    call serial_puts64
    mov eax, r12d
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64

.call:
    lea rbx, [rel legacy_tls_wire]
    movzx ecx, byte [rbx]
    lea rdx, [rbx+5]
    mov r8d, r12d
    call legacy_tls_record_patched64
    test eax, eax
    jnz .bad

    mov eax, r13d
    call legacy_tls_shift_wire64
    cmp dword [rel legacy_tls_state], LEGACY_TLS_FAILED
    jne .loop
    jmp .done
.bad:
    call legacy_tls_fail64
.done:
    pop r13
    pop r12
    pop rbx
    ret

; ecx type, rdx payload, r8d payload len keep lengths in nonvolatile registers across
; every helper call
legacy_tls_record_patched64:
    push rbx
    push r12
    push r13
    mov ebx, ecx
    mov r12, rdx
    mov r13d, r8d

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
    cmp r13d, ecx
    ja .fail
    lea rdi, [rel legacy_tls_hs]
    add rdi, rax
    mov rsi, r12
    mov ecx, r13d
    rep movsb
    add [rel legacy_tls_hs_len], r13d
    call legacy_tls_process_hs_patched64
    cmp dword [rel legacy_tls_state], LEGACY_TLS_FAILED
    je .fail
    xor eax, eax
    jmp .out

.ccs:
    cmp r13d, 1
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
    mov r8d, r13d
    call legacy_tls_decrypt_record64
    test rax, rax
    jz .fail
    mov r12, rax
    mov r13d, edx
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
    mov edx, r13d
    call legacy_tls_verify_server_finished_patched64
    jmp .out

.app:
    cmp dword [rel legacy_tls_state], LEGACY_TLS_UP
    jne .fail
    mov rcx, r12
    mov edx, r13d
    xor r8d, r8d
    call legacy_discord_rx64
    xor eax, eax
    jmp .out

.fail:
    mov eax, LEGACY_STATUS_DEVICE
.out:
    pop r13
    pop r12
    pop rbx
    ret

; process complete handshake messages while safely retaining partial ones
legacy_tls_process_hs_patched64:
    push rbx
    push r12
.loop:
    mov eax, [rel legacy_tls_hs_len]
    cmp eax, 4
    jb .done

    lea r12, [rel legacy_tls_hs]
    movzx ebx, byte [r12+1]
    shl ebx, 16
    movzx eax, byte [r12+2]
    shl eax, 8
    or ebx, eax
    movzx eax, byte [r12+3]
    or ebx, eax
    add ebx, 4

    cmp ebx, [rel legacy_tls_hs_len]
    jbe .complete

    cmp dword [rel tls_patch_wait_trace_once], 0
    jne .done
    mov dword [rel tls_patch_wait_trace_once], 1
    lea rsi, [rel msg_tlshs_wait_type]
    call serial_puts64
    movzx eax, byte [r12]
    call serial_hex32_64
    lea rsi, [rel msg_tlshs_have]
    call serial_puts64
    mov eax, [rel legacy_tls_hs_len]
    call serial_hex32_64
    lea rsi, [rel msg_tlshs_need]
    call serial_puts64
    mov eax, ebx
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    jmp .done

.complete:
    mov dword [rel tls_patch_wait_trace_once], 0

   ; transcript helper uses rsi/rdi, so never depend on them after this call
    mov rcx, r12
    mov edx, ebx
    call legacy_tls_transcript_add64
    test eax, eax
    jnz .fail

    movzx eax, byte [r12]
    lea rcx, [r12+4]
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
    call legacy_tls_keys_and_finish_patched64
    test eax, eax
    jnz .fail

.consume:
    mov eax, ebx
    call legacy_tls_shift_hs64
    jmp .loop

.fail:
    call legacy_tls_fail64
.done:
    pop r12
    pop rbx
    ret

; same finished verification as the base implementation, but discord owns websocket start
legacy_tls_verify_server_finished_patched64:
    push rbx
    push r12
    mov r12, rcx
    mov ebx, edx
    cmp ebx, 16
    jne .bad
    cmp byte [r12], 20
    jne .bad
    cmp byte [r12+1], 0
    jne .bad
    cmp byte [r12+2], 0
    jne .bad
    cmp byte [r12+3], 12
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

    lea rcx, [r12+4]
    lea rdx, [rel legacy_tls_verify]
    mov r8d, 12
    call mem_equal_x64
    test eax, eax
    jz .bad

    mov rcx, r12
    mov edx, 16
    call legacy_tls_transcript_add64
    test eax, eax
    jnz .bad

    mov dword [rel legacy_tls_state], LEGACY_TLS_UP
    lea rcx, [rel legacy_tls_send_app64]
    xor edx, edx
    call legacy_discord_set_transport64
    call legacy_discord_tls_ready64
    cmp dword [rel discord_base_state], DISCORD_BASE_FAILED
    je .bad
    lea rsi, [rel msg_tls_up]
    call serial_puts64
    xor eax, eax
    jmp .out
.bad:
    call legacy_tls_fail64
.out:
    pop r12
    pop rbx
    ret

align 8
tls_patch_rx_trace_count     dd 0
tls_patch_record_trace_count dd 0
tls_patch_wait_trace_once    dd 0

msg_tlsrx_chunk      db '[TLSRX] chunk=0x',0
msg_tlsrx_wire       db ' wire=0x',0
msg_tlsrx_hs         db ' hs=0x',0
msg_tlsrx_state      db ' state=0x',0
msg_tlsrec_type      db '[TLSREC] type=0x',0
msg_tlsrec_len       db ' len=0x',0
msg_tlshs_wait_type  db '[TLSHS] waiting type=0x',0
msg_tlshs_have       db ' have=0x',0
msg_tlshs_need       db ' need=0x',0
