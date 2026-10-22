; build and verify the discord websocket upgrade this keeps the http handshake ready
; before tls is plugged in

BITS 64

%define WS_REQ_CAP 768

legacy_ws_init64:
    mov dword [rel ws_request_len], 0
    mov dword [rel ws_ready], 0
    ret

; make a fresh key and the exact accept value discord must return
legacy_ws_make_key64:
    lea rcx, [rel ws_key_raw]
    mov edx, 16
    call rng_safe_get
    test eax, eax
    jnz .fail

    lea rcx, [rel ws_key_raw]
    mov edx, 16
    lea r8, [rel ws_key_b64]
    mov r9d, 24
    call legacy_base64_encode64
    cmp eax, 24
    jne .fail
    mov byte [rel ws_key_b64+24], 0

    lea rdi, [rel ws_accept_input]
    lea rsi, [rel ws_key_b64]
    mov ecx, 24
    rep movsb
    lea rsi, [rel ws_guid]
    mov ecx, 36
    rep movsb

    lea rcx, [rel ws_accept_input]
    lea rdx, [rel ws_accept_sha1]
    call ws_sha1_60_x64

    lea rcx, [rel ws_accept_sha1]
    mov edx, 20
    lea r8, [rel ws_accept_b64]
    mov r9d, 28
    call legacy_base64_encode64
    cmp eax, 28
    jne .fail
    mov byte [rel ws_accept_b64+28], 0
    xor eax, eax
    ret
.fail:
    mov eax, 1
    ret

; rcx src, edx len, r8 dst, r9d cap, eax output bytes
legacy_base64_encode64:
    push rbx
    push rsi
    push rdi
    push r12
    mov rsi, rcx
    mov ebx, edx
    mov rdi, r8
    mov r12d, r9d
    xor r10d, r10d
.loop:
    test ebx, ebx
    jz .done
    mov eax, r10d
    add eax, 4
    cmp eax, r12d
    ja .fail

    movzx eax, byte [rsi]
    shl eax, 16
    mov r11d, 1
    cmp ebx, 1
    jbe .packed
    movzx edx, byte [rsi+1]
    shl edx, 8
    or eax, edx
    mov r11d, 2
    cmp ebx, 2
    jbe .packed
    movzx edx, byte [rsi+2]
    or eax, edx
    mov r11d, 3
.packed:
    lea rcx, [rel ws_b64_table]
    mov edx, eax
    shr edx, 18
    and edx, 63
    mov dl, [rcx+rdx]
    mov [rdi+r10], dl
    mov edx, eax
    shr edx, 12
    and edx, 63
    mov dl, [rcx+rdx]
    mov [rdi+r10+1], dl

    cmp r11d, 1
    je .pad2
    mov edx, eax
    shr edx, 6
    and edx, 63
    mov dl, [rcx+rdx]
    mov [rdi+r10+2], dl
    cmp r11d, 2
    je .pad1
    and eax, 63
    mov al, [rcx+rax]
    mov [rdi+r10+3], al
    jmp .advance
.pad2:
    mov byte [rdi+r10+2], '='
.pad1:
    mov byte [rdi+r10+3], '='
.advance:
    add rsi, r11
    sub ebx, r11d
    add r10d, 4
    jmp .loop
.done:
    mov eax, r10d
    jmp .out
.fail:
    xor eax, eax
.out:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; put one zero ended string at the end of the request
legacy_ws_append64:
    push rsi
    push rdi
    mov rsi, rcx
    mov eax, [rel ws_request_len]
    lea rdi, [rel ws_request]
    add rdi, rax
.loop:
    mov dl, [rsi]
    test dl, dl
    jz .done
    cmp eax, WS_REQ_CAP-1
    jae .fail
    mov [rdi], dl
    inc rsi
    inc rdi
    inc eax
    jmp .loop
.done:
    mov [rel ws_request_len], eax
    mov byte [rdi], 0
    xor eax, eax
    pop rdi
    pop rsi
    ret
.fail:
    mov eax, 1
    pop rdi
    pop rsi
    ret

legacy_ws_build_request64:
    mov dword [rel ws_request_len], 0
    call legacy_ws_make_key64
    test eax, eax
    jnz .fail

    lea rcx, [rel ws_req_a]
    call legacy_ws_append64
    test eax, eax
    jnz .fail
    lea rcx, [rel ws_key_b64]
    call legacy_ws_append64
    test eax, eax
    jnz .fail
    lea rcx, [rel ws_req_b]
    call legacy_ws_append64
    test eax, eax
    jnz .fail
    xor eax, eax
    ret
.fail:
    mov eax, 1
    ret

; send the upgrade through whatever authenticated tls transport installed
legacy_ws_start64:
    call legacy_ws_build_request64
    test eax, eax
    jnz .fail
    mov rax, [rel discord_transport_send]
    test rax, rax
    jz .fail
    lea rcx, [rel ws_request]
    mov edx, [rel ws_request_len]
    mov r8, [rel discord_transport_arg]
    sub rsp, 32
    call rax
    add rsp, 32
    test eax, eax
    jnz .fail
    mov dword [rel ws_ready], 1
    lea rsi, [rel msg_ws_sent]
    call serial_puts64
    xor eax, eax
    ret
.fail:
    lea rsi, [rel msg_ws_fail]
    call serial_puts64
    mov eax, 1
    ret

; rcx header bytes and edx length, eax 1 when the accept header is correct
legacy_ws_validate_accept64:
    cmp dword [rel ws_ready], 1
    jne .no
    cmp edx, 28
    jb .no
    mov rsi, rcx
    mov r10d, edx
    xor r11d, r11d
.scan:
    mov eax, r11d
    add eax, 28
    cmp eax, r10d
    ja .no
    lea rdi, [rel ws_accept_b64]
    xor ecx, ecx
.check:
    cmp ecx, 28
    jae .yes
    mov al, [rsi+r11]
    cmp al, [rdi+rcx]
    jne .next
    inc r11d
    inc ecx
    jmp .check
.next:
    sub r11d, ecx
    inc r11d
    jmp .scan
.yes:
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

align 16
ws_key_raw      times 16 db 0
ws_key_b64      times 25 db 0
ws_accept_input times 60 db 0
ws_accept_sha1  times 20 db 0
ws_accept_b64   times 29 db 0
ws_request      times WS_REQ_CAP db 0
ws_request_len  dd 0
ws_ready        dd 0

ws_b64_table db 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
ws_guid db '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
ws_req_a db 'GET /?v=10&encoding=json HTTP/1.1',13,10,'Host: gateway.discord.gg',13,10,'Upgrade: websocket',13,10,'Connection: Upgrade',13,10,'Sec-WebSocket-Version: 13',13,10,'Sec-WebSocket-Key: ',0
ws_req_b db 13,10,'User-Agent: discord-pxe/1',13,10,13,10,0
msg_ws_sent db '[WS] upgrade request sent',13,10,0
msg_ws_fail db '[ERROR] websocket upgrade request could not be sent',13,10,0

%include "ws_sha1_x64.inc"
