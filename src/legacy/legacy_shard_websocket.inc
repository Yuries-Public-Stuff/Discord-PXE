; per-shard websocket handshake workspace one 4 kib page is allocated lazily for each
; shard that actually starts.

BITS 64

%define SHARD_WS_READY          0
%define SHARD_WS_REQUEST_LEN    4
%define SHARD_WS_KEY_RAW        8
%define SHARD_WS_KEY_B64       24
%define SHARD_WS_ACCEPT_INPUT  56
%define SHARD_WS_ACCEPT_SHA1  120
%define SHARD_WS_ACCEPT_B64   144
%define SHARD_WS_REQUEST      176
%define SHARD_WS_REQUEST_CAP  768

; rcx=shard ctx, rax=workspace or zero.
legacy_shard_ws_alloc64:
    push rbx
    mov rbx, rcx
    test rbx, rbx
    jz .bad
    mov rax, [rbx + SHARD_OFF_WS_CTX]
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
    mov [rbx + SHARD_OFF_WS_CTX], rax

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

; rcx=shard ctx, eax=0 success.
legacy_shard_ws_build_request64:
    push rbx
    push r12
    mov rbx, rcx
    call legacy_shard_ws_alloc64
    test rax, rax
    jz .bad
    mov r12, rax
    mov dword [r12 + SHARD_WS_READY], 0
    mov dword [r12 + SHARD_WS_REQUEST_LEN], 0

    lea rcx, [r12 + SHARD_WS_KEY_RAW]
    mov edx, 16
    call rng_safe_get
    test eax, eax
    jnz .bad

    lea rcx, [r12 + SHARD_WS_KEY_RAW]
    mov edx, 16
    lea r8, [r12 + SHARD_WS_KEY_B64]
    mov r9d, 24
    call legacy_base64_encode64
    cmp eax, 24
    jne .bad
    mov byte [r12 + SHARD_WS_KEY_B64 + 24], 0

    lea rdi, [r12 + SHARD_WS_ACCEPT_INPUT]
    lea rsi, [r12 + SHARD_WS_KEY_B64]
    mov ecx, 24
    rep movsb
    lea rsi, [rel ws_guid]
    mov ecx, 36
    rep movsb

    lea rcx, [r12 + SHARD_WS_ACCEPT_INPUT]
    lea rdx, [r12 + SHARD_WS_ACCEPT_SHA1]
    call ws_sha1_60_x64

    lea rcx, [r12 + SHARD_WS_ACCEPT_SHA1]
    mov edx, 20
    lea r8, [r12 + SHARD_WS_ACCEPT_B64]
    mov r9d, 28
    call legacy_base64_encode64
    cmp eax, 28
    jne .bad
    mov byte [r12 + SHARD_WS_ACCEPT_B64 + 28], 0

    mov rdi, r12
    lea rcx, [rel ws_req_a]
    call legacy_shard_ws_append64
    test eax, eax
    jnz .bad
    mov rdi, r12
    lea rcx, [r12 + SHARD_WS_KEY_B64]
    call legacy_shard_ws_append64
    test eax, eax
    jnz .bad
    mov rdi, r12
    lea rcx, [rel ws_req_b]
    call legacy_shard_ws_append64
    test eax, eax
    jnz .bad

    mov dword [r12 + SHARD_WS_READY], 1
    xor eax, eax
    jmp .out
.bad:
    mov eax, 1
.out:
    pop r12
    pop rbx
    ret

; rdi=workspace, rcx=z-string
legacy_shard_ws_append64:
    push rsi
    push rbx
    mov rsi, rcx
    mov ebx, [rdi + SHARD_WS_REQUEST_LEN]
.loop:
    mov al, [rsi]
    test al, al
    jz .ok
    cmp ebx, SHARD_WS_REQUEST_CAP-1
    jae .bad
    mov [rdi + SHARD_WS_REQUEST + rbx], al
    inc rsi
    inc ebx
    jmp .loop
.ok:
    mov [rdi + SHARD_WS_REQUEST_LEN], ebx
    mov byte [rdi + SHARD_WS_REQUEST + rbx], 0
    xor eax, eax
    jmp .out
.bad:
    mov eax, 1
.out:
    pop rbx
    pop rsi
    ret

; rcx=shard ctx, rdx=http header bytes, r8d=len eax=1 if this shard's exact
; sec-websocket-accept is present.
legacy_shard_ws_validate_accept64:
    push rbx
    push r12
    push r13
    mov rbx, rcx
    mov r12, rdx
    mov r13d, r8d
    test rbx, rbx
    jz .no
    mov rbx, [rbx + SHARD_OFF_WS_CTX]
    test rbx, rbx
    jz .no
    cmp dword [rbx + SHARD_WS_READY], 1
    jne .no
    cmp r13d, 28
    jb .no

    xor r9d, r9d
.scan:
    mov eax, r9d
    add eax, 28
    cmp eax, r13d
    ja .no
    xor ecx, ecx
.check:
    cmp ecx, 28
    jae .yes
    mov al, [r12+r9]
    cmp al, [rbx + SHARD_WS_ACCEPT_B64 + rcx]
    jne .next
    inc r9d
    inc ecx
    jmp .check
.next:
    sub r9d, ecx
    inc r9d
    jmp .scan
.yes:
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx, rax=request ptr, edx=request len.
legacy_shard_ws_request64:
    push rbx
    mov rbx, rcx
    test rbx, rbx
    jz .bad
    mov rbx, [rbx + SHARD_OFF_WS_CTX]
    test rbx, rbx
    jz .bad
    cmp dword [rbx + SHARD_WS_READY], 1
    jne .bad
    lea rax, [rbx + SHARD_WS_REQUEST]
    mov edx, [rbx + SHARD_WS_REQUEST_LEN]
    pop rbx
    ret
.bad:
    xor eax, eax
    xor edx, edx
    pop rbx
    ret
