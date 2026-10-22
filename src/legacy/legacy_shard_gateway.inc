; per-shard discord gateway helpers this file is context-based from day one.
; it does not access the singleton dgw_* / discord_*

BITS 64

%define SHARD_IDENTIFY_CAP 1024

; builds one gateway v10 identify payload.
; returns bytes in eax or 0xffffffff on failure
legacy_shard_build_identify64:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r15, rcx
    mov rdi, rdx
    mov r12d, r8d
    xor r13d, r13d

    test r15, r15
    jz .bad
    test rdi, rdi
    jz .bad
    cmp r12d, 32
    jb .bad
    cmp dword [rel legacy_config_ready], 1
    jne .bad

%ifdef LEGACY_HAVE_LOCAL_SECRETS
  ; keep the secret-bearing/static json byte-for-byte identical to the
  ; powershell-validated build artifact. only shard numbers are rendered here.
    lea rcx, [rel legacy_embedded_shard_ident_prefix]
    mov edx, legacy_embedded_shard_ident_prefix_len
    call legacy_shard_ident_append_bytes64
    test eax, eax
    jnz .bad
%else
    lea rcx, [rel shard_ident_a]
    call legacy_shard_ident_append_z64
    test eax, eax
    jnz .bad

    lea rcx, [rel legacy_token]
    mov edx, [rel legacy_token_len]
    call legacy_shard_ident_append_bytes64
    test eax, eax
    jnz .bad

    lea rcx, [rel shard_ident_b]
    call legacy_shard_ident_append_z64
    test eax, eax
    jnz .bad
%endif

    mov eax, [r15 + SHARD_OFF_ID]
    call legacy_shard_ident_append_u32_64
    test eax, eax
    jnz .bad

    lea rcx, [rel shard_ident_comma]
    call legacy_shard_ident_append_z64
    test eax, eax
    jnz .bad

    mov eax, [r15 + SHARD_OFF_TOTAL]
    call legacy_shard_ident_append_u32_64
    test eax, eax
    jnz .bad

%ifdef LEGACY_HAVE_LOCAL_SECRETS
    lea rcx, [rel legacy_embedded_shard_ident_suffix]
    mov edx, legacy_embedded_shard_ident_suffix_len
    call legacy_shard_ident_append_bytes64
    test eax, eax
    jnz .bad
%else
    lea rcx, [rel shard_ident_c]
    call legacy_shard_ident_append_z64
    test eax, eax
    jnz .bad
%endif

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

; implicit builder registers: rdi=dst, r12d=cap, r13d=len rcx=z-string, eax=0
; success / 1 fail
legacy_shard_ident_append_z64:
    push rsi
    mov rsi, rcx
.loop:
    mov al, [rsi]
    test al, al
    jz .ok
    cmp r13d, r12d
    jae .fail
    mov [rdi+r13], al
    inc r13d
    inc rsi
    jmp .loop
.ok:
    xor eax, eax
    pop rsi
    ret
.fail:
    mov eax, 1
    pop rsi
    ret

; rcx=bytes, edx=len
legacy_shard_ident_append_bytes64:
    push rsi
    mov rsi, rcx
    mov r14d, edx
    mov eax, r13d
    add eax, r14d
    jc .fail
    cmp eax, r12d
    ja .fail
.loop:
    test r14d, r14d
    jz .ok
    mov al, [rsi]
    mov [rdi+r13], al
    inc rsi
    inc r13d
    dec r14d
    jmp .loop
.ok:
    xor eax, eax
    pop rsi
    ret
.fail:
    mov eax, 1
    pop rsi
    ret

; eax=value
legacy_shard_ident_append_u32_64:
    push rbx
    push rcx
    push rdx
    push rsi
    lea rsi, [rel shard_ident_num + 15]
    mov byte [rsi], 0
    xor ecx, ecx
    mov ebx, eax
    test ebx, ebx
    jnz .digits
    dec rsi
    mov byte [rsi], '0'
    mov ecx, 1
    jmp .copy
.digits:
    mov eax, ebx
.more:
    xor edx, edx
    mov ebx, 10
    div ebx
    add dl, '0'
    dec rsi
    mov [rsi], dl
    inc ecx
    test eax, eax
    jnz .more
.copy:
    mov eax, r13d
    add eax, ecx
    jc .fail
    cmp eax, r12d
    ja .fail
.copy_loop:
    test ecx, ecx
    jz .ok
    mov al, [rsi]
    mov [rdi+r13], al
    inc rsi
    inc r13d
    dec ecx
    jmp .copy_loop
.ok:
    xor eax, eax
    jmp .out
.fail:
    mov eax, 1
.out:
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; rcx=ctx, edx=heartbeat interval ms.
legacy_shard_gateway_set_hello64:
    test rcx, rcx
    jz .bad
    test edx, edx
    jz .bad
    mov [rcx + SHARD_OFF_HEARTBEAT_MS], edx
    mov dword [rcx + SHARD_OFF_STATE], SHARD_STATE_STARTING
    mov dword [rcx + SHARD_OFF_HEARTBEAT_MISSES], 0
    xor eax, eax
    ret
.bad:
    mov eax, 1
    ret

; rcx=ctx, edx=new discord sequence.
legacy_shard_gateway_set_sequence64:
    test rcx, rcx
    jz .bad
    mov [rcx + SHARD_OFF_SEQUENCE], edx
    or dword [rcx + SHARD_OFF_FLAGS], SHARD_FLAG_SEQ_VALID
    xor eax, eax
    ret
.bad:
    mov eax, 1
    ret

; rcx=ctx. discord permits the first heartbeat at a jittered point inside the
; advertised interval. spread shard heartbeats deterministically so 128
legacy_shard_gateway_schedule_first_heartbeat64:
    push rbx
    mov rbx, rcx
    test rbx, rbx
    jz .bad
    mov eax, [rbx + SHARD_OFF_HEARTBEAT_MS]
    test eax, eax
    jz .bad

    mov r9d, eax
    mov eax, [rbx + SHARD_OFF_ID]
    xor edx, edx
    mov ecx, 20
    div ecx
    inc edx                         ; factor 1..20
    mov eax, r9d
    imul eax, edx
    xor edx, edx
    mov ecx, 20
    div ecx
    test eax, eax
    jnz .have_ms
    mov eax, 1
.have_ms:
    mov r8, [rel tsc_cycles_per_ms]
    test r8, r8
    jz .bad
    imul rax, r8
    mov r9, rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    add rax, r9
    mov [rbx + SHARD_OFF_HEARTBEAT_DEADLINE], rax
    xor eax, eax
    pop rbx
    ret
.bad:
    mov eax, 1
    pop rbx
    ret

; rcx=ctx. schedules the next heartbeat from tsc.
legacy_shard_gateway_schedule_heartbeat64:
    test rcx, rcx
    jz .bad
    mov eax, [rcx + SHARD_OFF_HEARTBEAT_MS]
    test eax, eax
    jz .bad
    mov r8, [rel tsc_cycles_per_ms]
    test r8, r8
    jz .bad
    imul rax, r8
    mov r9, rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    add rax, r9
    mov [rcx + SHARD_OFF_HEARTBEAT_DEADLINE], rax
    xor eax, eax
    ret
.bad:
    mov eax, 1
    ret

; rcx=ctx, eax=1 if heartbeat is due.
legacy_shard_gateway_heartbeat_due64:
    test rcx, rcx
    jz .no
    mov r8, [rcx + SHARD_OFF_HEARTBEAT_DEADLINE]
    test r8, r8
    jz .no
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, r8
    jb .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; rcx=ctx
legacy_shard_gateway_note_heartbeat64:
    test rcx, rcx
    jz .bad
    inc qword [rcx + SHARD_OFF_HEARTBEATS_SENT]
    or dword [rcx + SHARD_OFF_FLAGS], SHARD_FLAG_AWAITING_ACK
    call legacy_shard_gateway_schedule_heartbeat64
    ret
.bad:
    mov eax, 1
    ret

; rcx=ctx
legacy_shard_gateway_note_ack64:
    test rcx, rcx
    jz .bad
    inc qword [rcx + SHARD_OFF_HEARTBEAT_ACKS]
    and dword [rcx + SHARD_OFF_FLAGS], ~SHARD_FLAG_AWAITING_ACK
    mov dword [rcx + SHARD_OFF_HEARTBEAT_MISSES], 0
    xor eax, eax
    ret
.bad:
    mov eax, 1
    ret

; rcx=ctx
legacy_shard_gateway_mark_ready64:
    test rcx, rcx
    jz .bad
    mov dword [rcx + SHARD_OFF_STATE], SHARD_STATE_READY
    or dword [rcx + SHARD_OFF_FLAGS], SHARD_FLAG_READY
    inc qword [rcx + SHARD_OFF_SESSION_GEN]
    xor eax, eax
    ret
.bad:
    mov eax, 1
    ret

align 16
shard_ident_num times 16 db 0
shard_ident_a db '{"op":2,"d":{"token":"',0
shard_ident_b db '","properties":{"os":"legacy","browser":"discord-pxe-sharded","device":"discord-pxe"},"intents":0,"shard":[',0
shard_ident_comma db ',',0
shard_ident_c db ']}}',0

%include "legacy_bot_events.inc"
%include "legacy_shard_websocket.inc"
%include "legacy_shard_transport.inc"
%include "legacy_shard_tcp.inc"
%include "legacy_shard_tcp_reliable.inc"
%include "legacy_shard_tls.inc"
%include "legacy_shard_discord.inc"
%include "legacy_shard_lifecycle.inc"
