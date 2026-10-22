; stop cleanly when discord asks for a reconnect or rejects the session automatic
; reconnect stays off so a bad connection cannot loop forever

BITS 64

legacy_discord_gateway_text64:
    push rbx
    push r12
    mov r12, rcx
    mov ebx, edx

    mov rcx, r12
    mov edx, ebx
    lea r8, [rel dgw_op7]
    mov r9d, dgw_op7_len
    call legacy_dgw_find64
    test rax, rax
    jnz .reconnect

    mov rcx, r12
    mov edx, ebx
    lea r8, [rel dgw_op9]
    mov r9d, dgw_op9_len
    call legacy_dgw_find64
    test rax, rax
    jnz .invalid

    mov rcx, r12
    mov edx, ebx
    call legacy_discord_gateway_text64_old
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
.done:
    pop r12
    pop rbx
    ret

dgw_op7 db '"op":7'
dgw_op7_len equ $-dgw_op7
dgw_op9 db '"op":9'
dgw_op9_len equ $-dgw_op9
msg_dgw_reconnect db '[DISCORD] reconnect requested, stopped instead of looping',13,10,0
msg_dgw_invalid   db '[DISCORD] invalid session, stopped instead of looping',13,10,0
