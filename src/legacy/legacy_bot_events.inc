; local-only bot event layer.
; normal-account auth stays disabled; the poc credential is only stored

BITS 64

%define BOT_LISTENER_ENTRY_SIZE 24

legacy_bot_event_dispatch64:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov rbx, rcx
    mov r12, rdx
    mov r13d, r8d
    lea r14, [rel legacy_bot_listener_table]

.loop:
    mov r8, [r14+0]
    test r8, r8
    jz .done
    mov r9d, [r14+8]

    mov rcx, r12
    mov edx, r13d
    call legacy_dgw_find64
    test rax, rax
    jz .next

    mov rax, [r14+16]
    test rax, rax
    jz .next
    mov rcx, rbx
    mov rdx, r12
    mov r8d, r13d
    sub rsp, 32
    call rax
    add rsp, 32

.next:
    add r14, BOT_LISTENER_ENTRY_SIZE
    jmp .loop

.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; built-in listeners are intentionally tiny. real commands can hang additional
; handlers off this table without changing the gateway parser.
legacy_bot_on_ready64:
    inc qword [rel legacy_bot_ready_events]
    ret

legacy_bot_on_message_create64:
    inc qword [rel legacy_bot_message_events]
  ; future command parsing belongs here: parse content/channel/author ->
  ; dispatch static command table -> enqueue an outbound request through an authorized
    ret

legacy_bot_on_interaction_create64:
    inc qword [rel legacy_bot_interaction_events]
    ret

; local proof that a poc credential was loaded. never returns the bytes.
legacy_bot_poc_token_present64:
    xor eax, eax
    cmp dword [rel legacy_poc_account_token_len], 0
    setne al
    ret

; hard safety boundary: outbound account-credential transport is intentionally
; absent. this function always refuses the request and never reads the token
legacy_bot_poc_outbound64:
    inc qword [rel legacy_bot_blocked_outbound]
    mov eax, 1
    ret

align 8
legacy_bot_listener_table:
    dq RELOC_BASE + legacy_bot_evt_ready
    dd legacy_bot_evt_ready_len
    dd 0
    dq RELOC_BASE + legacy_bot_on_ready64

    dq RELOC_BASE + legacy_bot_evt_message
    dd legacy_bot_evt_message_len
    dd 0
    dq RELOC_BASE + legacy_bot_on_message_create64

    dq RELOC_BASE + legacy_bot_evt_interaction
    dd legacy_bot_evt_interaction_len
    dd 0
    dq RELOC_BASE + legacy_bot_on_interaction_create64

    dq 0
    dd 0
    dd 0
    dq 0

legacy_bot_evt_ready db '"t":"READY"'
legacy_bot_evt_ready_len equ $-legacy_bot_evt_ready
legacy_bot_evt_message db '"t":"MESSAGE_CREATE"'
legacy_bot_evt_message_len equ $-legacy_bot_evt_message
legacy_bot_evt_interaction db '"t":"INTERACTION_CREATE"'
legacy_bot_evt_interaction_len equ $-legacy_bot_evt_interaction

align 8
legacy_bot_ready_events       dq 0
legacy_bot_message_events     dq 0
legacy_bot_interaction_events dq 0
legacy_bot_blocked_outbound   dq 0
