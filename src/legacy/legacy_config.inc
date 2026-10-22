; discord config lives in source. local secrets are a build artifact only.
; build/generated/local-secrets.inc is never committed.

BITS 64

%define LEGACY_TOKEN_CAP 256
%define LEGACY_PIN_MAX   32
%define LEGACY_PIN_BYTES (LEGACY_PIN_MAX * 32)

%ifdef LEGACY_HAVE_LOCAL_SECRETS
%include "local-secrets.inc"
%endif

legacy_config_init64:
    mov dword [rel legacy_config_manual], 0
    mov dword [rel legacy_token_len], 0
    mov dword [rel legacy_pin_count], 0
    mov dword [rel legacy_pin_ready], 0
    mov dword [rel legacy_config_ready], 0
    mov dword [rel legacy_poc_account_token_len], 0

%ifdef LEGACY_HAVE_LOCAL_SECRETS
  ; proof-of-concept account credential: copy into its own local-only buffer. no
  ; discord gateway/rest builder references this buffer. it is intentionally inert
    mov ecx, legacy_embedded_poc_account_token_len
    test ecx, ecx
    jz .poc_done
    mov rsi, legacy_embedded_poc_account_token
    lea rdi, [rel legacy_poc_account_token]
    rep movsb
    mov byte [rdi], 0
    mov dword [rel legacy_poc_account_token_len], legacy_embedded_poc_account_token_len
.poc_done:

    mov ecx, legacy_embedded_token_len
    test ecx, ecx
    jz .embedded_no_bot_token
    mov rsi, legacy_embedded_token
    lea rdi, [rel legacy_token]
    mov ecx, legacy_embedded_token_len
    rep movsb
    mov byte [rdi], 0
    mov dword [rel legacy_token_len], legacy_embedded_token_len

    mov rsi, legacy_embedded_pins
    lea rdi, [rel legacy_pin_hashes]
    mov ecx, legacy_embedded_pin_count * 32
    rep movsb
    mov dword [rel legacy_pin_count], legacy_embedded_pin_count
    mov dword [rel legacy_pin_ready], 1
    mov dword [rel legacy_config_ready], 1
    lea rsi, [rel msg_config_embedded]
    call serial_puts64
    ret
.embedded_no_bot_token:
    lea rsi, [rel msg_config_poc_only]
    call serial_puts64
    ret
%else
    lea rsi, [rel msg_config_deferred]
    call serial_puts64
    ret
%endif

; print config state without revealing token or pin bytes.
legacy_config_status64:
    lea rsi, [rel msg_config_status]
    call serial_puts64
    mov eax, [rel legacy_config_ready]
    call serial_hex32_64
    lea rsi, [rel msg_config_status_token]
    call serial_puts64
    mov eax, [rel legacy_token_len]
    call serial_hex32_64
    lea rsi, [rel msg_config_status_poc]
    call serial_puts64
    mov eax, [rel legacy_poc_account_token_len]
    call serial_hex32_64
    lea rsi, [rel msg_config_status_pins]
    call serial_puts64
    mov eax, [rel legacy_pin_count]
    call serial_hex32_64
    lea rsi, [rel msg_config_status_source]
    call serial_puts64
    cmp dword [rel legacy_config_manual], 1
    je .manual
%ifdef LEGACY_HAVE_LOCAL_SECRETS
    lea rsi, [rel msg_config_source_embedded]
    call serial_puts64
    ret
%else
    lea rsi, [rel msg_config_source_none]
    call serial_puts64
    ret
%endif
.manual:
    lea rsi, [rel msg_config_source_tftp]
    call serial_puts64
    ret

; optional manual tftp load remains available from the shell
legacy_config_load64:
    mov dword [rel legacy_config_manual], 1
    mov dword [rel legacy_token_len], 0
    mov dword [rel legacy_pin_count], 0
    mov dword [rel legacy_pin_ready], 0
    mov dword [rel legacy_config_ready], 0

    lea rcx, [rel config_token_file]
    call legacy_tftp_fetch64
    test eax, eax
    jnz .token_missing
    call legacy_config_copy_token64
    test eax, eax
    jnz .token_bad
    jmp .pin
.token_missing:
    lea rsi, [rel msg_config_token_missing]
    call serial_puts64
    jmp .pin
.token_bad:
    lea rsi, [rel msg_config_token_bad]
    call serial_puts64
.pin:
    lea rcx, [rel config_pin_file]
    call legacy_tftp_fetch64
    test eax, eax
    jnz .pin_missing
    call legacy_config_copy_pin64
    test eax, eax
    jnz .pin_bad
    jmp .finish
.pin_missing:
    lea rsi, [rel msg_config_pin_missing]
    call serial_puts64
    jmp .finish
.pin_bad:
    lea rsi, [rel msg_config_pin_bad]
    call serial_puts64
.finish:
    call legacy_config_wipe_fetch64
    cmp dword [rel legacy_token_len], 0
    je .not_ready
    cmp dword [rel legacy_pin_ready], 1
    jne .not_ready
    mov dword [rel legacy_config_ready], 1
    lea rsi, [rel msg_config_ready]
    call serial_puts64
    ret
.not_ready:
    lea rsi, [rel msg_config_not_ready]
    call serial_puts64
    ret

legacy_config_copy_token64:
    cmp dword [rel tftp_file_valid], 1
    jne .fail
    mov ecx, [rel tftp_file_len]
    test ecx, ecx
    jz .fail
    cmp ecx, LEGACY_TOKEN_CAP
    jae .fail
    mov rsi, [rel tftp_file_buf]
    lea rdi, [rel legacy_token]
    mov edx, ecx
    rep movsb
    mov ecx, edx
.trim:
    test ecx, ecx
    jz .fail
    lea rdi, [rel legacy_token]
    mov al, [rdi+rcx-1]
    cmp al, 13
    je .cut
    cmp al, 10
    je .cut
    cmp al, ' '
    je .cut
    cmp al, 9
    jne .done
.cut:
    dec ecx
    jmp .trim
.done:
    mov byte [rdi+rcx], 0
    mov [rel legacy_token_len], ecx
    xor eax, eax
    ret
.fail:
    mov dword [rel legacy_token_len], 0
    mov eax, 1
    ret

legacy_config_copy_pin64:
    cmp dword [rel tftp_file_valid], 1
    jne .fail
    mov ecx, [rel tftp_file_len]
    cmp ecx, 32
    jb .fail
    cmp ecx, LEGACY_PIN_BYTES
    ja .fail
    test ecx, 31
    jnz .fail
    mov edx, ecx
    shr edx, 5
    mov rsi, [rel tftp_file_buf]
    lea rdi, [rel legacy_pin_hashes]
    rep movsb
    mov [rel legacy_pin_count], edx
    mov dword [rel legacy_pin_ready], 1
    xor eax, eax
    ret
.fail:
    mov dword [rel legacy_pin_count], 0
    mov dword [rel legacy_pin_ready], 0
    mov eax, 1
    ret

legacy_config_wipe_fetch64:
    mov rdi, [rel tftp_file_buf]
    test rdi, rdi
    jz .done
    xor eax, eax
    mov ecx, TFTP_FETCH_CAP / 8
    rep stosq
    mov dword [rel tftp_file_valid], 0
    mov dword [rel tftp_file_len], 0
.done:
    ret

align 16
legacy_token times LEGACY_TOKEN_CAP db 0
legacy_poc_account_token times LEGACY_TOKEN_CAP db 0
legacy_pin_hashes times LEGACY_PIN_BYTES db 0
legacy_token_len dd 0
legacy_poc_account_token_len dd 0
legacy_pin_count dd 0
legacy_pin_ready dd 0
legacy_config_ready dd 0
legacy_config_manual dd 0

config_token_file db 'discord/token.txt',0
config_pin_file   db 'discord/pin.bin',0

msg_config_embedded      db '[CONFIG] embedded bot token + trusted leaf pin set ready',13,10,0
msg_config_poc_only      db '[POC] local account credential loaded; Discord transmission disabled',13,10,0
msg_config_deferred      db '[CONFIG] runtime tftp deferred; network + shell continue without auth',13,10,0
msg_config_token_missing db '[CONFIG] discord/token.txt missing',13,10,0
msg_config_token_bad     db '[CONFIG] token file invalid',13,10,0
msg_config_pin_missing   db '[CONFIG] discord/pin.bin missing',13,10,0
msg_config_pin_bad       db '[CONFIG] pin file invalid',13,10,0
msg_config_ready         db '[CONFIG] token + trusted leaf pin set loaded',13,10,0
msg_config_not_ready     db '[CONFIG] discord stays disabled until token + pin exist',13,10,0

msg_config_status        db '[CONFIG] ready=0x',0
msg_config_status_token  db ' token-len=0x',0
msg_config_status_poc    db ' poc-account-token-len=0x',0
msg_config_status_pins   db ' pins=0x',0
msg_config_status_source db ' source=',0
msg_config_source_embedded db 'embedded',13,10,0
msg_config_source_tftp     db 'tftp',13,10,0
msg_config_source_none     db 'none',13,10,0
