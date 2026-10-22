; hardened tls 1.2 client key flight keep the working certificate/server-key path
; untouched and make every post-serverhellodone failure explicit instead of collapsing into one message.

BITS 64

%define TLS_KEYFLIGHT_TX_RETRIES 4

; retry a small plaintext tls record when the single-descriptor rtl transmitter is
; momentarily still owned by hardware. ecx type, rdx data, r8d len
legacy_tls_plain_record_retry64:
    push rbx
    push r12
    push r13
    push r14
    mov ebx, ecx
    mov r12, rdx
    mov r13d, r8d
    mov r14d, TLS_KEYFLIGHT_TX_RETRIES
.retry:
    mov ecx, ebx
    mov rdx, r12
    mov r8d, r13d
    call legacy_tls_plain_record64
    test eax, eax
    jz .ok
    mov ecx, 200000
.wait:
    pause
    loop .wait
    dec r14d
    jnz .retry
    mov eax, LEGACY_STATUS_DEVICE
    jmp .out
.ok:
    xor eax, eax
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; retry the encrypted finished record for the same transient tx condition. ecx type, rdx
; plaintext, r8d len
legacy_tls_encrypted_record_retry64:
    push rbx
    push r12
    push r13
    push r14
    mov ebx, ecx
    mov r12, rdx
    mov r13d, r8d
    mov r14d, TLS_KEYFLIGHT_TX_RETRIES
.retry:
    mov ecx, ebx
    mov rdx, r12
    mov r8d, r13d
    call legacy_tls_encrypted_record64
    test eax, eax
    jz .ok
    mov ecx, 200000
.wait:
    pause
    loop .wait
    dec r14d
    jnz .retry
    mov eax, LEGACY_STATUS_DEVICE
    jmp .out
.ok:
    xor eax, eax
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

legacy_tls_keys_and_finish_patched64:
   ; ephemeral private key
    lea rcx, [rel legacy_tls_private]
    mov edx, 32
    call rng_safe_get
    test eax, eax
    jnz .fail_rng

   ; x25519 public key and shared secret
    lea rcx, [rel legacy_tls_public]
    lea rdx, [rel legacy_tls_private]
    call x25519_public_from_private_x64
    lea rcx, [rel legacy_tls_public]
    call x25519_bytes_all_zero_x64
    test eax, eax
    jnz .fail_public

    lea rcx, [rel legacy_tls_shared]
    lea rdx, [rel legacy_tls_private]
    lea r8, [rel legacy_tls_server_ec]
    call x25519_x64
    lea rcx, [rel legacy_tls_shared]
    call x25519_bytes_all_zero_x64
    test eax, eax
    jnz .fail_shared

   ; clientkeyexchange joins the transcript before ems/master-secret derivation.
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
    jnz .fail_transcript

    mov ecx, 22
    lea rdx, [rel legacy_tls_kex_msg]
    mov r8d, 37
    call legacy_tls_plain_record_retry64
    test eax, eax
    jnz .fail_kex_tx

    cmp dword [rel legacy_tls_ems], 1
    jne .classic

   ; rfc 7627 extended master secret: session_hash includes clientkeyexchange.
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
    jnz .fail_master
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
    jnz .fail_master

.keyblock:
   ; key expansion seed is server_random || client_random.
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
    jnz .fail_keyblock

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

   ; changecipherspec stays plaintext.
    mov byte [rel legacy_tls_plain], 1
    mov ecx, 20
    lea rdx, [rel legacy_tls_plain]
    mov r8d, 1
    call legacy_tls_plain_record_retry64
    test eax, eax
    jnz .fail_ccs_tx
    mov dword [rel legacy_tls_wseq_hi], 0
    mov dword [rel legacy_tls_wseq_lo], 0
    mov dword [rel legacy_tls_write_on], 1

   ; client finished verify_data is based on transcript through clientkeyexchange.
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
    jnz .fail_finished_prf

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
    jnz .fail_transcript

    mov ecx, 22
    lea rdx, [rel legacy_tls_finished]
    mov r8d, 16
    call legacy_tls_encrypted_record_retry64
    test eax, eax
    jnz .fail_finished_tx

    mov dword [rel legacy_tls_state], LEGACY_TLS_WAIT_FINISH
    lea rsi, [rel msg_tls_finish_sent]
    call serial_puts64
    xor eax, eax
    ret

.fail_rng:
    lea rsi, [rel msg_tlskey_rng]
    jmp .report
.fail_public:
    lea rsi, [rel msg_tlskey_public]
    jmp .report
.fail_shared:
    lea rsi, [rel msg_tlskey_shared]
    jmp .report
.fail_transcript:
    lea rsi, [rel msg_tlskey_transcript]
    jmp .report
.fail_kex_tx:
    lea rsi, [rel msg_tlskey_kex_tx]
    jmp .report
.fail_master:
    lea rsi, [rel msg_tlskey_master]
    jmp .report
.fail_keyblock:
    lea rsi, [rel msg_tlskey_keyblock]
    jmp .report
.fail_ccs_tx:
    lea rsi, [rel msg_tlskey_ccs_tx]
    jmp .report
.fail_finished_prf:
    lea rsi, [rel msg_tlskey_finished_prf]
    jmp .report
.fail_finished_tx:
    lea rsi, [rel msg_tlskey_finished_tx]
.report:
    call serial_puts64
    mov eax, LEGACY_STATUS_DEVICE
    ret

msg_tlskey_rng          db '[TLSKEY] hardware RNG failed',13,10,0
msg_tlskey_public       db '[TLSKEY] x25519 public key was zero',13,10,0
msg_tlskey_shared       db '[TLSKEY] x25519 shared secret was zero',13,10,0
msg_tlskey_transcript   db '[TLSKEY] handshake transcript overflow',13,10,0
msg_tlskey_kex_tx       db '[TLSKEY] ClientKeyExchange transmit failed',13,10,0
msg_tlskey_master       db '[TLSKEY] master-secret PRF failed',13,10,0
msg_tlskey_keyblock     db '[TLSKEY] key-expansion PRF failed',13,10,0
msg_tlskey_ccs_tx       db '[TLSKEY] ChangeCipherSpec transmit failed',13,10,0
msg_tlskey_finished_prf db '[TLSKEY] client Finished PRF failed',13,10,0
msg_tlskey_finished_tx  db '[TLSKEY] encrypted Finished transmit failed',13,10,0
