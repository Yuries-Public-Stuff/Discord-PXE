; per-shard tls 1.2 workspace. this lays out the state needed to port the
; proven singleton tls engine without sharing record

BITS 64

%define SHARD_TLS_PAGES 45
%define SHARD_TLS_BYTES (SHARD_TLS_PAGES * 4096)

%define STLS_STATE           0
%define STLS_WIRE_LEN        4
%define STLS_HS_LEN          8
%define STLS_TRANSCRIPT_LEN 12
%define STLS_HELLO_LEN      16
%define STLS_EMS            20
%define STLS_SERVER_EC_LEN  24
%define STLS_KEX_PARAMS_LEN 28
%define STLS_SERVER_SIG_LEN 32
%define STLS_WRITE_ON       36
%define STLS_READ_ON        40
%define STLS_WSEQ_HI        44
%define STLS_WSEQ_LO        48
%define STLS_RSEQ_HI        52
%define STLS_RSEQ_LO        56
%define STLS_RX_BYTES       64
%define STLS_TX_BYTES       72
%define STLS_HANDSHAKE_GEN  80

%define STLS_WIRE          256
%define STLS_HS          33024
%define STLS_TRANSCRIPT  65792
%define STLS_RECORD     131328
%define STLS_PLAIN      148736
%define STLS_CIPHER     165120
%define STLS_HELLO      181504
%define STLS_CLIENT_RANDOM 182016
%define STLS_SERVER_RANDOM 182048
%define STLS_SERVER_EC     182080
%define STLS_KEX_PARAMS    182112
%define STLS_SERVER_SIG    182176
%define STLS_AUTH_HASH     182688
%define STLS_SIGNED        182720
%define STLS_PRIVATE       182880
%define STLS_PUBLIC        182912
%define STLS_SHARED        182944
%define STLS_MASTER        182976
%define STLS_KEYBLOCK      183024
%define STLS_CLIENT_KEY    183064
%define STLS_SERVER_KEY    183080
%define STLS_CLIENT_IV     183096
%define STLS_SERVER_IV     183100
%define STLS_SEED          183104
%define STLS_HASH          183168
%define STLS_VERIFY        183200
%define STLS_FINISHED      183212
%define STLS_KEX_MSG       183228
%define STLS_TAG           183265
%define STLS_NONCE         183281
%define STLS_AAD           183293
%define STLS_RSA_MODULUS   183320
%define STLS_RSA_BYTES     183832
%define STLS_RSA_LIMBS     183836
%define STLS_CERT_READY    183840

%if (STLS_CERT_READY + 4) > SHARD_TLS_BYTES
    %error "shard TLS workspace exceeds allocated pages"
%endif

; rcx=shard ctx, rax=tls workspace or zero.
legacy_shard_tls_alloc64:
    push rbx
    mov rbx, rcx
    test rbx, rbx
    jz .bad
    mov rax, [rbx + SHARD_OFF_TLS_CTX]
    test rax, rax
    jnz .done

    mov ecx, SHARD_TLS_PAGES
    call alloc_pages64
    test rax, rax
    jnz .got
    mov ecx, SHARD_TLS_PAGES
    call alloc_high_pages64
.got:
    test rax, rax
    jz .bad
    mov [rbx + SHARD_OFF_TLS_CTX], rax

    push rax
    mov rdi, rax
    xor eax, eax
    mov ecx, SHARD_TLS_BYTES / 8
    rep stosq
    pop rax
    mov dword [rax + STLS_STATE], LEGACY_TLS_IDLE
.done:
    pop rbx
    ret
.bad:
    xor eax, eax
    pop rbx
    ret

; rcx=shard ctx.
legacy_shard_tls_reset64:
    push rbx
    mov rbx, rcx
    call legacy_shard_tls_alloc64
    test rax, rax
    jz .bad
    mov rdi, rax
    xor eax, eax
    mov ecx, SHARD_TLS_BYTES / 8
    rep stosq
    mov rax, [rbx + SHARD_OFF_TLS_CTX]
    mov dword [rax + STLS_STATE], LEGACY_TLS_IDLE
    inc qword [rax + STLS_HANDSHAKE_GEN]
    xor eax, eax
    pop rbx
    ret
.bad:
    mov eax, 1
    pop rbx
    ret


; rcx=shard ctx, rdx=handshake bytes, r8d=len.
legacy_shard_tls_transcript_add64:
    push rbx
    push r12
    push r13
    mov rbx, rcx
    mov r12, rdx
    mov r13d, r8d
    mov rax, [rbx + SHARD_OFF_TLS_CTX]
    test rax, rax
    jz .bad
    mov edx, [rax + STLS_TRANSCRIPT_LEN]
    mov ecx, LEGACY_TLS_TRANSCRIPT_CAP
    sub ecx, edx
    cmp r13d, ecx
    ja .bad
    lea rdi, [rax + STLS_TRANSCRIPT]
    add rdi, rdx
    mov rsi, r12
    mov ecx, r13d
    rep movsb
    mov rax, [rbx + SHARD_OFF_TLS_CTX]
    add [rax + STLS_TRANSCRIPT_LEN], r13d
    xor eax, eax
    jmp .out
.bad:
    mov eax, 1
.out:
    pop r13
    pop r12
    pop rbx
    ret

legacy_shard_tls_fail64:
    test rcx, rcx
    jz .ret
    mov rax, [rcx + SHARD_OFF_TLS_CTX]
    test rax, rax
    jz .ret
    mov dword [rax + STLS_STATE], LEGACY_TLS_FAILED
    cmp dword [rcx + SHARD_OFF_LAST_ERROR], 0
    jne .ret
    mov dword [rcx + SHARD_OFF_LAST_ERROR], 4
.ret:
    mov eax, 1
    ret

; rcx=shard ctx. build/send the same proven tls 1.2 clienthello, but entirely
; from this shard's private workspace and tcp sequence space.
legacy_shard_tls_send_hello64:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov rbx, rcx
    cmp dword [rel rng_ready], 1
    jne .bad
    mov rcx, rbx
    call legacy_shard_tls_alloc64
    test rax, rax
    jz .bad
    mov r12, rax

    lea rcx, [r12 + STLS_CLIENT_RANDOM]
    mov edx, 32
    call rng_safe_get
    test eax, eax
    jnz .bad

    lea r10, [r12 + STLS_HELLO]
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
    lea r9, [r12 + STLS_CLIENT_RANDOM]
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
    mov r13, r8

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

    mov byte [r8], 0
    mov byte [r8+1], 0x0D
    mov byte [r8+2], 0
    mov byte [r8+3], 4
    mov byte [r8+4], 0
    mov byte [r8+5], 2
    mov byte [r8+6], 4
    mov byte [r8+7], 1
    add r8, 8

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
    sub rax, r13
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
    mov [r12 + STLS_HELLO_LEN], eax
    mov r14d, eax

    mov rcx, rbx
    lea rdx, [r10+5]
    mov r8d, r14d
    sub r8d, 5
    call legacy_shard_tls_transcript_add64
    test eax, eax
    jnz .bad

    mov rcx, rbx
    lea rdx, [r12 + STLS_HELLO]
    mov r8d, r14d
    call legacy_shard_tcp_send64
    test eax, eax
    jnz .tx_retry

    mov dword [r12 + STLS_STATE], LEGACY_TLS_HELLO_SENT
    add [r12 + STLS_TX_BYTES], r14
    xor eax, eax
    jmp .out
.tx_retry:
  ; one native-tx descriptor is shared by every shard. under smp a temporary
  ; busy/failure here is backpressure, not a broken tls
    xor eax, eax
    jmp .out
.bad:
    mov rcx, rbx
    call legacy_shard_tls_fail64
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx. advance the shard tls state when its private tcp session is
; up.
legacy_shard_tls_tick64:
    push rbx
    mov rbx, rcx
    test rbx, rbx
    jz .done
    mov rcx, rbx
    call legacy_shard_tls_alloc64
    test rax, rax
    jz .done
    cmp dword [rax + STLS_STATE], LEGACY_TLS_FAILED
    je .done
    cmp dword [rax + STLS_STATE], LEGACY_TLS_UP
    je .done
    cmp dword [rel legacy_config_ready], 1
    jne .done

    mov rdx, [rbx + SHARD_OFF_TCP_CTX]
    test rdx, rdx
    jz .done
    cmp dword [rdx + STCP_STATE], SHARD_TCP_UP
    jne .done
    cmp dword [rax + STLS_STATE], LEGACY_TLS_IDLE
    jne .done

    mov rcx, rbx
    call legacy_shard_tls_send_hello64
.done:
    pop rbx
    ret

legacy_shard_tls_tick_all64:
    cmp dword [rel shard_initialized], 1
    jne .done
    cmp dword [rel shard_network_enabled], 1
    jne .done
    push rbx
    xor ebx, ebx
.loop:
    cmp ebx, [rel shard_active_count]
    jae .out
    mov ecx, ebx
    call legacy_shards_get_ctx64
    test rax, rax
    jz .out
    mov rcx, rax
    call legacy_shard_tls_tick64
    inc ebx
    jmp .loop
.out:
    pop rbx
.done:
    ret

; bind one shard tcp stream to its private tls workspace. rcx=shard ctx.
legacy_shard_tls_bind_tcp64:
    push rbx
    mov rbx, rcx
    mov rcx, rbx
    call legacy_shard_tls_alloc64
    test rax, rax
    jz .bad
    mov rcx, rbx
    lea rdx, [rel legacy_shard_tls_tcp_rx64]
    mov r8, rbx
    call legacy_shard_tcp_set_rx64
    test eax, eax
    jnz .bad
    xor eax, eax
    pop rbx
    ret
.bad:
    mov eax, 1
    pop rbx
    ret


; rcx=shard ctx, eax=bytes to drop from wire buffer.
legacy_shard_tls_shift_wire64:
    push rbx
    mov rbx, rcx
    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .done
    mov edx, [r11 + STLS_WIRE_LEN]
    cmp eax, edx
    jae .empty
    sub edx, eax
    lea rsi, [r11 + STLS_WIRE]
    add rsi, rax
    lea rdi, [r11 + STLS_WIRE]
    mov ecx, edx
    rep movsb
    mov [r11 + STLS_WIRE_LEN], edx
    jmp .done
.empty:
    mov dword [r11 + STLS_WIRE_LEN], 0
.done:
    pop rbx
    ret

; rcx=shard ctx, eax=bytes to drop from handshake buffer.
legacy_shard_tls_shift_hs64:
    push rbx
    mov rbx, rcx
    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .done
    mov edx, [r11 + STLS_HS_LEN]
    cmp eax, edx
    jae .empty
    sub edx, eax
    lea rsi, [r11 + STLS_HS]
    add rsi, rax
    lea rdi, [r11 + STLS_HS]
    mov ecx, edx
    rep movsb
    mov [r11 + STLS_HS_LEN], edx
    jmp .done
.empty:
    mov dword [r11 + STLS_HS_LEN], 0
.done:
    pop rbx
    ret


; capture the verified leaf rsa key from the shared x.509 workspace into this
; shard's private tls workspace so another shard
legacy_shard_tls_capture_rsa64:
    push rbx
    mov rbx, rcx
    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .bad
    cmp dword [rel legacy_leaf_key_ready], 1
    jne .bad
    mov eax, [rel rsa_modulus_bytes_x64]
    test eax, eax
    jz .bad
    cmp eax, RSA_MAX_BYTES
    ja .bad
    mov [r11 + STLS_RSA_BYTES], eax
    mov eax, [rel rsa_modulus_limbs_x64]
    mov [r11 + STLS_RSA_LIMBS], eax
    lea rdi, [r11 + STLS_RSA_MODULUS]
    lea rsi, [rel rsa_modulus_x64]
    mov ecx, RSA_MAX_BYTES
    rep movsb
    mov dword [r11 + STLS_CERT_READY], 1
    xor eax, eax
    pop rbx
    ret
.bad:
    mov eax, 1
    pop rbx
    ret

; restore one shard's verified leaf rsa key into the serial shared verifier
; immediately before verifying that shard's signed key exchange.
legacy_shard_tls_restore_rsa64:
    push rbx
    mov rbx, rcx
    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .bad
    cmp dword [r11 + STLS_CERT_READY], 1
    jne .bad
    mov eax, [r11 + STLS_RSA_BYTES]
    test eax, eax
    jz .bad
    cmp eax, RSA_MAX_BYTES
    ja .bad
    mov [rel rsa_modulus_bytes_x64], eax
    mov eax, [r11 + STLS_RSA_LIMBS]
    mov [rel rsa_modulus_limbs_x64], eax
    lea rdi, [rel rsa_modulus_x64]
    lea rsi, [r11 + STLS_RSA_MODULUS]
    mov ecx, RSA_MAX_BYTES
    rep movsb
    mov dword [rel legacy_leaf_key_ready], 1
    xor eax, eax
    pop rbx
    ret
.bad:
    mov dword [rel legacy_leaf_key_ready], 0
    mov eax, 1
    pop rbx
    ret

; rcx=shard ctx, rdx=certificate handshake body, r8d=len.
legacy_shard_tls_certificate64:
    push rbx
    push r12
    push r13
    mov rbx, rcx
    mov r12, rdx
    mov r13d, r8d
    mov rcx, r12
    mov edx, r13d
    call legacy_x509_load_leaf64
    test eax, eax
    jnz .bad
    mov rcx, rbx
    call legacy_shard_tls_capture_rsa64
    test eax, eax
    jnz .bad
    xor eax, eax
    jmp .out
.bad:
    mov eax, 1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx, rdx=serverkeyexchange body, r8d=len.
legacy_shard_tls_server_kex64:
    push rbx
    push r12
    push r13
    mov rbx, rcx
    mov r12, rdx
    mov r13d, r8d
    cmp r13d, 40
    jb .bad
    cmp byte [r12], 3
    jne .bad
    cmp byte [r12+1], 0
    jne .bad
    cmp byte [r12+2], 0x1D
    jne .bad
    cmp byte [r12+3], 32
    jne .bad

    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .bad
    lea rdi, [r11 + STLS_SERVER_EC]
    lea rsi, [r12+4]
    mov ecx, 32
    rep movsb
    mov dword [r11 + STLS_SERVER_EC_LEN], 32

    lea rdi, [r11 + STLS_KEX_PARAMS]
    mov rsi, r12
    mov ecx, 36
    rep movsb
    mov dword [r11 + STLS_KEX_PARAMS_LEN], 36

    cmp byte [r12+36], 4
    jne .bad
    cmp byte [r12+37], 1
    jne .bad
    movzx eax, byte [r12+38]
    shl eax, 8
    mov al, [r12+39]
    cmp eax, RSA_MAX_BYTES
    ja .bad
    mov r10d, eax
    add eax, 40
    cmp eax, r13d
    ja .bad
    mov [r11 + STLS_SERVER_SIG_LEN], r10d
    lea rdi, [r11 + STLS_SERVER_SIG]
    lea rsi, [r12+40]
    mov ecx, r10d
    rep movsb
    xor eax, eax
    jmp .out
.bad:
    mov eax, 1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx. authenticate the signed x25519 parameters against the exact
; leaf rsa key captured from this shard's verified certificate chain.
legacy_shard_tls_auth_kex64:
    push rbx
    push r12
    mov rbx, rcx
    mov r12, [rbx + SHARD_OFF_TLS_CTX]
    test r12, r12
    jz .bad
    cmp dword [r12 + STLS_CERT_READY], 1
    jne .bad
    cmp dword [r12 + STLS_SERVER_EC_LEN], 32
    jne .bad
    cmp dword [r12 + STLS_SERVER_SIG_LEN], 0
    je .bad

    mov rcx, rbx
    call legacy_shard_tls_restore_rsa64
    test eax, eax
    jnz .bad

    lea rcx, [r12 + STLS_SIGNED]
    lea rdx, [r12 + STLS_CLIENT_RANDOM]
    mov r8d, 32
    call mem_copy_x64
    lea rcx, [r12 + STLS_SIGNED + 32]
    lea rdx, [r12 + STLS_SERVER_RANDOM]
    mov r8d, 32
    call mem_copy_x64
    lea rcx, [r12 + STLS_SIGNED + 64]
    lea rdx, [r12 + STLS_KEX_PARAMS]
    mov r8d, [r12 + STLS_KEX_PARAMS_LEN]
    call mem_copy_x64

    lea rcx, [r12 + STLS_SIGNED]
    mov edx, [r12 + STLS_KEX_PARAMS_LEN]
    add edx, 64
    lea r8, [r12 + STLS_AUTH_HASH]
    call sha256_hash3_x64

    lea rcx, [r12 + STLS_SERVER_SIG]
    mov edx, [r12 + STLS_SERVER_SIG_LEN]
    lea r8, [r12 + STLS_AUTH_HASH]
    call rsa_verify_pkcs1_sha256_x64
    test eax, eax
    jnz .bad
    xor eax, eax
    jmp .out
.bad:
    mov eax, 1
.out:
    pop r12
    pop rbx
    ret


; rcx=shard ctx, edx=record type, r8=plaintext, r9d=len.
legacy_shard_tls_plain_record64:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rcx
    mov r12d, edx
    mov r13, r8
    mov r14d, r9d
    cmp r14d, LEGACY_TLS_SEND_MAX
    ja .bad
    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .bad

    lea r10, [r11 + STLS_RECORD]
    mov [r10], r12b
    mov byte [r10+1], 3
    mov byte [r10+2], 3
    mov eax, r14d
    xchg al, ah
    mov [r10+3], ax
    lea rdi, [r10+5]
    mov rsi, r13
    mov ecx, r14d
    rep movsb

    mov rcx, rbx
    lea rdx, [r11 + STLS_RECORD]
    mov r8d, r14d
    add r8d, 5
    call legacy_shard_tcp_send64
    jmp .out
.bad:
    mov eax, 1
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx, edx=record type, r8d=plain length.
legacy_shard_tls_write_meta64:
    push rbx
    push r12
    mov rbx, rcx
    mov r12d, edx
    mov r10d, r8d
    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .done

    lea rcx, [r11 + STLS_AAD]
    mov edx, [r11 + STLS_WSEQ_HI]
    mov r8d, [r11 + STLS_WSEQ_LO]
    call legacy_tls_store_seq64
    mov [r11 + STLS_AAD + 8], r12b
    mov byte [r11 + STLS_AAD + 9], 3
    mov byte [r11 + STLS_AAD + 10], 3
    mov eax, r10d
    xchg al, ah
    mov [r11 + STLS_AAD + 11], ax

    mov eax, [r11 + STLS_CLIENT_IV]
    mov [r11 + STLS_NONCE], eax
    lea rcx, [r11 + STLS_NONCE + 4]
    mov edx, [r11 + STLS_WSEQ_HI]
    mov r8d, [r11 + STLS_WSEQ_LO]
    call legacy_tls_store_seq64
.done:
    pop r12
    pop rbx
    ret

; rcx=shard ctx, edx=record type, r8d=plain length, r9=explicit nonce bytes.
legacy_shard_tls_read_meta64:
    push rbx
    push r12
    push r13
    mov rbx, rcx
    mov r12d, edx
    mov r10d, r8d
    mov r13, r9
    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .done

    lea rcx, [r11 + STLS_AAD]
    mov edx, [r11 + STLS_RSEQ_HI]
    mov r8d, [r11 + STLS_RSEQ_LO]
    call legacy_tls_store_seq64
    mov [r11 + STLS_AAD + 8], r12b
    mov byte [r11 + STLS_AAD + 9], 3
    mov byte [r11 + STLS_AAD + 10], 3
    mov eax, r10d
    xchg al, ah
    mov [r11 + STLS_AAD + 11], ax

    mov eax, [r11 + STLS_SERVER_IV]
    mov [r11 + STLS_NONCE], eax
    lea rdi, [r11 + STLS_NONCE + 4]
    mov rsi, r13
    mov ecx, 8
    rep movsb
.done:
    pop r13
    pop r12
    pop rbx
    ret

legacy_shard_tls_inc_wseq64:
    mov r11, [rcx + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .done
    inc dword [r11 + STLS_WSEQ_LO]
    jnz .done
    inc dword [r11 + STLS_WSEQ_HI]
.done:
    ret

legacy_shard_tls_inc_rseq64:
    mov r11, [rcx + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .done
    inc dword [r11 + STLS_RSEQ_LO]
    jnz .done
    inc dword [r11 + STLS_RSEQ_HI]
.done:
    ret

; rcx=shard ctx, edx=record type, r8=plaintext, r9d=len.
legacy_shard_tls_encrypted_record64:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rcx
    mov r12d, edx
    mov r13, r8
    mov r14d, r9d
    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .bad
    cmp dword [r11 + STLS_WRITE_ON], 1
    jne .bad
    cmp r14d, LEGACY_TLS_SEND_MAX
    ja .bad

    mov rcx, rbx
    mov edx, r12d
    mov r8d, r14d
    call legacy_shard_tls_write_meta64
    mov r11, [rbx + SHARD_OFF_TLS_CTX]

    lea rcx, [r11 + STLS_CLIENT_KEY]
    lea rdx, [r11 + STLS_NONCE]
    lea r8, [r11 + STLS_AAD]
    mov r9d, 13
    sub rsp, 64
    mov [rsp+32], r13
    mov [rsp+40], r14
    lea rax, [r11 + STLS_CIPHER]
    mov [rsp+48], rax
    lea rax, [r11 + STLS_TAG]
    mov [rsp+56], rax
    call aes2_gcm_encrypt
    add rsp, 64
    test eax, eax
    jnz .bad

    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    lea r10, [r11 + STLS_RECORD]
    mov [r10], r12b
    mov byte [r10+1], 3
    mov byte [r10+2], 3
    mov eax, r14d
    add eax, 24
    xchg al, ah
    mov [r10+3], ax

    lea rcx, [r10+5]
    mov edx, [r11 + STLS_WSEQ_HI]
    mov r8d, [r11 + STLS_WSEQ_LO]
    call legacy_tls_store_seq64

    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    lea rdi, [r11 + STLS_RECORD + 13]
    lea rsi, [r11 + STLS_CIPHER]
    mov ecx, r14d
    rep movsb
    lea rsi, [r11 + STLS_TAG]
    mov ecx, 16
    rep movsb

    mov rcx, rbx
    lea rdx, [r11 + STLS_RECORD]
    mov r8d, r14d
    add r8d, 29
    call legacy_shard_tcp_send64
    test eax, eax
    jnz .bad

    mov rcx, rbx
    call legacy_shard_tls_inc_wseq64
    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    add [r11 + STLS_TX_BYTES], r14
    xor eax, eax
    jmp .out
.bad:
    mov eax, 1
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx, edx=record type, r8=encrypted payload, r9d=payload len.
; rax=private plaintext pointer or zero, edx=plaintext length.
legacy_shard_tls_decrypt_record64:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rcx
    mov r12d, edx
    mov r13, r8
    mov r14d, r9d
    cmp r14d, 24
    jb .bad
    sub r14d, 24
    cmp r14d, LEGACY_TLS_PLAIN_CAP
    ja .bad

    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .bad
    mov rcx, rbx
    mov edx, r12d
    mov r8d, r14d
    mov r9, r13
    call legacy_shard_tls_read_meta64

    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    lea rcx, [r11 + STLS_SERVER_KEY]
    lea rdx, [r11 + STLS_NONCE]
    lea r8, [r11 + STLS_AAD]
    mov r9d, 13
    sub rsp, 64
    lea rax, [r13+8]
    mov [rsp+32], rax
    mov [rsp+40], r14
    lea rax, [r13+8+r14]
    mov [rsp+48], rax
    lea rax, [r11 + STLS_PLAIN]
    mov [rsp+56], rax
    call aes2_gcm_decrypt
    add rsp, 64
    test eax, eax
    jnz .bad

    mov rcx, rbx
    call legacy_shard_tls_inc_rseq64
    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    lea rax, [r11 + STLS_PLAIN]
    mov edx, r14d
    jmp .out
.bad:
    xor eax, eax
    xor edx, edx
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx, rdx=application bytes, r8d=len.
legacy_shard_tls_send_app64:
    mov r9d, r8d
    mov r8, rdx
    mov edx, 23
    call legacy_shard_tls_encrypted_record64
    ret

; rcx=shard ctx. build key exchange, derive tls keys, send ccs + finished.
legacy_shard_tls_keys_and_finish64:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rcx
    mov r12, [rbx + SHARD_OFF_TLS_CTX]
    test r12, r12
    jz .bad

    lea rcx, [r12 + STLS_PRIVATE]
    mov edx, 32
    call rng_safe_get
    test eax, eax
    jnz .bad
    lea rcx, [r12 + STLS_PUBLIC]
    lea rdx, [r12 + STLS_PRIVATE]
    call x25519_public_from_private_x64
    lea rcx, [r12 + STLS_SHARED]
    lea rdx, [r12 + STLS_PRIVATE]
    lea r8, [r12 + STLS_SERVER_EC]
    call x25519_x64
    lea rcx, [r12 + STLS_SHARED]
    call x25519_bytes_all_zero_x64
    test eax, eax
    jnz .bad

    lea r10, [r12 + STLS_KEX_MSG]
    mov byte [r10], 16
    mov byte [r10+1], 0
    mov byte [r10+2], 0
    mov byte [r10+3], 33
    mov byte [r10+4], 32
    lea rcx, [r10+5]
    lea rdx, [r12 + STLS_PUBLIC]
    mov r8d, 32
    call mem_copy_x64

    mov rcx, rbx
    lea rdx, [r12 + STLS_KEX_MSG]
    mov r8d, 37
    call legacy_shard_tls_transcript_add64
    test eax, eax
    jnz .bad

    mov rcx, rbx
    mov edx, 22
    lea r8, [r12 + STLS_KEX_MSG]
    mov r9d, 37
    call legacy_shard_tls_plain_record64
    test eax, eax
    jnz .bad

    cmp dword [r12 + STLS_EMS], 1
    jne .classic
    lea rcx, [r12 + STLS_TRANSCRIPT]
    mov edx, [r12 + STLS_TRANSCRIPT_LEN]
    lea r8, [r12 + STLS_HASH]
    call sha256_hash3_x64
    lea rcx, [r12 + STLS_SHARED]
    mov edx, 32
    lea r8, [rel label_ext_master]
    mov r9d, label_ext_master_len
    sub rsp, 72
    lea rax, [r12 + STLS_HASH]
    mov [rsp+32], rax
    mov qword [rsp+40], 32
    lea rax, [r12 + STLS_MASTER]
    mov [rsp+48], rax
    mov qword [rsp+56], 48
    call tls12_prf2_sha256_x64
    add rsp, 72
    test eax, eax
    jnz .bad
    jmp .keyblock

.classic:
    lea rcx, [r12 + STLS_SEED]
    lea rdx, [r12 + STLS_CLIENT_RANDOM]
    mov r8d, 32
    call mem_copy_x64
    lea rcx, [r12 + STLS_SEED + 32]
    lea rdx, [r12 + STLS_SERVER_RANDOM]
    mov r8d, 32
    call mem_copy_x64
    lea rcx, [r12 + STLS_SHARED]
    mov edx, 32
    lea r8, [rel label_master]
    mov r9d, label_master_len
    sub rsp, 72
    lea rax, [r12 + STLS_SEED]
    mov [rsp+32], rax
    mov qword [rsp+40], 64
    lea rax, [r12 + STLS_MASTER]
    mov [rsp+48], rax
    mov qword [rsp+56], 48
    call tls12_prf2_sha256_x64
    add rsp, 72
    test eax, eax
    jnz .bad

.keyblock:
    lea rcx, [r12 + STLS_SEED]
    lea rdx, [r12 + STLS_SERVER_RANDOM]
    mov r8d, 32
    call mem_copy_x64
    lea rcx, [r12 + STLS_SEED + 32]
    lea rdx, [r12 + STLS_CLIENT_RANDOM]
    mov r8d, 32
    call mem_copy_x64

    lea rcx, [r12 + STLS_MASTER]
    mov edx, 48
    lea r8, [rel label_keys]
    mov r9d, label_keys_len
    sub rsp, 72
    lea rax, [r12 + STLS_SEED]
    mov [rsp+32], rax
    mov qword [rsp+40], 64
    lea rax, [r12 + STLS_KEYBLOCK]
    mov [rsp+48], rax
    mov qword [rsp+56], 40
    call tls12_prf2_sha256_x64
    add rsp, 72
    test eax, eax
    jnz .bad

    lea rcx, [r12 + STLS_CLIENT_KEY]
    lea rdx, [r12 + STLS_KEYBLOCK]
    mov r8d, 16
    call mem_copy_x64
    lea rcx, [r12 + STLS_SERVER_KEY]
    lea rdx, [r12 + STLS_KEYBLOCK + 16]
    mov r8d, 16
    call mem_copy_x64
    mov eax, [r12 + STLS_KEYBLOCK + 32]
    mov [r12 + STLS_CLIENT_IV], eax
    mov eax, [r12 + STLS_KEYBLOCK + 36]
    mov [r12 + STLS_SERVER_IV], eax

    mov byte [r12 + STLS_PLAIN], 1
    mov rcx, rbx
    mov edx, 20
    lea r8, [r12 + STLS_PLAIN]
    mov r9d, 1
    call legacy_shard_tls_plain_record64
    test eax, eax
    jnz .bad
    mov dword [r12 + STLS_WSEQ_HI], 0
    mov dword [r12 + STLS_WSEQ_LO], 0
    mov dword [r12 + STLS_WRITE_ON], 1

    lea rcx, [r12 + STLS_TRANSCRIPT]
    mov edx, [r12 + STLS_TRANSCRIPT_LEN]
    lea r8, [r12 + STLS_HASH]
    call sha256_hash3_x64

    lea rcx, [r12 + STLS_MASTER]
    mov edx, 48
    lea r8, [rel label_client_finished]
    mov r9d, label_client_finished_len
    sub rsp, 72
    lea rax, [r12 + STLS_HASH]
    mov [rsp+32], rax
    mov qword [rsp+40], 32
    lea rax, [r12 + STLS_VERIFY]
    mov [rsp+48], rax
    mov qword [rsp+56], 12
    call tls12_prf2_sha256_x64
    add rsp, 72
    test eax, eax
    jnz .bad

    lea r10, [r12 + STLS_FINISHED]
    mov byte [r10], 20
    mov byte [r10+1], 0
    mov byte [r10+2], 0
    mov byte [r10+3], 12
    lea rcx, [r10+4]
    lea rdx, [r12 + STLS_VERIFY]
    mov r8d, 12
    call mem_copy_x64

    mov rcx, rbx
    lea rdx, [r12 + STLS_FINISHED]
    mov r8d, 16
    call legacy_shard_tls_transcript_add64
    test eax, eax
    jnz .bad

    mov rcx, rbx
    mov edx, 22
    lea r8, [r12 + STLS_FINISHED]
    mov r9d, 16
    call legacy_shard_tls_encrypted_record64
    test eax, eax
    jnz .bad

    mov dword [r12 + STLS_STATE], LEGACY_TLS_WAIT_FINISH
    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_stls_finish]
    call serial_puts64
    xor eax, eax
    jmp .out
.bad:
    mov rcx, rbx
    call legacy_shard_tls_fail64
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx, rdx=decrypted finished handshake bytes, r8d=len.
legacy_shard_tls_verify_server_finished64:
    push rbx
    push r12
    push r13
    mov rbx, rcx
    mov r12, rdx
    mov r13d, r8d
    cmp r13d, 16
    jne .bad
    cmp byte [r12], 20
    jne .bad
    cmp byte [r12+1], 0
    jne .bad
    cmp byte [r12+2], 0
    jne .bad
    cmp byte [r12+3], 12
    jne .bad

    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .bad
    lea rcx, [r11 + STLS_TRANSCRIPT]
    mov edx, [r11 + STLS_TRANSCRIPT_LEN]
    lea r8, [r11 + STLS_HASH]
    call sha256_hash3_x64

    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    lea rcx, [r11 + STLS_MASTER]
    mov edx, 48
    lea r8, [rel label_server_finished]
    mov r9d, label_server_finished_len
    sub rsp, 72
    lea rax, [r11 + STLS_HASH]
    mov [rsp+32], rax
    mov qword [rsp+40], 32
    lea rax, [r11 + STLS_VERIFY]
    mov [rsp+48], rax
    mov qword [rsp+56], 12
    call tls12_prf2_sha256_x64
    add rsp, 72
    test eax, eax
    jnz .bad

    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    lea rcx, [r12+4]
    lea rdx, [r11 + STLS_VERIFY]
    mov r8d, 12
    call mem_equal_x64
    test eax, eax
    jz .bad

    mov rcx, rbx
    mov rdx, r12
    mov r8d, 16
    call legacy_shard_tls_transcript_add64
    test eax, eax
    jnz .bad

    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    mov dword [r11 + STLS_STATE], LEGACY_TLS_UP
    mov dword [rbx + SHARD_OFF_STATE], SHARD_STATE_STARTING
    or dword [rbx + SHARD_OFF_FLAGS], SHARD_FLAG_WS_HTTP

  ; tls is authenticated. send this shard's private websocket upgrade request.
    mov rcx, rbx
    call legacy_shard_ws_request64
    test rax, rax
    jz .bad
  ; legacy_shard_ws_request64 returns pointer in rax and length in edx.
    mov r13d, edx
    mov rdx, rax
    mov rcx, rbx
    mov r8d, r13d
    call legacy_shard_tls_send_app64
    test eax, eax
    jnz .bad

    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_stls_up]
    call serial_puts64
    xor eax, eax
    jmp .out
.bad:
    mov rcx, rbx
    call legacy_shard_tls_fail64
.out:
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx, rdx=serverhello body, r8d=len.
legacy_shard_tls_server_hello64:
    push rbx
    push r12
    push r13
    mov rbx, rcx
    mov r12, rdx
    mov r13d, r8d
    cmp r13d, 38
    jb .bad
    cmp byte [r12], 3
    jne .bad
    cmp byte [r12+1], 3
    jne .bad

    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .bad
    lea rdi, [r11 + STLS_SERVER_RANDOM]
    lea rsi, [r12+2]
    mov ecx, 32
    rep movsb

    movzx eax, byte [r12+34]
    mov r10d, 35
    add r10d, eax
    add r10d, 3
    cmp r10d, r13d
    ja .bad
    lea r9, [r12+35]
    add r9, rax
    cmp byte [r9], 0xC0
    jne .bad
    cmp byte [r9+1], 0x2F
    jne .bad
    cmp byte [r9+2], 0
    jne .bad

    mov dword [r11 + STLS_EMS], 0
    lea r10, [r9+3]
    lea r13, [r12+r13]
    cmp r10, r13
    je .ok
    lea rax, [r10+2]
    cmp rax, r13
    ja .bad
    movzx ecx, byte [r10]
    shl ecx, 8
    mov cl, [r10+1]
    add r10, 2
    lea rax, [r10+rcx]
    cmp rax, r13
    ja .bad
    mov r13, rax
.ext:
    cmp r10, r13
    jae .ok
    lea rax, [r10+4]
    cmp rax, r13
    ja .bad
    movzx eax, byte [r10]
    shl eax, 8
    mov al, [r10+1]
    movzx edx, byte [r10+2]
    shl edx, 8
    mov dl, [r10+3]
    lea r9, [r10+4]
    add r9, rdx
    cmp r9, r13
    ja .bad
    cmp eax, 0x17
    jne .next
    test edx, edx
    jnz .bad
    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    mov dword [r11 + STLS_EMS], 1
.next:
    mov r10, r9
    jmp .ext
.ok:
    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    mov dword [r11 + STLS_STATE], LEGACY_TLS_SERVER_FLIGHT
    xor eax, eax
    jmp .out
.bad:
    mov eax, 1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; process complete plaintext handshake messages. only messages whose parser is
; context-safe are consumed; later handshake types remain buffered until their
legacy_shard_tls_process_hs64:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rcx
.loop:
    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .bad
    mov eax, [r11 + STLS_HS_LEN]
    cmp eax, 4
    jb .ok
    lea r12, [r11 + STLS_HS]

    movzx edx, byte [r12+1]
    shl edx, 16
    movzx eax, byte [r12+2]
    shl eax, 8
    or edx, eax
    movzx eax, byte [r12+3]
    or edx, eax
    add edx, 4
    cmp edx, [r11 + STLS_HS_LEN]
    ja .ok

    movzx eax, byte [r12]
    cmp eax, 2
    je .server_hello
    cmp eax, 11
    je .certificate
    cmp eax, 12
    je .server_kex
    cmp eax, 14
    je .server_done
    jmp .ok

.server_hello:
    mov r14d, 2
    jmp .dispatch
.certificate:
    mov r14d, 11
    jmp .dispatch
.server_kex:
    mov r14d, 12
    jmp .dispatch
.server_done:
    mov r14d, 14
.dispatch:
    mov r13d, edx
    mov rcx, rbx
    mov rdx, r12
    mov r8d, r13d
    call legacy_shard_tls_transcript_add64
    test eax, eax
    jnz .bad

    mov rcx, rbx
    lea rdx, [r12+4]
    mov r8d, r13d
    sub r8d, 4
    cmp r14d, 2
    je .call_hello
    cmp r14d, 11
    je .call_cert
    cmp r14d, 12
    je .call_kex
  ; serverhellodone has an empty body. authenticate the signed key exchange
  ; against this shard's captured leaf key, then send the client
    call legacy_shard_tls_auth_kex64
    test eax, eax
    jnz .parsed
    mov rcx, rbx
    call legacy_shard_tls_keys_and_finish64
    jmp .parsed
.call_hello:
    call legacy_shard_tls_server_hello64
    jmp .parsed
.call_cert:
    call legacy_shard_tls_certificate64
    jmp .parsed
.call_kex:
    call legacy_shard_tls_server_kex64
.parsed:
    test eax, eax
    jnz .bad

    mov rcx, rbx
    mov eax, r13d
    call legacy_shard_tls_shift_hs64
    jmp .loop
.ok:
    xor eax, eax
    jmp .out
.bad:
    mov rcx, rbx
    call legacy_shard_tls_fail64
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx, edx=record type, r8=payload, r9d=len.
legacy_shard_tls_record64:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rcx
    mov r12d, edx
    mov r13, r8
    mov r14d, r9d

    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .bad
    cmp dword [r11 + STLS_READ_ON], 1
    je .encrypted_wait

    cmp r12d, 22
    je .handshake
    cmp r12d, 20
    je .ccs
    cmp r12d, 21
    je .bad
    xor eax, eax
    jmp .out

.handshake:
    mov eax, [r11 + STLS_HS_LEN]
    mov edx, LEGACY_TLS_HS_CAP
    sub edx, eax
    cmp r14d, edx
    ja .bad
    lea rdi, [r11 + STLS_HS]
    add rdi, rax
    mov rsi, r13
    mov ecx, r14d
    rep movsb
    add [r11 + STLS_HS_LEN], r14d
    mov rcx, rbx
    call legacy_shard_tls_process_hs64
    jmp .out

.ccs:
    cmp r14d, 1
    jne .bad
    cmp byte [r13], 1
    jne .bad
    mov dword [r11 + STLS_READ_ON], 1
    mov dword [r11 + STLS_RSEQ_HI], 0
    mov dword [r11 + STLS_RSEQ_LO], 0
    xor eax, eax
    jmp .out

.encrypted_wait:
    mov rcx, rbx
    mov edx, r12d
    mov r8, r13
    mov r9d, r14d
    call legacy_shard_tls_decrypt_record64
    test rax, rax
    jz .bad
    mov r13, rax
    mov r14d, edx

    cmp r12d, 22
    je .encrypted_hs
    cmp r12d, 23
    je .app
    cmp r12d, 21
    je .bad
    xor eax, eax
    jmp .out
.encrypted_hs:
    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    cmp dword [r11 + STLS_STATE], LEGACY_TLS_WAIT_FINISH
    jne .bad
    mov rcx, rbx
    mov rdx, r13
    mov r8d, r14d
    call legacy_shard_tls_verify_server_finished64
    jmp .out
.app:
    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    cmp dword [r11 + STLS_STATE], LEGACY_TLS_UP
    jne .bad
  ; until the per-shard discord http/websocket parser is wired, retain
  ; authenticated application bytes in the shard rx buffer.
    mov rcx, rbx
    mov rdx, r13
    mov r8d, r14d
    call legacy_shard_rx_append64
    test eax, eax
    jnz .bad
    mov rcx, rbx
    call legacy_shard_discord_parse64
  ; http/websocket/gateway parser failures are upper-layer failures. the tls
  ; record was already authenticated successfully, so do not convert them into a
    test eax, eax
    jz .app_ok
    xor eax, eax
    jmp .out
.app_ok:
    xor eax, eax
    jmp .out

.bad:
    mov eax, 1
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx.
legacy_shard_tls_parse_records64:
    push rbx
    push r12
    push r13
    mov rbx, rcx
.loop:
    mov r11, [rbx + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .bad
    mov ecx, [r11 + STLS_WIRE_LEN]
    cmp ecx, 5
    jb .ok
    lea r12, [r11 + STLS_WIRE]

    movzx eax, byte [r12+3]
    shl eax, 8
    movzx edx, byte [r12+4]
    or eax, edx
    cmp eax, LEGACY_TLS_RECORD_CAP-5
    ja .bad
    mov r13d, eax
    add eax, 5
    cmp ecx, eax
    jb .ok

    cmp byte [r12+1], 3
    jne .bad
    cmp byte [r12+2], 3
    je .dispatch
    cmp byte [r12+2], 1
    jne .bad
.dispatch:
    movzx edx, byte [r12]
    mov rcx, rbx
    lea r8, [r12+5]
    mov r9d, r13d
    call legacy_shard_tls_record64
    cmp eax, 2
    je .ok
    test eax, eax
    jnz .bad

    mov rcx, rbx
    mov eax, r13d
    add eax, 5
    call legacy_shard_tls_shift_wire64
    jmp .loop
.ok:
    xor eax, eax
    jmp .out
.bad:
    mov rcx, rbx
    call legacy_shard_tls_fail64
.out:
    pop r13
    pop r12
    pop rbx
    ret

; shard tcp callback: rcx=shard ctx, rdx=bytes, r8d=len, r9=callback arg. for
; now this safely accumulates independent wire bytes. the existing tls
legacy_shard_tls_tcp_rx64:
    push rbx
    push r12
    push r13
    mov rbx, rcx
    mov r12, rdx
    mov r13d, r8d
    test rbx, rbx
    jz .bad_noctx
    test r12, r12
    jz .bad
    test r13d, r13d
    jz .ok

    mov rcx, rbx
    call legacy_shard_tls_alloc64
    test rax, rax
    jz .bad
    mov r11, rax

    mov eax, [r11 + STLS_WIRE_LEN]
    mov edx, LEGACY_TLS_WIRE_CAP
    sub edx, eax
    cmp r13d, edx
    ja .bad

    lea rdi, [r11 + STLS_WIRE]
    add rdi, rax
    mov rsi, r12
    mov ecx, r13d
    rep movsb
    add [r11 + STLS_WIRE_LEN], r13d
    add [r11 + STLS_RX_BYTES], r13
    mov rcx, rbx
    call legacy_shard_tls_parse_records64
    test eax, eax
    jnz .bad
.ok:
    xor eax, eax
    jmp .out
.bad:
  ; keep a more specific websocket/gateway failure code if the upper layer
  ; already recorded one. error 3 is only for a
    cmp dword [rbx + SHARD_OFF_LAST_ERROR], 0
    jne .bad_noctx
    mov dword [rbx + SHARD_OFF_LAST_ERROR], 3
.bad_noctx:
    mov eax, 1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx, rax=tls state or failed if unavailable.
legacy_shard_tls_state64:
    push rbx
    mov rbx, rcx
    test rbx, rbx
    jz .bad
    mov rax, [rbx + SHARD_OFF_TLS_CTX]
    test rax, rax
    jz .idle
    mov eax, [rax + STLS_STATE]
    pop rbx
    ret
.idle:
    mov eax, LEGACY_TLS_IDLE
    pop rbx
    ret
.bad:
    mov eax, LEGACY_TLS_FAILED
    pop rbx
    ret

; prepare private tcp/tls/websocket memory for one shard without starting a
; second gateway session yet.
legacy_shard_connection_prepare64:
    push rbx
    mov rbx, rcx

    mov rcx, rbx
    call legacy_shard_transport_prepare64
    test eax, eax
    jnz .bad

  ; the first post-upgrade gateway packet is a websocket text frame (hello). its
  ; parser requires the private discord workspace immediately, before
    mov rcx, rbx
    call legacy_shard_discord_alloc64
    test rax, rax
    jz .bad

    mov rcx, rbx
    call legacy_shard_tls_bind_tcp64
    test eax, eax
    jnz .bad

    xor eax, eax
    pop rbx
    ret
.bad:
    mov eax, 1
    pop rbx
    ret

msg_stls_finish db 'TLS client key flight + Finished sent',13,10,0
msg_stls_up     db 'TLS authenticated; WebSocket upgrade sent',13,10,0
