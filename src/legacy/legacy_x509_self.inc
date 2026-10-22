; self-contained x.509 verifier for gateway.discord.gg no windows/build-time
; certificate discovery is used. trust is anchored to exact google trust services rsa

BITS 64

%define LEGACY_CERT_CAP 16384

legacy_x509_init64:
    mov dword [rel legacy_x509_ready], 1
    mov dword [rel legacy_leaf_cert_len], 0
    mov dword [rel legacy_ca_cert_len], 0
    mov dword [rel legacy_leaf_key_ready], 0
    mov dword [rel legacy_ca_key_type], 0
    lea rsi, [rel msg_x509_self_ready]
    call serial_puts64
    ret

; rcx certificate-message body, edx body length
legacy_x509_load_leaf64:
    push rbx
    push r12
    push r13
    cmp edx, 9
    jb .fail
    mov r12, rcx
    mov r13d, edx

  ; certificate_list length
    movzx eax, byte [r12]
    shl eax, 16
    movzx ebx, byte [r12+1]
    shl ebx, 8
    or eax, ebx
    movzx ebx, byte [r12+2]
    or eax, ebx
    add eax, 3
    cmp eax, r13d
    ja .fail

  ; leaf
    movzx eax, byte [r12+3]
    shl eax, 16
    movzx ebx, byte [r12+4]
    shl ebx, 8
    or eax, ebx
    movzx ebx, byte [r12+5]
    or eax, ebx
    test eax, eax
    jz .fail
    cmp eax, LEGACY_CERT_CAP
    ja .fail
    mov ebx, eax
    lea eax, [ebx+6]
    cmp eax, r13d
    ja .fail
    lea rsi, [r12+6]
    lea rdi, [rel legacy_leaf_cert]
    mov ecx, ebx
    rep movsb
    mov [rel legacy_leaf_cert_len], ebx

  ; first issuer follows leaf
    lea rsi, [r12+6+rbx]
    lea rdx, [r12+r13]
    lea rax, [rsi+3]
    cmp rax, rdx
    ja .fail
    movzx eax, byte [rsi]
    shl eax, 16
    movzx ecx, byte [rsi+1]
    shl ecx, 8
    or eax, ecx
    movzx ecx, byte [rsi+2]
    or eax, ecx
    test eax, eax
    jz .fail
    cmp eax, LEGACY_CERT_CAP
    ja .fail
    mov ebx, eax
    lea rax, [rsi+3+rbx]
    cmp rax, rdx
    ja .fail
    add rsi, 3
    lea rdi, [rel legacy_ca_cert]
    mov ecx, ebx
    rep movsb
    mov [rel legacy_ca_cert_len], ebx

    call legacy_x509_verify_chain64
    test eax, eax
    jnz .fail
    lea rsi, [rel msg_x509_leaf_ok]
    call serial_puts64
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret
.fail:
    mov dword [rel legacy_leaf_key_ready], 0
    lea rsi, [rel msg_x509_leaf_bad]
    call serial_puts64
    mov eax, LEGACY_STATUS_DEVICE
    pop r13
    pop r12
    pop rbx
    ret

legacy_der64:
    cmp rcx, rdx
    jae .bad
    movzx eax, byte [rcx]
    mov [rel legacy_der_tag], eax
    inc rcx
    cmp rcx, rdx
    jae .bad
    movzx eax, byte [rcx]
    inc rcx
    test eax, 0x80
    jz .short
    and eax, 0x7f
    test eax, eax
    jz .bad
    cmp eax, 4
    ja .bad
    mov r8d, eax
    xor r9d, r9d
.long:
    cmp rcx, rdx
    jae .bad
    shl r9d, 8
    mov r9b, [rcx]
    inc rcx
    dec r8d
    jnz .long
    mov eax, r9d
    jmp .have
.short:
    and eax, 0x7f
.have:
    mov [rel legacy_der_len], eax
    mov [rel legacy_der_value], rcx
    mov r8, rcx
    add r8, rax
    jc .bad
    cmp r8, rdx
    ja .bad
    mov [rel legacy_der_next], r8
    xor eax, eax
    ret
.bad:
    mov eax, LEGACY_STATUS_INVALID
    ret

; rcx cert, edx len -> rax raw rsa public-key sequence, edx len
legacy_x509_find_spki64:
    push rbx
    push r12
    push r13
    lea r12, [rcx+rdx]
    mov r13, rcx
    mov rcx, r13
    mov rdx, r12
    call legacy_der64
    test eax, eax
    jnz .bad
    cmp dword [rel legacy_der_tag], 0x30
    jne .bad
    mov rsi, [rel legacy_der_value]
    mov eax, [rel legacy_der_len]
    lea rbx, [rsi+rax]
    mov rcx, rsi
    mov rdx, rbx
    call legacy_der64
    test eax, eax
    jnz .bad
    cmp dword [rel legacy_der_tag], 0x30
    jne .bad
    mov rsi, [rel legacy_der_value]
    mov eax, [rel legacy_der_len]
    lea r12, [rsi+rax]
.scan:
    cmp rsi, r12
    jae .bad
    mov rcx, rsi
    mov rdx, r12
    call legacy_der64
    test eax, eax
    jnz .bad
    mov r13, [rel legacy_der_next]
    cmp dword [rel legacy_der_tag], 0x30
    jne .next
    mov rsi, [rel legacy_der_value]
    mov eax, [rel legacy_der_len]
    lea rbx, [rsi+rax]
    mov rcx, rsi
    mov rdx, rbx
    call legacy_der64
    test eax, eax
    jnz .next
    cmp dword [rel legacy_der_tag], 0x30
    jne .next
    mov rsi, [rel legacy_der_next]
    mov rcx, rsi
    mov rdx, rbx
    call legacy_der64
    test eax, eax
    jnz .next
    cmp dword [rel legacy_der_tag], 3
    jne .next
    cmp qword [rel legacy_der_next], rbx
    jne .next
    mov rax, [rel legacy_der_value]
    mov edx, [rel legacy_der_len]
    cmp edx, 2
    jb .bad
    cmp byte [rax], 0
    jne .bad
    inc rax
    dec edx
    pop r13
    pop r12
    pop rbx
    ret
.next:
    mov rsi, r13
    jmp .scan
.bad:
    xor eax, eax
    xor edx, edx
    pop r13
    pop r12
    pop rbx
    ret

legacy_x509_load_rsa_key64:
    push rbx
    push r12
    mov r12, rcx
    mov ebx, edx
    lea rdx, [r12+rbx]
    mov rcx, r12
    call legacy_der64
    test eax, eax
    jnz .bad
    cmp dword [rel legacy_der_tag], 0x30
    jne .bad
    mov rsi, [rel legacy_der_value]
    mov eax, [rel legacy_der_len]
    lea r12, [rsi+rax]
    mov rcx, rsi
    mov rdx, r12
    call legacy_der64
    test eax, eax
    jnz .bad
    cmp dword [rel legacy_der_tag], 2
    jne .bad
    mov rsi, [rel legacy_der_value]
    mov ebx, [rel legacy_der_len]
    cmp ebx, 1
    jb .bad
    cmp byte [rsi], 0
    jne .mod
    inc rsi
    dec ebx
.mod:
    cmp ebx, 128
    jb .bad
    cmp ebx, RSA_MAX_BYTES
    ja .bad
    mov [rel rsa_modulus_bytes_x64], ebx
    mov eax, ebx
    add eax, 3
    shr eax, 2
    mov [rel rsa_modulus_limbs_x64], eax
    lea rcx, [rel rsa_modulus_x64]
    mov rdx, rsi
    mov r8d, eax
    mov r9d, ebx
    call rsa_import_be_x64
    mov rsi, [rel legacy_der_next]
    mov rcx, rsi
    mov rdx, r12
    call legacy_der64
    test eax, eax
    jnz .bad
    cmp dword [rel legacy_der_tag], 2
    jne .bad
    cmp dword [rel legacy_der_len], 3
    jne .bad
    mov rsi, [rel legacy_der_value]
    cmp byte [rsi], 1
    jne .bad
    cmp byte [rsi+1], 0
    jne .bad
    cmp byte [rsi+2], 1
    jne .bad
    xor eax, eax
    pop r12
    pop rbx
    ret
.bad:
    mov eax, LEGACY_STATUS_DEVICE
    pop r12
    pop rbx
    ret

; trust exact issuer der certificate fingerprints. wr1/wr2 are the older rsa
; gts intermediates. we1 is the current p-256 google trust
legacy_x509_load_trusted_issuer64:
    lea rcx, [rel legacy_ca_cert]
    mov edx, [rel legacy_ca_cert_len]
    lea r8, [rel legacy_ca_cert_hash]
    call sha256_hash3_x64

  ; rsa issuer path: wr1 / wr2.
    lea rcx, [rel legacy_ca_cert_hash]
    lea rdx, [rel legacy_wr1_cert_sha256]
    mov r8d, 32
    call mem_equal_x64
    test eax, eax
    jnz .trusted_rsa
    lea rcx, [rel legacy_ca_cert_hash]
    lea rdx, [rel legacy_wr2_cert_sha256]
    mov r8d, 32
    call mem_equal_x64
    test eax, eax
    jnz .trusted_rsa

  ; current google trust services we1 intermediate, gts root r4 chain.
    lea rcx, [rel legacy_ca_cert_hash]
    lea rdx, [rel legacy_we1_cert_sha256]
    mov r8d, 32
    call mem_equal_x64
    test eax, eax
    jnz .trusted_ec

  ; also accept the same we1 key in the google-published globalsign-r4
  ; cross-signed certificate.
    lea rcx, [rel legacy_ca_cert_hash]
    lea rdx, [rel legacy_we1_cross_cert_sha256]
    mov r8d, 32
    call mem_equal_x64
    test eax, eax
    jnz .trusted_ec

  ; google trust services rotates cloudflare-managed leaves across sibling ecdsa
  ; intermediates. accept the official we2/we3 certificates in both their gts root
    lea rcx, [rel legacy_ca_cert_hash]
    lea rdx, [rel legacy_we2_cert_sha256]
    mov r8d, 32
    call mem_equal_x64
    test eax, eax
    jnz .trusted_ec
    lea rcx, [rel legacy_ca_cert_hash]
    lea rdx, [rel legacy_we2_cross_cert_sha256]
    mov r8d, 32
    call mem_equal_x64
    test eax, eax
    jnz .trusted_ec
    lea rcx, [rel legacy_ca_cert_hash]
    lea rdx, [rel legacy_we3_cert_sha256]
    mov r8d, 32
    call mem_equal_x64
    test eax, eax
    jnz .trusted_ec
    lea rcx, [rel legacy_ca_cert_hash]
    lea rdx, [rel legacy_we3_cross_cert_sha256]
    mov r8d, 32
    call mem_equal_x64
    test eax, eax
    jz .bad

.trusted_ec:
    lea rcx, [rel legacy_ca_cert]
    mov edx, [rel legacy_ca_cert_len]
    call legacy_x509_find_spki64
    test rax, rax
    jz .bad
    cmp edx, 65
    jne .bad
    cmp byte [rax], 4
    jne .bad
    lea rdi, [rel legacy_ca_ec_key]
    mov rsi, rax
    mov ecx, 65
    rep movsb
    mov dword [rel legacy_ca_key_type], 2
    xor eax, eax
    ret

.trusted_rsa:
    lea rcx, [rel legacy_ca_cert]
    mov edx, [rel legacy_ca_cert_len]
    call legacy_x509_find_spki64
    test rax, rax
    jz .bad
    mov rcx, rax
    call legacy_x509_load_rsa_key64
    test eax, eax
    jnz .bad
    mov dword [rel legacy_ca_key_type], 1
    xor eax, eax
    ret

.bad:
    lea rsi, [rel msg_x509_anchor_bad]
    call serial_puts64
  ; print only the sha-256 fingerprint of the presented intermediate. this is
  ; public certificate metadata and makes future ca rotations diagnosable
    lea rsi, [rel msg_x509_anchor_hash]
    call serial_puts64
    lea rbx, [rel legacy_ca_cert_hash]
    xor r12d, r12d
.hash_loop:
    cmp r12d, 32
    jae .hash_done
    movzx eax, byte [rbx+r12]
    call legacy_x509_print_hex8_64
    inc r12d
    jmp .hash_loop
.hash_done:
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    mov eax, LEGACY_STATUS_DEVICE
    ret

; al = byte, print exactly two uppercase hex digits.
legacy_x509_print_hex8_64:
    push rax
    push rbx
    mov bl, al
    shr al, 4
    and al, 0x0F
    cmp al, 9
    jbe .hi_num
    add al, 'A' - 10
    jmp .hi_out
.hi_num:
    add al, '0'
.hi_out:
    call serial_putc64_al
    mov al, bl
    and al, 0x0F
    cmp al, 9
    jbe .lo_num
    add al, 'A' - 10
    jmp .lo_out
.lo_num:
    add al, '0'
.lo_out:
    call serial_putc64_al
    pop rbx
    pop rax
    ret

legacy_x509_verify_leaf_signature64:
    push rbx
    push r12
    push r13
    lea r12, [rel legacy_leaf_cert]
    mov eax, [rel legacy_leaf_cert_len]
    lea r13, [r12+rax]
    mov rcx, r12
    mov rdx, r13
    call legacy_der64
    test eax, eax
    jnz .bad
    cmp dword [rel legacy_der_tag], 0x30
    jne .bad
    mov rsi, [rel legacy_der_value]
    mov eax, [rel legacy_der_len]
    lea rbx, [rsi+rax]
    mov r12, rsi
    mov rcx, r12
    mov rdx, rbx
    call legacy_der64
    test eax, eax
    jnz .bad
    cmp dword [rel legacy_der_tag], 0x30
    jne .bad
    mov r13, [rel legacy_der_next]
    mov rax, r13
    sub rax, r12
    mov edx, eax
    mov rcx, r12
    lea r8, [rel legacy_leaf_tbs_hash]
    call sha256_hash3_x64
    mov rcx, r13
    mov rdx, rbx
    call legacy_der64
    test eax, eax
    jnz .bad
    cmp dword [rel legacy_der_tag], 0x30
    jne .bad
    mov r13, [rel legacy_der_next]
    mov rcx, r13
    mov rdx, rbx
    call legacy_der64
    test eax, eax
    jnz .bad
    cmp dword [rel legacy_der_tag], 3
    jne .bad
    mov rsi, [rel legacy_der_value]
    mov edx, [rel legacy_der_len]
    cmp edx, 2
    jb .bad
    cmp byte [rsi], 0
    jne .bad
    inc rsi
    dec edx
    cmp dword [rel legacy_ca_key_type], 2
    je .verify_ec
    cmp dword [rel legacy_ca_key_type], 1
    jne .bad
    mov rcx, rsi
    lea r8, [rel legacy_leaf_tbs_hash]
    call rsa_verify_pkcs1_sha256_x64
    test eax, eax
    jnz .bad
    jmp .sig_ok
.verify_ec:
    lea rcx, [rel legacy_ca_ec_key]
    mov rdx, rsi
    lea r8, [rel legacy_leaf_tbs_hash]
    call ecdsa_p256_verify_sha256_x64
    test eax, eax
    jnz .bad
.sig_ok:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret
.bad:
    lea rsi, [rel msg_x509_sig_bad]
    call serial_puts64
    mov eax, LEGACY_STATUS_DEVICE
    pop r13
    pop r12
    pop rbx
    ret

; narrow san check for gateway.discord.gg or *.discord.gg
legacy_x509_hostname64:
    lea rsi, [rel legacy_leaf_cert]
    mov ecx, [rel legacy_leaf_cert_len]
.scan:
    cmp ecx, 2
    jb .bad
    cmp byte [rsi], 0x82
    jne .next
    movzx eax, byte [rsi+1]
    test eax, 0x80
    jnz .next
    cmp eax, legacy_tls_host_len
    je .exact
    cmp eax, legacy_tls_wild_len
    je .wild
    jmp .next
.exact:
    lea rcx, [rsi+2]
    lea rdx, [rel legacy_tls_host_name]
    mov r8d, legacy_tls_host_len
    call mem_equal_x64
    test eax, eax
    jnz .ok
    jmp .restart
.wild:
    lea rcx, [rsi+2]
    lea rdx, [rel legacy_tls_wild_name]
    mov r8d, legacy_tls_wild_len
    call mem_equal_x64
    test eax, eax
    jnz .ok
.restart:
    lea rsi, [rel legacy_leaf_cert]
    mov ecx, [rel legacy_leaf_cert_len]
.next:
    inc rsi
    dec ecx
    jmp .scan
.ok:
    xor eax, eax
    ret
.bad:
    lea rsi, [rel msg_x509_name_bad]
    call serial_puts64
    mov eax, LEGACY_STATUS_DEVICE
    ret

legacy_x509_load_leaf_key64:
    lea rcx, [rel legacy_leaf_cert]
    mov edx, [rel legacy_leaf_cert_len]
    call legacy_x509_find_spki64
    test rax, rax
    jz .bad
    mov rcx, rax
    call legacy_x509_load_rsa_key64
    test eax, eax
    jnz .bad
    mov dword [rel legacy_leaf_key_ready], 1
    xor eax, eax
    ret
.bad:
    mov dword [rel legacy_leaf_key_ready], 0
    mov eax, LEGACY_STATUS_DEVICE
    ret

legacy_x509_verify_chain64:
    call legacy_x509_hostname64
    test eax, eax
    jnz .bad
    call legacy_x509_load_trusted_issuer64
    test eax, eax
    jnz .bad
    call legacy_x509_verify_leaf_signature64
    test eax, eax
    jnz .bad
    call legacy_x509_load_leaf_key64
    test eax, eax
    jnz .bad
    lea rsi, [rel msg_x509_chain_ok]
    call serial_puts64
    xor eax, eax
    ret
.bad:
    mov eax, LEGACY_STATUS_DEVICE
    ret

; exact der certificate sha-256 fingerprints, not leaf pins.
legacy_wr1_cert_sha256 db 0xB1,0x0B,0x6F,0x00,0xE6,0x09,0x50,0x9E,0x87,0x00,0xF6,0xD3,0x46,0x87,0xA2,0xBF,0xCE,0x38,0xEA,0x05,0xA8,0xFD,0xF1,0xCD,0xC4,0x0C,0x3A,0x2A,0x0D,0x0D,0x0E,0x45
legacy_wr2_cert_sha256 db 0xE6,0xFE,0x22,0xBF,0x45,0xE4,0xF0,0xD3,0xB8,0x5C,0x59,0xE0,0x2C,0x0F,0x49,0x54,0x18,0xE1,0xEB,0x8D,0x32,0x10,0xF7,0x88,0xD4,0x8C,0xD5,0xE1,0xCB,0x54,0x7C,0xD4
legacy_we1_cert_sha256 db 0x1D,0xFC,0x16,0x05,0xFB,0xAD,0x35,0x8D,0x8B,0xC8,0x44,0xF7,0x6D,0x15,0x20,0x3F,0xAC,0x9C,0xA5,0xC1,0xA7,0x9F,0xD4,0x85,0x7F,0xFA,0xF2,0x86,0x4F,0xBE,0xBF,0x96
legacy_we1_cross_cert_sha256 db 0xA2,0x87,0xFF,0xAB,0x76,0x2C,0xC6,0x9A,0x26,0xD4,0x82,0x03,0x7E,0xDF,0x70,0x1F,0x65,0x3C,0xE8,0x99,0x02,0x5C,0x62,0xA7,0xE5,0xCB,0x88,0xBB,0x9B,0x41,0x9C,0xBB
legacy_we2_cert_sha256 db 0x9C,0x3F,0x2F,0xD1,0x1C,0x57,0xD7,0xC6,0x49,0xAD,0x5A,0x09,0x32,0xC0,0xF0,0xD2,0x97,0x56,0xF6,0xA0,0xA1,0xC7,0x4C,0x43,0xE1,0xE8,0x9A,0x62,0xD6,0x4C,0xD3,0x20
legacy_we2_cross_cert_sha256 db 0x54,0xF8,0xCA,0x85,0x8B,0xCC,0x75,0x91,0xF2,0x8D,0x8D,0xC3,0x77,0x2E,0x9B,0xC5,0x81,0x71,0x7F,0x3A,0x23,0xA2,0x88,0xBF,0xD4,0x05,0x93,0x9C,0x36,0x20,0x8D,0xE5
legacy_we3_cert_sha256 db 0x9F,0x81,0x9A,0x4C,0x87,0x6E,0x12,0xDC,0x84,0xE6,0xFE,0x0E,0x37,0xC1,0xA6,0x9B,0x13,0x70,0x94,0xB4,0x53,0xFA,0x98,0x44,0x93,0x98,0xF4,0xB7,0x1F,0x4D,0x00,0x92
legacy_we3_cross_cert_sha256 db 0x54,0xC6,0x60,0xDA,0x29,0xD7,0x5F,0xC8,0x1F,0x07,0xAD,0x6D,0xC8,0xBB,0x7A,0xEE,0x22,0x58,0xE0,0x71,0xE8,0xB1,0x07,0x75,0x44,0xFA,0x56,0x22,0xFF,0x44,0xC9,0x9D

legacy_tls_host_name db 'gateway.discord.gg'
legacy_tls_host_len equ $-legacy_tls_host_name
legacy_tls_wild_name db '*.discord.gg'
legacy_tls_wild_len equ $-legacy_tls_wild_name

align 16
legacy_leaf_cert      times LEGACY_CERT_CAP db 0
legacy_ca_cert        times LEGACY_CERT_CAP db 0
legacy_ca_cert_hash   times 32 db 0
legacy_ca_ec_key      times 65 db 0
legacy_leaf_tbs_hash  times 32 db 0
legacy_leaf_cert_len  dd 0
legacy_ca_cert_len    dd 0
legacy_ca_key_type    dd 0
legacy_leaf_key_ready dd 0
legacy_x509_ready     dd 0
legacy_der_tag        dd 0
legacy_der_len        dd 0
legacy_der_value      dq 0
legacy_der_next       dq 0

msg_x509_self_ready db '[X509] self-contained issuer trust store ready',13,10,0
msg_x509_chain_ok   db '[X509] leaf chain verified locally',13,10,0
msg_x509_leaf_ok    db '[X509] verified leaf RSA key ready',13,10,0
msg_x509_leaf_bad   db '[X509] leaf certificate rejected',13,10,0
msg_x509_anchor_bad db '[X509] issuer certificate is not in local trust store',13,10,0
msg_x509_anchor_hash db '[X509] presented issuer sha256=',0
msg_x509_sig_bad    db '[X509] leaf certificate signature invalid',13,10,0
msg_x509_name_bad   db '[X509] gateway.discord.gg SAN mismatch',13,10,0
