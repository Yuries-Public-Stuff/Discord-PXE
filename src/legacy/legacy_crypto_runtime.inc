; small helpers crypto needs without uefi keeps tls code from caring what firmware booted
; us

BITS 64

%define LEGACY_STATUS_OK           0
%define LEGACY_STATUS_INVALID      2
%define LEGACY_STATUS_UNSUPPORTED  3
%define LEGACY_STATUS_NOT_READY    6
%define LEGACY_STATUS_DEVICE       7
%define LEGACY_STATUS_BUFFER       8
%define LEGACY_STATUS_NO_MEMORY    9

; old tls code uses these names, keep them local to this runtime
%define EFI_SUCCESS           LEGACY_STATUS_OK
%define EFI_INVALID_PARAMETER LEGACY_STATUS_INVALID
%define EFI_UNSUPPORTED       LEGACY_STATUS_UNSUPPORTED
%define EFI_NOT_READY         LEGACY_STATUS_NOT_READY
%define EFI_DEVICE_ERROR      LEGACY_STATUS_DEVICE
%define EFI_BAD_BUFFER_SIZE   LEGACY_STATUS_BUFFER
%define EFI_OUT_OF_RESOURCES  LEGACY_STATUS_NO_MEMORY

legacy_crypto_init64:
    call legacy_rng_init64
    lea rsi, [rel msg_crypto_ready]
    call serial_puts64
    ret

; rcx dest, rdx src, r8 count
mem_copy_x64:
    mov rax, rcx
    test r8, r8
    jz .done
.loop:
    mov r9b, [rdx]
    mov [rcx], r9b
    inc rdx
    inc rcx
    dec r8
    jnz .loop
.done:
    ret

; rcx dest, dl value, r8 count
mem_set_x64:
    mov rax, rcx
    test r8, r8
    jz .done
.loop:
    mov [rcx], dl
    inc rcx
    dec r8
    jnz .loop
.done:
    ret

; compare every byte so secret checks do the same amount of work
mem_equal_x64:
    xor eax, eax
    xor r9d, r9d
.loop:
    test r8, r8
    jz .finish
    mov r10b, [rcx]
    xor r10b, [rdx]
    movzx r10d, r10b
    or r9d, r10d
    inc rcx
    inc rdx
    dec r8
    jmp .loop
.finish:
    test r9d, r9d
    setz al
    ret

; only use rdrand if the cpu says it has it tls fails closed instead of making fake random
; keys
legacy_rng_init64:
    mov dword [rel rng_ready], 0
    mov eax, 1
    cpuid
    bt ecx, 30
    jnc .fail
    mov dword [rel rng_ready], 1
    lea rsi, [rel msg_rng_ready]
    call serial_puts64
    xor eax, eax
    ret
.fail:
    lea rsi, [rel msg_rng_fail]
    call serial_puts64
    mov eax, LEGACY_STATUS_UNSUPPORTED
    ret

; rcx dest, rdx byte count
rng_safe_get:
    cmp dword [rel rng_ready], 1
    jne .unsupported
    test rdx, rdx
    jz .ok
    push rbx
    push rsi
    mov rsi, rcx
    mov rbx, rdx
.next_word:
    test rbx, rbx
    jz .done
    mov ecx, 32
.retry:
    rdrand rax
    jc .have
    loop .retry
    pop rsi
    pop rbx
    mov eax, LEGACY_STATUS_DEVICE
    ret
.have:
    mov rdx, 8
    cmp rbx, rdx
    jae .copy
    mov rdx, rbx
.copy:
    xor ecx, ecx
.copy_loop:
    cmp rcx, rdx
    jae .copied
    mov [rsi+rcx], al
    shr rax, 8
    inc rcx
    jmp .copy_loop
.copied:
    add rsi, rdx
    sub rbx, rdx
    jmp .next_word
.done:
    pop rsi
    pop rbx
.ok:
    xor eax, eax
    ret
.unsupported:
    mov eax, LEGACY_STATUS_UNSUPPORTED
    ret

; old tls code uses this name during setup
rng_safe_init:
    jmp legacy_rng_init64

align 8
rng_ready dd 0

msg_rng_ready    db '[RNG] cpu rdrand ready',13,10,0
msg_rng_fail     db '[ERROR] no hardware rng, tls disabled',13,10,0
msg_crypto_ready db '[CRYPTO] sha256 + hmac + prf + aes-gcm + x25519 + rsa + p256 ready',13,10,0

%include "sha256_full.inc"
%include "hmac_prf_full.inc"
%include "prf_safe.inc"
%include "aes128_safe.inc"
%include "gcm_safe.inc"
%include "x25519_full.inc"
%include "rsa_verify_full.inc"
%include "ecdsa_p256_verify.inc"
