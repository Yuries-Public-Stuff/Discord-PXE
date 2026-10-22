; load extra files from the same pxe server after boot this gives the shell real file
; access without needing a disk driver yet

BITS 64

%define PXENV_TFTP_OPEN       0x0020
%define PXENV_TFTP_CLOSE      0x0021
%define PXENV_TFTP_READ       0x0022

%define TFTP_OPEN_STATUS       0
%define TFTP_OPEN_SERVER_IP    2
%define TFTP_OPEN_GATEWAY_IP   6
%define TFTP_OPEN_FILENAME    10
%define TFTP_OPEN_PORT       138
%define TFTP_OPEN_PACKETSIZE 140
%define TFTP_OPEN_SIZE       142

%define TFTP_READ_STATUS       0
%define TFTP_READ_PACKET       2
%define TFTP_READ_BUFSIZE      4
%define TFTP_READ_BUFFER       6
%define TFTP_READ_SIZE        10

%define TFTP_CLOSE_STATUS      0
%define TFTP_CLOSE_SIZE        2

%define TFTP_FETCH_CAP       1048576
%define TFTP_BLOCK_BYTES     512
%define TFTP_SCRATCH_PHYS    0x00070000
%define TFTP_SCRATCH_SEG     0x7000
%define PXE_BOOT_SERVER_IPV4 0xB501A8C0

legacy_tftp_files_init64:
    mov dword [rel tftp_file_ready], 0
    mov dword [rel tftp_file_valid], 0
    mov dword [rel tftp_file_len], 0
    mov word [rel tftp_last_status], 0

   ; tiny pxe is the file server. option 54 is only the dhcp lease server.
    mov dword [rel tftp_server_ip], PXE_BOOT_SERVER_IPV4
    mov dword [rel tftp_gateway_ip], 0

    mov ecx, TFTP_FETCH_CAP / 4096
    call alloc_pages64
    mov [rel tftp_file_buf], rax
    test rax, rax
    jz .fail

    mov dword [rel tftp_file_ready], 1
    lea rsi, [rel msg_tftp_ready]
    call serial_puts64
    ret
.fail:
    lea rsi, [rel msg_tftp_mem_fail]
    call serial_puts64
    ret

; rcx is a zero ended filename on the pxe server use open/read/close because this realtek
; rom hangs on pxenv_tftp_read_file
legacy_tftp_fetch64:
    cmp dword [rel tftp_file_ready], 1
    jne .fail
    test rcx, rcx
    jz .fail

    push rbx
    push r12
    push r13
    push r14
    mov r12, rcx
    xor r13d, r13d
    xor r14d, r14d
    mov dword [rel tftp_file_valid], 0
    mov dword [rel tftp_file_len], 0
    mov dword [rel tftp_file_secret], 0
    mov word [rel tftp_last_status], 0

   ; keep a private copy of the requested name
    lea rdi, [rel tftp_file_name]
    xor eax, eax
    mov ecx, 128
    rep stosb
    lea rdi, [rel tftp_file_name]
    xor ecx, ecx
.copy_name:
    cmp ecx, 127
    jae .name_done
    mov al, [r12+rcx]
    mov [rdi+rcx], al
    test al, al
    jz .name_done
    inc ecx
    jmp .copy_name
.name_done:
    mov byte [rdi+127], 0

   ; auth files can be fetched but never dumped by shell helpers
    lea rcx, [rel tftp_file_name]
    lea rdx, [rel tftp_secret_token]
    call legacy_tftp_name_eq64
    test eax, eax
    jnz .secret
    lea rcx, [rel tftp_file_name]
    lea rdx, [rel tftp_secret_pin]
    call legacy_tftp_name_eq64
    test eax, eax
    jz .name_safe
.secret:
    mov dword [rel tftp_file_secret], 1
.name_safe:

   ; build pxenv_tftp_open exactly like the stage1 path that works on this rom
    lea rdi, [rel tftp_open_pb]
    xor eax, eax
    mov ecx, TFTP_OPEN_SIZE
    rep stosb
    mov eax, [rel tftp_server_ip]
    mov [rel tftp_open_pb + TFTP_OPEN_SERVER_IP], eax
    mov dword [rel tftp_open_pb + TFTP_OPEN_GATEWAY_IP], 0
    lea rsi, [rel tftp_file_name]
    lea rdi, [rel tftp_open_pb + TFTP_OPEN_FILENAME]
    mov ecx, 128
    rep movsb
    mov word [rel tftp_open_pb + TFTP_OPEN_PORT], 0x4500

   ; zero avoids blksize negotiation on the old realtek pxe rom
    mov word [rel tftp_open_pb + TFTP_OPEN_PACKETSIZE], 0

    mov ecx, PXENV_TFTP_OPEN
    lea rdx, [rel tftp_open_pb]
    mov r8d, TFTP_OPEN_SIZE
    call pxe_rm_call64
    test eax, eax
    jnz .open_call_fail
    mov ax, [rel tftp_open_pb + TFTP_OPEN_STATUS]
    test ax, ax
    jnz .open_status_fail
    mov r14d, 1

.read_next:
    lea rdi, [rel tftp_read_pb]
    xor eax, eax
    mov ecx, TFTP_READ_SIZE
    rep stosb
    mov word [rel tftp_read_pb + TFTP_READ_BUFSIZE], TFTP_BLOCK_BYTES
    mov word [rel tftp_read_pb + TFTP_READ_BUFFER + 0], 0
    mov word [rel tftp_read_pb + TFTP_READ_BUFFER + 2], TFTP_SCRATCH_SEG

    mov ecx, PXENV_TFTP_READ
    lea rdx, [rel tftp_read_pb]
    mov r8d, TFTP_READ_SIZE
    call pxe_rm_call64
    test eax, eax
    jnz .read_call_fail
    mov ax, [rel tftp_read_pb + TFTP_READ_STATUS]
    test ax, ax
    jnz .read_status_fail

    movzx ebx, word [rel tftp_read_pb + TFTP_READ_BUFSIZE]
    cmp ebx, TFTP_BLOCK_BYTES
    ja .bad_size
    mov eax, r13d
    add eax, ebx
    cmp eax, TFTP_FETCH_CAP
    ja .too_big

    test ebx, ebx
    jz .done_read
    mov rsi, TFTP_SCRATCH_PHYS
    mov rdi, [rel tftp_file_buf]
    add rdi, r13
    mov ecx, ebx
    rep movsb
    add r13d, ebx
    cmp ebx, TFTP_BLOCK_BYTES
    je .read_next

.done_read:
    call legacy_tftp_close64
    mov r14d, 0
    mov [rel tftp_file_len], r13d
    mov dword [rel tftp_file_valid], 1

    lea rsi, [rel msg_tftp_ok]
    call serial_puts64
    lea rsi, [rel tftp_file_name]
    call serial_puts64
    lea rsi, [rel msg_tftp_size]
    call serial_puts64
    mov eax, r13d
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64

    xor eax, eax
    jmp .out

.open_call_fail:
    mov [rel tftp_last_status], ax
    jmp .pxe_fail
.open_status_fail:
    mov [rel tftp_last_status], ax
    jmp .pxe_fail
.read_call_fail:
    mov [rel tftp_last_status], ax
    jmp .close_fail
.read_status_fail:
    mov [rel tftp_last_status], ax
    jmp .close_fail
.bad_size:
    mov word [rel tftp_last_status], 0xFF01
    jmp .close_fail
.too_big:
    mov word [rel tftp_last_status], 0xFF02
.close_fail:
    cmp r14d, 1
    jne .pxe_fail
    call legacy_tftp_close64
    mov r14d, 0
.pxe_fail:
    lea rsi, [rel msg_tftp_fail]
    call serial_puts64
    movzx eax, word [rel tftp_last_status]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    mov eax, 1
    jmp .out
.fail:
    mov eax, 1
    ret
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

legacy_tftp_close64:
    lea rdi, [rel tftp_close_pb]
    xor eax, eax
    mov ecx, TFTP_CLOSE_SIZE
    rep stosb
    mov ecx, PXENV_TFTP_CLOSE
    lea rdx, [rel tftp_close_pb]
    mov r8d, TFTP_CLOSE_SIZE
    call pxe_rm_call64
    test eax, eax
    jnz .ret
    movzx eax, word [rel tftp_close_pb + TFTP_CLOSE_STATUS]
.ret:
    ret

legacy_tftp_name_eq64:
.loop:
    mov al, [rcx]
    cmp al, [rdx]
    jne .no
    test al, al
    jz .yes
    inc rcx
    inc rdx
    jmp .loop
.yes:
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; print fetched text but never let secret config leak into com logs
legacy_tftp_cat64:
    cmp dword [rel tftp_file_valid], 1
    jne .none
    cmp dword [rel tftp_file_secret], 1
    je .secret
    mov rsi, [rel tftp_file_buf]
    mov ecx, [rel tftp_file_len]
    test ecx, ecx
    jz .done
.loop:
    mov al, [rsi]
    inc rsi
    dec ecx
    test al, al
    jz .done
    cmp al, 9
    je .emit
    cmp al, 10
    je .emit
    cmp al, 13
    je .emit
    cmp al, 32
    jb .binary
    cmp al, 126
    ja .binary
.emit:
    call serial_putc64_al
    test ecx, ecx
    jnz .loop
.done:
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    xor eax, eax
    ret
.binary:
    lea rsi, [rel msg_tftp_binary]
    call serial_puts64
    mov eax, 1
    ret
.secret:
    lea rsi, [rel msg_tftp_secret]
    call serial_puts64
    mov eax, 1
    ret
.none:
    lea rsi, [rel msg_tftp_none]
    call serial_puts64
    mov eax, 1
    ret

; show the first bytes unless this is one of the protected secret files
legacy_tftp_hex64:
    cmp dword [rel tftp_file_valid], 1
    jne .none
    cmp dword [rel tftp_file_secret], 1
    je .secret
    mov rbx, [rel tftp_file_buf]
    mov ecx, [rel tftp_file_len]
    cmp ecx, 256
    jbe .count_ok
    mov ecx, 256
.count_ok:
    xor r12d, r12d
.loop:
    test ecx, ecx
    jz .done
    test r12d, 15
    jnz .byte
    lea rsi, [rel msg_tftp_hex_line]
    call serial_puts64
    mov eax, r12d
    call serial_hex32_64
    mov al, ' '
    call serial_putc64_al
.byte:
    movzx eax, byte [rbx+r12]
    call legacy_hex_byte64
    mov al, ' '
    call serial_putc64_al
    inc r12d
    dec ecx
    test r12d, 15
    jnz .loop
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    jmp .loop
.done:
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    xor eax, eax
    ret
.secret:
    lea rsi, [rel msg_tftp_secret]
    call serial_puts64
    mov eax, 1
    ret
.none:
    lea rsi, [rel msg_tftp_none]
    call serial_puts64
    mov eax, 1
    ret

legacy_hex_byte64:
    push rbx
    mov ebx, eax
    shr eax, 4
    and eax, 0xF
    call legacy_hex_nibble64
    mov eax, ebx
    and eax, 0xF
    call legacy_hex_nibble64
    pop rbx
    ret

legacy_hex_nibble64:
    cmp eax, 9
    jbe .num
    add eax, 'A'-10
    jmp serial_putc64_al
.num:
    add eax, '0'
    jmp serial_putc64_al

align 16
tftp_open_pb    times TFTP_OPEN_SIZE db 0
tftp_read_pb    times TFTP_READ_SIZE db 0
tftp_close_pb   times TFTP_CLOSE_SIZE db 0
tftp_file_name  times 128 db 0
tftp_file_buf   dq 0
tftp_file_len   dd 0
tftp_file_ready dd 0
tftp_file_valid dd 0
tftp_file_secret dd 0
tftp_server_ip  dd 0
tftp_gateway_ip dd 0
tftp_last_status dw 0

tftp_secret_token db 'discord/token.txt',0
tftp_secret_pin   db 'discord/pin.bin',0

msg_tftp_ready     db '[FILE] realtek-safe pxe tftp ready at 192.168.1.181, max file 1mb',13,10,0
msg_tftp_mem_fail  db '[ERROR] no ram for tftp file buffer',13,10,0
msg_tftp_ok        db '[FILE] loaded ',0
msg_tftp_size      db ' bytes=0x',0
msg_tftp_fail      db '[FILE] pxe load failed status=0x',0
msg_tftp_none      db 'no fetched file',13,10,0
msg_tftp_secret    db 'secret file output blocked',13,10,0
msg_tftp_binary    db 13,10,'binary data stopped text output, use hex',13,10,0
msg_tftp_hex_line  db 13,10,'0x',0
