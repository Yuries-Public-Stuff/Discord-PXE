; small read only file view for debugging the runtime these files expose live state
; without needing a disk filesystem yet

BITS 64

legacy_vfs_init64:
    lea rsi, [rel msg_vfs_ready]
    call serial_puts64
    ret

legacy_vfs_ls64:
    lea rsi, [rel msg_vfs_ls]
    call serial_puts64
    ret

; rcx points at a zero ended path
legacy_vfs_cat64:
    push rbx
    mov rbx, rcx

    mov rcx, rbx
    lea rdx, [rel path_cpu]
    call legacy_str_eq64
    test eax, eax
    jnz .cpu

    mov rcx, rbx
    lea rdx, [rel path_mem]
    call legacy_str_eq64
    test eax, eax
    jnz .mem

    mov rcx, rbx
    lea rdx, [rel path_e820]
    call legacy_str_eq64
    test eax, eax
    jnz .e820

    mov rcx, rbx
    lea rdx, [rel path_pci]
    call legacy_str_eq64
    test eax, eax
    jnz .pci

    mov rcx, rbx
    lea rdx, [rel path_net]
    call legacy_str_eq64
    test eax, eax
    jnz .net

    mov rcx, rbx
    lea rdx, [rel path_netstats]
    call legacy_str_eq64
    test eax, eax
    jnz .netstats

    mov rcx, rbx
    lea rdx, [rel path_pxe]
    call legacy_str_eq64
    test eax, eax
    jnz .pxe

    mov rcx, rbx
    lea rdx, [rel path_tls]
    call legacy_str_eq64
    test eax, eax
    jnz .tls

    mov rcx, rbx
    lea rdx, [rel path_discord]
    call legacy_str_eq64
    test eax, eax
    jnz .discord

    lea rsi, [rel msg_vfs_missing]
    call serial_puts64
    jmp .done
.cpu:
    lea rsi, [rel msg_vfs_cpu]
    call serial_puts64
    lea rsi, [rel cpu_vendor]
    call serial_puts64
    lea rsi, [rel msg_vfs_cpu_count]
    call serial_puts64
    mov eax, [rel ap_online_count]
    call serial_hex32_64
    lea rsi, [rel msg_vfs_cpu_threads]
    call serial_puts64
    mov eax, [rel legacy_threads_per_core]
    call serial_hex32_64
    lea rsi, [rel msg_vfs_cpu_cores]
    call serial_puts64
    mov eax, [rel legacy_cores_per_package]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    jmp .done
.mem:
    lea rsi, [rel msg_vfs_mem]
    call serial_puts64
    mov rax, [rel ram_total_usable]
    call serial_hex64
    lea rsi, [rel msg_vfs_mem_high]
    call serial_puts64
    mov rax, [rel ram_highest]
    call serial_hex64
    lea rsi, [rel msg_vfs_mem_heap]
    call serial_puts64
    mov rax, [rel heap_next]
    call serial_hex64
    lea rsi, [rel msg_vfs_mem_direct]
    call serial_puts64
    mov eax, [rel direct_gib]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    jmp .done
.e820:
    call legacy_vfs_print_e82064
    jmp .done
.pci:
    call legacy_vfs_print_pci64
    jmp .done
.net:
    lea rsi, [rel msg_vfs_net]
    call serial_puts64
    lea rcx, [rel legacy_ipv4_addr]
    call legacy_print_ipv4_64
    lea rsi, [rel msg_vfs_net_router]
    call serial_puts64
    lea rcx, [rel legacy_router_addr]
    call legacy_print_ipv4_64
    lea rsi, [rel msg_vfs_net_dns]
    call serial_puts64
    lea rcx, [rel legacy_dns_addr]
    call legacy_print_ipv4_64
    lea rsi, [rel msg_vfs_tcp_state]
    call serial_puts64
    mov eax, [rel legacy_tcp_state]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    jmp .done
.netstats:
    lea rsi, [rel msg_vfs_rx]
    call serial_puts64
    mov rax, [rel legacy_rx_packets]
    call serial_hex64
    lea rsi, [rel msg_vfs_tx]
    call serial_puts64
    mov rax, [rel legacy_tx_packets]
    call serial_hex64
    lea rsi, [rel msg_vfs_drop]
    call serial_puts64
    mov rax, [rel legacy_rx_dropped]
    call serial_hex64
    lea rsi, [rel msg_vfs_tcp_rx]
    call serial_puts64
    mov rax, [rel legacy_tcp_rx_total]
    call serial_hex64
    lea rsi, [rel msg_vfs_tcp_tx]
    call serial_puts64
    mov rax, [rel legacy_tcp_tx_total]
    call serial_hex64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    jmp .done
.pxe:
    lea rsi, [rel msg_vfs_pxe]
    call serial_puts64
    movzx eax, word [rel pxe_version]
    call serial_hex32_64
    lea rsi, [rel msg_vfs_pxe_thunk]
    call serial_puts64
    mov eax, [rel pxe_thunk_proven]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    jmp .done
.tls:
    lea rsi, [rel msg_vfs_tls]
    call serial_puts64
    mov eax, [rel legacy_tls_state]
    call serial_hex32_64
    lea rsi, [rel msg_vfs_tls_rx]
    call serial_puts64
    mov rax, [rel legacy_tls_rx_bytes]
    call serial_hex64
    lea rsi, [rel msg_vfs_tls_tx]
    call serial_puts64
    mov rax, [rel legacy_tls_tx_bytes]
    call serial_hex64
    lea rsi, [rel msg_vfs_tls_pin]
    call serial_puts64
    mov eax, [rel legacy_leaf_key_ready]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    jmp .done
.discord:
    lea rsi, [rel msg_vfs_discord]
    call serial_puts64
    mov eax, [rel discord_base_state]
    call serial_hex32_64
    lea rsi, [rel msg_vfs_discord_rx]
    call serial_puts64
    mov rax, [rel discord_rx_total]
    call serial_hex64
    lea rsi, [rel msg_vfs_discord_hb]
    call serial_puts64
    mov rax, [rel dgw_heartbeats_sent]
    call serial_hex64
    lea rsi, [rel msg_vfs_discord_ack]
    call serial_puts64
    mov rax, [rel dgw_heartbeat_acks]
    call serial_hex64
    lea rsi, [rel msg_vfs_discord_ready]
    call serial_puts64
    mov eax, [rel dgw_ready]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
.done:
    pop rbx
    ret

; dump the bios ram ranges so bad memory choices are visible over serial
legacy_vfs_print_e82064:
    movzx ecx, word [rel e820_count]
    lea rbx, [rel e820_map]
    xor r12d, r12d
.loop:
    test ecx, ecx
    jz .done
    lea rsi, [rel msg_vfs_e820_idx]
    call serial_puts64
    mov eax, r12d
    call serial_hex32_64
    lea rsi, [rel msg_vfs_e820_base]
    call serial_puts64
    mov rax, [rbx+0]
    call serial_hex64
    lea rsi, [rel msg_vfs_e820_len]
    call serial_puts64
    mov rax, [rbx+8]
    call serial_hex64
    lea rsi, [rel msg_vfs_e820_type]
    call serial_puts64
    mov eax, [rbx+16]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    add rbx, E820_ENTRY_SIZE
    inc r12d
    dec ecx
    jmp .loop
.done:
    ret

; show every pci function we kept during the early hardware scan
legacy_vfs_print_pci64:
    mov ecx, [rel pci_device_count]
    lea rbx, [rel pci_devices]
    xor r12d, r12d
.loop:
    test ecx, ecx
    jz .done
    lea rsi, [rel msg_vfs_pci_idx]
    call serial_puts64
    mov eax, r12d
    call serial_hex32_64
    lea rsi, [rel msg_vfs_pci_bdf]
    call serial_puts64
    movzx eax, byte [rbx+0]
    call serial_hex32_64
    mov al, ':'
    call serial_putc64_al
    movzx eax, byte [rbx+1]
    call serial_hex32_64
    mov al, '.'
    call serial_putc64_al
    movzx eax, byte [rbx+2]
    call serial_hex32_64
    lea rsi, [rel msg_vfs_pci_id]
    call serial_puts64
    mov eax, [rbx+4]
    call serial_hex32_64
    lea rsi, [rel msg_vfs_pci_class]
    call serial_puts64
    mov eax, [rbx+8]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    add rbx, 16
    inc r12d
    dec ecx
    jmp .loop
.done:
    ret

; rcx and rdx are zero ended strings
legacy_str_eq64:
.loop:
    mov al, [rcx]
    mov r8b, [rdx]
    cmp al, r8b
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

path_cpu      db 'sys/cpu',0
path_mem      db 'sys/mem',0
path_e820     db 'sys/e820',0
path_pci      db 'sys/pci',0
path_net      db 'net/status',0
path_netstats db 'net/stats',0
path_pxe      db 'boot/pxe',0
path_tls      db 'net/tls',0
path_discord  db 'discord/status',0

msg_vfs_ready     db '[VFS] runtime file view ready',13,10,0
msg_vfs_ls        db 'boot/pxe',13,10,'sys/cpu',13,10,'sys/mem',13,10,'sys/e820',13,10,'sys/pci',13,10,'net/status',13,10,'net/stats',13,10,'net/tls',13,10,'discord/status',13,10,0
msg_vfs_missing   db 'file not found',13,10,0
msg_vfs_cpu       db 'vendor=',0
msg_vfs_cpu_count db ' cpus=0x',0
msg_vfs_cpu_threads db ' threads/core=0x',0
msg_vfs_cpu_cores db ' cores/package=0x',0
msg_vfs_mem       db 'usable=0x',0
msg_vfs_mem_high  db ' highest=0x',0
msg_vfs_mem_heap  db ' heap-next=0x',0
msg_vfs_mem_direct db ' direct-gib=0x',0
msg_vfs_net       db 'ip=',0
msg_vfs_net_router db ' router=',0
msg_vfs_net_dns   db ' dns=',0
msg_vfs_tcp_state db ' tcp-state=0x',0
msg_vfs_rx        db 'rx=0x',0
msg_vfs_tx        db ' tx=0x',0
msg_vfs_drop      db ' drop=0x',0
msg_vfs_tcp_rx    db ' tcp-rx=0x',0
msg_vfs_tcp_tx    db ' tcp-tx=0x',0
msg_vfs_pxe       db 'pxenv-version=0x',0
msg_vfs_pxe_thunk db ' thunk=0x',0
msg_vfs_tls       db 'state=0x',0
msg_vfs_tls_rx    db ' rx=0x',0
msg_vfs_tls_tx    db ' tx=0x',0
msg_vfs_tls_pin   db ' pin-ok=0x',0
msg_vfs_discord   db 'state=0x',0
msg_vfs_discord_rx db ' rx=0x',0
msg_vfs_discord_hb db ' hb=0x',0
msg_vfs_discord_ack db ' ack=0x',0
msg_vfs_discord_ready db ' ready=0x',0
msg_vfs_e820_idx  db '[',0
msg_vfs_e820_base db '] base=0x',0
msg_vfs_e820_len  db ' len=0x',0
msg_vfs_e820_type db ' type=0x',0
msg_vfs_pci_idx   db '[',0
msg_vfs_pci_bdf   db '] bdf=',0
msg_vfs_pci_id    db ' id=0x',0
msg_vfs_pci_class db ' class=0x',0

; experimental sharding support is kept behind the working shell path.
%include "legacy_shards.inc"
