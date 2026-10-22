; small tcp client for gateway.discord.gg:443 keeps one connection simple so tls can use
; it without dragging in uefi code

BITS 64

%define LEGACY_TCP_IDLE        0
%define LEGACY_TCP_WAIT_ARP    1
%define LEGACY_TCP_SYN_SENT    2
%define LEGACY_TCP_UP          3
%define LEGACY_TCP_FAILED      4
%define LEGACY_TCP_CLOSED      5

%define LEGACY_TCP_LOCAL_PORT  49153
%define LEGACY_TCP_REMOTE_PORT 443
%define LEGACY_TCP_MAX_PAYLOAD 1200
%define LEGACY_TCP_RX_CAP      65536

legacy_tcp_init64:
    mov dword [rel legacy_tcp_state], LEGACY_TCP_IDLE
    mov dword [rel legacy_tcp_retry], 0
    mov dword [rel legacy_tcp_retries], 0
    mov dword [rel legacy_tcp_rx_len], 0
    mov qword [rel legacy_tcp_rx_total], 0
    mov qword [rel legacy_tcp_tx_total], 0
    mov qword [rel legacy_tcp_bad], 0
    mov qword [rel legacy_tcp_rst], 0
    mov qword [rel legacy_tcp_rx_cb], 0
    mov qword [rel legacy_tcp_rx_arg], 0

%ifdef LEGACY_PINNED_GATEWAY_IP
   ; the pin helper validated one exact discord edge with windows. use that same endpoint so
   ; dns cannot hand the runtime a different edge with another leaf.
    mov dword [rel legacy_gateway_ip], LEGACY_PINNED_GATEWAY_IP
    mov dword [rel legacy_dns_state], LEGACY_DNS_READY
    lea rsi, [rel msg_tcp_pinned]
    call serial_puts64
    lea rcx, [rel legacy_gateway_ip]
    call legacy_print_ipv4_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
%endif

    mov ecx, (LEGACY_TCP_RX_CAP + 4095) / 4096
    call alloc_pages64
    test rax, rax
    jnz .got
    mov ecx, (LEGACY_TCP_RX_CAP + 4095) / 4096
    call alloc_high_pages64
.got:
    mov [rel legacy_tcp_rx_buf], rax
    test rax, rax
    jz .fail
    mov rdi, rax
    xor eax, eax
    mov ecx, LEGACY_TCP_RX_CAP / 8
    rep stosq
    lea rsi, [rel msg_tcp_ready]
    call serial_puts64
    ret
.fail:
    mov dword [rel legacy_tcp_state], LEGACY_TCP_FAILED
    lea rsi, [rel msg_tcp_mem_fail]
    call serial_puts64
    ret

; rcx callback, rdx arg
legacy_tcp_set_rx64:
    mov [rel legacy_tcp_rx_cb], rcx
    mov [rel legacy_tcp_rx_arg], rdx
    ret

legacy_tcp_load_be16:
    movzx eax, word [rcx]
    xchg al, ah
    and eax, 0xFFFF
    ret

legacy_tcp_load_be32:
    mov eax, [rcx]
    bswap eax
    ret

legacy_tcp_store_be16:
    mov eax, edx
    xchg al, ah
    mov [rcx], ax
    ret

legacy_tcp_store_be32:
    mov eax, edx
    bswap eax
    mov [rcx], eax
    ret

; checksum tcp plus the ipv4 pseudo header
legacy_tcp_checksum64:
    push rbx
    push rsi
    push rdi
    mov rsi, rcx
    mov edi, edx
    xor ebx, ebx

    lea r10, [rel legacy_ipv4_addr]
    xor r8d, r8d
.local_ip:
    movzx eax, byte [r10+r8]
    shl eax, 8
    movzx edx, byte [r10+r8+1]
    or eax, edx
    add ebx, eax
    add r8d, 2
    cmp r8d, 4
    jb .local_ip

    lea r10, [rel legacy_gateway_ip]
    xor r8d, r8d
.remote_ip:
    movzx eax, byte [r10+r8]
    shl eax, 8
    movzx edx, byte [r10+r8+1]
    or eax, edx
    add ebx, eax
    add r8d, 2
    cmp r8d, 4
    jb .remote_ip

    add ebx, 6
    add ebx, edi
.sum:
    cmp edi, 2
    jb .odd
    movzx eax, byte [rsi]
    shl eax, 8
    movzx edx, byte [rsi+1]
    or eax, edx
    add ebx, eax
    add rsi, 2
    sub edi, 2
    jmp .sum
.odd:
    test edi, edi
    jz .fold
    movzx eax, byte [rsi]
    shl eax, 8
    add ebx, eax
.fold:
    mov eax, ebx
    shr eax, 16
    and ebx, 0xFFFF
    add ebx, eax
    mov eax, ebx
    shr eax, 16
    and ebx, 0xFFFF
    add ebx, eax
    mov eax, ebx
    not eax
    and eax, 0xFFFF
    xchg al, ah
    pop rdi
    pop rsi
    pop rbx
    ret

; rcx payload or zero, edx len, r8d flags
legacy_tcp_send_segment64:
    push rbx
    push r12
    push r13
    push r14
    mov r12, rcx
    mov r13d, edx
    mov r14d, r8d
    cmp r13d, LEGACY_TCP_MAX_PAYLOAD
    ja .fail
    call legacy_tx_alloc64
    test rax, rax
    jz .fail
    mov rbx, rax

    mov rcx, rbx
    mov edx, LEGACY_TCP_LOCAL_PORT
    call legacy_tcp_store_be16
    lea rcx, [rbx+2]
    mov edx, LEGACY_TCP_REMOTE_PORT
    call legacy_tcp_store_be16
    lea rcx, [rbx+4]
    mov edx, [rel legacy_tcp_local_seq]
    call legacy_tcp_store_be32
    lea rcx, [rbx+8]
    mov edx, [rel legacy_tcp_remote_seq]
    call legacy_tcp_store_be32
    mov byte [rbx+12], 0x50
    mov [rbx+13], r14b
    mov word [rbx+14], 0xF0FA
    mov word [rbx+16], 0
    mov word [rbx+18], 0

    test r13d, r13d
    jz .checksum
    lea rdi, [rbx+20]
    mov rsi, r12
    mov ecx, r13d
    rep movsb
.checksum:
    mov rcx, rbx
    mov edx, r13d
    add edx, 20
    call legacy_tcp_checksum64
    mov [rbx+16], ax

    mov ecx, [rel legacy_gateway_ip]
    mov edx, 6
    mov r8, rbx
    mov r9d, r13d
    add r9d, 20
    call legacy_ipv4_send64
    test eax, eax
    jnz .out
    inc qword [rel legacy_tcp_tx_total]
    test r14b, 0x02
    jz .payload_seq
    inc dword [rel legacy_tcp_local_seq]
.payload_seq:
    test r13d, r13d
    jz .out
    add [rel legacy_tcp_local_seq], r13d
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.fail:
    mov eax, 0xFFFF
    jmp .out

legacy_tcp_send_ack64:
    xor ecx, ecx
    xor edx, edx
    mov r8d, 0x10
    call legacy_tcp_send_segment64
    ret

; rcx bytes, edx len
legacy_tcp_send64:
    cmp dword [rel legacy_tcp_state], LEGACY_TCP_UP
    jne .not_ready
    mov r8d, 0x18
    call legacy_tcp_send_segment64
    ret
.not_ready:
    mov eax, 1
    ret

legacy_tcp_start64:
    cmp dword [rel legacy_dns_state], LEGACY_DNS_READY
    jne .not_ready
    cmp dword [rel legacy_tcp_state], LEGACY_TCP_IDLE
    jne .not_ready
    mov eax, [rel legacy_gateway_ip]
    test eax, eax
    jz .not_ready
    rdtsc
    xor eax, edx
    test eax, eax
    jnz .seq
    mov eax, 0x145A2173
.seq:
    mov [rel legacy_tcp_local_seq], eax
    mov dword [rel legacy_tcp_remote_seq], 0
    mov dword [rel legacy_tcp_retry], 0
    mov dword [rel legacy_tcp_retries], 0
    mov dword [rel legacy_tcp_state], LEGACY_TCP_WAIT_ARP
    lea rsi, [rel msg_tcp_start]
    call serial_puts64
    xor eax, eax
    ret
.not_ready:
    mov eax, 1
    ret

; rcx tcp bytes, edx len, r8d source ip
legacy_tcp_rx64:
    push rbx
    push r12
    push r13
    mov r12, rcx
    mov r13d, edx
    cmp r8d, [rel legacy_gateway_ip]
    jne .done
    cmp r13d, 20
    jb .bad

    mov rcx, r12
    call legacy_tcp_load_be16
    cmp eax, LEGACY_TCP_REMOTE_PORT
    jne .done
    lea rcx, [r12+2]
    call legacy_tcp_load_be16
    cmp eax, LEGACY_TCP_LOCAL_PORT
    jne .done

    mov rcx, r12
    mov edx, r13d
    call legacy_tcp_checksum64
    test ax, ax
    jnz .bad

    movzx ebx, byte [r12+12]
    shr ebx, 4
    cmp ebx, 5
    jb .bad
    shl ebx, 2
    cmp ebx, r13d
    ja .bad

    test byte [r12+13], 0x04
    jz .state
    inc qword [rel legacy_tcp_rst]
    mov dword [rel legacy_tcp_state], LEGACY_TCP_FAILED
    lea rsi, [rel msg_tcp_rst]
    call serial_puts64
    jmp .done
.state:
    cmp dword [rel legacy_tcp_state], LEGACY_TCP_SYN_SENT
    je .syn
    cmp dword [rel legacy_tcp_state], LEGACY_TCP_UP
    je .up
    jmp .done
.syn:
    mov al, [r12+13]
    and al, 0x12
    cmp al, 0x12
    jne .done
    lea rcx, [r12+8]
    call legacy_tcp_load_be32
    cmp eax, [rel legacy_tcp_local_seq]
    jne .bad
    lea rcx, [r12+4]
    call legacy_tcp_load_be32
    inc eax
    mov [rel legacy_tcp_remote_seq], eax
    mov dword [rel legacy_tcp_state], LEGACY_TCP_UP
    call legacy_tcp_send_ack64
    lea rsi, [rel msg_tcp_up]
    call serial_puts64
    jmp .done
.up:
    lea rcx, [r12+4]
    call legacy_tcp_load_be32
    cmp eax, [rel legacy_tcp_remote_seq]
    jne .ack
    mov eax, r13d
    sub eax, ebx
    jbe .fin
    mov r10d, eax
    mov eax, [rel legacy_tcp_rx_len]
    mov edx, LEGACY_TCP_RX_CAP
    sub edx, eax
    cmp r10d, edx
    ja .bad
    mov rdi, [rel legacy_tcp_rx_buf]
    add rdi, rax
    lea rsi, [r12+rbx]
    mov ecx, r10d
    rep movsb
    add [rel legacy_tcp_rx_len], r10d
    add [rel legacy_tcp_remote_seq], r10d
    add qword [rel legacy_tcp_rx_total], r10

    mov rax, [rel legacy_tcp_rx_cb]
    test rax, rax
    jz .fin
    lea rcx, [r12+rbx]
    mov edx, r10d
    mov r8, [rel legacy_tcp_rx_arg]
    sub rsp, 32
    call rax
    add rsp, 32
.fin:
    test byte [r12+13], 0x01
    jz .ack
    inc dword [rel legacy_tcp_remote_seq]
    mov dword [rel legacy_tcp_state], LEGACY_TCP_CLOSED
.ack:
    call legacy_tcp_send_ack64
    jmp .done
.bad:
    inc qword [rel legacy_tcp_bad]
.done:
    pop r13
    pop r12
    pop rbx
    ret

; handle arp then syn retries without blocking packet polling
legacy_tcp_tick64:
    cmp dword [rel legacy_tcp_state], LEGACY_TCP_IDLE
    jne .state
    cmp dword [rel legacy_dns_state], LEGACY_DNS_READY
    jne .done
    call legacy_tcp_start64
.state:
    mov eax, [rel legacy_tcp_state]
    cmp eax, LEGACY_TCP_WAIT_ARP
    je .wait_arp
    cmp eax, LEGACY_TCP_SYN_SENT
    je .wait_syn
    jmp .done
.wait_arp:
    mov ecx, [rel legacy_gateway_ip]
    call legacy_route_ip64
    mov ecx, eax
    lea rdx, [rel legacy_tcp_dest_mac]
    call legacy_arp_lookup64
    test eax, eax
    jnz .syn
    inc dword [rel legacy_tcp_retry]
    cmp dword [rel legacy_tcp_retry], 150000
    jb .done
    mov dword [rel legacy_tcp_retry], 0
    mov ecx, [rel legacy_gateway_ip]
    call legacy_route_ip64
    mov ecx, eax
    call legacy_arp_request64
    jmp .done
.syn:
    xor ecx, ecx
    xor edx, edx
    mov r8d, 0x02
    call legacy_tcp_send_segment64
    test eax, eax
    jnz .done
    mov dword [rel legacy_tcp_state], LEGACY_TCP_SYN_SENT
    mov dword [rel legacy_tcp_retry], 0
    lea rsi, [rel msg_tcp_syn]
    call serial_puts64
    jmp .done
.wait_syn:
    inc dword [rel legacy_tcp_retry]
    cmp dword [rel legacy_tcp_retry], 500000
    jb .done
    mov dword [rel legacy_tcp_retry], 0
    inc dword [rel legacy_tcp_retries]
    cmp dword [rel legacy_tcp_retries], 5
    ja .fail
   ; resend with the original syn sequence number
    dec dword [rel legacy_tcp_local_seq]
    xor ecx, ecx
    xor edx, edx
    mov r8d, 0x02
    call legacy_tcp_send_segment64
    jmp .done
.fail:
    mov dword [rel legacy_tcp_state], LEGACY_TCP_FAILED
    lea rsi, [rel msg_tcp_fail]
    call serial_puts64
.done:
    ret

align 16
legacy_tcp_state       dd 0
legacy_tcp_local_seq   dd 0
legacy_tcp_remote_seq  dd 0
legacy_tcp_retry       dd 0
legacy_tcp_retries     dd 0
legacy_tcp_dest_mac    times 6 db 0
legacy_tcp_rx_buf      dq 0
legacy_tcp_rx_len      dd 0
legacy_tcp_rx_cb       dq 0
legacy_tcp_rx_arg      dq 0
legacy_tcp_rx_total    dq 0
legacy_tcp_tx_total    dq 0
legacy_tcp_bad         dq 0
legacy_tcp_rst         dq 0

msg_tcp_ready    db '[TCP] client runtime ready',13,10,0
msg_tcp_mem_fail db '[ERROR] tcp receive memory allocation failed',13,10,0
msg_tcp_pinned   db '[TCP] using build-validated Discord edge ',0
msg_tcp_start    db '[TCP] starting gateway.discord.gg:443',13,10,0
msg_tcp_syn      db '[TCP] SYN sent',13,10,0
msg_tcp_up       db '[TCP] gateway connection established',13,10,0
msg_tcp_rst      db '[TCP] gateway reset connection',13,10,0
msg_tcp_fail     db '[TCP] gateway connection failed',13,10,0
