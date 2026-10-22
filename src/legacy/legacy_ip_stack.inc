; arp ipv4 udp and dns for the legacy build uses the address pxe already got
; so we do not redo

BITS 64

%define LEGACY_ETH_HDR        14
%define LEGACY_IPV4_HDR       20
%define LEGACY_UDP_HDR         8
%define LEGACY_DNS_PORT       53
%define LEGACY_DNS_LOCAL      53000
%define LEGACY_TX_SLOTS        8
%define LEGACY_TX_SLOT_BYTES  2048
%define LEGACY_ARP_SLOTS      16

%define LEGACY_DNS_IDLE        0
%define LEGACY_DNS_WAIT_ARP    1
%define LEGACY_DNS_SENT        2
%define LEGACY_DNS_READY       3
%define LEGACY_DNS_FAILED      4
%define LEGACY_DNS_RETRY_TICKS 10000

legacy_ip_stack_init64:
    mov eax, [rel cached_ipv4]
    mov [rel legacy_ipv4_addr], eax

    mov eax, [rel undi_info + UNDI_CURR_MAC]
    mov [rel legacy_mac], eax
    mov ax, [rel undi_info + UNDI_CURR_MAC + 4]
    mov [rel legacy_mac + 4], ax

    mov dword [rel legacy_subnet_mask], 0
    mov dword [rel legacy_router_addr], 0
    mov dword [rel legacy_dns_addr], 0
    mov dword [rel legacy_dns_state], LEGACY_DNS_IDLE
    mov dword [rel legacy_arp_count], 0
    mov dword [rel legacy_tx_index], 0
    mov dword [rel legacy_dns_retry], 0
    mov dword [rel legacy_ip_ready], 0

    call legacy_parse_cached_dhcp64
    call legacy_tx_pool_init64
    test rax, rax
    jz .fail

    lea rcx, [rel legacy_eth_rx64]
    xor edx, edx
    call legacy_net_set_handler64

    mov dword [rel legacy_ip_ready], 1
    lea rsi, [rel msg_ip_addr]
    call serial_puts64
    lea rcx, [rel legacy_ipv4_addr]
    call legacy_print_ipv4_64
    lea rsi, [rel msg_ip_router]
    call serial_puts64
    lea rcx, [rel legacy_router_addr]
    call legacy_print_ipv4_64
    lea rsi, [rel msg_ip_dns]
    call serial_puts64
    lea rcx, [rel legacy_dns_addr]
    call legacy_print_ipv4_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    ret
.fail:
    lea rsi, [rel msg_ip_fail]
    call serial_puts64
    ret

; pull subnet router and dns out of the dhcp ack the pxe rom kept
legacy_parse_cached_dhcp64:
  ; current sharded stage1 publishes dhcp-derived network settings in low memory
  ; before runtime.bin replaces the pxe firmware stack. prefer that stable
    cmp dword [abs PXE_STACK_HANDOFF_PHYS], PXE_STACK_MAGIC
    jne .legacy_cached_packet

    mov eax, [abs PXE_STACK_HANDOFF_PHYS + PXE_HANDOFF_SUBNET]
    mov [rel legacy_subnet_mask], eax
    mov eax, [abs PXE_STACK_HANDOFF_PHYS + PXE_HANDOFF_ROUTER]
    mov [rel legacy_router_addr], eax
    mov eax, [abs PXE_STACK_HANDOFF_PHYS + PXE_HANDOFF_DNS]
    mov [rel legacy_dns_addr], eax
    ret

.legacy_cached_packet:
    movzx eax, word [rel cached_info + CACHED_BUFSEG]
    shl rax, 4
    movzx edx, word [rel cached_info + CACHED_BUFOFF]
    add rax, rdx
    mov [rel legacy_dhcp_packet], rax
    movzx edx, word [rel cached_info + CACHED_BUFSIZE]
    mov [rel legacy_dhcp_size], edx

    test rax, rax
    jz .done
    cmp edx, 244
    jb .done
    cmp dword [rax + 236], 0x63538263
    jne .done

    lea rsi, [rax + 240]
    mov ecx, edx
    sub ecx, 240
.next:
    test ecx, ecx
    jz .done
    movzx eax, byte [rsi]
    inc rsi
    dec ecx
    cmp eax, 255
    je .done
    test eax, eax
    jz .next
    test ecx, ecx
    jz .done
    movzx edx, byte [rsi]
    inc rsi
    dec ecx
    cmp edx, ecx
    ja .done
    cmp eax, 1
    je .subnet
    cmp eax, 3
    je .router
    cmp eax, 6
    je .dns
    jmp .skip
.subnet:
    cmp edx, 4
    jb .skip
    mov eax, [rsi]
    mov [rel legacy_subnet_mask], eax
    jmp .skip
.router:
    cmp edx, 4
    jb .skip
    mov eax, [rsi]
    mov [rel legacy_router_addr], eax
    jmp .skip
.dns:
    cmp edx, 4
    jb .skip
    mov eax, [rsi]
    mov [rel legacy_dns_addr], eax
.skip:
    add rsi, rdx
    sub ecx, edx
    jmp .next
.done:
    ret

; keep a small fixed pool in the runtime image. this removes
; allocator/high-memory state from the packet fast path and guarantees
legacy_tx_pool_init64:
    lea rax, [rel legacy_tx_pool_static]
    mov [rel legacy_tx_pool], rax
    mov rdi, rax
    xor eax, eax
    mov ecx, (LEGACY_TX_SLOTS * LEGACY_TX_SLOT_BYTES) / 8
    rep stosq
    mov rax, [rel legacy_tx_pool]
    ret

legacy_tx_alloc64:
  ; hand each cpu a distinct scratch slot. keep the pool base in r11: eax is
  ; consumed by xadd and therefore
    lea r11, [rel legacy_tx_pool_static]
    mov eax, 1
    lock xadd dword [rel legacy_tx_index], eax
    and eax, LEGACY_TX_SLOTS-1
    mov ecx, eax
    imul rcx, LEGACY_TX_SLOT_BYTES
    add r11, rcx

    mov rdi, r11
    xor eax, eax
    mov ecx, LEGACY_TX_SLOT_BYTES / 8
    rep stosq
    mov rax, r11
    ret

legacy_print_ipv4_64:
    push rbx
    push rsi
    mov rsi, rcx
    xor ebx, ebx
.loop:
    movzx eax, byte [rsi + rbx]
    call legacy_print_u8_64
    inc ebx
    cmp ebx, 4
    jae .done
    mov al, '.'
    call serial_putc64_al
    jmp .loop
.done:
    pop rsi
    pop rbx
    ret

legacy_print_u8_64:
    push rax
    push rbx
    push rdx
    xor edx, edx
    mov ebx, 100
    div ebx
    mov r8d, eax
    mov eax, edx
    xor edx, edx
    mov ebx, 10
    div ebx
    mov r9d, eax
    mov r10d, edx
    test r8d, r8d
    jz .tens
    mov eax, r8d
    add al, '0'
    call serial_putc64_al
.tens:
    test r8d, r8d
    jnz .emit_tens
    test r9d, r9d
    jz .ones
.emit_tens:
    mov eax, r9d
    add al, '0'
    call serial_putc64_al
.ones:
    mov eax, r10d
    add al, '0'
    call serial_putc64_al
    pop rdx
    pop rbx
    pop rax
    ret

; remember a mac so normal traffic does not keep doing arp
legacy_arp_learn64:
    mov r8d, [rel legacy_arp_count]
    xor r9d, r9d
.find:
    cmp r9d, r8d
    jae .new
    lea r10, [rel legacy_arp_table]
    mov eax, r9d
    imul rax, 16
    add r10, rax
    cmp [r10], ecx
    je .store
    inc r9d
    jmp .find
.new:
    cmp r8d, LEGACY_ARP_SLOTS
    jb .use_new
    xor r9d, r9d
    jmp .slot
.use_new:
    mov r9d, r8d
    inc dword [rel legacy_arp_count]
.slot:
    lea r10, [rel legacy_arp_table]
    mov eax, r9d
    imul rax, 16
    add r10, rax
.store:
    mov [r10], ecx
    mov eax, [rdx]
    mov [r10+4], eax
    mov ax, [rdx+4]
    mov [r10+8], ax

  ; if dns is waiting for a next-hop mac, send the dns packet on the next tick.
    cmp dword [rel legacy_dns_state], LEGACY_DNS_WAIT_ARP
    jne .done
    mov dword [rel legacy_dns_retry], LEGACY_DNS_RETRY_TICKS-1
.done:
    ret

legacy_arp_lookup64:
    mov r8d, [rel legacy_arp_count]
    xor r9d, r9d
.loop:
    cmp r9d, r8d
    jae .no
    lea r10, [rel legacy_arp_table]
    mov eax, r9d
    imul rax, 16
    add r10, rax
    cmp [r10], ecx
    je .yes
    inc r9d
    jmp .loop
.yes:
    mov eax, [r10+4]
    mov [rdx], eax
    mov ax, [r10+8]
    mov [rdx+4], ax
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; use the router unless the destination is on our own subnet
legacy_route_ip64:
    mov eax, ecx
    mov edx, [rel legacy_subnet_mask]
    test edx, edx
    jz .router
    mov r8d, eax
    and r8d, edx
    mov r9d, [rel legacy_ipv4_addr]
    and r9d, edx
    cmp r8d, r9d
    je .done
.router:
    mov eax, [rel legacy_router_addr]
.done:
    ret

legacy_arp_request64:
    push rbx
    mov ebx, ecx
    call legacy_tx_alloc64
    test rax, rax
    jz .fail
    mov r11, rax

    mov dword [r11+0], 0xFFFFFFFF
    mov word [r11+4], 0xFFFF
    mov eax, [rel legacy_mac]
    mov [r11+6], eax
    mov ax, [rel legacy_mac+4]
    mov [r11+10], ax
    mov word [r11+12], 0x0608
    mov word [r11+14], 0x0100
    mov word [r11+16], 0x0008
    mov byte [r11+18], 6
    mov byte [r11+19], 4
    mov word [r11+20], 0x0100
    mov eax, [rel legacy_mac]
    mov [r11+22], eax
    mov ax, [rel legacy_mac+4]
    mov [r11+26], ax
    mov eax, [rel legacy_ipv4_addr]
    mov [r11+28], eax
    mov dword [r11+32], 0
    mov word [r11+36], 0
    mov [r11+38], ebx

    mov rcx, r11
    mov edx, 42
    call legacy_net_send64
    pop rbx
    ret
.fail:
    mov eax, 0xFFFF
    pop rbx
    ret

legacy_arp_reply64:
    push rbx
    mov rbx, rcx
    call legacy_tx_alloc64
    test rax, rax
    jz .done
    mov r11, rax

    mov eax, [rbx+22]
    mov [r11+0], eax
    mov ax, [rbx+26]
    mov [r11+4], ax
    mov eax, [rel legacy_mac]
    mov [r11+6], eax
    mov ax, [rel legacy_mac+4]
    mov [r11+10], ax
    mov word [r11+12], 0x0608
    mov word [r11+14], 0x0100
    mov word [r11+16], 0x0008
    mov byte [r11+18], 6
    mov byte [r11+19], 4
    mov word [r11+20], 0x0200
    mov eax, [rel legacy_mac]
    mov [r11+22], eax
    mov ax, [rel legacy_mac+4]
    mov [r11+26], ax
    mov eax, [rel legacy_ipv4_addr]
    mov [r11+28], eax
    mov eax, [rbx+22]
    mov [r11+32], eax
    mov ax, [rbx+26]
    mov [r11+36], ax
    mov eax, [rbx+28]
    mov [r11+38], eax

    mov rcx, r11
    mov edx, 42
    call legacy_net_send64
.done:
    pop rbx
    ret

; normal internet checksum used by ipv4 udp and tcp
legacy_checksum64:
    push rbx
    push rsi
    mov rsi, rcx
    mov ecx, edx
    xor ebx, ebx
.sum:
    cmp ecx, 2
    jb .odd
    movzx eax, byte [rsi]
    shl eax, 8
    movzx edx, byte [rsi+1]
    or eax, edx
    add ebx, eax
    add rsi, 2
    sub ecx, 2
    jmp .sum
.odd:
    test ecx, ecx
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
    pop rsi
    pop rbx
    ret

; ecx dest ip, edx protocol, r8 payload, r9d payload length
legacy_ipv4_send64:
    push rbx
    push r12
    push r13
    push r14
    mov ebx, ecx
    mov r12d, edx
    mov r13, r8
    mov r14d, r9d

  ; ap shard workers share the tx allocator, ipv4 id and native nic tx path.
  ; serialize only packet construction/transmit; shard/tls state
.acquire_tx:
    xor eax, eax
    mov edx, 1
    lock cmpxchg dword [rel legacy_ipv4_tx_lock], edx
    je .tx_locked
    pause
    jmp .acquire_tx
.tx_locked:
    cmp r14d, LEGACY_TX_SLOT_BYTES - LEGACY_ETH_HDR - LEGACY_IPV4_HDR
    ja .fail

    mov ecx, ebx
    call legacy_route_ip64
    test eax, eax
    jz .fail
    mov r10d, eax
    mov ecx, r10d
    lea rdx, [rel legacy_next_hop_mac]
    call legacy_arp_lookup64
    test eax, eax
    jnz .have_mac
    mov ecx, r10d
    call legacy_arp_request64
    mov eax, 1
    jmp .out
.have_mac:
    call legacy_tx_alloc64
    test rax, rax
    jz .fail
    mov r11, rax

    mov eax, [rel legacy_next_hop_mac]
    mov [r11+0], eax
    mov ax, [rel legacy_next_hop_mac+4]
    mov [r11+4], ax
    mov eax, [rel legacy_mac]
    mov [r11+6], eax
    mov ax, [rel legacy_mac+4]
    mov [r11+10], ax
    mov word [r11+12], 0x0008

    mov byte [r11+14], 0x45
    mov byte [r11+15], 0
    mov eax, r14d
    add eax, LEGACY_IPV4_HDR
    xchg al, ah
    mov [r11+16], ax
    inc word [rel legacy_ip_id]
    mov ax, [rel legacy_ip_id]
    xchg al, ah
    mov [r11+18], ax
    mov word [r11+20], 0x0040
    mov byte [r11+22], 64
    mov [r11+23], r12b
    mov word [r11+24], 0
    mov eax, [rel legacy_ipv4_addr]
    mov [r11+26], eax
    mov [r11+30], ebx

    lea rcx, [r11+14]
    mov edx, LEGACY_IPV4_HDR
    call legacy_checksum64
    mov [r11+24], ax

    lea rdi, [r11+34]
    mov rsi, r13
    mov ecx, r14d
    rep movsb

    mov rcx, r11
    mov edx, r14d
    add edx, 34
    call legacy_net_send64
  ; preserve the real backend status so dns/tcp can retry a failed native tx.
    jmp .out
.fail:
    mov eax, 0xFFFF
.out:
    mov dword [rel legacy_ipv4_tx_lock], 0
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; r8 payload, r9d len, ecx dest ip, edx packed ports src<<16|dst
legacy_udp_send64:
    push rbx
    push r12
    push r13
    push r14
    mov ebx, ecx
    mov r12d, edx
    mov r13, r8
    mov r14d, r9d
    call legacy_tx_alloc64
    test rax, rax
    jz .fail
    mov r11, rax

    mov eax, r12d
    shr eax, 16
    xchg al, ah
    mov [r11+0], ax
    mov eax, r12d
    and eax, 0xFFFF
    xchg al, ah
    mov [r11+2], ax
    mov eax, r14d
    add eax, 8
    xchg al, ah
    mov [r11+4], ax
    mov word [r11+6], 0
    lea rdi, [r11+8]
    mov rsi, r13
    mov ecx, r14d
    rep movsb

    mov ecx, ebx
    mov edx, 17
    mov r8, r11
    mov r9d, r14d
    add r9d, 8
    call legacy_ipv4_send64
    jmp .out
.fail:
    mov eax, 0xFFFF
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; start dns immediately. the first attempt may only emit arp; learning that
; mac arms an immediate retry instead of waiting
legacy_dns_start64:
    cmp dword [rel legacy_dns_state], LEGACY_DNS_IDLE
    jne .done
    mov eax, [rel legacy_dns_addr]
    test eax, eax
    jz .fail
    mov dword [rel legacy_dns_state], LEGACY_DNS_WAIT_ARP
    mov dword [rel legacy_dns_retry], LEGACY_DNS_RETRY_TICKS-1
    lea rsi, [rel msg_dns_start]
    call serial_puts64
.done:
    ret
.fail:
    mov dword [rel legacy_dns_state], LEGACY_DNS_FAILED
    ret

legacy_dns_send64:
    call legacy_tx_alloc64
    test rax, rax
    jz .fail
    mov r11, rax
    rdtsc
    mov [rel legacy_dns_id], ax
    xchg al, ah
    mov [r11+0], ax
    mov word [r11+2], 0x0001
    mov word [r11+4], 0x0100
    mov word [r11+6], 0
    mov word [r11+8], 0
    mov word [r11+10], 0
    lea rdi, [r11+12]
    lea rsi, [rel legacy_dns_name]
.copy_name:
    lodsb
    stosb
    test al, al
    jnz .copy_name
    mov word [rdi], 0x0100
    add rdi, 2
    mov word [rdi], 0x0100
    add rdi, 2
    sub rdi, r11
    mov r9d, edi
    mov ecx, [rel legacy_dns_addr]
    mov edx, (LEGACY_DNS_LOCAL << 16) | LEGACY_DNS_PORT
    mov r8, r11
    call legacy_udp_send64
    test eax, eax
    jnz .wait
    mov dword [rel legacy_dns_state], LEGACY_DNS_SENT
    mov dword [rel legacy_dns_retry], 0
    lea rsi, [rel msg_dns_sent]
    call serial_puts64
    ret
.wait:
    mov dword [rel legacy_dns_state], LEGACY_DNS_WAIT_ARP
    mov dword [rel legacy_dns_retry], 0
    ret
.fail:
    mov dword [rel legacy_dns_state], LEGACY_DNS_FAILED
    ret

; skip one dns name so compressed replies do not confuse the parser
legacy_dns_skip_name64:
    mov rax, rcx
.loop:
    cmp rax, rdx
    jae .bad
    movzx ecx, byte [rax]
    test ecx, ecx
    jz .zero
    mov r8d, ecx
    and r8d, 0xC0
    cmp r8d, 0xC0
    je .ptr
    inc rax
    add rax, rcx
    jmp .loop
.zero:
    inc rax
    ret
.ptr:
    add rax, 2
    ret
.bad:
    xor eax, eax
    ret

; rcx dns bytes, edx dns length
legacy_dns_rx64:
    cmp edx, 12
    jb .ret
    mov rsi, rcx
    movzx eax, word [rsi]
    xchg al, ah
    cmp ax, [rel legacy_dns_id]
    jne .ret
    test byte [rsi+2], 0x80
    jz .ret
    movzx r8d, word [rsi+6]
    rol r8w, 8
    test r8d, r8d
    jz .ret
    lea rax, [rsi+12]
    lea rdx, [rsi+rdx]
    mov rcx, rax
    call legacy_dns_skip_name64
    test rax, rax
    jz .ret
    add rax, 4
.answer:
    cmp rax, rdx
    jae .ret
    mov rcx, rax
    call legacy_dns_skip_name64
    test rax, rax
    jz .ret
    lea r11, [rax+10]
    cmp r11, rdx
    ja .ret
    movzx ecx, word [rax]
    rol cx, 8
    movzx r9d, word [rax+2]
    rol r9w, 8
    movzx r10d, word [rax+8]
    rol r10w, 8
    add rax, 10
    lea r11, [rax+r10]
    cmp r11, rdx
    ja .ret
    cmp ecx, 1
    jne .next
    cmp r9d, 1
    jne .next
    cmp r10d, 4
    jne .next
    mov ecx, [rax]
    mov [rel legacy_gateway_ip], ecx
    mov dword [rel legacy_dns_state], LEGACY_DNS_READY
    lea rsi, [rel msg_dns_ready]
    call serial_puts64
    lea rcx, [rel legacy_gateway_ip]
    call legacy_print_ipv4_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    ret
.next:
    add rax, r10
    dec r8d
    jnz .answer
.ret:
    ret

; handle arp ipv4 udp and tcp from one ethernet callback
legacy_eth_rx64:
    cmp edx, 14
    jb .bad
    movzx eax, word [rcx+12]
    cmp ax, 0x0608
    je .arp
    cmp ax, 0x0008
    je .ipv4
    inc qword [rel legacy_frames_other]
    ret
.arp:
    inc qword [rel legacy_frames_arp]
    cmp edx, 42
    jb .bad
    mov r11, rcx
    mov eax, [r11+28]
    lea rdx, [r11+22]
    mov ecx, eax
    call legacy_arp_learn64
    cmp word [r11+20], 0x0100
    jne .ret
    mov eax, [rel legacy_ipv4_addr]
    cmp dword [r11+38], eax
    jne .ret
    mov rcx, r11
    call legacy_arp_reply64
    ret
.ipv4:
    inc qword [rel legacy_frames_ipv4]
    cmp edx, 34
    jb .bad
    mov r11, rcx
    movzx eax, byte [r11+14]
    and eax, 0x0F
    cmp eax, 5
    jb .bad
    shl eax, 2
    mov r10d, eax
    movzx eax, byte [r11+23]
    cmp eax, 17
    je .udp
    cmp eax, 6
    je .tcp
    ret
.udp:
    lea r9, [r11+14]
    add r9, r10
    movzx eax, word [r9+2]
    cmp ax, 0x08CF
    jne .ret
    movzx eax, word [r9+4]
    xchg al, ah
    cmp eax, 8
    jb .bad
    sub eax, 8
    lea rcx, [r9+8]
    mov edx, eax
    call legacy_dns_rx64
    ret
.tcp:
    movzx eax, byte [r11+16]
    shl eax, 8
    movzx r8d, byte [r11+17]
    or eax, r8d
    sub eax, r10d
    mov edx, eax
    mov r8d, [r11+26]
    lea rcx, [r11+14]
    add rcx, r10
    call legacy_tcp_demux_rx64
.ret:
    ret
.bad:
    inc qword [rel legacy_frames_bad]
    ret

; retry quickly enough that one lost arp or dns reply cannot leave boot
; sitting in netstat for seconds. packet polling
legacy_ip_tick64:
    cmp dword [rel legacy_ip_ready], 1
    jne .done
    cmp dword [rel legacy_dns_state], LEGACY_DNS_IDLE
    jne .state
    call legacy_dns_start64
.state:
    mov eax, [rel legacy_dns_state]
    cmp eax, LEGACY_DNS_READY
    je .done
    cmp eax, LEGACY_DNS_FAILED
    je .done
    inc dword [rel legacy_dns_retry]
    cmp dword [rel legacy_dns_retry], LEGACY_DNS_RETRY_TICKS
    jb .done
    mov dword [rel legacy_dns_retry], 0
    call legacy_dns_send64
.done:
    ret

align 16
legacy_mac            times 6 db 0
legacy_next_hop_mac   times 6 db 0
legacy_ipv4_addr      dd 0
legacy_subnet_mask    dd 0
legacy_router_addr    dd 0
legacy_dns_addr       dd 0
legacy_gateway_ip     dd 0
legacy_ip_id          dw 0
legacy_dns_id         dw 0
align 4
legacy_ipv4_tx_lock   dd 0
legacy_dns_state      dd 0
legacy_dns_retry      dd 0
legacy_ip_ready       dd 0
legacy_dhcp_packet    dq 0
legacy_dhcp_size      dd 0
legacy_tx_pool        dq 0
legacy_tx_index       dd 0
legacy_arp_count      dd 0
legacy_arp_table      times (LEGACY_ARP_SLOTS * 16) db 0
legacy_frames_arp     dq 0
legacy_frames_ipv4    dq 0
legacy_frames_other   dq 0
legacy_frames_bad     dq 0
legacy_dns_name       db 7,'gateway',7,'discord',2,'gg',0

align 16
legacy_tx_pool_static times (LEGACY_TX_SLOTS * LEGACY_TX_SLOT_BYTES) db 0

msg_ip_addr   db '[IP] address=',0
msg_ip_router db ' router=',0
msg_ip_dns    db ' dns=',0
msg_ip_fail   db '[ERROR] legacy ip stack could not allocate tx memory',13,10,0
msg_dns_start db '[DNS] starting gateway.discord.gg lookup',13,10,0
msg_dns_sent  db '[DNS] query sent',13,10,0
msg_dns_ready db '[DNS] gateway.discord.gg=',0
