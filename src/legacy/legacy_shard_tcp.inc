; context-based tcp client for sharded discord gateway sessions. each active shard gets
; its own local port and sequence space while sharing the machine's ipv4/arp layer and gateway ip.

BITS 64

%define SHARD_TCP_IDLE        0
%define SHARD_TCP_WAIT_ARP    1
%define SHARD_TCP_SYN_SENT    2
%define SHARD_TCP_UP          3
%define SHARD_TCP_FAILED      4
%define SHARD_TCP_CLOSED      5

%define SHARD_TCP_REMOTE_PORT 443
%define SHARD_TCP_PORT_BASE   50000
%define SHARD_TCP_PORT_MASK   0x0FFF
%define SHARD_TCP_MAX_PAYLOAD 1200

%define STCP_STATE       0
%define STCP_LOCAL_SEQ   4
%define STCP_REMOTE_SEQ  8
%define STCP_RETRY      12
%define STCP_RETRIES    16
%define STCP_LOCAL_PORT 20
%define STCP_REMOTE_IP  24
%define STCP_RX_CB      32
%define STCP_RX_ARG     40
%define STCP_RX_TOTAL   48
%define STCP_TX_TOTAL   56
%define STCP_BAD        64
%define STCP_RST        72
%define STCP_DEST_MAC   80

; rcx=shard ctx, rax=tcp ctx or zero.
legacy_shard_tcp_alloc64:
    push rbx
    mov rbx, rcx
    test rbx, rbx
    jz .bad
    mov rax, [rbx + SHARD_OFF_TCP_CTX]
    test rax, rax
    jnz .done

    mov ecx, 1
    call alloc_pages64
    test rax, rax
    jnz .got
    mov ecx, 1
    call alloc_high_pages64
.got:
    test rax, rax
    jz .bad
    mov [rbx + SHARD_OFF_TCP_CTX], rax

    push rax
    mov rdi, rax
    xor eax, eax
    mov ecx, 4096/8
    rep stosq
    pop rax

    mov dword [rax + STCP_STATE], SHARD_TCP_IDLE
    mov edx, [rbx + SHARD_OFF_ID]
    and edx, SHARD_TCP_PORT_MASK
    add edx, SHARD_TCP_PORT_BASE
    mov [rax + STCP_LOCAL_PORT], edx
.done:
    pop rbx
    ret
.bad:
    xor eax, eax
    pop rbx
    ret

; rcx=shard ctx, rdx=callback, r8=callback arg.
legacy_shard_tcp_set_rx64:
    push rbx
    push r12
    push r13
    mov rbx, rcx
    mov r12, rdx
    mov r13, r8
    call legacy_shard_tcp_alloc64
    test rax, rax
    jz .bad
    mov [rax + STCP_RX_CB], r12
    mov [rax + STCP_RX_ARG], r13
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret
.bad:
    mov eax, 1
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx, rdx=tcp bytes, r8d=tcp len. ax is checksum in wire byte order.
legacy_shard_tcp_checksum64:
    push rbx
    push rsi
    push rdi
    push r12
    mov r12, rcx
    mov rsi, rdx
    mov edi, r8d
    xor ebx, ebx

    lea r10, [rel legacy_ipv4_addr]
    xor r9d, r9d
.local_ip:
    movzx eax, byte [r10+r9]
    shl eax, 8
    movzx edx, byte [r10+r9+1]
    or eax, edx
    add ebx, eax
    add r9d, 2
    cmp r9d, 4
    jb .local_ip

    mov r11, [r12 + SHARD_OFF_TCP_CTX]
    test r11, r11
    jz .bad
    lea r10, [r11 + STCP_REMOTE_IP]
    xor r9d, r9d
.remote_ip:
    movzx eax, byte [r10+r9]
    shl eax, 8
    movzx edx, byte [r10+r9+1]
    or eax, edx
    add ebx, eax
    add r9d, 2
    cmp r9d, 4
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
    jmp .out
.bad:
    xor eax, eax
.out:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; rcx=shard ctx, rdx=payload-or-zero, r8d=len, r9d=flags.
legacy_shard_tcp_send_segment64:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov dword [rel shard_tcp_debug_step], 0x10
    mov [rel shard_tcp_debug_ctx], rcx
    mov r15, rcx
    mov r12, rdx
    mov r13d, r8d
    mov r14d, r9d
    test r15, r15
    jz .fail
    cmp r13d, SHARD_TCP_MAX_PAYLOAD
    ja .fail

    mov rcx, r15
    call legacy_shard_tcp_alloc64
    test rax, rax
    jz .fail
    mov rbx, rax
    mov [rel shard_tcp_debug_tcp], rbx
    mov dword [rel shard_tcp_debug_step], 0x11

    call legacy_tx_alloc64
    test rax, rax
    jz .fail
    mov r11, rax
    mov [rel shard_tcp_debug_tx], r11
    mov dword [rel shard_tcp_debug_step], 0x12

    mov rcx, r11
    mov edx, [rbx + STCP_LOCAL_PORT]
    call legacy_tcp_store_be16
    lea rcx, [r11+2]
    mov edx, SHARD_TCP_REMOTE_PORT
    call legacy_tcp_store_be16
    lea rcx, [r11+4]
    mov edx, [rbx + STCP_LOCAL_SEQ]
    call legacy_tcp_store_be32
    lea rcx, [r11+8]
    mov edx, [rbx + STCP_REMOTE_SEQ]
    call legacy_tcp_store_be32
    mov byte [r11+12], 0x50
    mov [r11+13], r14b
    mov word [r11+14], 0xF0FA
    mov word [r11+16], 0
    mov word [r11+18], 0

    test r13d, r13d
    jz .checksum
    lea rdi, [r11+20]
    mov rsi, r12
    mov ecx, r13d
    rep movsb
.checksum:
    mov r12, r11
    mov rcx, r15
    mov rdx, r12
    mov r8d, r13d
    add r8d, 20
    call legacy_shard_tcp_checksum64
    mov [r12+16], ax
    mov dword [rel shard_tcp_debug_step], 0x13

    mov ecx, [rbx + STCP_REMOTE_IP]
    mov edx, 6
    mov r8, r12
    mov r9d, r13d
    add r9d, 20
    mov dword [rel shard_tcp_debug_step], 0x14
    call legacy_ipv4_send64
    mov dword [rel shard_tcp_debug_step], 0x15
    test eax, eax
    jnz .out

    inc qword [rbx + STCP_TX_TOTAL]
    test r14b, 0x02
    jz .payload_seq
    inc dword [rbx + STCP_LOCAL_SEQ]
.payload_seq:
    test r13d, r13d
    jz .out
    add [rbx + STCP_LOCAL_SEQ], r13d
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.fail:
    mov eax, 1
    jmp .out

; rcx=shard ctx. tear down only this shard's tcp session.
legacy_shard_tcp_abort64:
    push rbx
    mov rbx, rcx
    test rbx, rbx
    jz .done
    mov r11, [rbx + SHARD_OFF_TCP_CTX]
    test r11, r11
    jz .done
    mov eax, [r11 + STCP_STATE]
    cmp eax, SHARD_TCP_UP
    je .rst
    cmp eax, SHARD_TCP_SYN_SENT
    jne .close
.rst:
    mov rcx, rbx
    xor edx, edx
    xor r8d, r8d
    mov r9d, 0x14
    call legacy_shard_tcp_send_segment64
.close:
    mov r11, [rbx + SHARD_OFF_TCP_CTX]
    test r11, r11
    jz .done
    mov dword [r11 + STCP_STATE], SHARD_TCP_CLOSED
.done:
    pop rbx
    ret

; rcx=shard ctx.
legacy_shard_tcp_send_ack64:
    xor edx, edx
    xor r8d, r8d
    mov r9d, 0x10
    call legacy_shard_tcp_send_segment64
    ret

; rcx=shard ctx, rdx=bytes, r8d=len.
legacy_shard_tcp_send64_raw:
    push rbx
    push r12
    push r13
    mov rbx, rcx
    mov r12, rdx
    mov r13d, r8d
    mov rcx, rbx
    call legacy_shard_tcp_alloc64
    test rax, rax
    jz .bad
    cmp dword [rax + STCP_STATE], SHARD_TCP_UP
    jne .bad
    mov rcx, rbx
    mov rdx, r12
    mov r8d, r13d
    mov r9d, 0x18
    call legacy_shard_tcp_send_segment64
    pop r13
    pop r12
    pop rbx
    ret
.bad:
    mov eax, 1
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx.
legacy_shard_tcp_start64:
    push rbx
    mov rbx, rcx
    cmp dword [rel legacy_dns_state], LEGACY_DNS_READY
    jne .bad
    mov rcx, rbx
    call legacy_shard_tcp_alloc64
    test rax, rax
    jz .bad
    cmp dword [rax + STCP_STATE], SHARD_TCP_IDLE
    jne .bad
    mov edx, [rel legacy_gateway_ip]
    test edx, edx
    jz .bad
    mov [rax + STCP_REMOTE_IP], edx

    mov r10, rax
    rdtsc
    xor eax, edx
    xor eax, [rbx + SHARD_OFF_ID]
    test eax, eax
    jnz .seq
    mov eax, 0x145A2173
.seq:
    mov [r10 + STCP_LOCAL_SEQ], eax
    mov dword [r10 + STCP_REMOTE_SEQ], 0
    mov dword [r10 + STCP_RETRY], 0
    mov dword [r10 + STCP_RETRIES], 0
    mov dword [r10 + STCP_STATE], SHARD_TCP_WAIT_ARP
    mov rcx, rbx
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_stcp_start]
    call serial_puts64
    mov eax, [r10 + STCP_LOCAL_PORT]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    xor eax, eax
    pop rbx
    ret
.bad:
    mov eax, 1
    pop rbx
    ret

; rcx=shard ctx, rdx=tcp bytes, r8d=len, r9d=source ip.
legacy_shard_tcp_rx_one64:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r15, rcx
    mov r12, rdx
    mov r13d, r8d
    mov r14d, r9d
    test r15, r15
    jz .done
    mov rbx, [r15 + SHARD_OFF_TCP_CTX]
    test rbx, rbx
    jz .done
    cmp r14d, [rbx + STCP_REMOTE_IP]
    jne .done
    cmp r13d, 20
    jb .bad

    mov rcx, r12
    call legacy_tcp_load_be16
    cmp eax, SHARD_TCP_REMOTE_PORT
    jne .done
    lea rcx, [r12+2]
    call legacy_tcp_load_be16
    cmp eax, [rbx + STCP_LOCAL_PORT]
    jne .done

    mov rcx, r15
    mov rdx, r12
    mov r8d, r13d
    call legacy_shard_tcp_checksum64
    test ax, ax
    jnz .bad

    movzx edx, byte [r12+12]
    shr edx, 4
    cmp edx, 5
    jb .bad
    shl edx, 2
    cmp edx, r13d
    ja .bad
   ; keep the tcp header length in a callee-saved register. the ack/reliable helpers below
   ; are normal calls and may freely clobber r10.
    mov r14d, edx

   ; ack processing belongs to the shard's reliable queue, independent of the receive state
   ; transition below.
    test byte [r12+13], 0x10
    jz .ack_done
    lea rcx, [r12+8]
    call legacy_tcp_load_be32
    mov edx, eax
    mov rcx, r15
    call legacy_shard_tcp_rel_ack64
.ack_done:

    test byte [r12+13], 0x04
    jz .state
    inc qword [rbx + STCP_RST]
    mov dword [rbx + STCP_STATE], SHARD_TCP_FAILED
    mov rcx, r15
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_stcp_rst]
    call serial_puts64
    jmp .done
.state:
    cmp dword [rbx + STCP_STATE], SHARD_TCP_SYN_SENT
    je .syn
    cmp dword [rbx + STCP_STATE], SHARD_TCP_UP
    je .up
    jmp .done
.syn:
    mov al, [r12+13]
    and al, 0x12
    cmp al, 0x12
    jne .done
    lea rcx, [r12+8]
    call legacy_tcp_load_be32
    cmp eax, [rbx + STCP_LOCAL_SEQ]
    jne .bad
    lea rcx, [r12+4]
    call legacy_tcp_load_be32
    inc eax
    mov [rbx + STCP_REMOTE_SEQ], eax
    mov dword [rbx + STCP_STATE], SHARD_TCP_UP
    mov rcx, r15
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_stcp_up]
    call serial_puts64
    mov rcx, r15
    call legacy_shard_tcp_send_ack64
    jmp .done
.up:
    lea rcx, [r12+4]
    call legacy_tcp_load_be32
    cmp eax, [rbx + STCP_REMOTE_SEQ]
    jne .ack

    mov eax, r13d
    sub eax, r14d
    jbe .fin
    mov r11d, eax
    add [rbx + STCP_REMOTE_SEQ], r11d
    add [rbx + STCP_RX_TOTAL], r11

    mov rax, [rbx + STCP_RX_CB]
    test rax, rax
    jz .fin
    lea rdx, [r12+r14]
    mov rcx, r15
    mov r8d, r11d
    mov r9, [rbx + STCP_RX_ARG]
    sub rsp, 32
    call rax
    add rsp, 32
.fin:
    test byte [r12+13], 0x01
    jz .ack
    inc dword [rbx + STCP_REMOTE_SEQ]
    mov dword [rbx + STCP_STATE], SHARD_TCP_CLOSED
.ack:
    mov rcx, r15
    call legacy_shard_tcp_send_ack64
    jmp .done
.bad:
    inc qword [rbx + STCP_BAD]
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; preserve the hardware-proven singleton local port exactly. any other tcp destination
; port is checked against active shard contexts. rcx=tcp bytes, edx=len, r8d=source ip.
legacy_tcp_demux_rx64:
    push rbx
    push r12
    push r13
    push r14
    mov r12, rcx
    mov r13d, edx
    mov r14d, r8d

    cmp r13d, 4
    jb .old
    lea rcx, [r12+2]
    call legacy_tcp_load_be16
    cmp eax, LEGACY_TCP_LOCAL_PORT
    je .old
    cmp eax, 8080
    je .http

    cmp dword [rel shard_initialized], 1
    jne .done
    cmp dword [rel shard_network_enabled], 1
    jne .done
    xor ebx, ebx
.scan:
    cmp ebx, [rel shard_active_count]
    jae .done
    mov ecx, ebx
    call legacy_shards_get_ctx64
    test rax, rax
    jz .done
    mov r11, [rax + SHARD_OFF_TCP_CTX]
    test r11, r11
    jz .next
    lea rcx, [r12+2]
    call legacy_tcp_load_be16
    cmp eax, [r11 + STCP_LOCAL_PORT]
    jne .next

    mov ecx, ebx
    call legacy_shards_get_ctx64
    mov rcx, rax
    mov rdx, r12
    mov r8d, r13d
    mov r9d, r14d
    call legacy_shard_tcp_rx_one64
    jmp .done
.next:
    inc ebx
    jmp .scan

.http:
    mov rcx, r12
    mov edx, r13d
    mov r8d, r14d
    call legacy_http_tcp_rx64
    jmp .done

.old:
    mov rcx, r12
    mov edx, r13d
    mov r8d, r14d
    call legacy_tcp_rx64
.done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rcx=shard ctx.
legacy_shard_tcp_tick64:
    push rbx
    push r12
    mov r12, rcx
    mov rcx, r12
    call legacy_shard_tcp_alloc64
    test rax, rax
    jz .done
    mov rbx, rax

    cmp dword [rbx + STCP_STATE], SHARD_TCP_IDLE
    jne .state
    test dword [r12 + SHARD_OFF_FLAGS], SHARD_FLAG_CONNECT_ALLOWED
    jz .done
    cmp dword [rel legacy_dns_state], LEGACY_DNS_READY
    jne .done
    mov rcx, r12
    call legacy_shard_tcp_start64
.state:
    mov eax, [rbx + STCP_STATE]
    cmp eax, SHARD_TCP_WAIT_ARP
    je .wait_arp
    cmp eax, SHARD_TCP_SYN_SENT
    je .wait_syn
    jmp .done
.wait_arp:
    mov ecx, [rbx + STCP_REMOTE_IP]
    call legacy_route_ip64
    mov ecx, eax
    lea rdx, [rbx + STCP_DEST_MAC]
    call legacy_arp_lookup64
    test eax, eax
    jnz .syn
    inc dword [rbx + STCP_RETRY]
    cmp dword [rbx + STCP_RETRY], 150000
    jb .done
    mov dword [rbx + STCP_RETRY], 0
    mov ecx, [rbx + STCP_REMOTE_IP]
    call legacy_route_ip64
    mov ecx, eax
    call legacy_arp_request64
    jmp .done
.syn:
    mov rcx, r12
    xor edx, edx
    xor r8d, r8d
    mov r9d, 0x02
    call legacy_shard_tcp_send_segment64
    test eax, eax
    jnz .done
    mov dword [rbx + STCP_STATE], SHARD_TCP_SYN_SENT
    mov dword [rbx + STCP_RETRY], 0
    mov rcx, r12
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_stcp_syn]
    call serial_puts64
    jmp .done
.wait_syn:
    inc dword [rbx + STCP_RETRY]
    cmp dword [rbx + STCP_RETRY], 500000
    jb .done
    mov dword [rbx + STCP_RETRY], 0
    inc dword [rbx + STCP_RETRIES]
    cmp dword [rbx + STCP_RETRIES], 5
    ja .fail
    dec dword [rbx + STCP_LOCAL_SEQ]
    mov rcx, r12
    xor edx, edx
    xor r8d, r8d
    mov r9d, 0x02
    call legacy_shard_tcp_send_segment64
    jmp .done
.fail:
    mov dword [rbx + STCP_STATE], SHARD_TCP_FAILED
    mov rcx, r12
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_stcp_fail]
    call serial_puts64
.done:
    pop r12
    pop rbx
    ret

legacy_shard_tcp_tick_all64:
    cmp dword [rel shard_initialized], 1
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
    call legacy_shard_tcp_tick64
    mov ecx, ebx
    call legacy_shards_get_ctx64
    test rax, rax
    jz .out
    mov rcx, rax
    call legacy_shard_tcp_rel_tick64
    inc ebx
    jmp .loop
.out:
    pop rbx
.done:
    ret


align 8
shard_tcp_debug_step dd 0
align 8
shard_tcp_debug_ctx dq 0
shard_tcp_debug_tcp dq 0
shard_tcp_debug_tx dq 0

msg_stcp_start db 'tcp start local-port=0x',0
msg_stcp_syn   db 'tcp SYN sent',13,10,0
msg_stcp_up    db 'tcp connected',13,10,0
msg_stcp_rst   db 'tcp reset by gateway',13,10,0
msg_stcp_fail  db 'tcp connection failed',13,10,0
