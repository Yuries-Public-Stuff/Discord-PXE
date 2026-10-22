; raw network stuff for the legacy build native rtl816x is preferred after boot; pxe/undi
; remains a fallback only

BITS 64

%define LEGACY_RX_SLOTS 64
%define LEGACY_RX_SLOT_BYTES 2048
%define LEGACY_HIGH_REGIONS 64
%define LEGACY_FW_RX_INTERVAL_MS 10
%define LEGACY_NET_TRACE_ISR_LIMIT 16
%define LEGACY_NET_DIAG_INTERVAL_MS 1000

legacy_net_core_init64:
    mov dword [rel legacy_net_ready], 0
    call highmem_init64
    call legacy_rx_ring_init64
    test eax, eax
    jz .fail
    mov qword [rel legacy_eth_handler], 0
    mov qword [rel legacy_eth_handler_arg], 0
    mov qword [rel legacy_fw_rx_deadline], 0
    mov qword [rel legacy_net_diag_deadline], 0
    mov dword [rel legacy_net_diag_fallback], 0
    mov qword [rel legacy_net_diag_last_tx], -1
    mov qword [rel legacy_net_diag_last_rx], -1
    mov qword [rel legacy_net_diag_last_drop], -1
    mov dword [rel legacy_fw_rx_enabled], 0
    mov dword [rel legacy_fw_tx_seen], 0
    mov dword [rel legacy_fw_rx_seen], 0
    mov dword [rel legacy_fw_frame_seen], 0
    mov dword [rel legacy_fw_tx_status_seen], 0
    mov dword [rel legacy_last_tx_status], 0xFFFFFFFF
    mov dword [rel legacy_isr_poll_count], 0
    mov dword [rel legacy_net_trace_seq], 0
    mov dword [rel legacy_net_trace_isr_count], 0
    mov qword [rel legacy_net_trace_start_ms], 0
    call legacy_net_trace_capture_start64
    mov dword [rel legacy_net_ready], 1
    lea rsi, [rel msg_net_core]
    call serial_puts64
    ret
.fail:
    lea rsi, [rel msg_net_alloc_fail]
    call serial_puts64
    ret

; capture a monotonic millisecond baseline for compact hardware traces
legacy_net_trace_capture_start64:
    push rax
    push rcx
    push rdx
    mov rcx, [rel tsc_cycles_per_ms]
    test rcx, rcx
    jz .done
    rdtsc
    shl rdx, 32
    or rax, rdx
    xor edx, edx
    div rcx
    mov [rel legacy_net_trace_start_ms], rax
.done:
    pop rdx
    pop rcx
    pop rax
    ret

; prefix traces with sequence + milliseconds since network init. preserve every volatile
; register used by packet callers so logging cannot alter io.
legacy_net_trace_prefix64:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11

    inc dword [rel legacy_net_trace_seq]
    lea rsi, [rel msg_net_trace_seq]
    call serial_puts64
    mov eax, [rel legacy_net_trace_seq]
    call serial_hex32_64
    lea rsi, [rel msg_net_trace_time]
    call serial_puts64

    mov rcx, [rel tsc_cycles_per_ms]
    test rcx, rcx
    jz .no_tsc
    rdtsc
    shl rdx, 32
    or rax, rdx
    xor edx, edx
    div rcx
    sub rax, [rel legacy_net_trace_start_ms]
    call serial_hex32_64
    jmp .suffix
.no_tsc:
    xor eax, eax
    call serial_hex32_64
.suffix:
    lea rsi, [rel msg_net_trace_suffix]
    call serial_puts64

    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret

; run this over and over on the main cpu to keep network packets moving. receive first so
; arp/dns/tcp replies are visible before protocol timers run.
legacy_runtime_tick64:
    call legacy_net_poll64
    call legacy_ip_tick64
    call legacy_tcp_tick64
    call legacy_net_diag_tick64
    inc qword [rel legacy_runtime_ticks]
    pause
    ret

highmem_init64:
    mov dword [rel high_region_count], 0
    movzx ecx, word [rel e820_count]
    lea rsi, [rel e820_map]
.scan:
    test ecx, ecx
    jz .done
    cmp dword [rsi+16], 1
    jne .next
    mov rax, [rsi+0]
    mov rdx, [rsi+8]
    mov r8, rax
    add r8, rdx
    mov r9, 0x100000000
    cmp r8, r9
    jbe .next
    cmp rax, r9
    jae .base_ok
    mov rax, r9
.base_ok:
    add rax, 0xFFF
    and rax, -4096
    and r8, -4096
    cmp r8, rax
    jbe .next
    mov edx, [rel high_region_count]
    cmp edx, LEGACY_HIGH_REGIONS
    jae .done
    lea r9, [rel high_regions]
    imul rdx, 16
    add r9, rdx
    mov [r9+0], rax
    mov [r9+8], r8
    inc dword [rel high_region_count]
.next:
    add rsi, E820_ENTRY_SIZE
    dec ecx
    jmp .scan
.done:
    lea rsi, [rel msg_highmem]
    call serial_puts64
    mov eax, [rel high_region_count]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    ret

alloc_high_pages64:
    test rcx, rcx
    jz .fail
    mov r10, rcx
    shl r10, 12
    mov ecx, [rel high_region_count]
    lea rsi, [rel high_regions]
.loop:
    test ecx, ecx
    jz .fail
    mov rax, [rsi+0]
    mov rdx, rax
    add rdx, r10
    cmp rdx, [rsi+8]
    ja .next
    mov [rsi+0], rdx
    ret
.next:
    add rsi, 16
    dec ecx
    jmp .loop
.fail:
    xor eax, eax
    ret

legacy_rx_ring_init64:
    mov dword [rel legacy_rx_head], 0
    mov dword [rel legacy_rx_tail], 0
    mov qword [rel legacy_rx_packets], 0
    mov qword [rel legacy_rx_dropped], 0
    mov qword [rel legacy_tx_packets], 0
    mov qword [rel legacy_runtime_ticks], 0

    mov ecx, ((LEGACY_RX_SLOTS * LEGACY_RX_SLOT_BYTES) + 4095) / 4096
    call alloc_pages64
    test rax, rax
    jnz .got
    mov ecx, ((LEGACY_RX_SLOTS * LEGACY_RX_SLOT_BYTES) + 4095) / 4096
    call alloc_high_pages64
.got:
    mov [rel legacy_rx_storage], rax
    test rax, rax
    jz .fail
    mov rdi, rax
    xor eax, eax
    mov ecx, LEGACY_RX_SLOTS * LEGACY_RX_SLOT_BYTES
    rep stosb
    mov eax, 1
    ret
.fail:
    xor eax, eax
    ret

; native rtl is polled every runtime tick. pxe/undi fallback keeps the old throttled isr
; behavior because firmware calls are expensive and fragile.
legacy_net_poll64:
    cmp dword [rel legacy_net_ready], 1
    jne .dispatch
    cmp dword [rel rtl_ready], 1
    je .poll_one
    cmp dword [rel pxe_thunk_proven], 1
    jne .dispatch
    cmp dword [rel legacy_fw_rx_enabled], 1
    jne .dispatch

    call legacy_net_fw_poll_due64
    test eax, eax
    jz .dispatch
    call legacy_net_fw_set_deadline64

.poll_one:
    mov eax, [rel legacy_rx_head]
    mov edx, eax
    inc edx
    and edx, LEGACY_RX_SLOTS-1
    cmp edx, [rel legacy_rx_tail]
    je .full

   ; pxe-only breadcrumbs. do not print fake isr state while rtl is active.
    cmp dword [rel rtl_ready], 1
    je .rx_call
    cmp dword [rel legacy_fw_rx_seen], 0
    jne .rx_call
    call legacy_net_trace_prefix64
    lea rsi, [rel msg_net_first_rx]
    call serial_puts64
.rx_call:
    inc dword [rel legacy_isr_poll_count]
    mov eax, [rel legacy_rx_head]
    mov r13d, eax
    imul r13, LEGACY_RX_SLOT_BYTES
    add r13, [rel legacy_rx_storage]
    lea rcx, [r13+4]
    mov edx, LEGACY_RX_SLOT_BYTES-4
    call pxe_net_rx64

    cmp dword [rel rtl_ready], 1
    je .isr_trace_done
    cmp dword [rel legacy_net_trace_isr_count], LEGACY_NET_TRACE_ISR_LIMIT
    jae .isr_trace_done
    inc dword [rel legacy_net_trace_isr_count]
    push rax
    call legacy_net_trace_prefix64
    lea rsi, [rel msg_net_isr_diag_status]
    call serial_puts64
    movzx eax, word [rel pxe_isr_param + ISR_STATUS]
    call serial_hex32_64
    lea rsi, [rel msg_net_isr_diag_func]
    call serial_puts64
    movzx eax, word [rel pxe_isr_param + ISR_FUNC]
    call serial_hex32_64
    lea rsi, [rel msg_net_isr_diag_buf]
    call serial_puts64
    movzx eax, word [rel pxe_isr_param + ISR_BUFLEN]
    call serial_hex32_64
    lea rsi, [rel msg_net_isr_diag_frame]
    call serial_puts64
    movzx eax, word [rel pxe_isr_param + ISR_FRAMELEN]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    pop rax
.isr_trace_done:

    cmp dword [rel rtl_ready], 1
    je .rx_checked
    cmp dword [rel legacy_fw_rx_seen], 0
    jne .rx_checked
    mov dword [rel legacy_fw_rx_seen], 1
    push rax
    call legacy_net_trace_prefix64
    lea rsi, [rel msg_net_first_rx_back]
    call serial_puts64
    pop rax
.rx_checked:
    test eax, eax
    jz .dispatch
    mov [r13], eax

    cmp dword [rel legacy_fw_frame_seen], 0
    jne .frame_traced
    mov dword [rel legacy_fw_frame_seen], 1
    mov r12d, eax
    call legacy_net_trace_prefix64
    lea rsi, [rel msg_net_first_frame]
    call serial_puts64
    mov eax, r12d
    call serial_hex32_64
    lea rsi, [rel msg_net_first_frame_type]
    call serial_puts64
    movzx eax, word [r13+4+12]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
.frame_traced:

    mov eax, [rel legacy_rx_head]
    inc eax
    and eax, LEGACY_RX_SLOTS-1
    mov [rel legacy_rx_head], eax
    inc qword [rel legacy_rx_packets]
    jmp .dispatch
.full:
    inc qword [rel legacy_rx_dropped]
.dispatch:
    call legacy_net_dispatch64
    ret

legacy_net_fw_set_deadline64:
    mov rax, [rel tsc_cycles_per_ms]
    test rax, rax
    jz .no_tsc
    imul rax, LEGACY_FW_RX_INTERVAL_MS
    mov r8, rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    add rax, r8
    mov [rel legacy_fw_rx_deadline], rax
    ret
.no_tsc:
    mov qword [rel legacy_fw_rx_deadline], 0
    ret

legacy_net_fw_poll_due64:
    mov r8, [rel legacy_fw_rx_deadline]
    test r8, r8
    jz .yes
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, r8
    jae .yes
    xor eax, eax
    ret
.yes:
    mov eax, 1
    ret

legacy_net_dispatch64:
.loop:
    mov eax, [rel legacy_rx_tail]
    cmp eax, [rel legacy_rx_head]
    je .done
    mov r12d, eax
    imul r12, LEGACY_RX_SLOT_BYTES
    add r12, [rel legacy_rx_storage]
    mov edx, [r12]
    lea rcx, [r12+4]
    mov rax, [rel legacy_eth_handler]
    test rax, rax
    jz .consume
    mov r8, [rel legacy_eth_handler_arg]
    sub rsp, 32
    call rax
    add rsp, 32
.consume:
    mov eax, [rel legacy_rx_tail]
    inc eax
    and eax, LEGACY_RX_SLOTS-1
    mov [rel legacy_rx_tail], eax
    jmp .loop
.done:
    ret

legacy_net_set_handler64:
    mov [rel legacy_eth_handler], rcx
    mov [rel legacy_eth_handler_arg], rdx
    ret

; send one full ethernet frame through whichever backend is actually active
legacy_net_send64:
    cmp dword [rel legacy_fw_tx_seen], 0
    jne .tx_call
    push rcx
    push rdx
    call legacy_net_trace_prefix64
    lea rsi, [rel msg_net_first_tx]
    call serial_puts64
    pop rdx
    pop rcx
.tx_call:
    call pxe_net_tx64
    mov [rel legacy_last_tx_status], eax

   ; only firmware rx needs the post-transmit isr gate. native rtl is polled continuously and
   ; must never depend on this flag.
    cmp dword [rel rtl_ready], 1
    je .mark_tx_seen
    mov dword [rel legacy_fw_rx_enabled], 1
.mark_tx_seen:

    cmp dword [rel legacy_fw_tx_seen], 0
    jne .tx_checked
    mov dword [rel legacy_fw_tx_seen], 1
    push rax
    call legacy_net_trace_prefix64
    lea rsi, [rel msg_net_first_tx_back]
    call serial_puts64
    pop rax
.tx_checked:
    test eax, eax
    jz .tx_ok

   ; pxe parameter status is meaningful only on the firmware fallback path.
    cmp dword [rel rtl_ready], 1
    je .ret
    cmp dword [rel legacy_fw_tx_status_seen], 0
    jne .ret
    mov dword [rel legacy_fw_tx_status_seen], 1
    push rax
    mov r12d, eax
    call legacy_net_trace_prefix64
    lea rsi, [rel msg_net_tx_exit]
    call serial_puts64
    mov eax, r12d
    call serial_hex32_64
    lea rsi, [rel msg_net_tx_pb_status]
    call serial_puts64
    movzx eax, word [rel pxe_tx_param + UNDI_TX_STATUS]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    pop rax
    jmp .ret
.tx_ok:
    inc qword [rel legacy_tx_packets]
.ret:
    ret

; live backend statistics once traffic begins. these counters describe the packets the
; runtime actually sent/received, not stale pxe parameter blocks.
legacy_net_diag_tick64:
   ; repeating runtime telemetry is opt-in. startup diagnostics still print, but netstat/com
   ; loops stay silent until "seriallive on".
    cmp dword [rel serial_live_enabled], 1
    jne .ret
    call legacy_shell_input_busy64
    test eax, eax
    jnz .ret
    cmp dword [rel legacy_fw_tx_seen], 1
    jne .ret

    mov rax, [rel tsc_cycles_per_ms]
    test rax, rax
    jz .fallback
    mov r8, [rel legacy_net_diag_deadline]
    test r8, r8
    jz .due
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, r8
    jb .ret
.due:
    mov rax, [rel tsc_cycles_per_ms]
    imul rax, LEGACY_NET_DIAG_INTERVAL_MS
    mov r9, rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    add rax, r9
    mov [rel legacy_net_diag_deadline], rax
    jmp .print
.fallback:
    inc dword [rel legacy_net_diag_fallback]
    cmp dword [rel legacy_net_diag_fallback], 250000
    jb .ret
    mov dword [rel legacy_net_diag_fallback], 0
.print:
   ; keep netstat event-driven even while seriallive is enabled. serial output already
   ; mirrors runtime events; seriallive only adds a periodic beacon.
    mov rax, [rel legacy_tx_packets]
    cmp rax, [rel legacy_net_diag_last_tx]
    jne .changed
    mov rax, [rel legacy_rx_packets]
    cmp rax, [rel legacy_net_diag_last_rx]
    jne .changed
    mov rax, [rel legacy_rx_dropped]
    cmp rax, [rel legacy_net_diag_last_drop]
    je .ret
.changed:
    mov rax, [rel legacy_tx_packets]
    mov [rel legacy_net_diag_last_tx], rax
    mov rax, [rel legacy_rx_packets]
    mov [rel legacy_net_diag_last_rx], rax
    mov rax, [rel legacy_rx_dropped]
    mov [rel legacy_net_diag_last_drop], rax

    lea rsi, [rel msg_netstat]
    call serial_puts64
    cmp dword [rel rtl_ready], 1
    jne .backend_pxe
    lea rsi, [rel msg_netstat_rtl]
    call serial_puts64
    jmp .backend_done
.backend_pxe:
    lea rsi, [rel msg_netstat_pxe]
    call serial_puts64
.backend_done:
    lea rsi, [rel msg_netstat_txpk]
    call serial_puts64
    mov eax, [rel legacy_tx_packets]
    call serial_hex32_64
    lea rsi, [rel msg_netstat_rxpk]
    call serial_puts64
    mov eax, [rel legacy_rx_packets]
    call serial_hex32_64
    lea rsi, [rel msg_netstat_drop]
    call serial_puts64
    mov eax, [rel legacy_rx_dropped]
    call serial_hex32_64
    lea rsi, [rel msg_netstat_polls]
    call serial_puts64
    mov eax, [rel legacy_isr_poll_count]
    call serial_hex32_64
    lea rsi, [rel msg_netstat_arp]
    call serial_puts64
    mov eax, [rel legacy_arp_count]
    call serial_hex32_64
    lea rsi, [rel msg_netstat_dns]
    call serial_puts64
    mov eax, [rel legacy_dns_state]
    call serial_hex32_64
    lea rsi, [rel msg_netstat_txst]
    call serial_puts64
    mov eax, [rel legacy_last_tx_status]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64

   ; keep uart diagnostics directly under each changed netstat snapshot so the physical
   ; serial mapping stays visible without spamming every runtime tick.
    lea rsi, [rel msg_com_active]
    call serial_puts64
    movzx eax, word [rel runtime_uart1]
    call serial_hex32_64
    mov al, ' '
    call serial_putc64_al
    movzx eax, word [rel runtime_uart2]
    call serial_hex32_64
    mov al, ' '
    call serial_putc64_al
    movzx eax, word [rel runtime_uart3]
    call serial_hex32_64
    mov al, ' '
    call serial_putc64_al
    movzx eax, word [rel runtime_uart4]
    call serial_hex32_64

    lea rsi, [rel msg_com_bios]
    call serial_puts64
    movzx eax, word [rel bios_uart1]
    call serial_hex32_64
    mov al, ' '
    call serial_putc64_al
    movzx eax, word [rel bios_uart2]
    call serial_hex32_64
    mov al, ' '
    call serial_putc64_al
    movzx eax, word [rel bios_uart3]
    call serial_hex32_64
    mov al, ' '
    call serial_putc64_al
    movzx eax, word [rel bios_uart4]
    call serial_hex32_64

    lea rsi, [rel msg_com_uarttest]
    call serial_puts64
    movzx eax, byte [rel uart_diag_lsr]
    call serial_hex32_64
    lea rsi, [rel msg_com_msr]
    call serial_puts64
    movzx eax, byte [rel uart_diag_msr]
    call serial_hex32_64
    lea rsi, [rel msg_com_loop]
    call serial_puts64
    movzx eax, byte [rel uart_diag_loop]
    call serial_hex32_64

    lea rsi, [rel msg_crlf64]
    call serial_puts64
.ret:
    ret

align 16
high_region_count      dd 0
high_regions           times (LEGACY_HIGH_REGIONS * 16) db 0
legacy_net_ready       dd 0
legacy_rx_head         dd 0
legacy_rx_tail         dd 0
legacy_rx_storage      dq 0
legacy_eth_handler     dq 0
legacy_eth_handler_arg dq 0
legacy_rx_packets      dq 0
legacy_rx_dropped      dq 0
legacy_tx_packets      dq 0
legacy_runtime_ticks   dq 0
legacy_fw_rx_deadline  dq 0
legacy_net_diag_deadline dq 0
legacy_net_diag_fallback dd 0
legacy_net_diag_last_tx dq -1
legacy_net_diag_last_rx dq -1
legacy_net_diag_last_drop dq -1
legacy_fw_rx_enabled   dd 0
legacy_fw_tx_seen      dd 0
legacy_fw_rx_seen      dd 0
legacy_fw_frame_seen   dd 0
legacy_fw_tx_status_seen dd 0
legacy_last_tx_status  dd 0
legacy_isr_poll_count  dd 0
legacy_net_trace_seq   dd 0
legacy_net_trace_isr_count dd 0
legacy_net_trace_start_ms dq 0

msg_highmem              db '[RAM] high-memory regions=0x',0
msg_net_core             db '[NET] ethernet ring online; native RTL preferred, PXE fallback armed',13,10,0
msg_net_alloc_fail       db '[ERROR] could not allocate raw Ethernet RX ring',13,10,0
msg_net_trace_seq        db '[TRACE #0x',0
msg_net_trace_time       db ' +0x',0
msg_net_trace_suffix     db 'ms] ',0
msg_net_first_tx         db '[NET] first transmit call',13,10,0
msg_net_first_tx_back    db '[NET] first transmit returned',13,10,0
msg_net_tx_exit          db '[NET] PXE transmit exit=0x',0
msg_net_tx_pb_status     db ' pb_status=0x',0
msg_net_first_rx         db '[NET] first PXE receive ISR call',13,10,0
msg_net_first_rx_back    db '[NET] first PXE receive ISR returned',13,10,0
msg_net_isr_diag_status  db '[NET] ISR status=0x',0
msg_net_isr_diag_func    db ' func=0x',0
msg_net_isr_diag_buf     db ' buflen=0x',0
msg_net_isr_diag_frame   db ' framelen=0x',0
msg_net_first_frame      db '[NET] first RX frame len=0x',0
msg_net_first_frame_type db ' ethertype=0x',0
msg_netstat              db '[NETSTAT] backend=',0
msg_netstat_rtl          db 'rtl',0
msg_netstat_pxe          db 'pxe',0
msg_netstat_txpk         db ' txpk=0x',0
msg_netstat_rxpk         db ' rxpk=0x',0
msg_netstat_drop         db ' drop=0x',0
msg_netstat_polls        db ' polls=0x',0
msg_netstat_arp          db ' arp=0x',0
msg_netstat_dns          db ' dns=0x',0
msg_netstat_txst         db ' txst=0x',0
msg_com_active            db '[COM] active bases=',0
msg_com_bios              db ' bios=',0
msg_com_uarttest          db ' lsr=',0
msg_com_msr               db ' msr=',0
msg_com_loop              db ' loopback=',0
