; tiny native realtek rtl8168/rtl8169 driver for the legacy runtime runtime networking
; stays native once stage1 hands off from pxe

BITS 64

%define RTL_VENDOR_REALTEK 0x10EC
%define RTL_DEV_8168       0x8168
%define RTL_DEV_8169       0x8169
%define RTL_DEV_8136       0x8136

; tls certificate flights arrive in a burst. eight descriptors was enough for dns/tcp
; setup but could overrun while serial/vga diagnostics were printing.
%define RTL_RX_DESC_COUNT  64
%define RTL_BUF_BYTES      2048

%define RTL_IDR0           0x00
%define RTL_TNPDS_LO       0x20
%define RTL_TNPDS_HI       0x24
%define RTL_CHIP_CMD       0x37
%define RTL_TX_POLL        0x38
%define RTL_IMR            0x3C
%define RTL_ISR            0x3E
%define RTL_TCR            0x40
%define RTL_RCR            0x44
%define RTL_CFG9346        0x50
%define RTL_RMS            0xDA
%define RTL_CPLUS_CMD      0xE0
%define RTL_RDSAR_LO       0xE4
%define RTL_RDSAR_HI       0xE8
%define RTL_ETTHR          0xEC

%define RTL_CMD_RESET      0x10
%define RTL_CMD_RX_ENABLE  0x08
%define RTL_CMD_TX_ENABLE  0x04
%define RTL_TX_NPQ         0x40

%define RTL_DESC_OWN       0x80000000
%define RTL_DESC_EOR       0x40000000
%define RTL_DESC_FS        0x20000000
%define RTL_DESC_LS        0x10000000
%define RTL_DESC_LEN_MASK  0x00003FFF

rtl816x_init64:
    mov dword [rel rtl_ready], 0
    mov qword [rel rtl_mmio], 0
    mov dword [rel rtl_rx_index], 0

   ; find a realtek gigabit nic from the pci table we already built
    mov ecx, [rel pci_device_count]
    lea rsi, [rel pci_devices]
.find:
    test ecx, ecx
    jz .no
    mov eax, [rsi+4]
    cmp ax, RTL_VENDOR_REALTEK
    jne .next
    shr eax, 16
    cmp ax, RTL_DEV_8168
    je .found
    cmp ax, RTL_DEV_8169
    je .found
    cmp ax, RTL_DEV_8136
    je .found
.next:
    add rsi, 16
    dec ecx
    jmp .find

.found:
    mov al, [rsi+0]
    mov [rel rtl_bus], al
    mov al, [rsi+1]
    mov [rel rtl_dev], al
    mov al, [rsi+2]
    mov [rel rtl_func], al
    mov eax, [rsi+4]
    shr eax, 16
    mov [rel rtl_device_id], ax

   ; enable io + memory + bus mastering without touching status bits
    mov ecx, 0x04
    call rtl_pci_read32
    or eax, 0x00000007
    mov edx, eax
    mov ecx, 0x04
    call rtl_pci_write32

   ; pick the first memory bar. old 8168 boards often put mmio in bar2/bar4.
    xor r11d, r11d
.bar_loop:
    cmp r11d, 6
    jae .no
    mov ecx, r11d
    shl ecx, 2
    add ecx, 0x10
    call rtl_pci_read32
    test eax, eax
    jz .bar_next
    test eax, 1
    jnz .bar_next
    mov r10d, eax
    and r10d, 0xFFFFFFF0
    test r10d, r10d
    jz .bar_next
    mov eax, r10d
    mov [rel rtl_mmio], rax
    jmp .bar_ok
.bar_next:
    inc r11d
    jmp .bar_loop

.bar_ok:
   ; keep tx dma state in the runtime image itself. the old allocator-backed tx pointers were
   ; the only writable pointers on the faulting tcp-syn path.
    lea rax, [rel rtl_tx_desc_static]
    mov [rel rtl_tx_desc], rax
    lea rax, [rel rtl_tx_buf_static]
    mov [rel rtl_tx_buf], rax

   ; descriptor table and packet buffers are allocator-backed and identity mapped.
    mov ecx, ((RTL_RX_DESC_COUNT * 16) + 4095) / 4096
    call alloc_pages64
    test rax, rax
    jz .no
    mov [rel rtl_rx_desc], rax

    mov ecx, ((RTL_RX_DESC_COUNT * RTL_BUF_BYTES) + 4095) / 4096
    call alloc_pages64
    test rax, rax
    jz .no
    mov [rel rtl_rx_bufs], rax

   ; disable interrupts and reset the chip. polling keeps this bsp-only and simple.
    mov rbx, [rel rtl_mmio]
    mov word [rbx+RTL_IMR], 0
    mov byte [rbx+RTL_CHIP_CMD], RTL_CMD_RESET
    mov ecx, 1000000
.reset_wait:
    test byte [rbx+RTL_CHIP_CMD], RTL_CMD_RESET
    jz .reset_done
    pause
    loop .reset_wait
    jmp .no
.reset_done:

    mov byte [rbx+RTL_CFG9346], 0xC0
    mov word [rbx+RTL_IMR], 0
    mov word [rbx+RTL_ISR], 0xFFFF
    mov word [rbx+RTL_RMS], RTL_BUF_BYTES
    mov dword [rbx+RTL_RCR], 0x0000E70F
    mov dword [rbx+RTL_TCR], 0x03000700
    mov byte [rbx+RTL_ETTHR], 0x3F

    mov ax, [rbx+RTL_CPLUS_CMD]
    or ax, 0x0008
    mov [rbx+RTL_CPLUS_CMD], ax

    xor r8d, r8d
.rx_build:
    cmp r8d, RTL_RX_DESC_COUNT
    jae .rx_done
    mov rdi, [rel rtl_rx_desc]
    mov eax, r8d
    shl rax, 4
    add rdi, rax
    mov eax, RTL_DESC_OWN | RTL_BUF_BYTES
    cmp r8d, RTL_RX_DESC_COUNT-1
    jne .not_last
    or eax, RTL_DESC_EOR
.not_last:
    mov [rdi+0], eax
    mov dword [rdi+4], 0
    mov rax, [rel rtl_rx_bufs]
    mov edx, r8d
    shl rdx, 11
    add rax, rdx
    mov [rdi+8], eax
    shr rax, 32
    mov [rdi+12], eax
    inc r8d
    jmp .rx_build
.rx_done:

    mov rdi, [rel rtl_tx_desc]
    mov dword [rdi+0], RTL_DESC_EOR
    mov dword [rdi+4], 0
    mov rax, [rel rtl_tx_buf]
    mov [rdi+8], eax
    shr rax, 32
    mov [rdi+12], eax

    mov rax, [rel rtl_tx_desc]
    mov [rbx+RTL_TNPDS_LO], eax
    shr rax, 32
    mov [rbx+RTL_TNPDS_HI], eax
    mov rax, [rel rtl_rx_desc]
    mov [rbx+RTL_RDSAR_LO], eax
    shr rax, 32
    mov [rbx+RTL_RDSAR_HI], eax

    mfence
    mov byte [rbx+RTL_CHIP_CMD], RTL_CMD_RX_ENABLE | RTL_CMD_TX_ENABLE
    mov byte [rbx+RTL_CFG9346], 0x00

   ; keep the stack source mac aligned with the physical nic
    lea rdi, [rel undi_info+12]
    mov rsi, rbx
    mov ecx, 6
    rep movsb

    mov dword [rel rtl_ready], 1
    lea rsi, [rel msg_rtl_ready]
    call serial_puts64
    movzx eax, word [rel rtl_device_id]
    call serial_hex32_64
    lea rsi, [rel msg_rtl_mmio]
    call serial_puts64
    mov rax, [rel rtl_mmio]
    call serial_hex64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; rcx frame pointer, edx length. eax=0 success, nonzero failure. preserve all state we
; depend on explicitly instead of hiding the source pointer in r9.
rtl816x_send64:
    push rbx
    push r12
    push r13
    push r14

    mov r12, rcx
    mov r13d, edx
    cmp dword [rel rtl_ready], 1
    jne .fail
    test r12, r12
    jz .fail
    cmp r13d, 14
    jb .fail
    cmp r13d, RTL_BUF_BYTES
    ja .fail

    mov r14, [rel rtl_tx_desc]
    test r14, r14
    jz .fail
    mov rdi, [rel rtl_tx_buf]
    test rdi, rdi
    jz .fail

    mov ecx, 200000
.wait_tx:
    test dword [r14+0], RTL_DESC_OWN
    jz .slot
    pause
    loop .wait_tx
    jmp .fail

.slot:
   ; copy through stable image-backed tx memory before handing ownership to dma
    mov rsi, r12
    mov rdi, [rel rtl_tx_buf]
    mov ecx, r13d
    rep movsb
    mfence

    mov eax, RTL_DESC_OWN | RTL_DESC_EOR | RTL_DESC_FS | RTL_DESC_LS
    or eax, r13d
    mov [r14+0], eax
    mfence

    mov rbx, [rel rtl_mmio]
    test rbx, rbx
    jz .fail
    mov byte [rbx+RTL_TX_POLL], RTL_TX_NPQ
    xor eax, eax
    jmp .out
.fail:
    mov eax, 1
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

rtl816x_send_frame64:
    jmp rtl816x_send64

; rcx destination, edx capacity. eax returns one frame length or zero.
rtl816x_recv64:
    cmp dword [rel rtl_ready], 1
    jne .none
    test rcx, rcx
    jz .none
    test edx, edx
    jz .none
    mov r9, rcx
    mov r10d, edx

   ; acknowledge accumulated polling-mode status. on some 8168 revisions a receive
   ; overflow/status latch can otherwise leave the descriptor engine idle.
    mov rbx, [rel rtl_mmio]
    test rbx, rbx
    jz .none
    mov ax, [rbx+RTL_ISR]
    test ax, ax
    jz .check_desc
    mov [rbx+RTL_ISR], ax
.check_desc:

    mov eax, [rel rtl_rx_index]
    and eax, RTL_RX_DESC_COUNT-1
    mov r8d, eax
    mov rdi, [rel rtl_rx_desc]
    shl rax, 4
    add rdi, rax
    mov eax, [rdi+0]
    test eax, RTL_DESC_OWN
    jnz .none

    mov r11d, eax
    and r11d, RTL_DESC_LEN_MASK
    cmp r11d, 4
    jb .rearm
    sub r11d, 4
    cmp r11d, r10d
    jbe .len_ok
    mov r11d, r10d
.len_ok:
    mov rsi, [rel rtl_rx_bufs]
    mov eax, r8d
    shl rax, 11
    add rsi, rax
    mov rdi, r9
    mov ecx, r11d
    rep movsb

.rearm:
    mov rdi, [rel rtl_rx_desc]
    mov eax, r8d
    shl rax, 4
    add rdi, rax
    mov eax, RTL_DESC_OWN | RTL_BUF_BYTES
    cmp r8d, RTL_RX_DESC_COUNT-1
    jne .rearm_not_last
    or eax, RTL_DESC_EOR
.rearm_not_last:
    mov [rdi+0], eax
    mfence

    inc r8d
    and r8d, RTL_RX_DESC_COUNT-1
    mov [rel rtl_rx_index], r8d

   ; clear receive status again after returning the descriptor to hardware.
    mov rbx, [rel rtl_mmio]
    mov ax, [rbx+RTL_ISR]
    test ax, ax
    jz .return_len
    mov [rbx+RTL_ISR], ax
.return_len:
    mov eax, r11d
    ret
.none:
    xor eax, eax
    ret

rtl_pci_make_addr:
    movzx eax, byte [rel rtl_bus]
    shl eax, 16
    movzx edx, byte [rel rtl_dev]
    shl edx, 11
    or eax, edx
    movzx edx, byte [rel rtl_func]
    shl edx, 8
    or eax, edx
    and ecx, 0xFC
    or eax, ecx
    or eax, 0x80000000
    ret

rtl_pci_read32:
    push rdx
    call rtl_pci_make_addr
    mov dx, 0xCF8
    out dx, eax
    mov dx, 0xCFC
    in eax, dx
    pop rdx
    ret

rtl_pci_write32:
    push rax
    push rbx
    mov ebx, edx
    call rtl_pci_make_addr
    mov dx, 0xCF8
    out dx, eax
    mov eax, ebx
    mov dx, 0xCFC
    out dx, eax
    pop rbx
    pop rax
    ret

align 16
rtl_ready       dd 0
rtl_bus         db 0
rtl_dev         db 0
rtl_func        db 0
align 2
rtl_device_id   dw 0
align 8
rtl_mmio        dq 0
rtl_tx_desc     dq 0
rtl_tx_buf      dq 0
rtl_rx_desc     dq 0
rtl_rx_bufs     dq 0
rtl_rx_index    dd 0

; single synchronous tx slot, identity mapped with the runtime image
align 256
rtl_tx_desc_static:
    times 16 db 0
align 256
rtl_tx_buf_static:
    times RTL_BUF_BYTES db 0

msg_rtl_ready db '[RTL] native polling backend online device=0x',0
msg_rtl_mmio  db ' mmio=0x',0
