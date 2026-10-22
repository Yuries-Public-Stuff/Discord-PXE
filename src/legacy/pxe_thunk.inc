; lets x64 call the old real mode pxe rom and come back firmware stays on the
; main cpu because old

%define PXE_THUNK_PHYS        0x5000
%define PXE_MAILBOX_PHYS      0x6000
%define PXE_PARAM_PHYS        0x6100
%define PXE_DATA_PHYS         0x6800
%define PXE_DATA_MAX          0x1800

%define PXE_MB_OPCODE         0x00
%define PXE_MB_PARAM_OFF      0x02
%define PXE_MB_PARAM_SEG      0x04
%define PXE_MB_ENTRY_OFF      0x06
%define PXE_MB_ENTRY_SEG      0x08
%define PXE_MB_RESULT_AX      0x0A
%define PXE_MB_SAVED_CR3      0x10
%define PXE_MB_SAVED_RSP      0x18
%define PXE_MB_RETURN_RIP     0x20

%define PXENV_UNDI_INITIALIZE 0x0003
%define PXENV_UNDI_OPEN       0x0006
%define PXENV_UNDI_TRANSMIT   0x0008
%define PXENV_UNDI_ISR        0x0014
%define PXENV_UNDI_GET_INFORMATION 0x000C
%define PXENV_UNDI_ISR_IN_START    1
%define PXENV_UNDI_ISR_IN_PROCESS  2
%define PXENV_UNDI_ISR_IN_GET_NEXT 3
%define PXENV_UNDI_ISR_OUT_OURS    0
%define PXENV_UNDI_ISR_OUT_DONE    0
%define PXENV_UNDI_ISR_OUT_TRANSMIT 2
%define PXENV_UNDI_ISR_OUT_RECEIVE 3
%define PXENV_UNDI_ISR_OUT_BUSY    4
%define FLTR_DIRECTED 0x0001
%define FLTR_BRDCST   0x0002
%define P_UNKNOWN 0
%define XMT_DESTADDR 0

%define ISR_STATUS        0
%define ISR_FUNC          2
%define ISR_BUFLEN        4
%define ISR_FRAMELEN      6
%define ISR_HDRLEN        8
%define ISR_FRAME_OFF    10
%define ISR_FRAME_SEG    12
%define ISR_PROT         14
%define ISR_PKTTYPE      15
%define ISR_SIZE         16

BITS 64

pxe_thunk_init64:
    lea rsi, [rel pxe_thunk_blob_start]
    mov rdi, PXE_THUNK_PHYS
    mov rcx, pxe_thunk_blob_end - pxe_thunk_blob_start
    rep movsb

    mov rdi, PXE_MAILBOX_PHYS
    xor eax, eax
    mov ecx, (0x100 + PXE_DATA_MAX) / 8
    rep stosq

    mov ax, [rel pxe_rm_entry+0]
    mov [abs PXE_MAILBOX_PHYS + PXE_MB_ENTRY_OFF], ax
    mov ax, [rel pxe_rm_entry+2]
    mov [abs PXE_MAILBOX_PHYS + PXE_MB_ENTRY_SEG], ax
    mov word [abs PXE_MAILBOX_PHYS + PXE_MB_PARAM_OFF], PXE_PARAM_PHYS
    mov word [abs PXE_MAILBOX_PHYS + PXE_MB_PARAM_SEG], 0

    mov dword [rel pxe_fw_lock], 0
    mov dword [rel pxe_thunk_ready], 1
    mov dword [rel pxe_thunk_proven], 1
    mov dword [rel pxe_undi_open_ok], 0
    mov dword [rel pxe_undi_init_attempted], 0
    mov dword [rel rtl_native_attempted], 0

  ; do not call firmware here. the exact thunk blob below is hardware-proven,
  ; but the redundant boot-time get_information call made this
    lea rsi, [rel msg_thunk_ready]
    call serial_puts64
    ret

; rcx is pxe opcode, rdx is params, r8d is param size
pxe_rm_call64:
    cmp dword [rel pxe_thunk_ready], 1
    jne .bad
    test rdx, rdx
    jz .bad
    cmp r8d, 256
    ja .bad

    pushfq
    cli
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    mov r12, rdx
    mov r13d, r8d
    mov r14d, ecx

.lock:
    mov eax, 1
    xchg eax, [rel pxe_fw_lock]
    test eax, eax
    jnz .lock

    mov rsi, r12
    mov rdi, PXE_PARAM_PHYS
    mov ecx, r13d
    rep movsb

    mov word [abs PXE_MAILBOX_PHYS + PXE_MB_OPCODE], r14w
    mov word [abs PXE_MAILBOX_PHYS + PXE_MB_RESULT_AX], 0xFFFF
    mov rax, cr3
    mov [abs PXE_MAILBOX_PHYS + PXE_MB_SAVED_CR3], rax

    mov rax, PXE_THUNK_PHYS
    call rax

    movzx r15d, word [abs PXE_MAILBOX_PHYS + PXE_MB_RESULT_AX]

    mov rsi, PXE_PARAM_PHYS
    mov rdi, r12
    mov ecx, r13d
    rep movsb

    mov dword [rel pxe_fw_lock], 0
    mov eax, r15d

    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    popfq
    ret
.bad:
    mov eax, 0xFFFF
    ret

; tftp leaves this realtek undi stack unable to transmit until it is opened
; again.
pxe_net_ensure_open64:
    cmp dword [rel pxe_undi_open_ok], 1
    je .ready

.try_open:
    lea rdi, [rel pxe_open_param]
    xor eax, eax
    mov ecx, 136
    rep stosb
    mov word [rel pxe_open_param+2], 0
    mov word [rel pxe_open_param+4], FLTR_DIRECTED | FLTR_BRDCST
    mov ecx, PXENV_UNDI_OPEN
    lea rdx, [rel pxe_open_param]
    mov r8d, 136
    call pxe_rm_call64
    mov [rel pxe_undi_open_exit], eax
    movzx r10d, word [rel pxe_open_param]
    mov [rel pxe_undi_open_status], r10d
    test eax, eax
    jnz .maybe_init
    test r10d, r10d
    jz .opened

.maybe_init:
    cmp r10d, 0x006A
    jne .failed
    cmp dword [rel pxe_undi_init_attempted], 1
    je .failed
    mov dword [rel pxe_undi_init_attempted], 1

    lea rdi, [rel pxe_init_param]
    xor eax, eax
    mov ecx, 14
    rep stosb
    mov ecx, PXENV_UNDI_INITIALIZE
    lea rdx, [rel pxe_init_param]
    mov r8d, 14
    call pxe_rm_call64
    mov [rel pxe_undi_init_exit], eax
    movzx r10d, word [rel pxe_init_param]
    mov [rel pxe_undi_init_status], r10d
    test eax, eax
    jnz .failed
    test r10d, r10d
    jnz .failed
    jmp .try_open

.opened:
    mov dword [rel pxe_undi_open_ok], 1
.ready:
    xor eax, eax
    ret
.failed:
    mov eax, [rel pxe_undi_open_exit]
    test eax, eax
    jnz .ret
    mov eax, [rel pxe_undi_open_status]
    test eax, eax
    jnz .ret
    mov eax, [rel pxe_undi_init_exit]
    test eax, eax
    jnz .ret
    mov eax, [rel pxe_undi_init_status]
    test eax, eax
    jnz .ret
    mov eax, 0xFFFF
.ret:
    ret

; rcx is a full ethernet frame, edx is length
pxe_net_tx64:
    cmp dword [rel rtl_ready], 1
    je rtl816x_send_frame64
    cmp dword [rel pxe_thunk_proven], 1
    jne .fail
    push rcx
    push rdx
    call pxe_net_ensure_open64
    pop rdx
    pop rcx
    test eax, eax
    jnz .ret
    test rcx, rcx
    jz .fail
    cmp edx, 14
    jb .fail
    cmp edx, PXE_DATA_MAX
    ja .fail

    mov rsi, rcx
    mov rdi, PXE_DATA_PHYS
    mov ecx, edx
    rep movsb

    lea rdi, [rel pxe_tx_param]
    xor eax, eax
    mov ecx, 96/8
    rep stosq
    mov byte [rel pxe_tx_param+2], P_UNKNOWN
    mov byte [rel pxe_tx_param+3], XMT_DESTADDR
    mov word [rel pxe_tx_param+8], 0x6120
    mov word [rel pxe_tx_param+10], 0
    mov [rel pxe_tx_param+0x20], dx
    mov word [rel pxe_tx_param+0x22], PXE_DATA_PHYS
    mov word [rel pxe_tx_param+0x24], 0
    mov word [rel pxe_tx_param+0x26], 0

    mov ecx, PXENV_UNDI_TRANSMIT
    lea rdx, [rel pxe_tx_param]
    mov r8d, 96
    call pxe_rm_call64
    test eax, eax
    jnz .ret
    movzx eax, word [rel pxe_tx_param]
.ret:
    ret
.fail:
    mov eax, 0xFFFF
    ret

; rcx is where the frame goes, edx is how much room it has
pxe_net_rx64:
    cmp dword [rel rtl_ready], 1
    je rtl816x_recv64
    cmp dword [rel pxe_thunk_proven], 1
    jne .none
    test rcx, rcx
    jz .none
    test edx, edx
    jz .none
    mov [rel pxe_rx_user], rcx
    mov [rel pxe_rx_cap], edx

    lea rdi, [rel pxe_isr_param]
    xor eax, eax
    mov ecx, ISR_SIZE/8
    rep stosq
    mov word [rel pxe_isr_param + ISR_FUNC], PXENV_UNDI_ISR_IN_START
    mov ecx, PXENV_UNDI_ISR
    lea rdx, [rel pxe_isr_param]
    mov r8d, ISR_SIZE
    call pxe_rm_call64
    test eax, eax
    jnz .poll_process
    cmp word [rel pxe_isr_param + ISR_STATUS], 0
    jne .poll_process
    cmp word [rel pxe_isr_param + ISR_FUNC], PXENV_UNDI_ISR_OUT_OURS
    je .process_first

.poll_process:
    lea rdi, [rel pxe_isr_param]
    xor eax, eax
    mov ecx, ISR_SIZE/8
    rep stosq
.process_first:
    mov word [rel pxe_isr_param + ISR_FUNC], PXENV_UNDI_ISR_IN_PROCESS

.process:
    mov ecx, PXENV_UNDI_ISR
    lea rdx, [rel pxe_isr_param]
    mov r8d, ISR_SIZE
    call pxe_rm_call64
    test eax, eax
    jnz .maybe_native
    cmp word [rel pxe_isr_param + ISR_STATUS], 0
    je .process_ok
    cmp word [rel pxe_isr_param + ISR_STATUS], 0x0003
    je .native_fallback
    jmp .none
.process_ok:
    movzx eax, word [rel pxe_isr_param + ISR_FUNC]
    cmp eax, PXENV_UNDI_ISR_OUT_RECEIVE
    je .received
    cmp eax, PXENV_UNDI_ISR_OUT_TRANSMIT
    je .next
    cmp eax, PXENV_UNDI_ISR_OUT_BUSY
    je .none
    cmp eax, PXENV_UNDI_ISR_OUT_DONE
    je .none
.next:
    mov word [rel pxe_isr_param + ISR_FUNC], PXENV_UNDI_ISR_IN_GET_NEXT
    jmp .process

.maybe_native:
    cmp word [rel pxe_isr_param + ISR_STATUS], 0x0003
    jne .none
.native_fallback:
    cmp dword [rel rtl_native_attempted], 1
    je .none
    mov dword [rel rtl_native_attempted], 1
    call rtl816x_init64
    test eax, eax
    jz .none
    mov rcx, [rel pxe_rx_user]
    mov edx, [rel pxe_rx_cap]
    jmp rtl816x_recv64

.received:
    movzx ecx, word [rel pxe_isr_param + ISR_BUFLEN]
    test ecx, ecx
    jz .next
    movzx eax, word [rel pxe_isr_param + ISR_FRAMELEN]
    test eax, eax
    jz .next
    cmp ecx, eax
    cmova ecx, eax
    mov edx, [rel pxe_rx_cap]
    cmp ecx, edx
    cmova ecx, edx

    movzx eax, word [rel pxe_isr_param + ISR_FRAME_SEG]
    shl rax, 4
    movzx edx, word [rel pxe_isr_param + ISR_FRAME_OFF]
    add rax, rdx
    mov rsi, rax
    mov rdi, [rel pxe_rx_user]
    mov r8d, ecx
    rep movsb
    mov eax, r8d
    ret
.none:
    xor eax, eax
    ret

%define THUNK_ADDR(x) (PXE_THUNK_PHYS + (x - pxe_thunk_blob_start))

; do not edit this blob casually. this exact mode-switch path is the version
; that already completed x64 -> real mode
align 16
pxe_thunk_blob_start:
BITS 64
thunk64_entry:
    pop rax
    mov [abs PXE_MAILBOX_PHYS + PXE_MB_RETURN_RIP], rax
    mov [abs PXE_MAILBOX_PHYS + PXE_MB_SAVED_RSP], rsp

    cli
    lgdt [abs THUNK_ADDR(thunk_gdt_ptr)]

    mov rax, THUNK_ADDR(thunk32_leave_long)
    push qword 0x18
    push rax
    retfq

BITS 32
thunk32_leave_long:
    mov eax, cr0
    and eax, 0x7FFFFFFF
    mov cr0, eax
    mov ecx, 0xC0000080
    rdmsr
    and eax, ~(1 << 8)
    wrmsr
    mov eax, cr4
    and eax, ~(1 << 5)
    mov cr4, eax
    jmp 0x20:THUNK_ADDR(thunk16_protected)

BITS 16
thunk16_protected:
    mov ax, 0x28
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov eax, cr0
    and eax, 0xFFFFFFFE
    mov cr0, eax
    jmp 0x0000:THUNK_ADDR(thunk16_real)

thunk16_real:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x4FF0
    sti

    mov bx, [PXE_MAILBOX_PHYS + PXE_MB_OPCODE]
    mov di, [PXE_MAILBOX_PHYS + PXE_MB_PARAM_OFF]
    mov ax, [PXE_MAILBOX_PHYS + PXE_MB_PARAM_SEG]
    mov es, ax
    call far [PXE_MAILBOX_PHYS + PXE_MB_ENTRY_OFF]
    mov [PXE_MAILBOX_PHYS + PXE_MB_RESULT_AX], ax

    cli
    lgdt [THUNK_ADDR(thunk_gdt_ptr)]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    jmp 0x18:THUNK_ADDR(thunk32_enter_long)

BITS 32
thunk32_enter_long:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov eax, cr4
    or eax, 1 << 5
    mov cr4, eax
    mov eax, [PXE_MAILBOX_PHYS + PXE_MB_SAVED_CR3]
    mov cr3, eax
    mov ecx, 0xC0000080
    rdmsr
    or eax, 1 << 8
    wrmsr
    mov eax, cr0
    or eax, (1 << 31) | 1
    mov cr0, eax
    jmp 0x08:THUNK_ADDR(thunk64_return)

BITS 64
thunk64_return:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov rsp, [abs PXE_MAILBOX_PHYS + PXE_MB_SAVED_RSP]
    jmp qword [abs PXE_MAILBOX_PHYS + PXE_MB_RETURN_RIP]

align 8
thunk_gdt:
    dq 0
    dq 0x00AF9A000000FFFF
    dq 0x00CF92000000FFFF
    dq 0x00CF9A000000FFFF
    dq 0x00009A000000FFFF
    dq 0x000092000000FFFF
thunk_gdt_end:
thunk_gdt_ptr:
    dw thunk_gdt_end - thunk_gdt - 1
    dd THUNK_ADDR(thunk_gdt)
pxe_thunk_blob_end:

BITS 64
align 16
pxe_fw_lock       dd 0
pxe_thunk_ready   dd 0
pxe_thunk_proven  dd 0
pxe_rx_cap        dd 0
pxe_rx_user       dq 0
pxe_probe_param   times 64 db 0
pxe_open_param    times 136 db 0
pxe_init_param    times 14 db 0
pxe_undi_open_ok  dd 0
pxe_undi_open_exit dd 0
pxe_undi_open_status dd 0
pxe_undi_init_attempted dd 0
pxe_undi_init_exit dd 0
pxe_undi_init_status dd 0
rtl_native_attempted dd 0
pxe_tx_param      times 96 db 0
pxe_isr_param     times ISR_SIZE db 0

msg_thunk_ready db '[PXE] hardware-proven thunk installed; firmware calls deferred',13,10,0
msg_thunk_ok    db '[PXE] x64 -> real-mode -> x64 firmware thunk verified',13,10,0
msg_thunk_fail  db '[WARN] PXE firmware thunk round-trip failed; raw network disabled',13,10,0

%include "legacy_rtl816x.inc"
