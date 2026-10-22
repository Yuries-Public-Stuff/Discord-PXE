; cpu setup for the legacy x64 runtime turn on normal x64 protections and keep enough cpu
; info for the scheduler

BITS 64

%define LEGACY_IDT_ENTRIES 256

legacy_cpu_runtime_init64:
    call legacy_enable_sse64
    call legacy_enable_protection64
    call legacy_cpu_topology64
    call legacy_idt_init64
    call legacy_msr_probe64
    lea rsi, [rel msg_cpu_runtime_ready]
    call serial_puts64
    ret

; crypto uses the fpu/sse state even though the boot loader did not set it up
legacy_enable_sse64:
    mov rax, cr0
    and rax, ~(1 << 2)
    and rax, ~(1 << 3)
    or rax, 1 << 1
    mov cr0, rax

    mov rax, cr4
    or rax, 1 << 9
    or rax, 1 << 10
    mov cr4, rax
    fninit
    ret

; keep supervisor pages read only too and use nx when the cpu has it
legacy_enable_protection64:
    mov rax, cr0
    or rax, 1 << 16
    mov cr0, rax

    mov byte [rel legacy_nx_ready], 0
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .done
    mov eax, 0x80000001
    cpuid
    test edx, 1 << 20
    jz .done
    mov ecx, 0xC0000080
    rdmsr
    or eax, 1 << 11
    wrmsr
    mov byte [rel legacy_nx_ready], 1
.done:
    ret

; get thread and core counts without guessing from the brand name
legacy_cpu_topology64:
    mov dword [rel legacy_threads_per_core], 1
    mov dword [rel legacy_logical_per_package], 1

    xor eax, eax
    cpuid
    cmp eax, 0x0B
    jb .old

    xor r10d, r10d
.level:
    mov eax, 0x0B
    mov ecx, r10d
    cpuid
    test ebx, ebx
    jz .finish
    mov eax, ecx
    shr eax, 8
    and eax, 0xFF
    cmp eax, 1
    jne .maybe_core
    mov [rel legacy_threads_per_core], ebx
    jmp .next
.maybe_core:
    cmp eax, 2
    jne .next
    mov [rel legacy_logical_per_package], ebx
.next:
    inc r10d
    cmp r10d, 8
    jb .level
    jmp .finish
.old:
    mov eax, 1
    cpuid
    mov eax, ebx
    shr eax, 16
    and eax, 0xFF
    test eax, eax
    jz .finish
    mov [rel legacy_logical_per_package], eax
.finish:
   ; some firmware exposes only the smt level in cpuid.0bh. never report fewer logical
   ; processors per package than threads per core.
    mov eax, [rel legacy_logical_per_package]
    mov ecx, [rel legacy_threads_per_core]
    cmp eax, ecx
    jae .logical_ok
    mov eax, ecx
    mov [rel legacy_logical_per_package], eax
.logical_ok:
    xor edx, edx
    test ecx, ecx
    jz .print
    div ecx
    test eax, eax
    jnz .store_core
    mov eax, 1
.store_core:
    mov [rel legacy_cores_per_package], eax
.print:
    lea rsi, [rel msg_cpu_topology]
    call serial_puts64
    mov eax, [rel legacy_threads_per_core]
    call serial_hex32_64
    lea rsi, [rel msg_cpu_cores]
    call serial_puts64
    mov eax, [rel legacy_cores_per_package]
    call serial_hex32_64
    lea rsi, [rel msg_cpu_logical]
    call serial_puts64
    mov eax, [rel legacy_logical_per_package]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    ret

; install a default trap and dedicated gp/page-fault stubs so the fault frame is usable
legacy_idt_init64:
   ; default external/unhandled entries still go to the generic sentinel.
    lea rdi, [rel legacy_idt]
    lea rax, [rel legacy_fault_stub64]
    mov ecx, LEGACY_IDT_ENTRIES
.loop:
    mov word [rdi+0], ax
    mov word [rdi+2], 0x08
    mov byte [rdi+4], 0
    mov byte [rdi+5], 0x8E
    mov rdx, rax
    shr rdx, 16
    mov word [rdi+6], dx
    mov rdx, rax
    shr rdx, 32
    mov dword [rdi+8], edx
    mov dword [rdi+12], 0
    add rdi, 16
    loop .loop

   ; cpu exceptions need their real vector number and correct error-code shape.
    lea rsi, [rel legacy_exception_stub_table]
    xor ecx, ecx
.exc_loop:
    mov rax, [rsi+rcx*8]
    push rcx
    call legacy_idt_set_gate64
    pop rcx
    inc ecx
    cmp ecx, 32
    jb .exc_loop

   ; xapic commonly uses vector ff for spurious interrupts. a true apic spurious interrupt
   ; gets no eoi and simply returns.
    mov ecx, 0xFF
    lea rax, [rel legacy_apic_spurious_stub64]
    call legacy_idt_set_gate64

    lidt [rel legacy_idtr]
    ret

; ecx vector, rax handler
legacy_idt_set_gate64:
    lea rdi, [rel legacy_idt]
    mov edx, ecx
    shl rdx, 4
    add rdi, rdx
    mov word [rdi+0], ax
    mov word [rdi+2], 0x08
    mov byte [rdi+4], 0
    mov byte [rdi+5], 0x8E
    mov rdx, rax
    shr rdx, 16
    mov word [rdi+6], dx
    mov rdx, rax
    shr rdx, 32
    mov dword [rdi+8], edx
    mov dword [rdi+12], 0
    ret

; generic non-exception sentinel.
legacy_fault_stub64:
    push qword 0
    push qword 0xFF
    jmp legacy_fault_common64

; exception stubs normalize the frame to: [rsp+0] vector, [rsp+8] error, [rsp+16] rip,
; [rsp+24] cs, [rsp+32] rflags exceptions 8,10,11,12,13,14,17,21,29,30 have a cpu error code.
legacy_exc_0_stub64:
    push qword 0
    push qword 0
    jmp legacy_fault_common64

legacy_exc_1_stub64:
    push qword 0
    push qword 1
    jmp legacy_fault_common64

legacy_exc_2_stub64:
    push qword 0
    push qword 2
    jmp legacy_fault_common64

legacy_exc_3_stub64:
    push qword 0
    push qword 3
    jmp legacy_fault_common64

legacy_exc_4_stub64:
    push qword 0
    push qword 4
    jmp legacy_fault_common64

legacy_exc_5_stub64:
    push qword 0
    push qword 5
    jmp legacy_fault_common64

legacy_exc_6_stub64:
    push qword 0
    push qword 6
    jmp legacy_fault_common64

legacy_exc_7_stub64:
    push qword 0
    push qword 7
    jmp legacy_fault_common64

legacy_exc_8_stub64:
    push qword 8
    jmp legacy_fault_common64

legacy_exc_9_stub64:
    push qword 0
    push qword 9
    jmp legacy_fault_common64

legacy_exc_10_stub64:
    push qword 10
    jmp legacy_fault_common64

legacy_exc_11_stub64:
    push qword 11
    jmp legacy_fault_common64

legacy_exc_12_stub64:
    push qword 12
    jmp legacy_fault_common64

legacy_exc_13_stub64:
    push qword 13
    jmp legacy_fault_common64

legacy_exc_14_stub64:
    push qword 14
    jmp legacy_fault_common64

legacy_exc_15_stub64:
    push qword 0
    push qword 15
    jmp legacy_fault_common64

legacy_exc_16_stub64:
    push qword 0
    push qword 16
    jmp legacy_fault_common64

legacy_exc_17_stub64:
    push qword 17
    jmp legacy_fault_common64

legacy_exc_18_stub64:
    push qword 0
    push qword 18
    jmp legacy_fault_common64

legacy_exc_19_stub64:
    push qword 0
    push qword 19
    jmp legacy_fault_common64

legacy_exc_20_stub64:
    push qword 0
    push qword 20
    jmp legacy_fault_common64

legacy_exc_21_stub64:
    push qword 21
    jmp legacy_fault_common64

legacy_exc_22_stub64:
    push qword 0
    push qword 22
    jmp legacy_fault_common64

legacy_exc_23_stub64:
    push qword 0
    push qword 23
    jmp legacy_fault_common64

legacy_exc_24_stub64:
    push qword 0
    push qword 24
    jmp legacy_fault_common64

legacy_exc_25_stub64:
    push qword 0
    push qword 25
    jmp legacy_fault_common64

legacy_exc_26_stub64:
    push qword 0
    push qword 26
    jmp legacy_fault_common64

legacy_exc_27_stub64:
    push qword 0
    push qword 27
    jmp legacy_fault_common64

legacy_exc_28_stub64:
    push qword 0
    push qword 28
    jmp legacy_fault_common64

legacy_exc_29_stub64:
    push qword 29
    jmp legacy_fault_common64

legacy_exc_30_stub64:
    push qword 30
    jmp legacy_fault_common64

legacy_exc_31_stub64:
    push qword 0
    push qword 31
    jmp legacy_fault_common64

legacy_apic_spurious_stub64:
    iretq

align 8
legacy_exception_stub_table:
    dq RELOC_BASE + legacy_exc_0_stub64
    dq RELOC_BASE + legacy_exc_1_stub64
    dq RELOC_BASE + legacy_exc_2_stub64
    dq RELOC_BASE + legacy_exc_3_stub64
    dq RELOC_BASE + legacy_exc_4_stub64
    dq RELOC_BASE + legacy_exc_5_stub64
    dq RELOC_BASE + legacy_exc_6_stub64
    dq RELOC_BASE + legacy_exc_7_stub64
    dq RELOC_BASE + legacy_exc_8_stub64
    dq RELOC_BASE + legacy_exc_9_stub64
    dq RELOC_BASE + legacy_exc_10_stub64
    dq RELOC_BASE + legacy_exc_11_stub64
    dq RELOC_BASE + legacy_exc_12_stub64
    dq RELOC_BASE + legacy_exc_13_stub64
    dq RELOC_BASE + legacy_exc_14_stub64
    dq RELOC_BASE + legacy_exc_15_stub64
    dq RELOC_BASE + legacy_exc_16_stub64
    dq RELOC_BASE + legacy_exc_17_stub64
    dq RELOC_BASE + legacy_exc_18_stub64
    dq RELOC_BASE + legacy_exc_19_stub64
    dq RELOC_BASE + legacy_exc_20_stub64
    dq RELOC_BASE + legacy_exc_21_stub64
    dq RELOC_BASE + legacy_exc_22_stub64
    dq RELOC_BASE + legacy_exc_23_stub64
    dq RELOC_BASE + legacy_exc_24_stub64
    dq RELOC_BASE + legacy_exc_25_stub64
    dq RELOC_BASE + legacy_exc_26_stub64
    dq RELOC_BASE + legacy_exc_27_stub64
    dq RELOC_BASE + legacy_exc_28_stub64
    dq RELOC_BASE + legacy_exc_29_stub64
    dq RELOC_BASE + legacy_exc_30_stub64
    dq RELOC_BASE + legacy_exc_31_stub64

; stack here is vector, error, rip, cs, rflags for the dedicated stubs
legacy_fault_common64:
    cli

   ; aps use stacks carved from [heap_end, ap_stack_base). if an ap faults, do not let
   ; several cpus concurrently print through the shared uart/vga path. record one snapshot and halt
    mov rbx, [rel heap_end]
    cmp rsp, rbx
    jb .bsp_fault
    mov rbx, [rel ap_stack_base]
    cmp rsp, rbx
    jae .bsp_fault

    lock inc dword [rel legacy_ap_fault_count]

   ; r12d is the stable ap worker id assigned before the runtime worker starts. keep a
   ; separate snapshot for each ap so simultaneous faults cannot destroy one another's evidence.
    mov ecx, r12d
    cmp ecx, MAX_CPUS
    jb .ap_slot_ok
    xor ecx, ecx
.ap_slot_ok:
    mov rax, [rsp+0]
    mov [rel legacy_ap_fault_vector_by_cpu+rcx*8], rax
    mov rax, [rsp+8]
    mov [rel legacy_ap_fault_error_by_cpu+rcx*8], rax
    mov rax, [rsp+16]
    mov [rel legacy_ap_fault_rip_by_cpu+rcx*8], rax
    mov rax, cr2
    mov [rel legacy_ap_fault_cr2_by_cpu+rcx*8], rax
    mov rax, rsp
    mov [rel legacy_ap_fault_rsp_by_cpu+rcx*8], rax

    mov rax, [rsp+24]
    mov [rel legacy_ap_fault_raw3_by_cpu+rcx*8], rax
    mov rax, [rsp+32]
    mov [rel legacy_ap_fault_raw4_by_cpu+rcx*8], rax
    mov rax, [rsp+40]
    mov [rel legacy_ap_fault_raw5_by_cpu+rcx*8], rax

    mov rax, cr0
    mov [rel legacy_ap_fault_cr0_by_cpu+rcx*8], rax
    mov rax, cr3
    mov [rel legacy_ap_fault_cr3_by_cpu+rcx*8], rax
    mov rax, cr4
    mov [rel legacy_ap_fault_cr4_by_cpu+rcx*8], rax
    mov ecx, 0xC0000080
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov ecx, r12d
    mov [rel legacy_ap_fault_efer_by_cpu+rcx*8], rax
.ap_halt:
    hlt
    jmp .ap_halt

.bsp_fault:
    mov rax, [rsp+0]
    mov [rel legacy_fault_vector], rax
    mov rax, [rsp+8]
    mov [rel legacy_fault_error], rax
    mov rax, [rsp+16]
    mov [rel legacy_fault_rip], rax
    mov rax, cr2
    mov [rel legacy_fault_cr2], rax

    lea rsi, [rel msg_fault]
    call serial_puts64
    lea rsi, [rel msg_fault_vector]
    call serial_puts64
    mov rax, [rel legacy_fault_vector]
    call serial_hex64
    lea rsi, [rel msg_fault_error]
    call serial_puts64
    mov rax, [rel legacy_fault_error]
    call serial_hex64
    lea rsi, [rel msg_fault_rip]
    call serial_puts64
    mov rax, [rel legacy_fault_rip]
    call serial_hex64
    lea rsi, [rel msg_fault_cr2]
    call serial_puts64
    mov rax, [rel legacy_fault_cr2]
    call serial_hex64

    lea rsi, [rel msg_fault_shard_step]
    call serial_puts64
    mov eax, [rel shard_tcp_debug_step]
    call serial_hex32_64
    lea rsi, [rel msg_fault_shard_ctx]
    call serial_puts64
    mov rax, [rel shard_tcp_debug_ctx]
    call serial_hex64
    lea rsi, [rel msg_fault_shard_tcp]
    call serial_puts64
    mov rax, [rel shard_tcp_debug_tcp]
    call serial_hex64
    lea rsi, [rel msg_fault_shard_tx]
    call serial_puts64
    mov rax, [rel shard_tcp_debug_tx]
    call serial_hex64
    lea rsi, [rel msg_fault_rtl_desc]
    call serial_puts64
    mov rax, [rel rtl_tx_desc]
    call serial_hex64
    lea rsi, [rel msg_fault_rtl_buf]
    call serial_puts64
    mov rax, [rel rtl_tx_buf]
    call serial_hex64

    lea rsi, [rel msg_crlf64]
    call serial_puts64
.halt:
    hlt
    jmp .halt

; save the important mode registers so shell output can show what firmware left us
legacy_msr_probe64:
    mov ecx, 0x1B
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov [rel legacy_apic_base_msr], rax
    mov ecx, 0xC0000080
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov [rel legacy_efer_msr], rax
    ret

align 16
legacy_idt times (LEGACY_IDT_ENTRIES * 16) db 0
legacy_idtr:
    dw (LEGACY_IDT_ENTRIES * 16) - 1
    dq RELOC_BASE + legacy_idt
legacy_apic_base_msr       dq 0
legacy_efer_msr            dq 0
legacy_fault_vector        dq 0
legacy_fault_error         dq 0
legacy_fault_rip           dq 0
legacy_fault_cr2           dq 0
legacy_ap_fault_count      dd 0
align 8
legacy_ap_fault_vector_by_cpu times MAX_CPUS dq 0
legacy_ap_fault_error_by_cpu  times MAX_CPUS dq 0
legacy_ap_fault_rip_by_cpu    times MAX_CPUS dq 0
legacy_ap_fault_cr2_by_cpu    times MAX_CPUS dq 0
legacy_ap_fault_rsp_by_cpu    times MAX_CPUS dq 0
legacy_ap_fault_raw3_by_cpu   times MAX_CPUS dq 0
legacy_ap_fault_raw4_by_cpu   times MAX_CPUS dq 0
legacy_ap_fault_raw5_by_cpu   times MAX_CPUS dq 0
legacy_ap_fault_cr0_by_cpu    times MAX_CPUS dq 0
legacy_ap_fault_cr3_by_cpu    times MAX_CPUS dq 0
legacy_ap_fault_cr4_by_cpu    times MAX_CPUS dq 0
legacy_ap_fault_efer_by_cpu   times MAX_CPUS dq 0
legacy_threads_per_core    dd 1
legacy_cores_per_package   dd 1
legacy_logical_per_package dd 1
legacy_nx_ready            db 0

msg_cpu_runtime_ready db '[CPU] protections + SSE/FPU + IDT + MSR state ready',13,10,0
msg_cpu_topology      db '[CPU] threads/core=0x',0
msg_cpu_cores         db ' cores/package=0x',0
msg_cpu_logical       db ' logical/package=0x',0
msg_fault             db '[FAULT] x64 trap',13,10,0
msg_fault_vector      db '[FAULT] vector=0x',0
msg_fault_error       db ' error=0x',0
msg_fault_rip         db ' rip=0x',0
msg_fault_cr2         db ' cr2=0x',0
msg_fault_shard_step  db ' shard-step=0x',0
msg_fault_shard_ctx   db ' ctx=0x',0
msg_fault_shard_tcp   db ' tcp=0x',0
msg_fault_shard_tx    db ' tx=0x',0
msg_fault_rtl_desc    db ' rtl-desc=0x',0
msg_fault_rtl_buf     db ' rtl-buf=0x',0
