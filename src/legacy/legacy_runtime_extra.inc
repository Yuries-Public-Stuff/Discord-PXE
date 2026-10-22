; x64 runtime services: cpu feature discovery, timing, heap, pci, and ap workers

BITS 64

%define LEGACY_MAX_PCI_DEVICES 128

runtime_extra_init64:
    call cpu_features_init64
    call tsc_init64
    call heap_init64
    call pci_scan64

   ; ap bring-up used to be permanently deferred, so the worker self-test always ran with
   ; only the bsp online. tftp is already closed by stage1 before this runtime starts
    call smp_init64
    call runtime_smp_selftest64
    lea rsi, [rel msg_runtime_extra_ready]
    call serial_puts64
    ret

; save cpu feature bits so later code can choose faster paths safely
cpu_features_init64:
    xor eax, eax
    cpuid
    mov [rel cpu_max_leaf], eax
    mov [rel cpu_vendor+0], ebx
    mov [rel cpu_vendor+4], edx
    mov [rel cpu_vendor+8], ecx

    mov eax, 1
    cpuid
    mov [rel cpu_signature64], eax
    mov [rel cpu_feat_ecx], ecx
    mov [rel cpu_feat_edx], edx

    cmp dword [rel cpu_max_leaf], 7
    jb .extended
    mov eax, 7
    xor ecx, ecx
    cpuid
    mov [rel cpu_feat7_ebx], ebx
    mov [rel cpu_feat7_ecx], ecx
.extended:
    mov eax, 0x80000000
    cpuid
    mov [rel cpu_max_ext_leaf], eax
    cmp eax, 0x80000001
    jb .print
    mov eax, 0x80000001
    cpuid
    mov [rel cpu_ext_ecx], ecx
    mov [rel cpu_ext_edx], edx
.print:
    lea rsi, [rel msg_cpu_vendor64]
    call serial_puts64
    lea rsi, [rel cpu_vendor]
    call serial_puts64
    lea rsi, [rel msg_cpu_sig64]
    call serial_puts64
    mov eax, [rel cpu_signature64]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    ret

; measure the tsc against the old pit so delays work on random hardware
tsc_init64:
    mov byte [rel tsc_invariant], 0
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000007
    jb .calibrate
    mov eax, 0x80000007
    cpuid
    test edx, 1 << 8
    jz .calibrate
    mov byte [rel tsc_invariant], 1
.calibrate:
    pushfq
    cli
    in al, 0x61
    and al, 0xFC
    or al, 0x01
    out 0x61, al
    mov al, 0xB0
    out 0x43, al
    mov ax, 11932
    out 0x42, al
    mov al, ah
    out 0x42, al
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r8, rax
.wait_pit:
    in al, 0x61
    test al, 0x20
    jz .wait_pit
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, r8
    xor edx, edx
    mov ecx, 10
    div rcx
    mov [rel tsc_cycles_per_ms], rax
    popfq

    lea rsi, [rel msg_tsc]
    call serial_puts64
    mov rax, [rel tsc_cycles_per_ms]
    call serial_hex64
    lea rsi, [rel msg_tsc_inv]
    call serial_puts64
    movzx eax, byte [rel tsc_invariant]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    ret

; rcx is milliseconds keep rdx untouched because ap startup keeps the target id in it
tsc_delay_ms64:
    push rdx
    test rcx, rcx
    jz .done
    mov rax, [rel tsc_cycles_per_ms]
    test rax, rax
    jz .fallback
    imul rcx, rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    add rcx, rax
.spin:
    pause
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, rcx
    jb .spin
.done:
    pop rdx
    ret
.fallback:
    mov rax, rcx
    imul rax, 50000
.fallback_loop:
    pause
    dec rax
    jnz .fallback_loop
    pop rdx
    ret

; simple heap for stuff that lives most of the boot not recycling yet keeps memory
; corruption way easier to debug
heap_init64:
    mov qword [rel heap_arena_cur], 0
    mov qword [rel heap_arena_end], 0
    mov qword [rel heap_bytes_live], 0
    lea rsi, [rel msg_heap2]
    call serial_puts64
    ret

; rcx is requested bytes, rax is a zeroed pointer or zero
kmalloc64:
    test rcx, rcx
    jz .fail
    mov r11, rcx
    add r11, 15
    and r11, -16
    add r11, 16

    mov rax, [rel heap_arena_cur]
    mov rdx, rax
    add rdx, r11
    cmp rdx, [rel heap_arena_end]
    jbe .consume

    mov r10, r11
    cmp r10, 0x10000
    jae .size_ok
    mov r10, 0x10000
.size_ok:
    add r10, 0xFFF
    and r10, -4096
    mov rcx, r10
    shr rcx, 12
    call alloc_pages64
    test rax, rax
    jz .fail
    mov [rel heap_arena_cur], rax
    lea rdx, [rax+r10]
    mov [rel heap_arena_end], rdx

.consume:
    mov rdx, rax
    add rdx, r11
    mov [rel heap_arena_cur], rdx
    mov qword [rax+0], 0x4B4D414C4C4F4300
    mov [rax+8], r11
    add qword [rel heap_bytes_live], r11

    lea rdi, [rax+16]
    mov rcx, r11
    sub rcx, 16
    push rax
    xor eax, eax
    rep stosb
    pop rax
    add rax, 16
    ret
.fail:
    xor eax, eax
    ret

; free only fixes accounting for now because boot objects mostly stay alive
kfree64:
    test rcx, rcx
    jz .done
    lea rax, [rcx-16]
    cmp qword [rax], 0x4B4D414C4C4F4300
    jne .done
    mov rdx, [rax+8]
    sub qword [rel heap_bytes_live], rdx
    mov qword [rax], 0
.done:
    ret

; scan old pci config ports so we know what hardware this box has
pci_scan64:
    mov dword [rel pci_device_count], 0
    xor r8d, r8d
.bus:
    xor r9d, r9d
.dev:
    xor r10d, r10d
.func:
    mov eax, r8d
    shl eax, 16
    mov edx, r9d
    shl edx, 11
    or eax, edx
    mov edx, r10d
    shl edx, 8
    or eax, edx
    or eax, 0x80000000
    mov dx, 0xCF8
    out dx, eax
    mov dx, 0xCFC
    in eax, dx
    cmp ax, 0xFFFF
    je .next_func

    mov ecx, [rel pci_device_count]
    cmp ecx, LEGACY_MAX_PCI_DEVICES
    jae .done
    lea rdi, [rel pci_devices]
    imul rcx, 16
    add rdi, rcx
    mov [rdi+0], r8b
    mov [rdi+1], r9b
    mov [rdi+2], r10b
    mov [rdi+4], eax

    mov eax, r8d
    shl eax, 16
    mov edx, r9d
    shl edx, 11
    or eax, edx
    mov edx, r10d
    shl edx, 8
    or eax, edx
    or eax, 0x80000008
    mov dx, 0xCF8
    out dx, eax
    mov dx, 0xCFC
    in eax, dx
    mov [rdi+8], eax
    inc dword [rel pci_device_count]
.next_func:
    inc r10d
    cmp r10d, 8
    jb .func
    inc r9d
    cmp r9d, 32
    jb .dev
    inc r8d
    cmp r8d, 256
    jb .bus
.done:
    lea rsi, [rel msg_pci]
    call serial_puts64
    mov eax, [rel pci_device_count]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    ret

; make every ap run one tiny job so we know the worker pool is actually alive
runtime_smp_selftest64:
    lea rdi, [rel smp_heartbeats]
    xor eax, eax
    mov ecx, MAX_CPUS
    rep stosd
    mov dword [rel legacy_ap_fault_count], 0

    lea rcx, [rel smp_heartbeat_job64]
    xor edx, edx
    call smp_dispatch_all64
    test eax, eax
    jz .failed

    lea rsi, [rel msg_smp_dispatch_ok]
    call serial_puts64
    ret

.failed:
    lea rsi, [rel msg_smp_dispatch_fail]
    call serial_puts64
    mov eax, [rel ap_job_done]
    call serial_hex32_64

    lea rsi, [rel msg_smp_worker_stages]
    call serial_puts64
    mov ecx, 1
.stage_loop:
    cmp ecx, [rel ap_online_count]
    jae .faults
    movzx eax, byte [rel ap_worker_stage+rcx]
    call serial_hex32_64
    mov al, ' '
    call serial_putc64_al
    inc ecx
    jmp .stage_loop

.faults:
    lea rsi, [rel msg_smp_ap_faults]
    call serial_puts64
    mov eax, [rel legacy_ap_fault_count]
    call serial_hex32_64
    test eax, eax
    jz .disable

   ; print one compact record per ap worker. empty slots remain zero.
    mov ecx, 1
.ap_fault_loop:
    cmp ecx, [rel ap_online_count]
    jae .disable
    lea rsi, [rel msg_smp_ap_cpu]
    call serial_puts64
    mov eax, ecx
    call serial_hex32_64
    lea rsi, [rel msg_smp_ap_vec]
    call serial_puts64
    mov rax, [rel legacy_ap_fault_vector_by_cpu+rcx*8]
    call serial_hex64
    lea rsi, [rel msg_smp_ap_err]
    call serial_puts64
    mov rax, [rel legacy_ap_fault_error_by_cpu+rcx*8]
    call serial_hex64
    lea rsi, [rel msg_smp_ap_rip]
    call serial_puts64
    mov rax, [rel legacy_ap_fault_rip_by_cpu+rcx*8]
    call serial_hex64
    lea rsi, [rel msg_smp_ap_cr2]
    call serial_puts64
    mov rax, [rel legacy_ap_fault_cr2_by_cpu+rcx*8]
    call serial_hex64
    lea rsi, [rel msg_smp_ap_rsp]
    call serial_puts64
    mov rax, [rel legacy_ap_fault_rsp_by_cpu+rcx*8]
    call serial_hex64

    lea rsi, [rel msg_smp_ap_raw3]
    call serial_puts64
    mov rax, [rel legacy_ap_fault_raw3_by_cpu+rcx*8]
    call serial_hex64
    lea rsi, [rel msg_smp_ap_raw4]
    call serial_puts64
    mov rax, [rel legacy_ap_fault_raw4_by_cpu+rcx*8]
    call serial_hex64
    lea rsi, [rel msg_smp_ap_raw5]
    call serial_puts64
    mov rax, [rel legacy_ap_fault_raw5_by_cpu+rcx*8]
    call serial_hex64

    lea rsi, [rel msg_smp_ap_cr0]
    call serial_puts64
    mov rax, [rel legacy_ap_fault_cr0_by_cpu+rcx*8]
    call serial_hex64
    lea rsi, [rel msg_smp_ap_cr3]
    call serial_puts64
    mov rax, [rel legacy_ap_fault_cr3_by_cpu+rcx*8]
    call serial_hex64
    lea rsi, [rel msg_smp_ap_cr4]
    call serial_puts64
    mov rax, [rel legacy_ap_fault_cr4_by_cpu+rcx*8]
    call serial_hex64
    lea rsi, [rel msg_smp_ap_efer]
    call serial_puts64
    mov rax, [rel legacy_ap_fault_efer_by_cpu+rcx*8]
    call serial_hex64
    inc ecx
    jmp .ap_fault_loop

.disable:
    lea rsi, [rel msg_crlf64]
    call serial_puts64

   ; dead/faulted aps must never be targeted again this boot. keep them halted and fall back
   ; to the proven bsp-only runtime so networking/shards still run.
    mov dword [rel ap_online_count], 1
    lea rsi, [rel msg_smp_dispatch_single]
    call serial_puts64
    ret

smp_heartbeat_job64:
    cmp edx, MAX_CPUS
    jae .ret
    lea rax, [rel smp_heartbeats]
    lock inc dword [rax+rdx*4]
.ret:
    ret

align 16
cpu_vendor         db '............',0
cpu_max_leaf       dd 0
cpu_max_ext_leaf   dd 0
cpu_signature64    dd 0
cpu_feat_ecx       dd 0
cpu_feat_edx       dd 0
cpu_feat7_ebx      dd 0
cpu_feat7_ecx      dd 0
cpu_ext_ecx        dd 0
cpu_ext_edx        dd 0

tsc_cycles_per_ms  dq 0
tsc_invariant      db 0
align 8
heap_arena_cur     dq 0
heap_arena_end     dq 0
heap_bytes_live    dq 0
pci_device_count   dd 0
align 16
pci_devices        times (LEGACY_MAX_PCI_DEVICES * 16) db 0
smp_heartbeats     times MAX_CPUS dd 0

msg_cpu_vendor64       db '[CPU] vendor=',0
msg_cpu_sig64          db ' signature=0x',0
msg_tsc                db '[TIME] TSC cycles/ms=0x',0
msg_tsc_inv            db ' invariant=0x',0
msg_heap2               db '[HEAP] general allocator online',13,10,0
msg_pci                 db '[PCI] devices discovered=0x',0
msg_smp_dispatch_ok     db '[SMP] multicore worker dispatch verified',13,10,0
msg_smp_dispatch_fail   db '[SMP] worker dispatch failed done=0x',0
msg_smp_worker_stages   db ' stages=',0
msg_smp_ap_faults       db ' ap-faults=0x',0
msg_smp_ap_cpu          db 13,10,'  ap=0x',0
msg_smp_ap_vec          db ' vec=0x',0
msg_smp_ap_err          db ' err=0x',0
msg_smp_ap_rip          db ' rip=0x',0
msg_smp_ap_cr2          db ' cr2=0x',0
msg_smp_ap_rsp          db ' rsp=0x',0
msg_smp_ap_raw3         db ' raw3=0x',0
msg_smp_ap_raw4         db ' raw4=0x',0
msg_smp_ap_raw5         db ' raw5=0x',0
msg_smp_ap_cr0          db ' cr0=0x',0
msg_smp_ap_cr3          db ' cr3=0x',0
msg_smp_ap_cr4          db ' cr4=0x',0
msg_smp_ap_efer         db ' efer=0x',0
msg_smp_dispatch_single db '[SMP] worker dispatch unavailable; BSP-only runtime remains valid',13,10,0
msg_runtime_extra_ready db '[CORE] timers + heap + PCI + multicore services online',13,10,0
