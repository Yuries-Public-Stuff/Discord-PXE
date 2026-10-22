; use every safe low ram range instead of wasting everything after the first one the old
; heap range stays reserved for ap stacks exactly like before

BITS 64

%define LOW_REGION_MAX 64

; build the range list on first use so memory_init can call us while it is starting
legacy_lowmem_init64:
    cmp dword [rel lowmem_ready], 1
    je .done
    mov dword [rel low_region_count], 0
    mov dword [rel low_region_index], 0
    mov qword [rel low_alloc_bytes], 0

    movzx ecx, word [rel e820_count]
    lea rsi, [rel e820_map]
.scan:
    test ecx, ecx
    jz .finish
    cmp dword [rsi+16], 1
    jne .next

    mov rax, [rsi+0]
    mov rdx, [rsi+8]
    test rdx, rdx
    jz .next
    mov r8, rax
    add r8, rdx
    jc .next

    cmp r8, BOOT64_HEAP_FLOOR
    jbe .next
    cmp rax, BOOT64_HEAP_FLOOR
    jae .base_ok
    mov rax, BOOT64_HEAP_FLOOR
.base_ok:
    mov r9, 0x100000000
    cmp rax, r9
    jae .next
    cmp r8, r9
    jbe .end_ok
    mov r8, r9
.end_ok:
    add rax, 0xFFF
    and rax, -4096
    and r8, -4096
    cmp r8, rax
    jbe .next

   ; never return the ap stack reservation [ap_stack_floor, ap_stack_base). memory_init
   ; places it at the bottom of a verified usable e820 region.
    mov r9, [rel ap_stack_floor]
    mov r10, [rel ap_stack_base]
    test r9, r9
    jz .store
    test r10, r10
    jz .store
    cmp r8, r9
    jbe .store
    cmp rax, r10
    jae .store
    cmp rax, r9
    jb .clip_before_stack

   ; range starts inside the reserved stack area: resume after it.
    mov rax, r10
    jmp .store

.clip_before_stack:
   ; preserve only the portion before the reservation. on this runtime that area is below
   ; heap_next and will not be selected for general allocation.
    mov r8, r9
.store:
    cmp r8, rax
    jbe .next
    mov edx, [rel low_region_count]
    cmp edx, LOW_REGION_MAX
    jae .finish
    lea r11, [rel low_regions]
    imul rdx, 16
    add r11, rdx
    mov [r11+0], rax
    mov [r11+8], r8
    inc dword [rel low_region_count]
.next:
    add rsi, E820_ENTRY_SIZE
    dec ecx
    jmp .scan
.finish:
    cmp dword [rel low_region_count], 0
    je .done
    mov dword [rel lowmem_ready], 1
.done:
    ret

; rcx page count, rax is zeroed identity mapped ram or zero
alloc_pages64:
    test rcx, rcx
    jz .fail
    push rbx
    push r12
    mov r12, rcx
    call legacy_lowmem_init64
    cmp dword [rel lowmem_ready], 1
    jne .fail_pop

    mov rbx, r12
    shl rbx, 12
    mov r10d, [rel low_region_index]
.loop:
    cmp r10d, [rel low_region_count]
    jae .fail_pop
    lea r11, [rel low_regions]
    mov eax, r10d
    imul rax, 16
    add r11, rax
    mov rax, [r11+0]
    mov rdx, rax
    add rdx, rbx
    jc .next
    cmp rdx, [r11+8]
    ja .next
    mov [r11+0], rdx
    add [rel low_alloc_bytes], rbx

   ; keep the old heap cursor useful for shell status when this is its range
    cmp rax, [rel heap_next]
    jb .clear
    cmp rax, [rel heap_end]
    jae .clear
    mov [rel heap_next], rdx
.clear:
    mov rdi, rax
    mov rcx, r12
    shl rcx, 9
    push rax
    xor eax, eax
    rep stosq
    pop rax
    pop r12
    pop rbx
    ret
.next:
    inc r10d
    mov [rel low_region_index], r10d
    jmp .loop
.fail_pop:
    pop r12
    pop rbx
.fail:
    xor eax, eax
    ret

align 16
low_regions times (LOW_REGION_MAX * 16) db 0
low_region_count dd 0
low_region_index dd 0
lowmem_ready dd 0
align 8
low_alloc_bytes dq 0
