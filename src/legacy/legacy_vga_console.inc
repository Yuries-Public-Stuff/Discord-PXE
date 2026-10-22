; basic vga text output for the target screen com1 still gets everything but this keeps
; the box usable without another pc

BITS 64

%define VGA_TEXT_BASE 0xB8000
%define VGA_COLS 80
%define VGA_ROWS 25
%define VGA_CELLS (VGA_COLS * VGA_ROWS)
%define VGA_ATTR 0x07

legacy_vga_init64:
   ; clear old bios/pxe text so runtime failures stay readable
    mov rdi, VGA_TEXT_BASE
    mov ax, (VGA_ATTR << 8) | ' '
    mov ecx, VGA_CELLS
.clear:
    mov [rdi], ax
    add rdi, 2
    dec ecx
    jnz .clear
    mov dword [rel vga_cursor], 0
    mov byte [rel vga_ready], 1
    ret

; al is one byte from the normal console stream
legacy_vga_putc64:
    cmp byte [rel vga_ready], 1
    jne .done
    cmp al, 13
    je .cr
    cmp al, 10
    je .lf
    cmp al, 8
    je .backspace
    cmp al, 9
    je .tab
    cmp al, 32
    jb .done

    mov ecx, [rel vga_cursor]
    cmp ecx, VGA_CELLS
    jb .write
    call legacy_vga_scroll64
    mov ecx, [rel vga_cursor]
.write:
    mov edx, ecx
    shl edx, 1
    mov r8, VGA_TEXT_BASE
    add r8, rdx
    mov [r8], al
    mov byte [r8+1], VGA_ATTR
    inc ecx
    mov [rel vga_cursor], ecx
    cmp ecx, VGA_CELLS
    jb .done
    call legacy_vga_scroll64
    jmp .done

.cr:
    mov eax, [rel vga_cursor]
    xor edx, edx
    mov ecx, VGA_COLS
    div ecx
    imul eax, eax, VGA_COLS
    mov [rel vga_cursor], eax
    jmp .done

.lf:
    mov eax, [rel vga_cursor]
    xor edx, edx
    mov ecx, VGA_COLS
    div ecx
    inc eax
    imul eax, eax, VGA_COLS
    mov [rel vga_cursor], eax
    cmp eax, VGA_CELLS
    jb .done
    call legacy_vga_scroll64
    jmp .done

.backspace:
    cmp dword [rel vga_cursor], 0
    je .done
    dec dword [rel vga_cursor]
    mov ecx, [rel vga_cursor]
    mov edx, ecx
    shl edx, 1
    mov r8, VGA_TEXT_BASE
    add r8, rdx
    mov byte [r8], ' '
    mov byte [r8+1], VGA_ATTR
    jmp .done

.tab:
   ; move to the next 8 wide stop without calling ourselves again
    mov eax, [rel vga_cursor]
    and eax, 7
    mov ecx, 8
    sub ecx, eax
.tab_loop:
    push rcx
    mov al, ' '
    call legacy_vga_putc64
    pop rcx
    dec ecx
    jnz .tab_loop
.done:
    ret

; move the screen up one row and keep the last row blank
legacy_vga_scroll64:
    push rsi
    push rdi
    push rcx
    mov rsi, VGA_TEXT_BASE + (VGA_COLS * 2)
    mov rdi, VGA_TEXT_BASE
    mov ecx, (VGA_ROWS - 1) * VGA_COLS
.copy:
    mov ax, [rsi]
    mov [rdi], ax
    add rsi, 2
    add rdi, 2
    dec ecx
    jnz .copy

    mov ax, (VGA_ATTR << 8) | ' '
    mov ecx, VGA_COLS
.clear:
    mov [rdi], ax
    add rdi, 2
    dec ecx
    jnz .clear
    mov dword [rel vga_cursor], (VGA_ROWS - 1) * VGA_COLS
    pop rcx
    pop rdi
    pop rsi
    ret

align 8
vga_cursor dd 0
vga_ready  db 0
