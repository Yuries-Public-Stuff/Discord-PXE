; keyboard and serial input for the legacy shell use bios uart bases when present and keep
; a raw 8042 fallback for local input

BITS 64

%define INPUT_RING_SIZE 128

legacy_input_init64:
    mov dword [rel input_head], 0
    mov dword [rel input_tail], 0
    mov dword [rel input_serial_bytes], 0
    mov dword [rel input_keyboard_bytes], 0
    mov byte [rel input_shift], 0
    mov byte [rel input_caps], 0
    mov byte [rel input_e0], 0

   ; the bios data area is still identity mapped in long mode
    movzx eax, word [abs 0x400]
    test eax, eax
    jnz .uart1_ok
    mov eax, COM1
.uart1_ok:
    mov [rel input_uart1], ax

    movzx eax, word [abs 0x402]
    test eax, eax
    jnz .uart2_ok
    mov eax, COM2
.uart2_ok:
    mov [rel input_uart2], ax

   ; snapshot uart line status so bad/nonexistent ports are visible on screen
    movzx edx, word [rel input_uart1]
    test dx, dx
    jz .uart1_status_done
    add dx, 5
    in al, dx
    mov [rel input_uart1_lsr], al
.uart1_status_done:
    movzx edx, word [rel input_uart2]
    test dx, dx
    jz .uart2_status_done
    add dx, 5
    in al, dx
    mov [rel input_uart2_lsr], al
.uart2_status_done:

   ; enable the first 8042 port when a real/legacy controller is present
    in al, 0x64
    mov [rel input_kbc_status], al
    cmp al, 0xFF
    je .flush
    mov ecx, 65535
.wait_write:
    in al, 0x64
    test al, 2
    jz .enable
    dec ecx
    jnz .wait_write
    jmp .flush
.enable:
    mov al, 0xAE
    out 0x64, al

.flush:
   ; clear stale bytes so firmware keystrokes do not become shell commands
    mov ecx, 256
.flush_loop:
    in al, 0x64
    test al, 1
    jz .ready
    in al, 0x60
    dec ecx
    jnz .flush_loop
.ready:
    lea rsi, [rel msg_input_ready]
    call serial_puts64
    lea rsi, [rel msg_input_uart1]
    call serial_puts64
    movzx eax, word [rel input_uart1]
    call serial_hex32_64
    lea rsi, [rel msg_input_uart1_lsr]
    call serial_puts64
    movzx eax, byte [rel input_uart1_lsr]
    call serial_hex32_64
    lea rsi, [rel msg_input_uart2]
    call serial_puts64
    movzx eax, word [rel input_uart2]
    call serial_hex32_64
    lea rsi, [rel msg_input_uart2_lsr]
    call serial_puts64
    movzx eax, byte [rel input_uart2_lsr]
    call serial_hex32_64
    lea rsi, [rel msg_input_kbc]
    call serial_puts64
    movzx eax, byte [rel input_kbc_status]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    ret

legacy_input_poll64:
    push rbx
    push rsi
    push rdi
    call legacy_input_poll_serial64
    call legacy_input_poll_ps2_64
    pop rdi
    pop rsi
    pop rbx
    ret

; poll bios-reported serial ports, falling back to the normal legacy bases
legacy_input_poll_serial64:
    movzx edx, word [rel input_uart1]
    call legacy_input_poll_uart64
    movzx edx, word [rel input_uart2]
    cmp dx, [rel input_uart1]
    je .done
    call legacy_input_poll_uart64
.done:
    ret

; dx is uart base
legacy_input_poll_uart64:
    test dx, dx
    jz .done
    mov r8w, dx
    mov ecx, 64
.more:
    mov dx, r8w
    add dx, 5
    in al, dx
    test al, 1
    jz .done
    mov dx, r8w
    in al, dx
    test al, al
    jz .next
    inc dword [rel input_serial_bytes]
    call legacy_input_push_al64
.next:
    dec ecx
    jnz .more
.done:
    ret

legacy_input_poll_ps2_64:
    mov ecx, 64
.more:
    in al, 0x64
    test al, 1
    jz .done

   ; bit 5 means auxiliary/mouse data on normal 8042 controllers
    test al, 0x20
    jnz .drop_aux
    in al, 0x60
    inc dword [rel input_keyboard_bytes]

    cmp al, 0xE0
    je .e0
    cmp byte [rel input_e0], 1
    jne .normal
    mov byte [rel input_e0], 0
    jmp .next
.e0:
    mov byte [rel input_e0], 1
    jmp .next
.normal:
    cmp al, 0x2A
    je .shift_on
    cmp al, 0x36
    je .shift_on
    cmp al, 0xAA
    je .shift_off
    cmp al, 0xB6
    je .shift_off
    cmp al, 0x3A
    je .caps
    test al, 0x80
    jnz .next

    movzx ebx, al
    cmp ebx, legacy_scancode_table_end-legacy_scancode_table
    jae .next
    lea rsi, [rel legacy_scancode_table]
    mov al, [rsi+rbx]
    test al, al
    jz .next

    cmp al, 'a'
    jb .symbol
    cmp al, 'z'
    ja .symbol
    mov dl, [rel input_shift]
    xor dl, [rel input_caps]
    test dl, dl
    jz .push
    sub al, 32
    jmp .push
.symbol:
    cmp byte [rel input_shift], 1
    jne .push
    lea rsi, [rel legacy_scancode_shift]
    mov al, [rsi+rbx]
    test al, al
    jz .next
.push:
    call legacy_input_push_al64
    jmp .next
.shift_on:
    mov byte [rel input_shift], 1
    jmp .next
.shift_off:
    mov byte [rel input_shift], 0
    jmp .next
.caps:
    xor byte [rel input_caps], 1
    jmp .next
.drop_aux:
    in al, 0x60
.next:
    dec ecx
    jnz .more
.done:
    ret

; al is queued if there is room
legacy_input_push_al64:
    push rbx
    push rcx
    push rdx
    mov ecx, [rel input_head]
    mov edx, ecx
    inc edx
    and edx, INPUT_RING_SIZE-1
    cmp edx, [rel input_tail]
    je .full
    lea rbx, [rel input_ring]
    mov [rbx+rcx], al
    mov [rel input_head], edx
.full:
    pop rdx
    pop rcx
    pop rbx
    ret

; carry set means al has one byte
legacy_input_getc64:
    mov ecx, [rel input_tail]
    cmp ecx, [rel input_head]
    je .none
    lea rdx, [rel input_ring]
    mov al, [rdx+rcx]
    inc ecx
    and ecx, INPUT_RING_SIZE-1
    mov [rel input_tail], ecx
    stc
    ret
.none:
    clc
    ret

legacy_input_status64:
    lea rsi, [rel msg_input_status_serial]
    call serial_puts64
    mov eax, [rel input_serial_bytes]
    call serial_hex32_64
    lea rsi, [rel msg_input_status_keyboard]
    call serial_puts64
    mov eax, [rel input_keyboard_bytes]
    call serial_hex32_64
    lea rsi, [rel msg_input_status_queue]
    call serial_puts64
    mov eax, [rel input_head]
    sub eax, [rel input_tail]
    and eax, INPUT_RING_SIZE-1
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    ret

align 16
input_ring times INPUT_RING_SIZE db 0
input_head dd 0
input_tail dd 0
input_serial_bytes dd 0
input_keyboard_bytes dd 0
input_shift db 0
input_caps db 0
input_e0 db 0
input_uart1 dw COM1
input_uart2 dw COM2
input_uart1_lsr db 0
input_uart2_lsr db 0
input_kbc_status db 0

; set 1 scancodes used by normal bios/legacy usb keyboard emulation
legacy_scancode_table:
    db 0,27,'1','2','3','4','5','6','7','8','9','0','-','=',8,9
    db 'q','w','e','r','t','y','u','i','o','p','[',']',13,0,'a','s'
    db 'd','f','g','h','j','k','l',';',39,'`',0,92,'z','x','c','v'
    db 'b','n','m',',','.','/',0,'*',0,' ',0,0,0,0,0,0
legacy_scancode_table_end:

legacy_scancode_shift:
    db 0,27,'!','@','#','$','%','^','&','*','(',')','_','+',8,9
    db 0,0,0,0,0,0,0,0,0,0,'{','}',13,0,0,0
    db 0,0,0,0,0,0,0,':',34,'~',0,'|',0,0,0,0
    db 0,0,0,'<','>','?',0,'*',0,' ',0,0,0,0,0,0

msg_input_ready db '[INPUT] serial + legacy keyboard polling ready',13,10,0
msg_input_uart1 db '[INPUT] uart1=0x',0
msg_input_uart1_lsr db ' lsr=0x',0
msg_input_uart2 db ' uart2=0x',0
msg_input_uart2_lsr db ' lsr=0x',0
msg_input_kbc db ' kbc=0x',0
msg_input_status_serial db '[INPUT] serial bytes=0x',0
msg_input_status_keyboard db ' keyboard bytes=0x',0
msg_input_status_queue db ' queued=0x',0
