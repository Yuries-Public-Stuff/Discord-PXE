BITS 16
ORG 0

; legacy pxe entry move to known low ram first so mode switches and pxe calls
; have fixed addresses

%define COM1 0x3F8
%define COM2 0x2F8
%define COM3 0x3E8
%define COM4 0x2E8
%define PXE_CLIENT_IP_FALLBACK 0xB101A8C0
%define PXE_STACK_HANDOFF_PHYS 0x4E00
%define PXE_STACK_MAGIC        0x53545850
%define PXE_HANDOFF_CLIENT_IP  8
%define PXE_HANDOFF_SERVER_IP  12
%define PXE_HANDOFF_GATEWAY_IP 16
%define PXE_HANDOFF_SUBNET      20
%define PXE_HANDOFF_ROUTER      24
%define PXE_HANDOFF_DNS         28
%define RELOC_SEG 0x2000
%define RELOC_BASE 0x20000
%define BOOT64_STACK_TOP 0x001FF000
%define BOOT64_HEAP_FLOOR 0x00200000

%define PML4_PHYS 0x90000
%define PDPT_PHYS 0x91000
%define PD0_PHYS  0x92000

%define AP_TRAMP_PHYS 0x8000
%define AP_STACK_BYTES 0x4000
%define AP_STACK_RESERVE 0x200000
%define MAX_CPUS 64
%define MAX_E820_ENTRIES 128
%define E820_ENTRY_SIZE 24
%define MAX_DIRECT_GIB 512

%define PXENV_UNDI_GET_INFORMATION 0x000C
%define PXENV_GET_CACHED_INFO      0x0071
%define PXENV_PACKET_TYPE_DHCP_ACK 2

%define UNDI_STATUS       0
%define UNDI_BASEIO       2
%define UNDI_IRQ          4
%define UNDI_MTU          6
%define UNDI_HWTYPE       8
%define UNDI_HWADDRLEN   10
%define UNDI_CURR_MAC    12
%define UNDI_PERM_MAC    28
%define UNDI_ROMSEG      44
%define UNDI_RXBUFS      46
%define UNDI_TXBUFS      48
%define UNDI_INFO_SIZE   50

%define CACHED_STATUS      0
%define CACHED_PACKETTYPE  2
%define CACHED_BUFSIZE     4
%define CACHED_BUFOFF      6
%define CACHED_BUFSEG      8
%define CACHED_BUFLIMIT   10
%define CACHED_INFO_SIZE  12

%define BOOTP_YIP 16
%define BOOTP_SIADDR 20
%define BOOTP_GIADDR 24

start:
    cli
    cld
    push cs
    pop ds
    push cs
    pop es
    jmp relocated

relocated:
    mov ax, RELOC_SEG
    mov ds, ax
    mov es, ax
  ; keep the 16-bit bootstrap stack below runtime.bin. the runtime now extends
  ; through physical 0x7fffe, so the old 0x7000:fffe stack corrupts
    mov ax, 0x1000
    mov ss, ax
    mov sp, 0xFFFE
    sti

    call serial_detect_bios_ports
    call serial_init
    mov si, msg_banner
    call puts
    mov si, msg_uart_bda
    call puts
    mov ax, [bios_uart1]
    call hex16
    mov al, ' '
    call putc
    mov ax, [bios_uart2]
    call hex16
    mov al, ' '
    call putc
    mov ax, [bios_uart3]
    call hex16
    mov al, ' '
    call putc
    mov ax, [bios_uart4]
    call hex16
    call newline

  ; grab the bios ram map before leaving real mode
    call e820_collect

  ; ask bios where the pxe rom left its api table
    mov ax, 0x5650
    int 0x1A
    cmp ax, 0x564E
    jne no_pxe
    mov [pxenv_off], bx
    mov [pxenv_seg], es

    push ds
    mov ax, es
    mov ds, ax
    mov si, bx
    cmp byte [si+0], 'P'
    jne .bad
    cmp byte [si+1], 'X'
    jne .bad
    cmp byte [si+2], 'E'
    jne .bad
    cmp byte [si+3], 'N'
    jne .bad
    cmp byte [si+4], 'V'
    jne .bad
    cmp byte [si+5], '+'
    jne .bad
    xor ax, ax
    mov cl, [si+8]
    xor ch, ch
    jcxz .bad
    mov di, si
.sum:
    add al, [di]
    inc di
    loop .sum
    test al, al
    jne .bad
    mov ax, [si+10]
    mov [cs:pxe_rm_entry], ax
    mov ax, [si+12]
    mov [cs:pxe_rm_entry+2], ax
    mov ax, [si+6]
    mov [cs:pxe_version], ax
    pop ds
    jmp .pxe_ok
.bad:
    pop ds
    jmp no_pxe
.pxe_ok:
    mov ax, RELOC_SEG
    mov ds, ax
    mov es, ax

    mov si, msg_pxe
    call puts
    mov ax, [pxe_version]
    call hex16
    call newline

    call pxe_undi_get_information
    call pxe_get_cached_dhcp_ack

  ; x64 is required because the rest of the project already uses it
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb no_long
    mov eax, 0x80000001
    cpuid
    test edx, 1 << 29
    jz no_long

  ; fast a20 works on the hardware class this target is meant for
    in al, 0x92
    or al, 2
    and al, 0xFE
    out 0x92, al

    mov si, msg_boot16_long
    call puts
    call setup_page_tables
    cli
    lgdt [gdt_ptr]

    mov eax, cr4
    or eax, 1 << 5
    mov cr4, eax
    mov eax, PML4_PHYS
    mov cr3, eax
    mov ecx, 0xC0000080
    rdmsr
    or eax, 1 << 8
    wrmsr
    mov eax, cr0
    or eax, (1 << 31) | 1
    mov cr0, eax

    db 0x66,0xEA
    dd RELOC_BASE + long_mode_entry
    dw 0x08

no_pxe:
    mov ax, RELOC_SEG
    mov ds, ax
    mov si, msg_no_pxe
    call puts
    jmp hang16

no_long:
    mov si, msg_no_long
    call puts
hang16:
    cli
.h:
    hlt
    jmp .h

; get every usable ram range the bios knows about
e820_collect:
    pushad
    push es
    mov ax, RELOC_SEG
    mov es, ax
    mov di, e820_map
    xor ebx, ebx
    mov word [e820_count], 0
.next:
    cmp word [e820_count], MAX_E820_ENTRIES
    jae .done
    mov eax, 0xE820
    mov edx, 0x534D4150
    mov ecx, E820_ENTRY_SIZE
    mov dword [es:di+20], 1
    int 0x15
    jc .done
    cmp eax, 0x534D4150
    jne .done
    cmp ecx, 20
    jb .skip
    inc word [e820_count]
    add di, E820_ENTRY_SIZE
.skip:
    test ebx, ebx
    jnz .next
.done:
    mov ax, RELOC_SEG
    mov ds, ax
    mov es, ax
    mov si, msg_e820
    call puts
    mov ax, [e820_count]
    call hex16
    call newline
    pop es
    popad
    ret

; pxe wants bx opcode and es:di params
pxe_call:
    push ds
    push si
    push bp
    call far [cs:pxe_rm_entry]
    pop bp
    pop si
    pop ds
    ret

pxe_undi_get_information:
    push es
    mov ax, RELOC_SEG
    mov es, ax
    mov di, undi_info
    xor ax, ax
    mov cx, UNDI_INFO_SIZE/2
    rep stosw
    mov bx, PXENV_UNDI_GET_INFORMATION
    mov di, undi_info
    call pxe_call
    mov dx, ax
    mov ax, RELOC_SEG
    mov ds, ax
    mov es, ax
    mov ax, dx
    test ax, ax
    jnz .fail
    cmp word [undi_info+UNDI_STATUS], 0
    jne .fail
    mov si, msg_undi
    call puts
    mov si, undi_info+UNDI_CURR_MAC
    mov cx, 6
.mac:
    mov al, [si]
    call hex8
    inc si
    dec cx
    jz .done
    mov al, ':'
    call putc
    jmp .mac
.done:
    call newline
    pop es
    ret
.fail:
    mov si, msg_undi_fail
    call puts
    pop es
    ret

pxe_get_cached_dhcp_ack:
  ; stage1 fetched dhcp before tftp replaced the original pxe firmware stack.
  ; consume that handoff and avoid the post-tftp get_cached_info call
    push es
    xor ax, ax
    mov es, ax
    cmp dword [es:PXE_STACK_HANDOFF_PHYS], PXE_STACK_MAGIC
    jne .firmware_fallback
    mov eax, [es:PXE_STACK_HANDOFF_PHYS+PXE_HANDOFF_CLIENT_IP]
    test eax, eax
    jz .firmware_fallback
    mov edx, [es:PXE_STACK_HANDOFF_PHYS+PXE_HANDOFF_SERVER_IP]
    mov ecx, [es:PXE_STACK_HANDOFF_PHYS+PXE_HANDOFF_GATEWAY_IP]
    mov [cs:cached_ipv4], eax
    mov [cs:cached_server_ipv4], edx
    mov [cs:cached_gateway_ipv4], ecx
    mov ax, RELOC_SEG
    mov ds, ax
    mov es, ax
    mov si, msg_dhcp
    call puts
    mov eax, [cached_ipv4]
    call ipv4_print
    call newline
    pop es
    ret

.firmware_fallback:
    mov ax, RELOC_SEG
    mov es, ax
    mov di, cached_info
    xor ax, ax
    mov cx, CACHED_INFO_SIZE/2
    rep stosw
    mov word [cached_info+CACHED_PACKETTYPE], PXENV_PACKET_TYPE_DHCP_ACK
    mov bx, PXENV_GET_CACHED_INFO
    mov di, cached_info
    call pxe_call
    mov dx, ax
    mov ax, RELOC_SEG
    mov ds, ax
    mov es, ax
    mov ax, dx
    test ax, ax
    jnz .fail
    cmp word [cached_info+CACHED_STATUS], 0
    jne .fail
    push ds
    mov ax, [cached_info+CACHED_BUFSEG]
    mov ds, ax
    mov si, [cached_info+CACHED_BUFOFF]
    mov eax, [si+BOOTP_YIP]
    mov edx, [si+BOOTP_SIADDR]
    mov ecx, [si+BOOTP_GIADDR]
    pop ds
    mov ebx, eax
    and ebx, 0x00FFFFFF
    cmp ebx, 0x0001A8C0
    je .have_cached_ip
    mov eax, PXE_CLIENT_IP_FALLBACK
.have_cached_ip:
    mov [cached_ipv4], eax
    mov [cached_server_ipv4], edx
    mov [cached_gateway_ipv4], ecx
    mov si, msg_dhcp
    call puts
    mov eax, [cached_ipv4]
    call ipv4_print
    call newline
    pop es
    ret
.fail:
    mov si, msg_dhcp_fail
    call puts
    pop es
    ret

; start with 4gb mapped so all early hardware state is reachable
setup_page_tables:
    pushad
    push es
    mov ax, 0x9000
    mov es, ax
    xor di, di
    xor ax, ax
    mov cx, (6*4096)/2
    rep stosw

    mov dword [es:0], PDPT_PHYS | 3
    mov dword [es:4], 0

    mov ax, 0x9100
    mov es, ax
    xor di, di
    mov eax, PD0_PHYS | 3
    mov cx, 4
.pdpt:
    mov [es:di], eax
    mov dword [es:di+4], 0
    add eax, 0x1000
    add di, 8
    loop .pdpt

    mov dx, 0x9200
    xor ebx, ebx
    mov bp, 4
.pd:
    mov es, dx
    xor di, di
    mov cx, 512
.pde:
    mov eax, ebx
    or eax, 0x83
    mov [es:di], eax
    mov dword [es:di+4], 0
    add ebx, 0x200000
    add di, 8
    loop .pde
    add dx, 0x100
    dec bp
    jnz .pd
    pop es
    popad
    ret

; read bios data area com assignments before long mode. these are printed on
; screen and also added to the serial
serial_detect_bios_ports:
    push ax
    push ds
    xor ax, ax
    mov ds, ax
    mov ax, [0x400]
    mov [cs:bios_uart1], ax
    mov ax, [0x402]
    mov [cs:bios_uart2], ax
    mov ax, [0x404]
    mov [cs:bios_uart3], ax
    mov ax, [0x406]
    mov [cs:bios_uart4], ax
    pop ds
    pop ax
    ret

serial_init_if_dx16:
    test dx, dx
    jz .done
    call serial_init_dx
.done:
    ret

; early runtime diagnostics must never block forever on a dead uart. configure
; standard and bios-advertised legacy ports and mirror every
serial_init:
    mov dx, COM1
    call serial_init_dx
    mov dx, COM2
    call serial_init_dx
    mov dx, COM3
    call serial_init_dx
    mov dx, COM4
    call serial_init_dx
    mov dx, [bios_uart1]
    call serial_init_if_dx16
    mov dx, [bios_uart2]
    call serial_init_if_dx16
    mov dx, [bios_uart3]
    call serial_init_if_dx16
    mov dx, [bios_uart4]
    call serial_init_if_dx16
    ret

serial_init_dx:
    push ax
    push bx
    mov bx, dx
    inc dx
    xor al, al
    out dx, al
    mov dx, bx
    add dx, 3
    mov al, 0x80
    out dx, al
    mov dx, bx
    mov al, 1
    out dx, al
    mov dx, bx
    inc dx
    xor al, al
    out dx, al
    mov dx, bx
    add dx, 3
    mov al, 3
    out dx, al
    mov dx, bx
    add dx, 2
    mov al, 0xC7
    out dx, al
    mov dx, bx
    add dx, 4
    mov al, 0x0B
    out dx, al
    pop bx
    pop ax
    ret

; bl is one diagnostic byte. a missing uart is skipped after a bounded wait.
serial_write_bl16:
    push ax
    push cx
    push dx
    mov dx, COM1
    call serial_try_write_dx16
    mov dx, COM2
    call serial_try_write_dx16
    mov dx, COM3
    call serial_try_write_dx16
    mov dx, COM4
    call serial_try_write_dx16
    mov dx, [bios_uart1]
    call serial_try_write_if_dx16
    mov dx, [bios_uart2]
    call serial_try_write_if_dx16
    mov dx, [bios_uart3]
    call serial_try_write_if_dx16
    mov dx, [bios_uart4]
    call serial_try_write_if_dx16
    pop dx
    pop cx
    pop ax
    ret

serial_try_write_if_dx16:
    test dx, dx
    jz .done
    call serial_try_write_dx16
.done:
    ret

serial_try_write_dx16:
    push dx
    add dx, 5
    mov cx, 0x0800
.wait:
    in al, dx
    test al, 0x20
    jnz .send
    loop .wait
    pop dx
    ret
.send:
    pop dx
    mov al, bl
    out dx, al
    ret

putc:
    push ax
    push bx
    push cx
    push dx
    mov bl, al
    call serial_write_bl16
  ; always mirror early diagnostics to bios text even when serial is absent.
    mov ah, 0x0E
    mov al, bl
    xor bh, bh
    int 0x10
    pop dx
    pop cx
    pop bx
    pop ax
    ret

puts:
    push ax
.n:
    lodsb
    test al, al
    jz .d
    call putc
    jmp .n
.d:
    pop ax
    ret

newline:
    mov al, 13
    call putc
    mov al, 10
    call putc
    ret

hex8:
    push ax
    mov ah, al
    shr al, 4
    call hex_nibble
    mov al, ah
    and al, 0x0F
    call hex_nibble
    pop ax
    ret

hex_nibble:
    and al, 0x0F
    cmp al, 9
    jbe .num
    add al, 'A'-10
    jmp putc
.num:
    add al, '0'
    jmp putc

hex16:
    push ax
    push bx
    push cx
    mov bx, ax
    mov cx, 4
.l:
    rol bx, 4
    mov al, bl
    and al, 0x0F
    call hex_nibble
    loop .l
    pop cx
    pop bx
    pop ax
    ret

ipv4_print:
    push eax
    push ebx
    push ecx
    mov ebx, eax
    mov ecx, 4
.l:
    mov eax, ebx
    and eax, 0xFF
    call dec8
    shr ebx, 8
    dec ecx
    jz .d
    mov al, '.'
    call putc
    jmp .l
.d:
    pop ecx
    pop ebx
    pop eax
    ret

dec8:
    push ax
    push bx
    push dx
    push si
    xor ah, ah
    mov si, ax
    mov bl, 100
    div bl
    mov dl, ah
    cmp si, 100
    jb .tens
    add al, '0'
    call putc
.tens:
    mov al, dl
    xor ah, ah
    mov bl, 10
    div bl
    mov dl, ah
    cmp si, 10
    jb .ones
    add al, '0'
    call putc
.ones:
    mov al, dl
    add al, '0'
    call putc
    pop si
    pop dx
    pop bx
    pop ax
    ret

align 8
gdt:
    dq 0
    dq 0x00AF9A000000FFFF
    dq 0x00CF92000000FFFF
    dq 0x00CF9A000000FFFF
    dq 0x00009A000000FFFF
gdt_end:
gdt_ptr:
    dw gdt_end-gdt-1
    dd RELOC_BASE+gdt
gdt_ptr64:
    dw gdt_end-gdt-1
    dq RELOC_BASE+gdt

pxenv_off   dw 0
pxenv_seg   dw 0
pxe_version dw 0
pxe_rm_entry dw 0,0
cached_ipv4 dd 0
cached_server_ipv4 dd 0
cached_gateway_ipv4 dd 0
runtime_uart1 dw COM1
runtime_uart2 dw COM2
runtime_uart3 dw COM3
runtime_uart4 dw COM4
bios_uart1 dw 0
bios_uart2 dw 0
bios_uart3 dw 0
bios_uart4 dw 0
undi_info   times UNDI_INFO_SIZE db 0
cached_info times CACHED_INFO_SIZE db 0
e820_count  dw 0
align 8
e820_map    times (MAX_E820_ENTRIES*E820_ENTRY_SIZE) db 0

msg_banner    db 13,10,'=== DISCORD-PXE SHARDED RUNTIME ===',13,10,0
msg_uart_bda  db '[UART] BIOS bases=',0
msg_e820      db '[RAM] e820 entries=0x',0
msg_pxe       db '[PXE] PXENV+ version=0x',0
msg_no_pxe    db '[ERROR] PXENV+ not found',13,10,0
msg_no_long   db '[ERROR] cpu has no x64 long mode',13,10,0
msg_undi      db '[UNDI] mac=',0
msg_undi_fail db '[ERROR] UNDI info failed',13,10,0
msg_dhcp      db '[DHCP] cached ip=',0
msg_dhcp_fail db '[ERROR] cached dhcp ack missing',13,10,0
msg_boot16_long db '[BOOT16] page tables + long mode transition',13,10,0

BITS 64
long_mode_entry:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
  ; the sharded image is large enough to reach the old 0x7f000 stack. keep the
  ; bootstrap x64 stack in the reserved
    mov rsp, BOOT64_STACK_TOP
    and rsp, -16

  ; this bios has returned garbage com bases in the bda on hardware. use the
  ; standard legacy uart bases directly and
    mov dx, COM1
    mov [rel runtime_uart1], dx
    call serial_init_port64_dx

    mov dx, COM2
    mov [rel runtime_uart2], dx
    call serial_init_port64_dx

    mov dx, COM3
    mov [rel runtime_uart3], dx
    call serial_init_port64_dx

    mov dx, COM4
    mov [rel runtime_uart4], dx
    call serial_init_port64_dx
.serial_ports_ready:

    call legacy_vga_init64
    call serial_uart_diag64

    lea rsi, [rel msg_long]
    call serial_puts64

    call memory_init64
    call legacy_cpu_runtime_init64
  ; stage1 has already closed its tftp session; runtime_extra_init64 can now
  ; bring ap workers online before discord/network scheduling begins.
    call runtime_extra_init64
    lea rsi, [rel msg_boot_crypto]
    call serial_puts64
    call legacy_crypto_init64
    lea rsi, [rel msg_boot_crypto_ok]
    call serial_puts64
    lea rsi, [rel msg_boot_pxe]
    call serial_puts64
    call pxe_thunk_init64
    call rtl816x_init64
    test eax, eax
    jnz .native_net_ready
    mov dword [rel pxe_thunk_proven], 0
    lea rsi, [rel msg_native_net_fail]
    call serial_puts64
.native_net_ready:
    lea rsi, [rel msg_boot_tftp]
    call serial_puts64
    call legacy_tftp_files_init64
    lea rsi, [rel msg_boot_config]
    call serial_puts64
    call legacy_config_init64
    lea rsi, [rel msg_boot_net]
    call serial_puts64
    call legacy_net_core_init64
    lea rsi, [rel msg_boot_ip]
    call serial_puts64
    call legacy_ip_stack_init64
    lea rsi, [rel msg_boot_tcp]
    call serial_puts64
    call legacy_tcp_init64
    lea rsi, [rel msg_boot_reliable]
    call serial_puts64
    call legacy_tcp_reliable_init64
    lea rsi, [rel msg_boot_discord]
    call serial_puts64
    call legacy_discord_init64
    lea rsi, [rel msg_boot_tls]
    call serial_puts64
    call legacy_tls_init64
    lea rsi, [rel msg_boot_tls_patch]
    call serial_puts64
    call legacy_tls_patch_init64
    lea rsi, [rel msg_boot_input]
    call serial_puts64
    call legacy_input_init64
    lea rsi, [rel msg_boot_vfs]
    call serial_puts64
    call legacy_vfs_init64
    lea rsi, [rel msg_boot_shell]
    call serial_puts64
    call legacy_shell_init64
    call legacy_http_server_init64
    lea rsi, [rel msg_boot_init_done]
    call serial_puts64

    lea rsi, [rel msg_ready]
    call serial_puts64

.loop:
    cli
    call serial_beacon_tick64
    call legacy_shell_tick64
    cmp dword [rel cached_ipv4], 0
    je .loop
    call legacy_runtime_tick64
    cmp dword [rel legacy_config_ready], 1
    jne .loop
    call legacy_tls_tick64
    call legacy_discord_tick64
    call legacy_shards_tick64
    jmp .loop

; pick a low usable ram range for normal pages and map installed ram
memory_init64:
    mov qword [rel ram_total_usable], 0
    mov qword [rel ram_highest], 0
    mov qword [rel heap_next], 0
    mov qword [rel heap_end], 0

    movzx ecx, word [rel e820_count]
    lea rsi, [rel e820_map]
.scan:
    test ecx, ecx
    jz .choose
    cmp dword [rsi+16], 1
    jne .next
    mov rax, [rsi+8]
    add [rel ram_total_usable], rax
    mov rax, [rsi]
    add rax, [rsi+8]
    cmp rax, [rel ram_highest]
    jbe .next
    mov [rel ram_highest], rax
.next:
    add rsi, E820_ENTRY_SIZE
    dec ecx
    jmp .scan
.choose:
    movzx ecx, word [rel e820_count]
    lea rsi, [rel e820_map]
.find:
    test ecx, ecx
    jz .fail
    cmp dword [rsi+16], 1
    jne .n
    mov rax, [rsi]
    mov rdx, [rsi+8]
    mov r8, rax
    add r8, rdx
    cmp r8, 0x200000
    jbe .n
    cmp rax, BOOT64_HEAP_FLOOR
    jae .base
    mov rax, BOOT64_HEAP_FLOOR
.base:
    add rax, 0xFFF
    and rax, -4096
    cmp r8, 0x100000000
    jbe .limit_ok
    mov r8, 0x100000000
.limit_ok:
  ; reserve ap stacks at the *bottom* of this verified usable e820 region. the
  ; old code put them at the top
    mov [rel ap_stack_floor], rax
    mov r9, rax
    add r9, AP_STACK_RESERVE
    add r9, 0xFFF
    and r9, -4096
    cmp r9, r8
    jae .n

    mov [rel ap_stack_base], r9
    mov [rel heap_next], r9
    mov [rel heap_end], r8
    call map_installed_ram64
    lea rsi, [rel msg_ram]
    call serial_puts64
    mov rax, [rel ram_total_usable]
    call serial_hex64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    ret
.n:
    add rsi, E820_ENTRY_SIZE
    dec ecx
    jmp .find
.fail:
    lea rsi, [rel msg_mem_fail]
    call serial_puts64
.h:
    hlt
    jmp .h

; rcx is page count, rax comes back with identity mapped pages
alloc_pages64_single_old:
    test rcx, rcx
    jz .fail
    mov rax, [rel heap_next]
    mov rdx, rcx
    shl rdx, 12
    add rdx, rax
    cmp rdx, [rel heap_end]
    ja .fail
    mov [rel heap_next], rdx
    mov rdi, rax
    push rax
    xor eax, eax
    mov rdx, rcx
    shl rdx, 9
    mov rcx, rdx
    rep stosq
    pop rax
    ret
.fail:
    xor eax, eax
    ret

; add 1gb chunks to the direct map when the box has more than 4gb
map_installed_ram64:
    mov rax, [rel ram_highest]
    add rax, 0x3FFFFFFF
    shr rax, 30
    cmp rax, 4
    jae .min_ok
    mov rax, 4
.min_ok:
    cmp rax, MAX_DIRECT_GIB
    jbe .cap_ok
    mov rax, MAX_DIRECT_GIB
.cap_ok:
    mov [rel direct_gib], eax
    mov r8d, 4
.next_gib:
    cmp r8d, [rel direct_gib]
    jae .done
    mov ecx, r8d
    lea rbx, [abs PDPT_PHYS]
    cmp qword [rbx+rcx*8], 0
    jne .have_pd
    push rcx
    mov ecx, 1
    call alloc_pages64
    mov r9, rax
    pop rcx
    test r9, r9
    jz .done
    mov r10, r9
    or r10, 3
    mov [rbx+rcx*8], r10
.have_pd:
    mov rbx, [rbx+rcx*8]
    and rbx, -4096
    mov r10, r8
    shl r10, 30
    xor edx, edx
    mov ecx, 512
.fill:
    mov r11, r10
    or r11, 0x83
    mov [rbx+rdx*8], r11
    add r10, 0x200000
    inc edx
    dec ecx
    jnz .fill
    inc r8d
    jmp .next_gib
.done:
    mov rax, cr3
    mov cr3, rax
    ret

; find acpi madt and start the other cpus when firmware lists them
smp_init64:
    mov dword [rel cpu_count], 1
    mov dword [rel ap_online_count], 1
    mov dword [rel ap_stack_claim], 0
    lea rdi, [rel ap_worker_stage]
    xor eax, eax
    mov ecx, MAX_CPUS
    rep stosb
    call find_rsdp64
    test rax, rax
    jz .single
    mov [rel rsdp_phys], rax
    call find_madt64
    test rax, rax
    jz .single
    mov [rel madt_phys], rax
    call parse_madt64

  ; a few old bioses advertise smt in cpuid but omit the sibling from madt.
  ; probe the one smt sibling derived
    cmp dword [rel cpu_count], 1
    jne .have_ids
    cmp dword [rel legacy_threads_per_core], 1
    jbe .single
    call smp_add_cpuid_sibling64
.have_ids:
    cmp dword [rel cpu_count], 1
    jbe .single
    call install_ap_trampoline64
    mov byte [abs AP_TRAMP_PHYS+(ap_boot_stage-ap_trampoline_start)], 0
    call lapic_start_aps64
    mov ecx, 50
.wait:
    mov eax, [rel ap_online_count]
    cmp eax, [rel cpu_count]
    jae .done
    push rcx
    mov ecx, 10
    call tsc_delay_ms64
    pop rcx
    loop .wait
.done:
    lea rsi, [rel msg_smp]
    call serial_puts64
    mov eax, [rel ap_online_count]
    call serial_hex32_64
    lea rsi, [rel msg_smp_expected]
    call serial_puts64
    mov eax, [rel cpu_count]
    call serial_hex32_64
    lea rsi, [rel msg_smp_stage]
    call serial_puts64
    movzx eax, byte [abs AP_TRAMP_PHYS+(ap_boot_stage-ap_trampoline_start)]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    ret
.single:
    lea rsi, [rel msg_smp_single]
    call serial_puts64
    ret

; search ebda then the bios rom area for the acpi root pointer
find_rsdp64:
    movzx eax, word [abs 0x40E]
    shl rax, 4
    mov rcx, 1024
    call scan_rsdp64
    test rax, rax
    jnz .ret
    mov rax, 0xE0000
    mov rcx, 0x20000
    call scan_rsdp64
.ret:
    ret

scan_rsdp64:
    mov r8, rax
    add r8, rcx
.loop:
    cmp rax, r8
    jae .no
    cmp dword [rax], 0x20445352
    jne .next
    cmp dword [rax+4], 0x20525450
    jne .next

    mov r9, rax
    mov rcx, rax
    mov edx, 20
    call acpi_checksum64
    test eax, eax
    jnz .restore_next
    mov rax, r9

    cmp byte [rax+15], 2
    jb .yes
    mov edx, [rax+20]
    cmp edx, 36
    jb .next
    cmp edx, 4096
    ja .next
    mov r9, rax
    mov rcx, rax
    call acpi_checksum64
    test eax, eax
    jnz .restore_next
    mov rax, r9
    jmp .yes
.restore_next:
    mov rax, r9
.next:
    add rax, 16
    jmp .loop
.yes:
    ret
.no:
    xor eax, eax
    ret

; rcx table and edx byte count, eax is zero when the checksum is valid
acpi_checksum64:
    xor eax, eax
    test edx, edx
    jz .done
.sum:
    add al, [rcx]
    inc rcx
    dec edx
    jnz .sum
.done:
    movzx eax, al
    ret

; walk xsdt or rsdt until the apic table shows up
find_madt64:
    mov rbx, [rel rsdp_phys]
    cmp byte [rbx+15], 2
    jb .rsdt
    mov rax, [rbx+24]
    test rax, rax
    jz .rsdt
    mov ecx, 8
    jmp .walk
.rsdt:
    mov eax, [rbx+16]
    mov ecx, 4
.walk:
    test rax, rax
    jz .no
    mov rbx, rax
    mov eax, [rbx+4]
    cmp eax, 36
    jb .no
    cmp eax, 1048576
    ja .no
    push rcx
    push rax
    mov edx, eax
    mov rcx, rbx
    call acpi_checksum64
    mov r11d, eax
    pop rax
    pop rcx
    test r11d, r11d
    jnz .no
    sub eax, 36
    xor edx, edx
    div ecx
    mov r9d, eax
    lea r10, [rbx+36]
.next:
    test r9d, r9d
    jz .no
    cmp ecx, 8
    jne .e32
    mov rax, [r10]
    add r10, 8
    jmp .check
.e32:
    mov eax, [r10]
    add r10, 4
.check:
    test rax, rax
    jz .skip
    cmp dword [rax], 0x43495041
    jne .skip
    mov edx, [rax+4]
    cmp edx, 44
    jb .skip
    cmp edx, 1048576
    ja .skip
    push rcx
    push rax
    mov rcx, rax
    call acpi_checksum64
    mov r11d, eax
    pop rax
    pop rcx
    test r11d, r11d
    jz .yes
.skip:
    dec r9d
    jmp .next
.yes:
    ret
.no:
    xor eax, eax
    ret

; keep enabled apic ids so we only start processors firmware listed
parse_madt64:
    mov rbx, [rel madt_phys]
    mov eax, [rbx+36]
    mov [rel lapic_phys], rax
    mov edx, [rbx+4]
    lea rsi, [rbx+44]
    lea rdi, [rbx+rdx]
    mov dword [rel cpu_count], 0
.loop:
    cmp rsi, rdi
    jae .done
    movzx eax, byte [rsi+1]
    cmp eax, 2
    jb .done
    movzx edx, byte [rsi]
    cmp edx, 0
    je .lapic
    cmp edx, 9
    je .x2apic
    jmp .next
.lapic:
    cmp eax, 8
    jb .next
    test dword [rsi+4], 1
    jz .next
    movzx edx, byte [rsi+3]
    call legacy_smp_add_id64
    jmp .next
.x2apic:
    cmp eax, 16
    jb .next
    test dword [rsi+8], 1
    jz .next
    mov edx, [rsi+4]
    call legacy_smp_add_id64
.next:
    movzx eax, byte [rsi+1]
    add rsi, rax
    jmp .loop
.done:
    cmp dword [rel cpu_count], 0
    jne .ret
    mov dword [rel cpu_count], 1
.ret:
    ret

; edx is one apic id, skip duplicates when firmware lists both table types
legacy_smp_add_id64:
    push rax
    push rcx
    xor ecx, ecx
.check:
    cmp ecx, [rel cpu_count]
    jae .new
    cmp [cpu_apic_ids+rcx*4], edx
    je .done
    inc ecx
    jmp .check
.new:
    cmp ecx, MAX_CPUS
    jae .done
    mov [cpu_apic_ids+rcx*4], edx
    inc dword [rel cpu_count]
.done:
    pop rcx
    pop rax
    ret

; if madt exposes only the bsp but cpuid reports smt, derive the sibling apic
; id from the smt shift width
smp_add_cpuid_sibling64:
    push rbx
    push rcx
    push rdx
    push r8

    xor r9d, r9d
.find_smt:
    mov eax, 0x0B
    mov ecx, r9d
    cpuid
    test ebx, ebx
    jz .done
    mov r8d, ecx
    shr r8d, 8
    and r8d, 0xFF
    cmp r8d, 1
    je .have_smt
    inc r9d
    cmp r9d, 8
    jb .find_smt
    jmp .done

.have_smt:
  ; eax[4:0] is the smt id width and edx is this cpu's x2apic id.
    and eax, 0x1F
    test eax, eax
    jz .done
    cmp eax, 5
    ja .done
    mov r8d, 1
    mov ecx, eax
    shl r8d, cl
    dec r8d
    mov eax, edx
    and eax, r8d
    xor eax, 1
  ; preserve all apic bits above the smt field from the current cpu id.
    mov ecx, r8d
    not ecx
    and edx, ecx
    or edx, eax
    call legacy_smp_add_id64
.done:
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

install_ap_trampoline64:
    lea rsi, [rel ap_trampoline_start]
    mov rdi, AP_TRAMP_PHYS
    mov rcx, ap_trampoline_end-ap_trampoline_start
    rep movsb
    ret

lapic_start_aps64:
    mov byte [rel smp_x2apic], 0

  ; init/sipi requires the local apic to be globally enabled. firmware normally
  ; leaves it on, but old bios/pxe paths are not
    mov ecx, 0x1B
    rdmsr
    test eax, 1 << 11
    jnz .apic_global_on
    or eax, 1 << 11
    wrmsr
.apic_global_on:
    test eax, 1 << 10
    jz .xapic

  ; x2apic uses msrs so full 32-bit apic ids keep working.
    mov byte [rel smp_x2apic], 1
    mov ecx, 0x80F
    rdmsr
    or eax, 1 << 8
    wrmsr
    mov ecx, 0x802
    rdmsr
    mov [rel bsp_apic_id], eax
    jmp .diag

.xapic:
    mov rbx, [rel lapic_phys]
    test rbx, rbx
    jz .ret

  ; software-enable the local apic through the spurious-vector register too.
    mov eax, [rbx+0xF0]
    or eax, 1 << 8
    mov [rbx+0xF0], eax

    mov eax, [rbx+0x20]
    shr eax, 24
    mov [rel bsp_apic_id], eax

.diag:
    lea rsi, [rel msg_smp_apic]
    call serial_puts64
    movzx eax, byte [rel smp_x2apic]
    call serial_hex32_64
    lea rsi, [rel msg_smp_bsp]
    call serial_puts64
    mov eax, [rel bsp_apic_id]
    call serial_hex32_64
    lea rsi, [rel msg_smp_ids]
    call serial_puts64
    xor r12d, r12d
.diag_ids:
    cmp r12d, [rel cpu_count]
    jae .diag_done
    mov eax, [cpu_apic_ids+r12*4]
    call serial_hex32_64
    mov al, ' '
    call serial_putc64_al
    inc r12d
    jmp .diag_ids
.diag_done:
    lea rsi, [rel msg_crlf64]
    call serial_puts64

.start:
    xor r12d, r12d
.loop:
    cmp r12d, [rel cpu_count]
    jae .ret
    mov edx, [cpu_apic_ids+r12*4]
    cmp edx, [rel bsp_apic_id]
    je .next
    cmp byte [rel smp_x2apic], 1
    je .send
    cmp edx, 255
    ja .next
.send:
    call lapic_start_one64
.next:
    inc r12d
    jmp .loop
.ret:
    ret

; edx is the destination apic id
lapic_start_one64:
    push r13
    mov r13d, edx
    mov eax, 0x0000C500
    call lapic_send_icr64
    mov ecx, 10
    call tsc_delay_ms64
    mov eax, 0x00008500
    call lapic_send_icr64
    mov ecx, 10
    call tsc_delay_ms64
    mov ecx, 2
.sipi:
    push rcx
    mov eax, 0x00000608
    call lapic_send_icr64
    mov ecx, 1
    call tsc_delay_ms64
    pop rcx
    loop .sipi
    pop r13
    ret

; eax is icr low and r13d is destination
lapic_send_icr64:
    cmp byte [rel smp_x2apic], 1
    je .x2

  ; preserve the requested icr-low value. lapic_wait_icr64 reads icr-low into
  ; eax while polling delivery status, so without this save we would
    push rax
    call lapic_wait_icr64
    mov edx, r13d
    shl edx, 24
    mov [rbx+0x310], edx
    pop rax
    mov [rbx+0x300], eax
    ret
.x2:
    push rcx
    push rdx
    mov edx, r13d
    mov ecx, 0x830
    wrmsr
    pop rdx
    pop rcx
    ret

lapic_wait_icr64:
    cmp byte [rel smp_x2apic], 1
    je .done
.wait:
    mov eax, [rbx+0x300]
    test eax, 1<<12
    jnz .wait
.done:
    ret

; rcx function and rdx arg, every ap runs the same job
smp_dispatch_all64:
    test rcx, rcx
    jz .fail
    mov r10, rcx
    mov r11, rdx

    mov eax, [rel ap_online_count]
    cmp eax, 1
    jbe .fail
    mov r8d, eax
    dec r8d

  ; clear per-worker checkpoints so a failed dispatch can be diagnosed without
  ; letting aps fight over the uart from exception context.
    lea rdi, [rel ap_worker_stage]
    xor eax, eax
    mov ecx, MAX_CPUS
    rep stosb

    mov [rel ap_job_fn], r10
    mov [rel ap_job_arg], r11
    mov dword [rel ap_job_done], 0
    mfence
    lock inc dword [rel ap_job_epoch]

  ; never hang the bsp forever if an ap faults. give the job ~500 ms.
    mov r9, [rel tsc_cycles_per_ms]
    test r9, r9
    jz .fallback_wait
    imul r9, 500
    rdtsc
    shl rdx, 32
    or rax, rdx
    add r9, rax
.wait:
    cmp [rel ap_job_done], r8d
    jae .ok
    pause
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, r9
    jb .wait
    jmp .fail

.fallback_wait:
    mov r9d, 50000000
.fallback_loop:
    cmp [rel ap_job_done], r8d
    jae .ok
    pause
    dec r9d
    jnz .fallback_loop
    jmp .fail

.ok:
    mov eax, 1
    ret
.fail:
    xor eax, eax
    ret

BITS 16
ap_trampoline_start:
    cli

  ; sipi starts an ap in real mode. take the conservative route through a 32-bit
  ; protected-mode code segment before enabling long-mode
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    mov byte [cs:ap_boot_stage-ap_trampoline_start], 1

    lgdt [cs:ap_gdt_ptr-ap_trampoline_start]

    mov eax, cr0
    or eax, 1
    mov cr0, eax
    db 0x66,0xEA
    dd AP_TRAMP_PHYS+(ap_prot32-ap_trampoline_start)
    dw 0x18

BITS 32
ap_prot32:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov esp, 0x7C00
    mov byte [AP_TRAMP_PHYS+(ap_boot_stage-ap_trampoline_start)], 2

  ; long mode sequence: pae -> cr3 -> efer.lme -> paging.
    mov eax, cr4
    or eax, 1<<5
    mov cr4, eax
    mov eax, PML4_PHYS
    mov cr3, eax
    mov byte [AP_TRAMP_PHYS+(ap_boot_stage-ap_trampoline_start)], 3

    mov ecx, 0xC0000080
    rdmsr
    or eax, 1<<8
    wrmsr

    mov eax, cr0
    or eax, 1<<31
    mov cr0, eax

    jmp 0x08:AP_TRAMP_PHYS+(ap_long64-ap_trampoline_start)

align 8
ap_gdt:
    dq 0
    dq 0x00AF9A000000FFFF       ; 0x08 64-bit code (matches runtime idt)
    dq 0x00CF92000000FFFF       ; 0x10 flat data (matches bsp gdt)
    dq 0x00CF9A000000FFFF       ; 0x18 temporary 32-bit code
ap_gdt_end:
ap_gdt_ptr:
    dw ap_gdt_end-ap_gdt-1
    dd AP_TRAMP_PHYS+(ap_gdt-ap_trampoline_start)

BITS 64
ap_long64:
    mov byte [abs AP_TRAMP_PHYS+(ap_boot_stage-ap_trampoline_start)], 4

    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax

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

  ; claim a stable ap worker index without advertising the cpu as online yet.
  ; the bsp must not dispatch work until
    mov rbx, RELOC_BASE+ap_stack_claim
    mov eax, 1
    lock xadd dword [rbx], eax
    inc eax
    mov r12d, eax

    mov rbx, [abs RELOC_BASE+ap_stack_base]
    mov eax, r12d
  ; worker ids are 1..n. use that id directly as the stack slot number. adding
  ; one here pushed the last ap
    imul rax, AP_STACK_BYTES
    sub rbx, rax
    mov rsp, rbx
    and rsp, -16
    mov byte [abs AP_TRAMP_PHYS+(ap_boot_stage-ap_trampoline_start)], 5

    lidt [abs RELOC_BASE+legacy_idtr]
    mov r13d, [abs RELOC_BASE+ap_job_epoch]

  ; leave the temporary 0x8000 trampoline completely once long mode and the
  ; private stack are ready. steady-state worker code lives with
    mov byte [abs AP_TRAMP_PHYS+(ap_boot_stage-ap_trampoline_start)], 6
    mov rax, RELOC_BASE+ap_worker_runtime64
    jmp rax

; highest startup checkpoint reached by any ap.
ap_boot_stage db 0
ap_trampoline_end:

BITS 64

; permanent ap worker loop. r12d is the stable worker id (1..n), r13d is the
; last observed job epoch, and rsp
ap_worker_runtime64:
    lea rbx, [rel ap_worker_stage]
    mov byte [rbx+r12], 0xA0

  ; complete the handoff into normal runtime cpu state. the trampoline gdt is
  ; only for mode transition; steady-state aps must use
    lgdt [rel gdt_ptr64]
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax

    mov rax, cr0
    or rax, 1 << 16                ; cr0.wp, same as bsp protection init
    mov cr0, rax

    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .nx_done
    mov eax, 0x80000001
    cpuid
    test edx, 1 << 20
    jz .nx_done
    mov ecx, 0xC0000080
    rdmsr
    or eax, 1 << 11                ; efer.nxe
    wrmsr
.nx_done:
    lidt [rel legacy_idtr]
    mov byte [rbx+r12], 0xA1

  ; publish readiness only after the ap matches normal runtime cpu state.
    lock inc dword [rel ap_online_count]
    mov byte [rbx+r12], 0xA2

.worker:
    pause
    mov byte [rbx+r12], 0xA3
    mov eax, [rel ap_job_epoch]
    mov byte [rbx+r12], 0xA4
    cmp eax, r13d
    je .worker
    mov r13d, eax

    lea rbx, [rel ap_worker_stage]
    mov byte [rbx+r12], 1

    mov rax, [rel ap_job_fn]
    test rax, rax
    jz .worker
    mov byte [rbx+r12], 2

    mov rcx, [rel ap_job_arg]
    mov edx, r12d
    mov byte [rbx+r12], 3

    sub rsp, 32
    call rax
    add rsp, 32

    lea rbx, [rel ap_worker_stage]
    mov byte [rbx+r12], 4
    lock inc dword [rel ap_job_done]
    mov byte [rbx+r12], 5
    jmp .worker

; com1 hardware diagnostic visible on vga even when the external serial link
; is dead. tests the 16550 internal loopback, snapshots
serial_uart_diag64:
    push rax
    push rbx
    push rcx
    push rdx
    mov bx, COM1

    mov dx, bx
    add dx, 5
    in al, dx
    mov [rel uart_diag_lsr], al

    mov dx, bx
    add dx, 6
    in al, dx
    mov [rel uart_diag_msr], al

  ; internal loopback: mcr loopback + all modem outputs asserted.
    mov dx, bx
    add dx, 4
    mov al, 0x1F
    out dx, al

  ; flush any stale receive byte, then transmit a5 through internal loopback.
    mov dx, bx
    add dx, 2
    mov al, 0xC7
    out dx, al
    mov dx, bx
    mov al, 0xA5
    out dx, al

    mov ecx, 65535
.wait_rx:
    mov dx, bx
    add dx, 5
    in al, dx
    test al, 1
    jnz .read
    dec ecx
    jnz .wait_rx
    mov byte [rel uart_diag_loop], 0
    jmp .restore
.read:
    mov dx, bx
    in al, dx
    cmp al, 0xA5
    sete al
    mov [rel uart_diag_loop], al

.restore:
    mov dx, bx
    add dx, 4
    mov al, 0x0B
    out dx, al

    lea rsi, [rel msg_uart_diag]
    call serial_puts64
    movzx eax, byte [rel uart_diag_lsr]
    call serial_hex32_64
    lea rsi, [rel msg_uart_diag_msr]
    call serial_puts64
    movzx eax, byte [rel uart_diag_msr]
    call serial_hex32_64
    lea rsi, [rel msg_uart_diag_loop]
    call serial_puts64
    movzx eax, byte [rel uart_diag_loop]
    call serial_hex32_64
    lea rsi, [rel msg_uart_diag_hint]
    call serial_puts64

    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret

; keep the uart verdict on screen long enough to photograph/read. during this
; hold com1 continuously transmits an alternating test pattern
serial_uart_diag_hold64:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    lea rsi, [rel msg_uart_hold]
    call serial_puts64

  ; ~8 seconds using the calibrated tsc when available; otherwise a bounded
  ; fallback loop. we intentionally transmit regardless of terminal state.
    mov rbx, [rel tsc_cycles_per_ms]
    test rbx, rbx
    jz .fallback
    imul rbx, 8000
    rdtsc
    shl rdx, 32
    or rax, rdx
    add rbx, rax
.tsc_loop:
    mov al, 'U'
    call serial_com1_putc64
    mov al, '5'
    call serial_com1_putc64
    mov al, 13
    call serial_com1_putc64
    mov al, 10
    call serial_com1_putc64
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, rbx
    jb .tsc_loop
    jmp .done

.fallback:
    mov ecx, 128
.fb_loop:
    mov al, 'U'
    call serial_com1_putc64
    mov al, '5'
    call serial_com1_putc64
    mov r9d, 0x10000
.fb_delay:
    pause
    dec r9d
    jnz .fb_delay
    dec ecx
    jnz .fb_loop
.done:
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret

; temporary com1-only beacon. it intentionally bypasses vga mirroring so the
; external receiver gets a fresh line every second without flooding
serial_beacon_tick64:
    cmp dword [rel serial_live_enabled], 1
    jne .done
    call legacy_shell_input_busy64
    test eax, eax
    jnz .done
    mov r9, [rel tsc_cycles_per_ms]
    test r9, r9
    jz .done
    mov r8, [rel serial_beacon_deadline]
    rdtsc
    shl rdx, 32
    or rax, rdx
    test r8, r8
    jz .send
    cmp rax, r8
    jb .done
.send:
    push rax
    lea rsi, [rel msg_serial_beacon]
.next:
    lodsb
    test al, al
    jz .arm
    call serial_com1_putc64
    jmp .next
.arm:
    pop rax
    imul r9, 1000
    add rax, r9
    mov [rel serial_beacon_deadline], rax
.done:
    ret

serial_live_enable64:
    mov dword [rel serial_live_enabled], 1
    mov qword [rel serial_beacon_deadline], 0
    mov qword [rel legacy_net_diag_deadline], 0
    mov qword [rel legacy_net_diag_last_tx], -1
    mov qword [rel legacy_net_diag_last_rx], -1
    mov qword [rel legacy_net_diag_last_drop], -1
    lea rsi, [rel msg_serial_live_on]
    call serial_puts64
    ret

serial_live_disable64:
    mov dword [rel serial_live_enabled], 0
    lea rsi, [rel msg_serial_live_off]
    call serial_puts64
    ret

serial_live_status64:
    cmp dword [rel serial_live_enabled], 1
    jne .off
    lea rsi, [rel msg_serial_live_status_on]
    call serial_puts64
    ret
.off:
    lea rsi, [rel msg_serial_live_status_off]
    call serial_puts64
    ret

serial_com1_putc64:
    push rax
    push rcx
    push rdx
    mov cl, al
    mov edx, COM1+5
    mov eax, 65535
.wait:
    in al, dx
    test al, 0x20
    jnz .send
    dec eax
    jnz .wait
    jmp .out
.send:
    mov edx, COM1
    mov al, cl
    out dx, al
.out:
    pop rdx
    pop rcx
    pop rax
    ret

serial_puts64:
.n:
    lodsb
    test al, al
    jz .d
    call serial_putc64_al
    jmp .n
.d:
    ret

serial_init_port64_dx:
    push rax
    push rbx
    mov bx, dx
    inc dx
    xor al, al
    out dx, al
    mov dx, bx
    add dx, 3
    mov al, 0x80
    out dx, al
    mov dx, bx
    mov al, 1
    out dx, al
    mov dx, bx
    inc dx
    xor al, al
    out dx, al
    mov dx, bx
    add dx, 3
    mov al, 3
    out dx, al
    mov dx, bx
    add dx, 2
    mov al, 0xC7
    out dx, al
    mov dx, bx
    add dx, 4
    mov al, 0x0B
    out dx, al
    mov dx, bx
    pop rbx
    pop rax
    ret

serial_putc64_al:
    push rax
    push rbx
    push rdx
    push rcx
    push r9
    mov cl, al

  ; once the operator has started a command, the shell owns the terminal. drop
  ; asynchronous/background characters until enter is handled so
    cmp dword [rel shell_len], 0
    je .console_ok
    cmp dword [rel shell_console_owned], 1
    jne .drop
.console_ok:

    movzx ebx, word [rel runtime_uart1]
    test bx, bx
    jz .second
    mov r9d, 4096
.first_wait:
    mov dx, bx
    add dx, 5
    in al, dx
    test al, 0x20
    jnz .first_send
    dec r9d
    jnz .first_wait
    jmp .second
.first_send:
    mov dx, bx
    mov al, cl
    out dx, al

.second:
    movzx ebx, word [rel runtime_uart2]
    test bx, bx
    jz .third
    cmp bx, [rel runtime_uart1]
    je .third
    mov r9d, 4096
.second_wait:
    mov dx, bx
    add dx, 5
    in al, dx
    test al, 0x20
    jnz .second_send
    dec r9d
    jnz .second_wait
    jmp .third
.second_send:
    mov dx, bx
    mov al, cl
    out dx, al

.third:
    movzx ebx, word [rel runtime_uart3]
    test bx, bx
    jz .fourth
    cmp bx, [rel runtime_uart1]
    je .fourth
    cmp bx, [rel runtime_uart2]
    je .fourth
    mov r9d, 4096
.third_wait:
    mov dx, bx
    add dx, 5
    in al, dx
    test al, 0x20
    jnz .third_send
    dec r9d
    jnz .third_wait
    jmp .fourth
.third_send:
    mov dx, bx
    mov al, cl
    out dx, al

.fourth:
    movzx ebx, word [rel runtime_uart4]
    test bx, bx
    jz .screen
    cmp bx, [rel runtime_uart1]
    je .screen
    cmp bx, [rel runtime_uart2]
    je .screen
    cmp bx, [rel runtime_uart3]
    je .screen
    mov r9d, 4096
.fourth_wait:
    mov dx, bx
    add dx, 5
    in al, dx
    test al, 0x20
    jnz .fourth_send
    dec r9d
    jnz .fourth_wait
    jmp .screen
.fourth_send:
    mov dx, bx
    mov al, cl
    out dx, al

.screen:
    mov al, cl
    call legacy_vga_putc64
    jmp .restore

.drop:
.restore:
    pop r9
    pop rcx
    pop rdx
    pop rbx
    pop rax
    ret

serial_hex32_64:
    push rbx
    push rcx
    mov ebx, eax
    mov ecx, 8
.l:
    rol ebx, 4
    mov eax, ebx
    and eax, 0xF
    cmp eax, 9
    jbe .n
    add eax, 'A'-10
    jmp .e
.n:
    add eax, '0'
.e:
    call serial_putc64_al
    loop .l
    pop rcx
    pop rbx
    ret

serial_hex64:
    push rbx
    push rcx
    mov rbx, rax
    mov ecx, 16
.l:
    rol rbx, 4
    mov rax, rbx
    and eax, 0xF
    cmp eax, 9
    jbe .n
    add eax, 'A'-10
    jmp .e
.n:
    add eax, '0'
.e:
    call serial_putc64_al
    loop .l
    pop rcx
    pop rbx
    ret

align 8
ram_total_usable dq 0
ram_highest      dq 0
heap_next        dq 0
heap_end         dq 0
direct_gib       dd 4
uart_diag_lsr    db 0
uart_diag_msr    db 0
uart_diag_loop   db 0
align 8
serial_beacon_deadline dq 0
serial_live_enabled dd 0
ap_stack_floor   dq 0
ap_stack_base    dq 0
rsdp_phys        dq 0
madt_phys        dq 0
lapic_phys       dq 0
cpu_count        dd 1
ap_online_count  dd 1
ap_job_epoch     dd 0
ap_job_done      dd 0
ap_stack_claim   dd 0
ap_worker_stage  times MAX_CPUS db 0
align 8
ap_job_fn        dq 0
ap_job_arg       dq 0
bsp_apic_id      dd 0
smp_x2apic       db 0
align 8
cpu_apic_ids times MAX_CPUS dd 0

msg_uart_diag  db '[UARTTEST] COM1 0x03F8 lsr=0x',0
msg_uart_diag_msr db ' msr=0x',0
msg_uart_diag_loop db ' loopback=0x',0
msg_uart_diag_hint db ' (loopback 1 = UART CORE OK)',13,10,0
msg_uart_hold db '[UARTTEST] HOLDING SCREEN + blasting COM1 test pattern for ~8 seconds',13,10,0
msg_serial_beacon db '[SERIAL-BEACON] COM1 115200 8N1',13,10,0
msg_serial_live_on db '[SERIAL-LIVE] ON: beacon + live NETSTAT/COM diagnostics enabled',13,10,0
msg_serial_live_off db '[SERIAL-LIVE] OFF: periodic serial diagnostics disabled',13,10,0
msg_serial_live_status_on db '[SERIAL-LIVE] status=ON',13,10,0
msg_serial_live_status_off db '[SERIAL-LIVE] status=OFF',13,10,0
msg_long       db '[MODE] x86-64 long mode active',13,10,0
msg_ram        db '[RAM] usable bytes=0x',0
msg_mem_fail   db '[ERROR] no usable low ram for allocator',13,10,0
msg_smp        db '[SMP] processors online=0x',0
msg_smp_expected db ' expected=0x',0
msg_smp_stage    db ' ap-stage=0x',0
msg_smp_apic     db '[SMP] apic-mode-x2=0x',0
msg_smp_bsp      db ' bsp-id=0x',0
msg_smp_ids      db ' madt-ids=',0
msg_smp_single db '[SMP] staying on one cpu',13,10,0
msg_ready      db '[CORE] legacy runtime online',13,10,0
msg_crlf64     db 13,10,0

%include "legacy_cpu_runtime.inc"
%include "legacy_runtime_extra.inc"
%include "pxe_thunk.inc"
%include "legacy_net_core.inc"
%include "legacy_ip_stack.inc"
%include "legacy_vga_console.inc"
%include "legacy_memory_pool.inc"
%define legacy_tcp_send64 legacy_tcp_send64_raw
%define legacy_tcp_rx64 legacy_tcp_rx64_raw
%define legacy_tcp_tick64 legacy_tcp_tick64_raw
%include "legacy_tcp.inc"
%undef legacy_tcp_tick64
%undef legacy_tcp_rx64
%undef legacy_tcp_send64
%define legacy_tcp_rx64 legacy_tcp_rx64_reliable_old
%include "legacy_tcp_reliable.inc"
%undef legacy_tcp_rx64
%include "legacy_tcp_stream_patch.inc"
%include "legacy_crypto_runtime.inc"
%define legacy_ws_start64 legacy_ws_start64_raw
%include "legacy_websocket.inc"
%undef legacy_ws_start64
%include "legacy_websocket_guard.inc"
%include "legacy_discord_base.inc"
%include "legacy_discord_gateway.inc"
%include "legacy_tftp_files.inc"
%include "legacy_config.inc"
%include "legacy_x509_pin.inc"
%include "legacy_tls.inc"
%include "legacy_tls_patch.inc"
%include "legacy_input.inc"
%include "legacy_vfs.inc"
%include "legacy_shell.inc"
%include "legacy_http_server.inc"

msg_boot_crypto    db '[BOOT] crypto init',13,10,0
msg_boot_crypto_ok db '[BOOT] crypto ok',13,10,0
msg_boot_pxe       db '[BOOT] pxe thunk init',13,10,0
msg_boot_tftp      db '[BOOT] tftp files init',13,10,0
msg_boot_config    db '[BOOT] config init',13,10,0
msg_boot_net       db '[BOOT] net core init',13,10,0
msg_boot_ip        db '[BOOT] ip stack init',13,10,0
msg_boot_tcp       db '[BOOT] tcp init',13,10,0
msg_boot_reliable  db '[BOOT] tcp reliable init',13,10,0
msg_boot_discord   db '[BOOT] discord init',13,10,0
msg_boot_tls       db '[BOOT] tls init',13,10,0
msg_boot_tls_patch db '[BOOT] tls patch init',13,10,0
msg_boot_input     db '[BOOT] input init',13,10,0
msg_boot_vfs       db '[BOOT] vfs init',13,10,0
msg_boot_shell     db '[BOOT] shell init',13,10,0
msg_boot_init_done db '[BOOT] runtime init complete',13,10,0
msg_native_net_fail db '[ERROR] native Realtek init failed; runtime PXE firmware calls disabled',13,10,0

image_end:
