BITS 16
ORG 0

; tiny first loader so the real runtime can grow past 64k pxe downloads
; runtime.bin straight to 0x20000 then we jump

%define COM1 0x3F8
%define COM2 0x2F8
%define RUNTIME_PHYS 0x00020000
%define RUNTIME_SEG  0x2000
%define RUNTIME_MAX  0x000D0000
%define PXE_SERVER_IP 0xB501A8C0
%define PXE_CLIENT_IP_FALLBACK 0xB101A8C0
%define PXE_SUBNET_FALLBACK    0x00FFFFFF
%define PXE_ROUTER_FALLBACK    0x0101A8C0
%define PXE_DNS_FALLBACK       0x0101A8C0

; the realtek pxe entry stack on this target lives around physical 0x83e68.
; runtime.bin now grows through that address before tftp
%define PXE_GUARD_SEG       0x8000
%define PXE_GUARD_END_SEG   0x8800
%define PXE_STASH_SEG       0x1000
%define PXE_GUARD_BYTES     0x8000

; fixed handoff below the runtime thunk so later pxe calls can reuse the nbp
; stack
%define PXE_STACK_HANDOFF_PHYS 0x4E00
%define PXE_STACK_MAGIC        0x53545850
%define PXE_HANDOFF_SS         4
%define PXE_HANDOFF_SP         6
%define PXE_HANDOFF_CLIENT_IP  8
%define PXE_HANDOFF_SERVER_IP  12
%define PXE_HANDOFF_GATEWAY_IP 16
%define PXE_HANDOFF_SUBNET      20
%define PXE_HANDOFF_ROUTER      24
%define PXE_HANDOFF_DNS         28

%define PXENV_GET_CACHED_INFO 0x0071
%define PXENV_TFTP_OPEN       0x0020
%define PXENV_TFTP_CLOSE      0x0021
%define PXENV_TFTP_READ       0x0022
%define PXENV_PACKET_TYPE_DHCP_ACK 2
%define PXENV_PACKET_TYPE_CACHED_REPLY 3

%define CACHED_STATUS      0
%define CACHED_PACKETTYPE  2
%define CACHED_BUFSIZE     4
%define CACHED_BUFOFF      6
%define CACHED_BUFSEG      8
%define CACHED_INFO_SIZE  12

%define BOOTP_YIP    16
%define BOOTP_SIADDR 20
%define BOOTP_GIADDR 24

; pxenv_tftp_open
%define OPEN_STATUS       0
%define OPEN_SERVER_IP    2
%define OPEN_GATEWAY_IP   6
%define OPEN_FILENAME    10
%define OPEN_PORT       138
%define OPEN_PACKETSIZE 140
%define OPEN_SIZE       142

; pxenv_tftp_read
%define READ_STATUS       0
%define READ_PACKET       2
%define READ_BUFSIZE      4
%define READ_BUFFER       6
%define READ_SIZE        10

%define CLOSE_STATUS      0
%define CLOSE_SIZE        2

start:
    cli
    cld

  ; some old pxe roms only behave on the stack they entered the nbp with
    mov [cs:pxe_initial_sp], sp
    mov ax, ss
    mov [cs:pxe_initial_ss], ax

  ; leave the original nbp stack where the x64 runtime can recover it
    push es
    xor ax, ax
    mov es, ax
    mov dword [es:PXE_STACK_HANDOFF_PHYS+0], PXE_STACK_MAGIC
    mov ax, [cs:pxe_initial_ss]
    mov [es:PXE_STACK_HANDOFF_PHYS+PXE_HANDOFF_SS], ax
    mov ax, [cs:pxe_initial_sp]
    mov [es:PXE_STACK_HANDOFF_PHYS+PXE_HANDOFF_SP], ax
    mov dword [es:PXE_STACK_HANDOFF_PHYS+PXE_HANDOFF_CLIENT_IP], 0
    mov dword [es:PXE_STACK_HANDOFF_PHYS+PXE_HANDOFF_SERVER_IP], 0
    mov dword [es:PXE_STACK_HANDOFF_PHYS+PXE_HANDOFF_GATEWAY_IP], 0
    mov dword [es:PXE_STACK_HANDOFF_PHYS+PXE_HANDOFF_SUBNET], 0
    mov dword [es:PXE_STACK_HANDOFF_PHYS+PXE_HANDOFF_ROUTER], 0
    mov dword [es:PXE_STACK_HANDOFF_PHYS+PXE_HANDOFF_DNS], 0
    pop es

    push cs
    pop ds
    push cs
    pop es
  ; keep the loader stack below runtime.bin. the sharded runtime is now large
  ; enough that the old 0x7000:fffe stack was overwritten
    mov ax, 0x1000
    mov ss, ax
    mov sp, 0xFFFE
    sti

  ; bring up direct uart breadcrumbs immediately. do not stall boot here: the
  ; old five-second debug pause was only useful while
    call serial_init
    mov si, msg_serial_diag
    call puts
    mov al, 'A'
    call debug_mark
    mov al, 'B'
    call debug_mark

  ; ask bios for the pxe api
    mov al, 'C'
    call debug_mark
    mov ax, 0x5650
    int 0x1A
    cmp ax, 0x564E
    jne fail_pxe
    mov al, 'D'
    call debug_mark

  ; validate pxenv+ before saving its far entry point
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
    mov [cs:pxe_entry], ax
    mov ax, [si+12]
    mov [cs:pxe_entry+2], ax
    pop ds
    mov al, 'E'
    call debug_mark
    jmp .ready
.bad:
    pop ds
    jmp fail_pxe
.ready:
    push cs
    pop ds
    push cs
    pop es

    mov al, 'F'
    call debug_mark
    call get_cached_ack
    jc fail_dhcp
    mov al, 'G'
    call debug_mark

    mov al, 'H'
    call debug_mark
    call load_runtime
    jc fail_tftp
    mov al, 'K'
    call debug_mark

  ; pxe transfer is closed now; normal vga + serial messages are safe.
    call serial_init
    mov si, msg_loaded
    call puts
    mov eax, [runtime_size]
    call hex32
    call newline
    mov si, msg_jump
    call puts
    cli
    jmp RUNTIME_SEG:0

fail_pxe:
    push cs
    pop ds
    call serial_init
    mov si, msg_pxe_fail
    call puts
    jmp hang
fail_dhcp:
    call serial_init
    mov si, msg_dhcp_fail
    call puts
    jmp hang
fail_tftp:
    call serial_init
    mov si, msg_tftp_fail
    call puts
hang:
    cli
.loop:
    hlt
    jmp .loop

; bx is the pxe function and es:di is its parameter block call old firmware on
; the exact stack it gave
pxe_call:
    cli
    mov [cs:loader_sp], sp
    mov ax, ss
    mov [cs:loader_ss], ax
    mov ax, [cs:pxe_initial_ss]
    mov ss, ax
    mov sp, [cs:pxe_initial_sp]
    sti

    push ds
    push si
    push bp
    call far [cs:pxe_entry]
    pop bp
    pop si
    pop ds

    cli
    mov dx, [cs:loader_ss]
    mov ss, dx
    mov sp, [cs:loader_sp]
    cld
    sti
    ret

; al is the cached packet type, returns carry on firmware/status failure
get_cached_packet:
    push ax
    push es
    push cs
    pop es
    mov di, cached_info
    xor ax, ax
    mov cx, CACHED_INFO_SIZE/2
    rep stosw
    pop ax
    mov ah, 0
    mov [cached_info+CACHED_PACKETTYPE], ax
    mov bx, PXENV_GET_CACHED_INFO
    mov di, cached_info
    call pxe_call
    test ax, ax
    jnz .fail
    cmp word [cached_info+CACHED_STATUS], 0
    jne .fail
    clc
    pop es
    ret
.fail:
    stc
    pop es
    ret

get_cached_ack:
  ; capture all network configuration while the pxe firmware stack is still
  ; intact. runtime consumes only this handoff and never relies
    mov dword [server_ip], PXE_SERVER_IP
    mov dword [gateway_ip], 0
    mov dword [handoff_client_ip], PXE_CLIENT_IP_FALLBACK
    mov dword [handoff_server_ip], PXE_SERVER_IP
    mov dword [handoff_gateway_ip], 0
    mov dword [handoff_subnet], PXE_SUBNET_FALLBACK
    mov dword [handoff_router], PXE_ROUTER_FALLBACK
    mov dword [handoff_dns], PXE_DNS_FALLBACK

  ; keep the cached-reply probe for this rom's proven pxe flow.
    mov al, '1'
    call debug_mark
    mov al, PXENV_PACKET_TYPE_CACHED_REPLY
    call get_cached_packet

  ; always fetch the real dhcp ack too: it contains subnet/router/dns options.
    mov al, '3'
    call debug_mark
    mov al, PXENV_PACKET_TYPE_DHCP_ACK
    call get_cached_packet
    jc .publish
    mov al, '4'
    call debug_mark

  ; snapshot packet pointer/length before switching ds.
    mov cx, [cached_info+CACHED_BUFSIZE]
    mov dx, [cached_info+CACHED_BUFOFF]
    mov bx, [cached_info+CACHED_BUFSEG]
    cmp cx, 240
    jb .publish

    push ds
    mov ds, bx
    mov si, dx

  ; yiaddr
    mov eax, [si+BOOTP_YIP]
    mov ebx, eax
    and ebx, 0x00FFFFFF
    cmp ebx, 0x0001A8C0
    jne .skip_client
    mov [cs:handoff_client_ip], eax
.skip_client:

  ; siaddr, if present
    mov eax, [si+BOOTP_SIADDR]
    test eax, eax
    jz .skip_server
    mov [cs:handoff_server_ip], eax
.skip_server:

  ; giaddr is retained for diagnostics only.
    mov eax, [si+BOOTP_GIADDR]
    mov [cs:handoff_gateway_ip], eax

  ; dhcp magic cookie + options.
    cmp dword [si+236], 0x63538263
    jne .options_done
    add si, 240
    sub cx, 240
.opt_loop:
    test cx, cx
    jz .options_done
    mov al, [si]
    inc si
    dec cx
    cmp al, 255
    je .options_done
    test al, al
    jz .opt_loop
    test cx, cx
    jz .options_done
    mov dl, [si]
    inc si
    dec cx
    movzx dx, dl
    cmp dx, cx
    ja .options_done

    cmp al, 1
    je .opt_subnet
    cmp al, 3
    je .opt_router
    cmp al, 6
    je .opt_dns
    jmp .opt_skip
.opt_subnet:
    cmp dx, 4
    jb .opt_skip
    mov eax, [si]
    mov [cs:handoff_subnet], eax
    jmp .opt_skip
.opt_router:
    cmp dx, 4
    jb .opt_skip
    mov eax, [si]
    mov [cs:handoff_router], eax
    jmp .opt_skip
.opt_dns:
    cmp dx, 4
    jb .opt_skip
    mov eax, [si]
    mov [cs:handoff_dns], eax
.opt_skip:
    add si, dx
    sub cx, dx
    jmp .opt_loop

.options_done:
    pop ds

.publish:
    mov eax, [handoff_server_ip]
    mov [server_ip], eax
    mov dword [gateway_ip], 0

    push es
    xor bx, bx
    mov es, bx
    mov eax, [handoff_client_ip]
    mov [es:PXE_STACK_HANDOFF_PHYS+PXE_HANDOFF_CLIENT_IP], eax
    mov eax, [handoff_server_ip]
    mov [es:PXE_STACK_HANDOFF_PHYS+PXE_HANDOFF_SERVER_IP], eax
    mov eax, [handoff_gateway_ip]
    mov [es:PXE_STACK_HANDOFF_PHYS+PXE_HANDOFF_GATEWAY_IP], eax
    mov eax, [handoff_subnet]
    mov [es:PXE_STACK_HANDOFF_PHYS+PXE_HANDOFF_SUBNET], eax
    mov eax, [handoff_router]
    mov [es:PXE_STACK_HANDOFF_PHYS+PXE_HANDOFF_ROUTER], eax
    mov eax, [handoff_dns]
    mov [es:PXE_STACK_HANDOFF_PHYS+PXE_HANDOFF_DNS], eax
    pop es
    clc
    ret

; old realtek rom mangles read_file so use the smaller tftp calls directly
load_runtime:
    push ds
    push es
    push cs
    pop ds
    push cs
    pop es

  ; build tftp open exactly as the pxe api defines it
    mov di, tftp_open
    xor ax, ax
    mov cx, OPEN_SIZE/2
    rep stosw
    mov eax, [server_ip]
    mov [tftp_open+OPEN_SERVER_IP], eax
    mov dword [tftp_open+OPEN_GATEWAY_IP], 0

  ; write runtime.bin directly into the fixed 128 byte filename field
    mov dword [tftp_open+OPEN_FILENAME+0], 0x746E7572
    mov dword [tftp_open+OPEN_FILENAME+4], 0x2E656D69
    mov word  [tftp_open+OPEN_FILENAME+8], 0x6962
    mov byte  [tftp_open+OPEN_FILENAME+10], 0x6E
    mov byte  [tftp_open+OPEN_FILENAME+11], 0

  ; 69 is network order in the api field
    mov word [tftp_open+OPEN_PORT], 0x4500

  ; zero asks the rom for its normal 512-byte tftp mode without blksize
  ; negotiation
    mov word [tftp_open+OPEN_PACKETSIZE], 0

    mov al, 'I'
    call debug_mark
    mov bx, PXENV_TFTP_OPEN
    mov di, tftp_open
    call pxe_call
    test ax, ax
    jnz .fail_open
    cmp word [tftp_open+OPEN_STATUS], 0
    jne .fail_open
    mov al, 'J'
    call debug_mark

    mov dword [runtime_size], 0
    mov word [runtime_seg], RUNTIME_SEG
    mov word [runtime_blocks], 0

.read_next:
    cld
    push cs
    pop es
    mov di, tftp_read
    xor ax, ax
    mov cx, READ_SIZE/2
    rep stosw
    mov word [tftp_read+READ_BUFSIZE], 512
    mov word [tftp_read+READ_BUFFER+0], tftp_bounce
    mov ax, cs
    mov word [tftp_read+READ_BUFFER+2], ax

  ; n means we are about to ask the rom for block 2.
    cmp word [runtime_blocks], 1
    jne .do_read
    mov al, 'N'
    call debug_mark
.do_read:
    mov bx, PXENV_TFTP_READ
    mov di, tftp_read
    call pxe_call
    test ax, ax
    jnz .fail_close
    cmp word [tftp_read+READ_STATUS], 0
    jne .fail_close

  ; l = block 1 returned. o = block 2 returned.
    cmp word [runtime_blocks], 0
    jne .mark_second_return
    mov al, 'L'
    call debug_mark
    jmp .returned_marked
.mark_second_return:
    cmp word [runtime_blocks], 1
    jne .returned_marked
    mov al, 'O'
    call debug_mark
.returned_marked:

    movzx eax, word [tftp_read+READ_BUFSIZE]
    test eax, eax
    jz .done_read
    mov edx, [runtime_size]
    add edx, eax
    cmp edx, RUNTIME_MAX
    ja .fail_close

  ; copy from the fixed pxe bounce buffer. do not overwrite the 32 kib window
  ; containing the live firmware stack until
    push ds
    push es
    push cs
    pop ds
    mov ax, [runtime_seg]
    cmp ax, PXE_GUARD_SEG
    jb .copy_direct
    cmp ax, PXE_GUARD_END_SEG
    jae .copy_direct

  ; temporary destination: 0x1000:(runtime_seg-pxe_guard_seg)*16. this occupies
  ; physical 0x10000-0x17fff; our loader stack is at the top of the same segment near 0x1fffe
    mov dx, ax
    sub dx, PXE_GUARD_SEG
    shl dx, 4
    mov ax, PXE_STASH_SEG
    mov es, ax
    mov di, dx
    jmp .copy_bytes

.copy_direct:
    mov es, ax
    xor di, di

.copy_bytes:
    mov si, tftp_bounce
    mov cx, [tftp_read+READ_BUFSIZE]
    cld
    rep movsb
    pop es
    pop ds

    movzx eax, word [tftp_read+READ_BUFSIZE]
    add [runtime_size], eax

  ; m = block 1 copied. p = block 2 copied.
    cmp word [runtime_blocks], 0
    jne .mark_second_copy
    mov al, 'M'
    call debug_mark
    jmp .copy_marked
.mark_second_copy:
    cmp word [runtime_blocks], 1
    jne .copy_marked
    mov al, 'P'
    call debug_mark
.copy_marked:
    inc word [runtime_blocks]

    cmp word [tftp_read+READ_BUFSIZE], 512
    jb .done_read

    add word [runtime_seg], 0x20
    cmp word [runtime_seg], 0xF000
    jae .fail_close
    jmp .read_next

.done_read:
    mov al, 'Q'
    call debug_mark
    mov al, 'V'
    call debug_mark
    call tftp_close
    jc .close_failed
    mov al, 'R'
    call debug_mark
    call restore_pxe_guard_window
    jmp .close_ok
.close_failed:
    mov al, 'X'
    call debug_mark
    jmp .fail
.close_ok:

    clc
    pop es
    pop ds
    ret

.fail_open:
    stc
    pop es
    pop ds
    ret

.fail_close:
    call tftp_close
.fail:
    stc
    pop es
    pop ds
    ret

; after the final pxe firmware call, fill the protected runtime window from
; the low-memory stash. no firmware code may run
restore_pxe_guard_window:
    push ax
    push cx
    push si
    push di
    push ds
    push es

    mov ax, PXE_STASH_SEG
    mov ds, ax
    xor si, si
    mov ax, PXE_GUARD_SEG
    mov es, ax
    xor di, di
    mov cx, PXE_GUARD_BYTES / 2
    cld
    rep movsw

    pop es
    pop ds
    pop di
    pop si
    pop cx
    pop ax
    ret

tftp_close:
    push es
    push cs
    pop es
    mov word [tftp_close_pb+CLOSE_STATUS], 0
    mov bx, PXENV_TFTP_CLOSE
    mov di, tftp_close_pb
    call pxe_call
    test ax, ax
    jnz .bad
    cmp word [tftp_close_pb+CLOSE_STATUS], 0
    jne .bad
    clc
    pop es
    ret
.bad:
    stc
    pop es
    ret

; initialize both standard legacy uarts identically: 115200 8n1, fifo,
; dtr/rts, no flow control
serial_init:
    mov dx, COM1
    call serial_init_dx
    mov dx, COM2
    call serial_init_dx
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

; bl is sent to both standard uarts if their transmitter is ready
serial_write_bl:
    push ax
    push cx
    push dx
    mov dx, COM1
    call serial_write_dx
    mov dx, COM2
    call serial_write_dx
    pop dx
    pop cx
    pop ax
    ret

serial_write_dx:
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

; serial-only checkpoint used while pxe firmware owns the nic/tftp session.
debug_mark_serial:
    push ax
    push bx
    push cx
    push dx
    mov bl, al
    call serial_write_bl
    mov bl, ' '
    call serial_write_bl
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; one-character checkpoint goes to vga text memory and both uarts. do not call
; int 10h here: this pxe rom can
debug_mark:
    push ax
    push bx
    mov bl, al
    call serial_write_bl
    call vga_write_bl
    mov bl, ' '
    call serial_write_bl
    call vga_write_bl
    pop bx
    pop ax
    ret

putc:
    push ax
    push bx
    mov bl, al
    call serial_write_bl
    call vga_write_bl
    pop bx
    pop ax
    ret

; bl -> vga 80x25 text page 0 without bios calls.
vga_write_bl:
    push ax
    push bx
    push dx
    push es
    push di
    mov di, [cs:stage1_vga_pos]

    cmp bl, 13
    je .cr
    cmp bl, 10
    je .lf

    mov ax, 0xB800
    mov es, ax
    mov al, bl
    mov ah, 0x07
    mov [es:di], ax
    add di, 2
    jmp .wrap

.cr:
    mov ax, di
    xor dx, dx
    mov bx, 160
    div bx
    imul ax, 160
    mov di, ax
    jmp .save

.lf:
    add di, 160
    jmp .wrap

.wrap:
    cmp di, 4000
    jb .save
    xor di, di
.save:
    mov [cs:stage1_vga_pos], di
    pop di
    pop es
    pop dx
    pop bx
    pop ax
    ret

puts:
    push ax
.next:
    lodsb
    test al, al
    jz .done
    call putc
    jmp .next
.done:
    pop ax
    ret

newline:
    mov al, 13
    call putc
    mov al, 10
    call putc
    ret

hex32:
    push eax
    push ebx
    push ecx
    mov ebx, eax
    mov ecx, 8
.loop:
    rol ebx, 4
    mov eax, ebx
    and eax, 0xF
    cmp eax, 9
    jbe .num
    add eax, 'A'-10
    jmp .emit
.num:
    add eax, '0'
.emit:
    call putc
    loop .loop
    pop ecx
    pop ebx
    pop eax
    ret

align 4
pxe_entry      dw 0,0
pxe_initial_sp dw 0
pxe_initial_ss dw 0
loader_sp      dw 0
loader_ss      dw 0
server_ip      dd 0
gateway_ip     dd 0
handoff_client_ip dd 0
handoff_server_ip dd 0
handoff_gateway_ip dd 0
handoff_subnet dd 0
handoff_router dd 0
handoff_dns dd 0
runtime_size   dd 0
runtime_seg    dw RUNTIME_SEG
runtime_blocks dw 0
stage1_vga_pos dw 0
cached_info times CACHED_INFO_SIZE db 0
tftp_open   times OPEN_SIZE db 0
tftp_read   times READ_SIZE db 0
tftp_close_pb times CLOSE_SIZE db 0
align 16
tftp_bounce times 512 db 0

msg_serial_diag db 13,10,'[SHARDED-NBP-DEBUG] fresh stage1 loaded',13,10,'[SERIAL/VGA] startup diagnostics active',13,10,0
msg_start     db 13,10,'discord-pxe stage1',13,10,0
msg_loaded    db '[LOAD] runtime bytes=0x',0
msg_jump      db '[BOOT] starting x64 runtime',13,10,0
msg_pxe_fail  db '[ERROR] pxe api missing',13,10,0
msg_dhcp_fail db '[ERROR] pxe boot server address missing',13,10,0
msg_tftp_fail db '[ERROR] runtime.bin download failed',13,10,0
