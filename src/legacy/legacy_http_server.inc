; minimal http/1.0 status server running entirely inside the bare-metal runtime. one
; browser connection at a time; page contents come directly from live shard ram.

BITS 64

%define HTTP_SERVER_PORT       8080
%define HTTP_STATE_IDLE        0
%define HTTP_STATE_UP          1
%define HTTP_BODY_CAP          24576
%define HTTP_TX_CHUNK          1000

legacy_http_server_init64:
    mov dword [rel http_state], HTTP_STATE_IDLE
    mov dword [rel http_remote_ip], 0
    mov dword [rel http_remote_port], 0
    mov dword [rel http_local_seq], 0
    mov dword [rel http_remote_seq], 0
    mov dword [rel http_hits], 0
    mov qword [rel http_body_ptr], 0

   ; allocate scratch after boot so pxe does not transfer 24 kib of zeroes.
    mov ecx, HTTP_BODY_CAP / 4096
    call alloc_pages64
    test rax, rax
    jnz .body_ok
    mov ecx, HTTP_BODY_CAP / 4096
    call alloc_high_pages64
.body_ok:
    mov [rel http_body_ptr], rax
    test rax, rax
    jz .mem_fail

    lea rsi, [rel msg_http_ready]
    call serial_puts64
    lea rcx, [rel legacy_ipv4_addr]
    call legacy_print_ipv4_64
    lea rsi, [rel msg_http_ready_port]
    call serial_puts64
    ret
.mem_fail:
    lea rsi, [rel msg_http_mem_fail]
    call serial_puts64
    ret

; tcp checksum over ipv4 pseudo-header + tcp segment. rcx=tcp bytes, edx=len. ax=checksum
; in wire byte order.

legacy_http_tcp_checksum64:
    push rbx
    push rsi
    push rdi
    push r12
    mov rsi, rcx
    mov edi, edx
    xor ebx, ebx

    lea r12, [rel legacy_ipv4_addr]
    xor r10d, r10d
.local:
    movzx eax, byte [r12+r10]
    shl eax, 8
    movzx edx, byte [r12+r10+1]
    or eax, edx
    add ebx, eax
    add r10d, 2
    cmp r10d, 4
    jb .local

    lea r12, [rel http_remote_ip]
    xor r10d, r10d
.remote:
    movzx eax, byte [r12+r10]
    shl eax, 8
    movzx edx, byte [r12+r10+1]
    or eax, edx
    add ebx, eax
    add r10d, 2
    cmp r10d, 4
    jb .remote

    add ebx, 6
    add ebx, edi
.sum:
    cmp edi, 2
    jb .odd
    movzx eax, byte [rsi]
    shl eax, 8
    movzx edx, byte [rsi+1]
    or eax, edx
    add ebx, eax
    add rsi, 2
    sub edi, 2
    jmp .sum
.odd:
    test edi, edi
    jz .fold
    movzx eax, byte [rsi]
    shl eax, 8
    add ebx, eax
.fold:
    mov eax, ebx
    shr eax, 16
    and ebx, 0xFFFF
    add ebx, eax
    mov eax, ebx
    shr eax, 16
    and ebx, 0xFFFF
    add ebx, eax
    mov eax, ebx
    not eax
    and eax, 0xFFFF
    xchg al, ah

    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; rcx=payload or 0, edx=len, r8d=tcp flags.
legacy_http_send_segment64:
    push rbx
    push r12
    push r13
    push r14
    mov r12, rcx
    mov r13d, edx
    mov r14d, r8d
    cmp r13d, HTTP_TX_CHUNK
    ja .fail

    call legacy_tx_alloc64
    test rax, rax
    jz .fail
    mov rbx, rax

    mov rcx, rbx
    mov edx, HTTP_SERVER_PORT
    call legacy_tcp_store_be16
    lea rcx, [rbx+2]
    mov edx, [rel http_remote_port]
    call legacy_tcp_store_be16
    lea rcx, [rbx+4]
    mov edx, [rel http_local_seq]
    call legacy_tcp_store_be32
    lea rcx, [rbx+8]
    mov edx, [rel http_remote_seq]
    call legacy_tcp_store_be32
    mov byte [rbx+12], 0x50
    mov [rbx+13], r14b
    mov word [rbx+14], 0xF0FA
    mov word [rbx+16], 0
    mov word [rbx+18], 0

    test r13d, r13d
    jz .sum
    lea rdi, [rbx+20]
    mov rsi, r12
    mov ecx, r13d
    rep movsb
.sum:
    mov rcx, rbx
    mov edx, r13d
    add edx, 20
    call legacy_http_tcp_checksum64
    mov [rbx+16], ax

    mov ecx, [rel http_remote_ip]
    mov edx, 6
    mov r8, rbx
    mov r9d, r13d
    add r9d, 20
    call legacy_ipv4_send64
    test eax, eax
    jnz .out

    test r14b, 0x02
    jz .fin_seq
    inc dword [rel http_local_seq]
.fin_seq:
    test r14b, 0x01
    jz .payload_seq
    inc dword [rel http_local_seq]
.payload_seq:
    add [rel http_local_seq], r13d
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.fail:
    mov eax, 1
    jmp .out

legacy_http_send_ack64:
    xor ecx, ecx
    xor edx, edx
    mov r8d, 0x10
    call legacy_http_send_segment64
    ret

; append zero-terminated rsi to the http build buffer.
legacy_http_append_cstr64:
    push rax
    push rdi
    mov rdi, [rel http_build_ptr]
.loop:
    lodsb
    test al, al
    jz .done
    cmp rdi, [rel http_build_end]
    jae .done
    stosb
    jmp .loop
.done:
    mov [rel http_build_ptr], rdi
    pop rdi
    pop rax
    ret

; append eax as eight hexadecimal digits.
legacy_http_append_hex32_64:
    push rax
    push rbx
    push rcx
    push rdx
    push rdi
    mov ebx, eax
    mov ecx, 8
    mov rdi, [rel http_build_ptr]
.loop:
    cmp rdi, [rel http_build_end]
    jae .done
    rol ebx, 4
    mov edx, ebx
    and edx, 0xF
    cmp edx, 9
    jbe .digit
    add edx, 'A'-10
    jmp .emit
.digit:
    add edx, '0'
.emit:
    mov [rdi], dl
    inc rdi
    loop .loop
.done:
    mov [rel http_build_ptr], rdi
    pop rdi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret


; build the deliberately late-90s status page from live runtime state.
legacy_http_build_page64:
    push rbx
    push r12
    push r13

    call legacy_shards_ensure_init64

    mov rax, [rel http_body_ptr]
    test rax, rax
    jz .no_body
    mov [rel http_build_ptr], rax
    lea rdx, [rax + HTTP_BODY_CAP]
    mov [rel http_build_end], rdx

   ; let ap workers aggregate shard state when secondary cpus are online.
    call legacy_shards_parallel_health64
    test eax, eax
    jz .count_local
    mov eax, [rel shard_health_ready]
    mov [rel http_count_ready], eax
    mov eax, [rel shard_health_starting]
    mov [rel http_count_starting], eax
    mov eax, [rel shard_health_backoff]
    mov [rel http_count_backoff], eax
    mov eax, [rel shard_health_fatal]
    mov [rel http_count_fatal], eax
    jmp .counted

.count_local:
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    xor ebx, ebx
.count:
    cmp ebx, [rel shard_active_count]
    jae .counted
    mov ecx, ebx
    call legacy_shards_get_ctx64
    test rax, rax
    jz .counted
    mov edx, [rax + SHARD_OFF_STATE]
    cmp edx, SHARD_STATE_READY
    jne .not_ready
    inc r8d
    jmp .next_count
.not_ready:
    cmp edx, SHARD_STATE_STARTING
    jne .not_start
    inc r9d
    jmp .next_count
.not_start:
    cmp edx, SHARD_STATE_BACKOFF
    jne .not_back
    inc r10d
    jmp .next_count
.not_back:
    cmp edx, SHARD_STATE_FATAL
    jne .next_count
    inc r11d
.next_count:
    inc ebx
    jmp .count
.counted:
    mov [rel http_count_ready], r8d
    mov [rel http_count_starting], r9d
    mov [rel http_count_backoff], r10d
    mov [rel http_count_fatal], r11d

    lea rsi, [rel http_page_a]
    call legacy_http_append_cstr64
    mov eax, [rel http_count_ready]
    call legacy_http_append_hex32_64
    lea rsi, [rel http_page_b]
    call legacy_http_append_cstr64
    mov eax, [rel http_count_starting]
    call legacy_http_append_hex32_64
    lea rsi, [rel http_page_c]
    call legacy_http_append_cstr64
    mov eax, [rel http_count_backoff]
    call legacy_http_append_hex32_64
    lea rsi, [rel http_page_d]
    call legacy_http_append_cstr64
    mov eax, [rel http_count_fatal]
    call legacy_http_append_hex32_64
    lea rsi, [rel http_page_e]
    call legacy_http_append_cstr64
    mov eax, [rel shard_total_global]
    call legacy_http_append_hex32_64
    lea rsi, [rel http_page_f]
    call legacy_http_append_cstr64
    mov eax, [rel shard_local_start]
    call legacy_http_append_hex32_64
    lea rsi, [rel http_page_g]
    call legacy_http_append_cstr64
    mov eax, [rel shard_local_count]
    call legacy_http_append_hex32_64
    lea rsi, [rel http_page_h]
    call legacy_http_append_cstr64
    mov eax, [rel http_hits]
    call legacy_http_append_hex32_64
    lea rsi, [rel http_page_i]
    call legacy_http_append_cstr64
    mov eax, [rel ap_online_count]
    call legacy_http_append_hex32_64
    lea rsi, [rel http_page_rows]
    call legacy_http_append_cstr64

    xor ebx, ebx
.rows:
    cmp ebx, [rel shard_active_count]
    jae .rows_done
    mov ecx, ebx
    call legacy_shards_get_ctx64
    test rax, rax
    jz .rows_done
    mov r12, rax

    lea rsi, [rel http_row_a]
    call legacy_http_append_cstr64
    mov eax, [r12 + SHARD_OFF_ID]
    call legacy_http_append_hex32_64
    lea rsi, [rel http_row_b]
    call legacy_http_append_cstr64
    mov eax, [r12 + SHARD_OFF_STATE]
    call legacy_http_append_hex32_64
    lea rsi, [rel http_row_c]
    call legacy_http_append_cstr64
    mov r13, [r12 + SHARD_OFF_TCP_CTX]
    xor eax, eax
    test r13, r13
    jz .tcp
    mov eax, [r13 + STCP_STATE]
.tcp:
    call legacy_http_append_hex32_64
    lea rsi, [rel http_row_d]
    call legacy_http_append_cstr64
    mov r13, [r12 + SHARD_OFF_TLS_CTX]
    xor eax, eax
    test r13, r13
    jz .tls
    mov eax, [r13]
.tls:
    call legacy_http_append_hex32_64
    lea rsi, [rel http_row_e]
    call legacy_http_append_cstr64
    mov eax, [r12 + SHARD_OFF_HEARTBEATS_SENT]
    call legacy_http_append_hex32_64
    lea rsi, [rel http_row_f]
    call legacy_http_append_cstr64
    mov eax, [r12 + SHARD_OFF_HEARTBEAT_ACKS]
    call legacy_http_append_hex32_64
    lea rsi, [rel http_row_g]
    call legacy_http_append_cstr64
    mov eax, [r12 + SHARD_OFF_LAST_ERROR]
    call legacy_http_append_hex32_64
    lea rsi, [rel http_row_h]
    call legacy_http_append_cstr64

    inc ebx
    jmp .rows
.rows_done:
    lea rsi, [rel http_page_end]
    call legacy_http_append_cstr64

    mov rax, [rel http_build_ptr]
    sub rax, [rel http_body_ptr]
    mov [rel http_response_len], eax
    jmp .built
.no_body:
    mov dword [rel http_response_len], 0
.built:
    pop r13
    pop r12
    pop rbx
    ret

legacy_http_send_page64:
    push rbx
    push r12

    inc dword [rel http_hits]
    call legacy_http_build_page64

    lea rcx, [rel http_header]
    mov edx, http_header_end-http_header
    mov r8d, 0x18
    call legacy_http_send_segment64

    mov r12, [rel http_body_ptr]
    test r12, r12
    jz .fin
    mov ebx, [rel http_response_len]
.loop:
    test ebx, ebx
    jz .fin
    mov edx, ebx
    cmp edx, HTTP_TX_CHUNK
    jbe .send
    mov edx, HTTP_TX_CHUNK
.send:
    mov rcx, r12
    mov r8d, 0x18
    push rdx
    call legacy_http_send_segment64
    pop rdx
    add r12, rdx
    sub ebx, edx
    jmp .loop
.fin:
    xor ecx, ecx
    xor edx, edx
    mov r8d, 0x11
    call legacy_http_send_segment64
    mov dword [rel http_state], HTTP_STATE_IDLE

    pop r12
    pop rbx
    ret

; rcx=tcp bytes, edx=len, r8d=source ipv4.
legacy_http_tcp_rx64:
    push rbx
    push r12
    push r13
    push r14
    mov r12, rcx
    mov r13d, edx
    mov r14d, r8d

    cmp r13d, 20
    jb .done
    lea rcx, [r12+2]
    call legacy_tcp_load_be16
    cmp eax, HTTP_SERVER_PORT
    jne .done

   ; source port
    mov rcx, r12
    call legacy_tcp_load_be16
    mov ebx, eax

   ; accept new syn, replacing any stale connection
    test byte [r12+13], 0x02
    jz .existing
    mov [rel http_remote_ip], r14d
    mov [rel http_remote_port], ebx
    lea rcx, [r12+4]
    call legacy_tcp_load_be32
    inc eax
    mov [rel http_remote_seq], eax
    rdtsc
    xor eax, edx
    test eax, eax
    jnz .seq_ok
    mov eax, 0x48545450
.seq_ok:
    mov [rel http_local_seq], eax
    mov dword [rel http_state], HTTP_STATE_UP
    xor ecx, ecx
    xor edx, edx
    mov r8d, 0x12
    call legacy_http_send_segment64
    jmp .done

.existing:
    cmp dword [rel http_state], HTTP_STATE_UP
    jne .done
    cmp r14d, [rel http_remote_ip]
    jne .done
    cmp ebx, [rel http_remote_port]
    jne .done

    mov rcx, r12
    mov edx, r13d
    call legacy_http_tcp_checksum64
    test ax, ax
    jnz .done

    movzx ebx, byte [r12+12]
    shr ebx, 4
    cmp ebx, 5
    jb .done
    shl ebx, 2
    cmp ebx, r13d
    ja .done

    test byte [r12+13], 0x04
    jz .seq
    mov dword [rel http_state], HTTP_STATE_IDLE
    jmp .done
.seq:
    lea rcx, [r12+4]
    call legacy_tcp_load_be32
    cmp eax, [rel http_remote_seq]
    jne .ack

    mov eax, r13d
    sub eax, ebx
    jbe .fin_check
    add [rel http_remote_seq], eax

   ; serve the same local status page for every get path.
    lea rsi, [r12+rbx]
    cmp eax, 4
    jb .ack
    cmp byte [rsi], 'G'
    jne .ack
    cmp byte [rsi+1], 'E'
    jne .ack
    cmp byte [rsi+2], 'T'
    jne .ack
    cmp byte [rsi+3], ' '
    jne .ack
    call legacy_http_send_page64
    jmp .done

.fin_check:
    test byte [r12+13], 0x01
    jz .done
    inc dword [rel http_remote_seq]
    call legacy_http_send_ack64
    mov dword [rel http_state], HTTP_STATE_IDLE
    jmp .done
.ack:
    call legacy_http_send_ack64
.done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

align 16
http_state          dd 0
http_remote_ip      dd 0
http_remote_port    dd 0
http_local_seq      dd 0
http_remote_seq     dd 0
http_hits           dd 0
http_response_len   dd 0
http_count_ready    dd 0
http_count_starting dd 0
http_count_backoff  dd 0
http_count_fatal    dd 0
http_build_ptr      dq 0
http_build_end      dq 0
http_body_ptr       dq 0

http_header:
    db 'HTTP/1.0 200 OK',13,10
    db 'Content-Type: text/html; charset=utf-8',13,10
    db 'Cache-Control: no-store',13,10
    db 'Connection: close',13,10,13,10
http_header_end:

http_page_a db '<!doctype html><html><head><meta http-equiv="refresh" content="3"><title>DISCORD-PXE // SYSTEM STATUS</title></head><body bgcolor="#008080" text="#000000"><font face="Tahoma,Arial,Courier New"><center><table width="96%" border="2" cellpadding="0" cellspacing="0" bgcolor="#C0C0C0"><tr bgcolor="#000080"><td><font color="#FFFFFF"><b>&nbsp; DISCORD-PXE CONTROL PANEL</b></font></td></tr><tr><td><marquee scrollamount="3">BARE METAL DISCORD GATEWAY // NO OS // NO FRAMEWORK // JUST QUESTIONABLE DECISIONS</marquee></td></tr></table><p><table width="96%" border="2" cellpadding="6" bgcolor="#C0C0C0"><tr><td><b>Gateway health</b><br><table width="100%" border="1" cellpadding="4" bgcolor="#FFFFFF"><tr><th>READY</th><th>STARTING</th><th>BACKOFF</th><th>FATAL</th></tr><tr align="center"><td><font color="#008000"><b>0x',0
http_page_b db '</b></font></td><td>0x',0
http_page_c db '</td><td><font color="#808000">0x',0
http_page_d db '</font></td><td><font color="#800000"><b>0x',0
http_page_e db '</b></font></td></tr></table></td></tr><tr><td><b>TOTAL:</b> 0x',0
http_page_f db ' &nbsp; <b>LOCAL START:</b> 0x',0
http_page_g db ' &nbsp; <b>LOCAL COUNT:</b> 0x',0
http_page_h db ' &nbsp; <b>PAGE HITS:</b> 0x',0
http_page_i db ' &nbsp; <b>CPUS ONLINE:</b> 0x',0
http_page_rows db '</td></tr></table><p><table width="96%" border="2" cellpadding="3" bgcolor="#FFFFFF"><tr bgcolor="#C0C0C0"><th>SHARD</th><th>STATE</th><th>TCP</th><th>TLS</th><th>HEARTBEATS</th><th>ACKS</th><th>LAST ERR</th></tr>',0
http_row_a db '<tr align="center"><td>0x',0
http_row_b db '</td><td>0x',0
http_row_c db '</td><td>0x',0
http_row_d db '</td><td>0x',0
http_row_e db '</td><td>0x',0
http_row_f db '</td><td>0x',0
http_row_g db '</td><td>0x',0
http_row_h db '</td></tr>',0
http_page_end db '</table><p><table width="96%" border="2" bgcolor="#C0C0C0" cellpadding="5"><tr><td><font size="-1">STATE 3=READY &nbsp; TCP 3=UP &nbsp; TLS 4=UP &nbsp; auto-refresh 3s &nbsp; served directly by x86-64 assembly</font></td></tr></table></center></font></body></html>',0

msg_http_ready db '[HTTP] bare-metal panel ready at http://',0
msg_http_ready_port db ':8080/',13,10,0
msg_http_mem_fail db '[HTTP] panel disabled: no RAM for response buffer',13,10,0
