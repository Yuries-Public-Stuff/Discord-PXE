; tiny shell for serial and keyboard control keep commands simple so crashes are easy to
; pin down on real hardware

BITS 64

%define SHELL_LINE_MAX 128

legacy_shell_init64:
    mov dword [rel shell_len], 0
    lea rsi, [rel msg_shell_ready]
    call serial_puts64
    call legacy_shell_prompt64
    ret

legacy_shell_tick64:
    mov dword [rel shell_console_owned], 1
    call legacy_input_poll64
.next:
    call legacy_input_getc64
    jnc .done

    cmp al, 13
    je .enter
    cmp al, 10
    jne .not_lf
   ; some serial terminals send lf-only for enter. treat it as enter when a line is pending,
   ; but ignore the lf half of a normal crlf pair.
    cmp dword [rel shell_len], 0
    je .next
    jmp .enter
.not_lf:
    cmp al, 8
    je .backspace
    cmp al, 32
    jb .next
    cmp al, 126
    ja .next

    mov ecx, [rel shell_len]
    cmp ecx, SHELL_LINE_MAX-1
    jae .next
    lea rdx, [rel shell_line]
    mov [rdx+rcx], al
    inc ecx
    mov [rel shell_len], ecx
    mov byte [rdx+rcx], 0
    call serial_putc64_al
    jmp .next
.backspace:
    cmp dword [rel shell_len], 0
    je .next
    dec dword [rel shell_len]
    lea rdx, [rel shell_line]
    mov ecx, [rel shell_len]
    mov byte [rdx+rcx], 0
    mov al, 8
    call serial_putc64_al
    mov al, ' '
    call serial_putc64_al
    mov al, 8
    call serial_putc64_al
    jmp .next
.enter:
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    call legacy_shell_exec64
    mov dword [rel shell_len], 0
    mov byte [rel shell_line], 0
    call legacy_shell_prompt64
    jmp .next
.done:
    mov dword [rel shell_console_owned], 0
    ret

legacy_shell_prompt64:
    lea rsi, [rel msg_shell_prompt]
    call serial_puts64
    ret

; eax=1 while the operator is typing (or the first serial/key byte is waiting). live
; telemetry uses this to stay out of the interactive command line.
legacy_shell_input_busy64:
    cmp dword [rel shell_len], 0
    jne .busy

    mov eax, [rel input_head]
    cmp eax, [rel input_tail]
    jne .busy

   ; catch a com1 keystroke before legacy_shell_tick64 has drained it into the input ring.
   ; this matters because the main loop emits the serial beacon before polling shell input.
    movzx edx, word [rel input_uart1]
    test dx, dx
    jz .check_kbd
    add dx, 5
    in al, dx
    test al, 1
    jnz .busy

.check_kbd:
   ; likewise, do not print over the first pending keyboard byte.
    in al, 0x64
    test al, 1
    jnz .busy

    xor eax, eax
    ret
.busy:
    mov eax, 1
    ret

legacy_shell_exec64:
    lea rcx, [rel shell_line]
    call legacy_shell_skip_spaces64
    mov rbx, rax
    cmp byte [rbx], 0
    je .done

    mov rcx, rbx
    lea rdx, [rel cmd_help]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .help

    mov rcx, rbx
    lea rdx, [rel cmd_cpu]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .cpu

    mov rcx, rbx
    lea rdx, [rel cmd_mem]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .mem

    mov rcx, rbx
    lea rdx, [rel cmd_memmap]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .memmap

    mov rcx, rbx
    lea rdx, [rel cmd_pci]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .pci

    mov rcx, rbx
    lea rdx, [rel cmd_net]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .net

    mov rcx, rbx
    lea rdx, [rel cmd_stats]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .stats

    mov rcx, rbx
    lea rdx, [rel cmd_input]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .input

    mov rcx, rbx
    lea rdx, [rel cmd_ls]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .ls

    mov rcx, rbx
    lea rdx, [rel cmd_cat]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .cat

    mov rcx, rbx
    lea rdx, [rel cmd_fetch]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .fetch

    mov rcx, rbx
    lea rdx, [rel cmd_fcat]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .fcat

    mov rcx, rbx
    lea rdx, [rel cmd_hex]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .hex

    mov rcx, rbx
    lea rdx, [rel cmd_discord]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .discord

    mov rcx, rbx
    lea rdx, [rel cmd_pxe]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .pxe

    mov rcx, rbx
    lea rdx, [rel cmd_config]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .config

    mov rcx, rbx
    lea rdx, [rel cmd_reboot]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .reboot

    mov rcx, rbx
    lea rdx, [rel cmd_restart]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .reboot

    mov rcx, rbx
    lea rdx, [rel cmd_seriallive]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .seriallive

    mov rcx, rbx
    lea rdx, [rel cmd_shards]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .shards

    mov rcx, rbx
    lea rdx, [rel cmd_shardstart]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .shardstart

    mov rcx, rbx
    lea rdx, [rel cmd_shardstop]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .shardstop

    mov rcx, rbx
    lea rdx, [rel cmd_shardplan]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .shardplan

    mov rcx, rbx
    lea rdx, [rel cmd_shardreset]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .shardreset

    mov rcx, rbx
    lea rdx, [rel cmd_shardlease]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .shardlease

    mov rcx, rbx
    lea rdx, [rel cmd_shardtest2]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .shardtest2

    mov rcx, rbx
    lea rdx, [rel cmd_shardteststatus]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .shardteststatus

    lea rsi, [rel msg_shell_unknown]
    call serial_puts64
    jmp .done
.help:
    lea rsi, [rel msg_shell_help]
    call serial_puts64
    jmp .done
.cpu:
    lea rcx, [rel path_cpu]
    call legacy_vfs_cat64
    jmp .done
.mem:
    lea rcx, [rel path_mem]
    call legacy_vfs_cat64
    jmp .done
.memmap:
    lea rcx, [rel path_e820]
    call legacy_vfs_cat64
    jmp .done
.pci:
    lea rcx, [rel path_pci]
    call legacy_vfs_cat64
    jmp .done
.net:
    lea rcx, [rel path_net]
    call legacy_vfs_cat64
    jmp .done
.stats:
    lea rcx, [rel path_netstats]
    call legacy_vfs_cat64
    jmp .done
.input:
    call legacy_input_status64
    jmp .done
.ls:
    call legacy_vfs_ls64
    jmp .done
.cat:
    mov rcx, rbx
    call legacy_shell_after_word64
    mov rcx, rax
    call legacy_shell_skip_spaces64
    mov rcx, rax
    cmp byte [rcx], 0
    je .cat_help
    call legacy_vfs_cat64
    jmp .done
.fetch:
    mov rcx, rbx
    call legacy_shell_after_word64
    mov rcx, rax
    call legacy_shell_skip_spaces64
    mov rcx, rax
    cmp byte [rcx], 0
    je .fetch_help
    call legacy_tftp_fetch64
    jmp .done
.fcat:
    call legacy_tftp_cat64
    jmp .done
.hex:
    call legacy_tftp_hex64
    jmp .done
.cat_help:
    lea rsi, [rel msg_shell_cat]
    call serial_puts64
    jmp .done
.fetch_help:
    lea rsi, [rel msg_shell_fetch]
    call serial_puts64
    jmp .done
.discord:
    lea rcx, [rel path_discord]
    call legacy_vfs_cat64
    jmp .done
.pxe:
    lea rcx, [rel path_pxe]
    call legacy_vfs_cat64
    jmp .done
.reboot:
    lea rsi, [rel msg_shell_reboot]
    call serial_puts64

   ; first use the classic 8042 cpu reset pulse. this is the best match for the legacy compaq
   ; hardware this runtime targets.
    mov ecx, 0x10000
.wait_kbc:
    in al, 0x64
    test al, 2
    jz .kbc_reset
    dec ecx
    jnz .wait_kbc
    jmp .triple_fault
.kbc_reset:
    mov al, 0xFE
    out 0x64, al

   ; give reset a moment to assert. if the controller ignores the pulse, deliberately
   ; triple-fault as a hardware reset fallback.
    mov ecx, 0x100000
.reset_wait:
    pause
    dec ecx
    jnz .reset_wait
.triple_fault:
    cli
    lidt [rel reboot_null_idtr]
    int 3
.reboot_hang:
    hlt
    jmp .reboot_hang

.config:
    mov rcx, rbx
    call legacy_shell_after_word64
    mov rcx, rax
    call legacy_shell_skip_spaces64
    mov r12, rax
    cmp byte [r12], 0
    je .config_status

    mov rcx, r12
    lea rdx, [rel cmd_reload]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .config_reload

    lea rsi, [rel msg_shell_config_usage]
    call serial_puts64
    jmp .done
.config_status:
    call legacy_config_status64
    jmp .done
.config_reload:
    lea rsi, [rel msg_shell_config_reload]
    call serial_puts64
    call legacy_config_load64
    jmp .done
.seriallive:
    mov rcx, rbx
    call legacy_shell_after_word64
    mov rcx, rax
    call legacy_shell_skip_spaces64
    mov r12, rax
    cmp byte [r12], 0
    je .seriallive_status

    mov rcx, r12
    lea rdx, [rel cmd_on]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .seriallive_on

    mov rcx, r12
    lea rdx, [rel cmd_off]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .seriallive_off

    mov rcx, r12
    lea rdx, [rel cmd_status]
    call legacy_shell_word_eq64
    test eax, eax
    jnz .seriallive_status

    lea rsi, [rel msg_shell_seriallive]
    call serial_puts64
    jmp .done
.seriallive_on:
    call serial_live_enable64
    jmp .done
.seriallive_off:
    call serial_live_disable64
    jmp .done
.seriallive_status:
    call serial_live_status64
    jmp .done

.shards:
    call legacy_shards_print64
    jmp .done
.shardstart:
    call legacy_shards_start_network64
    jmp .done
.shardstop:
    call legacy_shards_stop_network64
    jmp .done
.shardplan:
    mov rcx, rbx
    call legacy_shell_after_word64
    mov rcx, rax
    call legacy_shards_configure_text64
    jmp .done
.shardreset:
    mov rcx, rbx
    call legacy_shell_after_word64
    mov rcx, rax
    call legacy_shards_reset_text64
    jmp .done
.shardlease:
    mov rcx, rbx
    call legacy_shell_after_word64
    mov rcx, rax
    call legacy_shards_lease_text64
    jmp .done
.shardtest2:
    call legacy_shards_test2_64
    jmp .done
.shardteststatus:
    call legacy_shards_test_status64
.done:
    ret

legacy_shell_skip_spaces64:
    mov rax, rcx
.loop:
    cmp byte [rax], ' '
    jne .done
    inc rax
    jmp .loop
.done:
    ret

legacy_shell_after_word64:
    mov rax, rcx
.loop:
    mov dl, [rax]
    test dl, dl
    jz .done
    cmp dl, ' '
    je .done
    inc rax
    jmp .loop
.done:
    ret

; match one command word without caring what comes after the space
legacy_shell_word_eq64:
.loop:
    mov al, [rdx]
    test al, al
    jz .end_cmd
    cmp al, [rcx]
    jne .no
    inc rcx
    inc rdx
    jmp .loop
.end_cmd:
    mov al, [rcx]
    test al, al
    jz .yes
    cmp al, ' '
    je .yes
.no:
    xor eax, eax
    ret
.yes:
    mov eax, 1
    ret

align 16
shell_line times SHELL_LINE_MAX db 0
shell_len dd 0
shell_console_owned dd 0

cmd_help    db 'help',0
cmd_cpu     db 'cpu',0
cmd_mem     db 'mem',0
cmd_memmap  db 'memmap',0
cmd_pci     db 'pci',0
cmd_net     db 'net',0
cmd_stats   db 'stats',0
cmd_input   db 'input',0
cmd_ls      db 'ls',0
cmd_cat     db 'cat',0
cmd_fetch   db 'fetch',0
cmd_fcat    db 'fcat',0
cmd_hex     db 'hex',0
cmd_discord db 'discord',0
cmd_pxe     db 'pxe',0
cmd_config  db 'config',0
cmd_reboot  db 'reboot',0
cmd_restart db 'restart',0
cmd_reload  db 'reload',0
cmd_seriallive db 'seriallive',0
cmd_on db 'on',0
cmd_off db 'off',0
cmd_status db 'status',0
cmd_shards  db 'shards',0
cmd_shardstart db 'shardstart',0
cmd_shardstop  db 'shardstop',0
cmd_shardplan  db 'shardplan',0
cmd_shardreset db 'shardreset',0
cmd_shardlease db 'shardlease',0
cmd_shardtest2 db 'shardtest2',0
cmd_shardteststatus db 'shardteststatus',0

msg_shell_ready   db '[SHELL] serial + keyboard shell ready',13,10,'[SHELL] commands: reboot/restart installed',13,10,0
msg_shell_prompt  db 'pxe> ',0
msg_shell_unknown db 'unknown command, type help',13,10,0
msg_shell_cat     db 'usage: cat <file>, use ls to see files',13,10,0
msg_shell_fetch   db 'usage: fetch <pxe filename>',13,10,0
msg_shell_config_reload db '[CONFIG] manual TFTP reload started',13,10,0
msg_shell_config_usage db 'usage: config [reload]',13,10,0
msg_shell_help    db 'help  cpu  mem  memmap  pci  net  stats  input  pxe  ls  cat <file>',13,10,'fetch <file>  fcat  hex  discord  config  reboot  restart  seriallive  shards  shardplan',13,10,'shardreset  shardlease  shardstart  shardstop  shardtest2  shardteststatus',13,10,0
msg_shell_seriallive db 'usage: seriallive [on|off|status]',13,10,0

align 8
reboot_null_idtr:
    dw 0
    dq 0
msg_shell_reboot db '[REBOOT] resetting machine now',13,10,0
