; callback mode does not need a second copy of the whole tcp stream clear the debug buffer
; after delivery so long discord sessions do not fill it

BITS 64

legacy_tcp_rx64:
    call legacy_tcp_rx64_reliable_old
    cmp qword [rel legacy_tcp_rx_cb], 0
    je .done
    mov dword [rel legacy_tcp_rx_len], 0
.done:
    ret
