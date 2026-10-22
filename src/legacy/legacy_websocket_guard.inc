; do not send the websocket upgrade twice tls and discord can both ask for it so the first
; one wins

BITS 64

legacy_ws_start64:
    cmp dword [rel ws_ready], 1
    je .ok
    call legacy_ws_start64_raw
    ret
.ok:
    xor eax, eax
    ret
