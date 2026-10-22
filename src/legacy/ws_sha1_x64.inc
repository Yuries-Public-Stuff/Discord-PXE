; sha1 used only for the websocket accept check input is always the 24 byte key plus the
; 36 byte websocket guid

section .bss align=16
ws_sha1_h      resd 5
ws_sha1_w      resd 80
ws_sha1_block  resb 64

section .text
ws_sha1_transform_x64:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    mov rsi,rcx
    mov rdi,rdx
    lea r11,[rel ws_sha1_w]
    xor ecx,ecx
.load:
    cmp ecx,16
    jae .expand
    movzx eax,byte [rdi+rcx*4]
    shl eax,24
    movzx edx,byte [rdi+rcx*4+1]
    shl edx,16
    or eax,edx
    movzx edx,byte [rdi+rcx*4+2]
    shl edx,8
    or eax,edx
    movzx edx,byte [rdi+rcx*4+3]
    or eax,edx
    mov [r11+rcx*4],eax
    inc ecx
    jmp .load
.expand:
    cmp ecx,80
    jae .work
    mov eax,[r11+rcx*4-12]
    xor eax,[r11+rcx*4-32]
    xor eax,[r11+rcx*4-56]
    xor eax,[r11+rcx*4-64]
    rol eax,1
    mov [r11+rcx*4],eax
    inc ecx
    jmp .expand
.work:
    mov r12d,[rsi+0]
    mov r13d,[rsi+4]
    mov r14d,[rsi+8]
    mov r15d,[rsi+12]
    mov ebx,[rsi+16]
    xor ecx,ecx
.round:
    cmp ecx,80
    jae .finish
    cmp ecx,20
    jb .r0
    cmp ecx,40
    jb .r1
    cmp ecx,60
    jb .r2
    mov eax,r13d
    xor eax,r14d
    xor eax,r15d
    mov edx,0CA62C1D6h
    jmp .mix
.r0:
    mov eax,r13d
    and eax,r14d
    mov edx,r13d
    not edx
    and edx,r15d
    or eax,edx
    mov edx,05A827999h
    jmp .mix
.r1:
    mov eax,r13d
    xor eax,r14d
    xor eax,r15d
    mov edx,06ED9EBA1h
    jmp .mix
.r2:
    mov eax,r13d
    and eax,r14d
    mov edx,r13d
    and edx,r15d
    or eax,edx
    mov r8d,r14d
    and r8d,r15d
    or eax,r8d
    mov edx,08F1BBCDCh
.mix:
    mov r8d,r12d
    rol r8d,5
    add eax,r8d
    add eax,ebx
    add eax,edx
    add eax,[r11+rcx*4]
    mov ebx,r15d
    mov r15d,r14d
    mov r14d,r13d
    ror r14d,2
    mov r13d,r12d
    mov r12d,eax
    inc ecx
    jmp .round
.finish:
    add [rsi+0],r12d
    add [rsi+4],r13d
    add [rsi+8],r14d
    add [rsi+12],r15d
    add [rsi+16],ebx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

ws_sha1_60_x64:
    push rbx
    push rsi
    push rdi
    mov rsi,rcx
    mov rdi,rdx
    mov dword [rel ws_sha1_h+0],067452301h
    mov dword [rel ws_sha1_h+4],0EFCDAB89h
    mov dword [rel ws_sha1_h+8],098BADCFEh
    mov dword [rel ws_sha1_h+12],010325476h
    mov dword [rel ws_sha1_h+16],0C3D2E1F0h
    lea r10,[rel ws_sha1_block]
    xor eax,eax
    mov ecx,8
.clear0:
    mov [r10],rax
    add r10,8
    dec ecx
    jnz .clear0
    lea r10,[rel ws_sha1_block]
    xor ecx,ecx
.cp60:
    cmp ecx,60
    jae .pad0
    mov al,[rsi+rcx]
    mov [r10+rcx],al
    inc ecx
    jmp .cp60
.pad0:
    mov byte [r10+60],080h
    lea rcx,[rel ws_sha1_h]
    lea rdx,[rel ws_sha1_block]
    sub rsp,32
    call ws_sha1_transform_x64
    add rsp,32
    lea r10,[rel ws_sha1_block]
    xor eax,eax
    mov ecx,8
.clear1:
    mov [r10],rax
    add r10,8
    dec ecx
    jnz .clear1
    mov byte [rel ws_sha1_block+62],01h
    mov byte [rel ws_sha1_block+63],0E0h
    lea rcx,[rel ws_sha1_h]
    lea rdx,[rel ws_sha1_block]
    sub rsp,32
    call ws_sha1_transform_x64
    add rsp,32
    lea rsi,[rel ws_sha1_h]
    xor ecx,ecx
.out:
    cmp ecx,5
    jae .done
    mov eax,[rsi+rcx*4]
    bswap eax
    mov [rdi+rcx*4],eax
    inc ecx
    jmp .out
.done:
    xor eax,eax
    pop rdi
    pop rsi
    pop rbx
    ret
