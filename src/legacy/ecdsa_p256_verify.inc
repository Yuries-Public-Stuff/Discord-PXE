; minimal p-256 ecdsa/sha-256 verifier for x.509 issuer signatures. flat,
; allocation-free, little-endian 8x32-bit limbs. slow but only used once during certificate

BITS 64

%define P256_LIMBS 8

section .data align=16
p256_prime dd 0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0x00000000,0x00000000,0x00000000,0x00000001,0xFFFFFFFF
p256_prime_minus2 dd 0xFFFFFFFD,0xFFFFFFFF,0xFFFFFFFF,0x00000000,0x00000000,0x00000000,0x00000001,0xFFFFFFFF
p256_order dd 0xFC632551,0xF3B9CAC2,0xA7179E84,0xBCE6FAAD,0xFFFFFFFF,0xFFFFFFFF,0x00000000,0xFFFFFFFF
p256_order_minus2 dd 0xFC63254F,0xF3B9CAC2,0xA7179E84,0xBCE6FAAD,0xFFFFFFFF,0xFFFFFFFF,0x00000000,0xFFFFFFFF
p256_gx dd 0xD898C296,0xF4A13945,0x2DEB33A0,0x77037D81,0x63A440F2,0xF8BCE6E5,0xE12C4247,0x6B17D1F2
p256_gy dd 0x37BF51F5,0xCBB64068,0x6B315ECE,0x2BCE3357,0x7C0F9E16,0x8EE7EB4A,0xFE1A7F9B,0x4FE342E2
p256_one dd 1,0,0,0,0,0,0,0
p256_mod_ptr dq 0

section .bss align=16
p256_add_tmp resd 8
p256_mul_a resd 8
p256_mul_b resd 8
p256_mul_acc resd 8
p256_mul_tmp resd 8
p256_inv_base resd 8
p256_inv_acc resd 8

p256_t0 resd 8
p256_t1 resd 8
p256_t2 resd 8
p256_t3 resd 8
p256_t4 resd 8
p256_t5 resd 8
p256_t6 resd 8
p256_t7 resd 8
p256_t8 resd 8
p256_t9 resd 8
p256_t10 resd 8
p256_t11 resd 8

p256_work_x resd 8
p256_work_y resd 8
p256_work_z resd 8
p256_q_x resd 8
p256_q_y resd 8
p256_q_z resd 8
p256_out_x resd 8
p256_out_y resd 8
p256_out_z resd 8
p256_p1_x resd 8
p256_p1_y resd 8
p256_p1_z resd 8
p256_p2_x resd 8
p256_p2_y resd 8
p256_p2_z resd 8

p256_pub_x resd 8
p256_pub_y resd 8
p256_sig_r resd 8
p256_sig_s resd 8
p256_hash_z resd 8
p256_w resd 8
p256_u1 resd 8
p256_u2 resd 8
p256_x_aff resd 8

section .text

; rcx=dst, rdx=src
p256_copy:
    push rax
    mov rax,[rdx+0]
    mov [rcx+0],rax
    mov rax,[rdx+8]
    mov [rcx+8],rax
    mov rax,[rdx+16]
    mov [rcx+16],rax
    mov rax,[rdx+24]
    mov [rcx+24],rax
    pop rax
    ret

; rcx=dst
p256_zero:
    xor eax,eax
    mov [rcx+0],rax
    mov [rcx+8],rax
    mov [rcx+16],rax
    mov [rcx+24],rax
    ret

; rcx=a -> eax 1 if zero
p256_is_zero:
    mov rax,[rcx+0]
    or rax,[rcx+8]
    or rax,[rcx+16]
    or rax,[rcx+24]
    sete al
    movzx eax,al
    ret

; rcx=a, rdx=b -> eax 1 if a>=b
p256_ge:
    mov eax,[rcx+28]
    cmp eax,[rdx+28]
    ja .yes
    jb .no
    mov eax,[rcx+24]
    cmp eax,[rdx+24]
    ja .yes
    jb .no
    mov eax,[rcx+20]
    cmp eax,[rdx+20]
    ja .yes
    jb .no
    mov eax,[rcx+16]
    cmp eax,[rdx+16]
    ja .yes
    jb .no
    mov eax,[rcx+12]
    cmp eax,[rdx+12]
    ja .yes
    jb .no
    mov eax,[rcx+8]
    cmp eax,[rdx+8]
    ja .yes
    jb .no
    mov eax,[rcx+4]
    cmp eax,[rdx+4]
    ja .yes
    jb .no
    mov eax,[rcx]
    cmp eax,[rdx]
    jae .yes
.no:
    xor eax,eax
    ret
.yes:
    mov eax,1
    ret

; rcx=dst, rdx=a, r8=b. raw subtract mod 2^256.
p256_sub_raw:
    push rbx
    push rsi
    push rdi
    mov rdi,rcx
    mov rsi,rdx
    mov rbx,r8
    xor r9d,r9d
    xor r10d,r10d
    lea r11,[rel p256_add_tmp]
.loop:
    mov eax,[rsi+r9*4]
    mov edx,[rbx+r9*4]
    movzx r11,r10b
    add rdx,r11
    cmp rax,rdx
    setb r10b
    sub rax,rdx
    mov [rdi+r9*4],eax
    inc r9d
    cmp r9d,8
    jb .loop
    movzx eax,r10b
    pop rdi
    pop rsi
    pop rbx
    ret

; rcx=dst, rdx=a, r8=b, modulus=[p256_mod_ptr]
p256_add_mod:
    push rbx
    push rsi
    push rdi
    push r12
    mov rdi,rcx
    mov rsi,rdx
    mov rbx,r8
    xor r9d,r9d
    xor r10d,r10d
.loop:
    mov eax,[rsi+r9*4]
    mov edx,[rbx+r9*4]
    add rax,rdx
    add rax,r10
    mov [r11+r9*4],eax
    shr rax,32
    mov r10d,eax
    inc r9d
    cmp r9d,8
    jb .loop
    mov r12,[rel p256_mod_ptr]
    test r10d,r10d
    jnz .subtract
    lea rcx,[rel p256_add_tmp]
    mov rdx,r12
    call p256_ge
    test eax,eax
    jz .copy
.subtract:
    lea rcx,[rel p256_add_tmp]
    lea rdx,[rel p256_add_tmp]
    mov r8,r12
    call p256_sub_raw
.copy:
    mov rcx,rdi
    lea rdx,[rel p256_add_tmp]
    call p256_copy
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; rcx=dst, rdx=a, r8=b. raw add mod 2^256.
p256_add_raw:
    push rbx
    push rsi
    push rdi
    mov rdi,rcx
    mov rsi,rdx
    mov rbx,r8
    xor r9d,r9d
    xor r10d,r10d
.loop:
    mov eax,[rsi+r9*4]
    mov edx,[rbx+r9*4]
    add rax,rdx
    add rax,r10
    mov [rdi+r9*4],eax
    shr rax,32
    mov r10d,eax
    inc r9d
    cmp r9d,8
    jb .loop
    mov eax,r10d
    pop rdi
    pop rsi
    pop rbx
    ret

; rcx=dst, rdx=a, r8=b
p256_sub_mod:
    push rdi
    push r12
    mov rdi,rcx
    lea rcx,[rel p256_add_tmp]
    call p256_sub_raw
    test eax,eax
    jz .copy
    mov r12,[rel p256_mod_ptr]
    lea rcx,[rel p256_add_tmp]
    lea rdx,[rel p256_add_tmp]
    mov r8,r12
    call p256_add_raw
.copy:
    mov rcx,rdi
    lea rdx,[rel p256_add_tmp]
    call p256_copy
    pop r12
    pop rdi
    ret

; rcx=dst, rdx=a, r8=b
p256_mul_mod:
    push rbx
    push r12
    push r13
    mov r12,rcx
    mov r13,r8
    lea rcx,[rel p256_mul_a]
    call p256_copy
    lea rcx,[rel p256_mul_b]
    mov rdx,r13
    call p256_copy
    lea rcx,[rel p256_mul_acc]
    call p256_zero
    lea rcx,[rel p256_mul_tmp]
    lea rdx,[rel p256_mul_a]
    call p256_copy
    xor ebx,ebx
.loop:
    bt dword [rel p256_mul_b],ebx
    jnc .double
    lea rcx,[rel p256_mul_acc]
    lea rdx,[rel p256_mul_acc]
    lea r8,[rel p256_mul_tmp]
    call p256_add_mod
.double:
    lea rcx,[rel p256_mul_tmp]
    lea rdx,[rel p256_mul_tmp]
    lea r8,[rel p256_mul_tmp]
    call p256_add_mod
    inc ebx
    cmp ebx,256
    jb .loop
    mov rcx,r12
    lea rdx,[rel p256_mul_acc]
    call p256_copy
    pop r13
    pop r12
    pop rbx
    ret

; rcx=dst, rdx=a, r8=exponent (256-bit le)
p256_pow_mod:
    push rbx
    push r12
    push r13
    mov r12,rcx
    mov r13,r8
    lea rcx,[rel p256_inv_base]
    call p256_copy
    lea rcx,[rel p256_inv_acc]
    lea rdx,[rel p256_one]
    call p256_copy
    mov ebx,255
.loop:
    lea rcx,[rel p256_inv_acc]
    lea rdx,[rel p256_inv_acc]
    lea r8,[rel p256_inv_acc]
    call p256_mul_mod
    bt dword [r13],ebx
    jnc .next
    lea rcx,[rel p256_inv_acc]
    lea rdx,[rel p256_inv_acc]
    lea r8,[rel p256_inv_base]
    call p256_mul_mod
.next:
    dec ebx
    jns .loop
    mov rcx,r12
    lea rdx,[rel p256_inv_acc]
    call p256_copy
    pop r13
    pop r12
    pop rbx
    ret

; rcx=dst, rdx=big-endian 32 bytes
p256_import_be32:
    push rbx
    xor ebx,ebx
.loop:
    mov al,[rdx+rbx]
    mov r8d,31
    sub r8d,ebx
    mov [rcx+r8],al
    inc ebx
    cmp ebx,32
    jb .loop
    pop rbx
    ret

; rcx=dst, rdx=der integer payload, r8d=len. returns eax 0 on success.
p256_import_der_int:
    push rbx
    push rsi
    push rdi
    mov rdi,rcx
    mov rsi,rdx
    mov ebx,r8d
    cmp ebx,33
    ja .bad
    test ebx,ebx
    jz .bad
    cmp ebx,33
    jne .lenok
    cmp byte [rsi],0
    jne .bad
    inc rsi
    dec ebx
.lenok:
    mov rcx,rdi
    call p256_zero
    xor r9d,r9d
.loop:
    cmp r9d,ebx
    jae .ok
    mov al,[rsi+r9]
    mov r10d,ebx
    dec r10d
    sub r10d,r9d
    mov [rdi+r10],al
    inc r9d
    jmp .loop
.ok:
    xor eax,eax
    jmp .done
.bad:
    mov eax,LEGACY_STATUS_INVALID
.done:
    pop rdi
    pop rsi
    pop rbx
    ret

; point double. rcx/dx/r8 = out x/y/z; r9/r10/r11 = in x/y/z.
p256_point_double:
    push r12
    mov [rel p256_double_outx],rcx
    mov [rel p256_double_outy],rdx
    mov [rel p256_double_outz],r8
    mov [rel p256_double_inx],r9
    mov [rel p256_double_iny],r10
    mov [rel p256_double_inz],r11

    mov rcx,r11
    call p256_is_zero
    test eax,eax
    jz .go
    mov rcx,[rel p256_double_outx]
    call p256_zero
    mov rcx,[rel p256_double_outy]
    lea rdx,[rel p256_one]
    call p256_copy
    mov rcx,[rel p256_double_outz]
    call p256_zero
    jmp .done
.go:
  ; t0=z^2, t1=y^2, t2=x*gamma
    lea rcx,[rel p256_t0]
    mov rdx,[rel p256_double_inz]
    mov r8,rdx
    call p256_mul_mod
    lea rcx,[rel p256_t1]
    mov rdx,[rel p256_double_iny]
    mov r8,rdx
    call p256_mul_mod
    lea rcx,[rel p256_t2]
    mov rdx,[rel p256_double_inx]
    lea r8,[rel p256_t1]
    call p256_mul_mod

  ; alpha=3*(x-z^2)*(x+z^2)
    lea rcx,[rel p256_t3]
    mov rdx,[rel p256_double_inx]
    lea r8,[rel p256_t0]
    call p256_sub_mod
    lea rcx,[rel p256_t4]
    mov rdx,[rel p256_double_inx]
    lea r8,[rel p256_t0]
    call p256_add_mod
    lea rcx,[rel p256_t5]
    lea rdx,[rel p256_t3]
    lea r8,[rel p256_t4]
    call p256_mul_mod
    lea rcx,[rel p256_t6]
    lea rdx,[rel p256_t5]
    lea r8,[rel p256_t5]
    call p256_add_mod
    lea rcx,[rel p256_t5]
    lea rdx,[rel p256_t6]
    lea r8,[rel p256_t5]
    call p256_add_mod

  ; x3=alpha^2-8*beta
    lea rcx,[rel p256_t6]
    lea rdx,[rel p256_t2]
    lea r8,[rel p256_t2]
    call p256_add_mod
    lea rcx,[rel p256_t6]
    lea rdx,[rel p256_t6]
    lea r8,[rel p256_t6]
    call p256_add_mod
    lea rcx,[rel p256_t6]
    lea rdx,[rel p256_t6]
    lea r8,[rel p256_t6]
    call p256_add_mod
    lea rcx,[rel p256_t7]
    lea rdx,[rel p256_t5]
    lea r8,[rel p256_t5]
    call p256_mul_mod
    mov rcx,[rel p256_double_outx]
    lea rdx,[rel p256_t7]
    lea r8,[rel p256_t6]
    call p256_sub_mod

  ; z3=(y+z)^2-gamma-delta
    lea rcx,[rel p256_t7]
    mov rdx,[rel p256_double_iny]
    mov r8,[rel p256_double_inz]
    call p256_add_mod
    lea rcx,[rel p256_t7]
    lea rdx,[rel p256_t7]
    lea r8,[rel p256_t7]
    call p256_mul_mod
    lea rcx,[rel p256_t7]
    lea rdx,[rel p256_t7]
    lea r8,[rel p256_t1]
    call p256_sub_mod
    mov rcx,[rel p256_double_outz]
    lea rdx,[rel p256_t7]
    lea r8,[rel p256_t0]
    call p256_sub_mod

  ; y3=alpha*(4*beta-x3)-8*gamma^2
    lea rcx,[rel p256_t6]
    lea rdx,[rel p256_t2]
    lea r8,[rel p256_t2]
    call p256_add_mod
    lea rcx,[rel p256_t6]
    lea rdx,[rel p256_t6]
    lea r8,[rel p256_t6]
    call p256_add_mod
    lea rcx,[rel p256_t6]
    lea rdx,[rel p256_t6]
    mov r8,[rel p256_double_outx]
    call p256_sub_mod
    lea rcx,[rel p256_t7]
    lea rdx,[rel p256_t5]
    lea r8,[rel p256_t6]
    call p256_mul_mod
    lea rcx,[rel p256_t6]
    lea rdx,[rel p256_t1]
    lea r8,[rel p256_t1]
    call p256_mul_mod
    lea rcx,[rel p256_t6]
    lea rdx,[rel p256_t6]
    lea r8,[rel p256_t6]
    call p256_add_mod
    lea rcx,[rel p256_t6]
    lea rdx,[rel p256_t6]
    lea r8,[rel p256_t6]
    call p256_add_mod
    lea rcx,[rel p256_t6]
    lea rdx,[rel p256_t6]
    lea r8,[rel p256_t6]
    call p256_add_mod
    mov rcx,[rel p256_double_outy]
    lea rdx,[rel p256_t7]
    lea r8,[rel p256_t6]
    call p256_sub_mod
.done:
    pop r12
    ret

; jacobian add. out rcx/rdx/r8, p1 r9/r10/r11, p2 pointers on stack:
; [rsp+40]=x2 [rsp+48]=y2 [rsp+56]=z2 at entry (after return address).
p256_point_add:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rcx
    mov r13,rdx
    mov r14,r8
    mov r15,r9
    mov rbx,r10
    mov [rel p256_arg_x1],r9
    mov [rel p256_arg_y1],r10
    mov [rel p256_arg_z1],r11
  ; 5 pushes + return address: caller's x2/y2/z2 are at +48/+56/+64.
    mov rax,[rsp+48]
    mov [rel p256_arg_x2],rax
    mov rax,[rsp+56]
    mov [rel p256_arg_y2],rax
    mov rax,[rsp+64]
    mov [rel p256_arg_z2],rax

    mov rcx,r11
    call p256_is_zero
    test eax,eax
    jz .check2
    mov rcx,r12
    mov rdx,[rel p256_arg_x2]
    call p256_copy
    mov rcx,r13
    mov rdx,[rel p256_arg_y2]
    call p256_copy
    mov rcx,r14
    mov rdx,[rel p256_arg_z2]
    call p256_copy
    jmp .done
.check2:
    mov rcx,[rel p256_arg_z2]
    call p256_is_zero
    test eax,eax
    jz .go
    mov rcx,r12
    mov rdx,r15
    call p256_copy
    mov rcx,r13
    mov rdx,rbx
    call p256_copy
    mov rcx,r14
    mov rdx,[rel p256_arg_z1]
    call p256_copy
    jmp .done
.go:
  ; z1z1=t0 z2z2=t1
    lea rcx,[rel p256_t0]
    mov rdx,[rel p256_arg_z1]
    mov r8,rdx
    call p256_mul_mod
    lea rcx,[rel p256_t1]
    mov rdx,[rel p256_arg_z2]
    mov r8,rdx
    call p256_mul_mod
  ; u1=t2 u2=t3
    lea rcx,[rel p256_t2]
    mov rdx,r15
    lea r8,[rel p256_t1]
    call p256_mul_mod
    lea rcx,[rel p256_t3]
    mov rdx,[rel p256_arg_x2]
    lea r8,[rel p256_t0]
    call p256_mul_mod
  ; s1=t4, s2=t5
    lea rcx,[rel p256_t4]
    mov rdx,[rel p256_arg_z2]
    lea r8,[rel p256_t1]
    call p256_mul_mod
    lea rcx,[rel p256_t4]
    mov rdx,rbx
    lea r8,[rel p256_t4]
    call p256_mul_mod
    lea rcx,[rel p256_t5]
    mov rdx,[rel p256_arg_z1]
    lea r8,[rel p256_t0]
    call p256_mul_mod
    lea rcx,[rel p256_t5]
    mov rdx,[rel p256_arg_y2]
    lea r8,[rel p256_t5]
    call p256_mul_mod
  ; h=t6, r=t7
    lea rcx,[rel p256_t6]
    lea rdx,[rel p256_t3]
    lea r8,[rel p256_t2]
    call p256_sub_mod
    lea rcx,[rel p256_t7]
    lea rdx,[rel p256_t5]
    lea r8,[rel p256_t4]
    call p256_sub_mod
    lea rcx,[rel p256_t6]
    call p256_is_zero
    test eax,eax
    jz .normal
    lea rcx,[rel p256_t7]
    call p256_is_zero
    test eax,eax
    jz .infinity
  ; p1 == p2
    mov rcx,r12
    mov rdx,r13
    mov r8,r14
    mov r9,[rel p256_arg_x1]
    mov r10,[rel p256_arg_y1]
    mov r11,[rel p256_arg_z1]
    call p256_point_double
    jmp .done
.infinity:
    mov rcx,r12
    call p256_zero
    mov rcx,r13
    lea rdx,[rel p256_one]
    call p256_copy
    mov rcx,r14
    call p256_zero
    jmp .done
.normal:
  ; i=(2h)^2=t8, j=h*i=t9, r=2r=t7, v=u1*i=t10
    lea rcx,[rel p256_t8]
    lea rdx,[rel p256_t6]
    lea r8,[rel p256_t6]
    call p256_add_mod
    lea rcx,[rel p256_t8]
    lea rdx,[rel p256_t8]
    lea r8,[rel p256_t8]
    call p256_mul_mod
    lea rcx,[rel p256_t9]
    lea rdx,[rel p256_t6]
    lea r8,[rel p256_t8]
    call p256_mul_mod
    lea rcx,[rel p256_t7]
    lea rdx,[rel p256_t7]
    lea r8,[rel p256_t7]
    call p256_add_mod
    lea rcx,[rel p256_t10]
    lea rdx,[rel p256_t2]
    lea r8,[rel p256_t8]
    call p256_mul_mod

  ; x3=r^2-j-2v
    lea rcx,[rel p256_t11]
    lea rdx,[rel p256_t7]
    lea r8,[rel p256_t7]
    call p256_mul_mod
    lea rcx,[rel p256_t11]
    lea rdx,[rel p256_t11]
    lea r8,[rel p256_t9]
    call p256_sub_mod
    lea rcx,[rel p256_t8]
    lea rdx,[rel p256_t10]
    lea r8,[rel p256_t10]
    call p256_add_mod
    mov rcx,r12
    lea rdx,[rel p256_t11]
    lea r8,[rel p256_t8]
    call p256_sub_mod

  ; y3=r*(v-x3)-2*s1*j
    lea rcx,[rel p256_t8]
    lea rdx,[rel p256_t10]
    mov r8,r12
    call p256_sub_mod
    lea rcx,[rel p256_t8]
    lea rdx,[rel p256_t7]
    lea r8,[rel p256_t8]
    call p256_mul_mod
    lea rcx,[rel p256_t11]
    lea rdx,[rel p256_t4]
    lea r8,[rel p256_t9]
    call p256_mul_mod
    lea rcx,[rel p256_t11]
    lea rdx,[rel p256_t11]
    lea r8,[rel p256_t11]
    call p256_add_mod
    mov rcx,r13
    lea rdx,[rel p256_t8]
    lea r8,[rel p256_t11]
    call p256_sub_mod

  ; z3=((z1+z2)^2-z1z1-z2z2)*h
    lea rcx,[rel p256_t8]
    mov rdx,[rel p256_arg_z1]
    mov r8,[rel p256_arg_z2]
    call p256_add_mod
    lea rcx,[rel p256_t8]
    lea rdx,[rel p256_t8]
    lea r8,[rel p256_t8]
    call p256_mul_mod
    lea rcx,[rel p256_t8]
    lea rdx,[rel p256_t8]
    lea r8,[rel p256_t0]
    call p256_sub_mod
    lea rcx,[rel p256_t8]
    lea rdx,[rel p256_t8]
    lea r8,[rel p256_t1]
    call p256_sub_mod
    mov rcx,r14
    lea rdx,[rel p256_t8]
    lea r8,[rel p256_t6]
    call p256_mul_mod
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

section .bss align=8
p256_arg_x1 resq 1
p256_arg_y1 resq 1
p256_arg_z1 resq 1
p256_arg_x2 resq 1
p256_arg_y2 resq 1
p256_arg_z2 resq 1
p256_double_outx resq 1
p256_double_outy resq 1
p256_double_outz resq 1
p256_double_inx resq 1
p256_double_iny resq 1
p256_double_inz resq 1
section .text

; rcx=outx rdx=outy r8=outz r9=affine x r10=affine y r11=scalar
p256_scalar_mult:
    push rbx
    push r12
    push r13
    push r14
    mov r12,rcx
    mov r13,rdx
    mov r14,r8
    lea rcx,[rel p256_q_x]
    mov rdx,r9
    call p256_copy
    lea rcx,[rel p256_q_y]
    mov rdx,r10
    call p256_copy
    lea rcx,[rel p256_q_z]
    lea rdx,[rel p256_one]
    call p256_copy
    lea rcx,[rel p256_work_x]
    call p256_zero
    lea rcx,[rel p256_work_y]
    lea rdx,[rel p256_one]
    call p256_copy
    lea rcx,[rel p256_work_z]
    call p256_zero
    mov r14,r8
    mov r13,rdx
    mov r12,rcx
    mov rbx,255
.loop:
    lea rcx,[rel p256_work_z]
    call p256_is_zero
    test eax,eax
    jnz .bit
    lea rcx,[rel p256_out_x]
    lea rdx,[rel p256_out_y]
    lea r8,[rel p256_out_z]
    lea r9,[rel p256_work_x]
    lea r10,[rel p256_work_y]
    lea r11,[rel p256_work_z]
    call p256_point_double
    lea rcx,[rel p256_work_x]
    lea rdx,[rel p256_out_x]
    call p256_copy
    lea rcx,[rel p256_work_y]
    lea rdx,[rel p256_out_y]
    call p256_copy
    lea rcx,[rel p256_work_z]
    lea rdx,[rel p256_out_z]
    call p256_copy
.bit:
    mov rax,[rel p256_scalar_ptr]
    bt dword [rax],ebx
    jnc .next
    lea rcx,[rel p256_work_z]
    call p256_is_zero
    test eax,eax
    jz .add
    lea rcx,[rel p256_work_x]
    lea rdx,[rel p256_q_x]
    call p256_copy
    lea rcx,[rel p256_work_y]
    lea rdx,[rel p256_q_y]
    call p256_copy
    lea rcx,[rel p256_work_z]
    lea rdx,[rel p256_one]
    call p256_copy
    jmp .next
.add:
    sub rsp,24
    lea rax,[rel p256_q_x]
    mov [rsp],rax
    lea rax,[rel p256_q_y]
    mov [rsp+8],rax
    lea rax,[rel p256_q_z]
    mov [rsp+16],rax
    lea rcx,[rel p256_out_x]
    lea rdx,[rel p256_out_y]
    lea r8,[rel p256_out_z]
    lea r9,[rel p256_work_x]
    lea r10,[rel p256_work_y]
    lea r11,[rel p256_work_z]
    call p256_point_add
    add rsp,24
    lea rcx,[rel p256_work_x]
    lea rdx,[rel p256_out_x]
    call p256_copy
    lea rcx,[rel p256_work_y]
    lea rdx,[rel p256_out_y]
    call p256_copy
    lea rcx,[rel p256_work_z]
    lea rdx,[rel p256_out_z]
    call p256_copy
.next:
    dec ebx
    jns .loop
  ; output pointers were saved by caller in globals
    mov rcx,[rel p256_scalar_outx]
    lea rdx,[rel p256_work_x]
    call p256_copy
    mov rcx,[rel p256_scalar_outy]
    lea rdx,[rel p256_work_y]
    call p256_copy
    mov rcx,[rel p256_scalar_outz]
    lea rdx,[rel p256_work_z]
    call p256_copy
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

section .bss align=8
p256_scalar_outx resq 1
p256_scalar_outy resq 1
p256_scalar_outz resq 1
p256_scalar_ptr resq 1
section .text

; wrapper sets output globals because scalar loop uses all volatile registers.
; rcx=outx rdx=outy r8=outz r9=qx r10=qy r11=scalar
p256_scalar_mult_safe:
    mov [rel p256_scalar_outx],rcx
    mov [rel p256_scalar_outy],rdx
    mov [rel p256_scalar_outz],r8
    mov [rel p256_scalar_ptr],r11
    jmp p256_scalar_mult

; rcx=uncompressed issuer key (04||x||y), rdx=der ecdsa signature, r8=sha256
; hash returns eax=0 on valid signature.
ecdsa_p256_verify_sha256_x64:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rcx
    mov r13,rdx
    mov r14,r8
    cmp byte [r12],4
    jne .bad

    lea rcx,[rel p256_pub_x]
    lea rdx,[r12+1]
    call p256_import_be32
    lea rcx,[rel p256_pub_y]
    lea rdx,[r12+33]
    call p256_import_be32
    lea rcx,[rel p256_hash_z]
    mov rdx,r14
    call p256_import_be32

  ; der sequence(integer r, integer s)
    cmp byte [r13],0x30
    jne .bad
    movzx ebx,byte [r13+1]
    lea r15,[r13+2]
    cmp byte [r15],2
    jne .bad
    movzx r8d,byte [r15+1]
    lea rdx,[r15+2]
    lea rcx,[rel p256_sig_r]
    call p256_import_der_int
    test eax,eax
    jnz .bad
    movzx eax,byte [r15+1]
    lea r15,[r15+2+rax]
    cmp byte [r15],2
    jne .bad
    movzx r8d,byte [r15+1]
    lea rdx,[r15+2]
    lea rcx,[rel p256_sig_s]
    call p256_import_der_int
    test eax,eax
    jnz .bad

  ; 1 <= r,s < n
    lea rcx,[rel p256_sig_r]
    call p256_is_zero
    test eax,eax
    jnz .bad
    lea rcx,[rel p256_sig_s]
    call p256_is_zero
    test eax,eax
    jnz .bad
    lea rcx,[rel p256_sig_r]
    lea rdx,[rel p256_order]
    call p256_ge
    test eax,eax
    jnz .bad
    lea rcx,[rel p256_sig_s]
    lea rdx,[rel p256_order]
    call p256_ge
    test eax,eax
    jnz .bad

  ; w=s^-1 mod n, u1=z*w, u2=r*w
    lea rax,[rel p256_order]
    mov [rel p256_mod_ptr],rax
    lea rcx,[rel p256_w]
    lea rdx,[rel p256_sig_s]
    lea r8,[rel p256_order_minus2]
    call p256_pow_mod
    lea rcx,[rel p256_u1]
    lea rdx,[rel p256_hash_z]
    lea r8,[rel p256_w]
    call p256_mul_mod
    lea rcx,[rel p256_u2]
    lea rdx,[rel p256_sig_r]
    lea r8,[rel p256_w]
    call p256_mul_mod

  ; p1=u1*g, p2=u2*q over field p.
    lea rax,[rel p256_prime]
    mov [rel p256_mod_ptr],rax
    lea rcx,[rel p256_p1_x]
    lea rdx,[rel p256_p1_y]
    lea r8,[rel p256_p1_z]
    lea r9,[rel p256_gx]
    lea r10,[rel p256_gy]
    lea r11,[rel p256_u1]
    call p256_scalar_mult_safe
    lea rcx,[rel p256_p2_x]
    lea rdx,[rel p256_p2_y]
    lea r8,[rel p256_p2_z]
    lea r9,[rel p256_pub_x]
    lea r10,[rel p256_pub_y]
    lea r11,[rel p256_u2]
    call p256_scalar_mult_safe

  ; r=p1+p2
    sub rsp,24
    lea rax,[rel p256_p2_x]
    mov [rsp],rax
    lea rax,[rel p256_p2_y]
    mov [rsp+8],rax
    lea rax,[rel p256_p2_z]
    mov [rsp+16],rax
    lea rcx,[rel p256_out_x]
    lea rdx,[rel p256_out_y]
    lea r8,[rel p256_out_z]
    lea r9,[rel p256_p1_x]
    lea r10,[rel p256_p1_y]
    lea r11,[rel p256_p1_z]
    call p256_point_add
    add rsp,24
    lea rcx,[rel p256_out_z]
    call p256_is_zero
    test eax,eax
    jnz .bad

  ; affine x = x / z^2
    lea rcx,[rel p256_t0]
    lea rdx,[rel p256_out_z]
    lea r8,[rel p256_prime_minus2]
    call p256_pow_mod
    lea rcx,[rel p256_t1]
    lea rdx,[rel p256_t0]
    lea r8,[rel p256_t0]
    call p256_mul_mod
    lea rcx,[rel p256_x_aff]
    lea rdx,[rel p256_out_x]
    lea r8,[rel p256_t1]
    call p256_mul_mod

  ; v = x mod n (p < 2n, so at most one subtraction)
    lea rcx,[rel p256_x_aff]
    lea rdx,[rel p256_order]
    call p256_ge
    test eax,eax
    jz .compare
    lea rcx,[rel p256_x_aff]
    lea rdx,[rel p256_x_aff]
    lea r8,[rel p256_order]
    call p256_sub_raw
.compare:
    lea rcx,[rel p256_x_aff]
    lea rdx,[rel p256_sig_r]
    mov r8d,32
    call mem_equal_x64
    test eax,eax
    jz .bad
    xor eax,eax
    jmp .done
.bad:
    mov eax,LEGACY_STATUS_DEVICE
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
