; multi-shard runtime state.
; shard ownership stays separate from the singleton transport

BITS 64

%define LEGACY_SHARD_MAX        128
%define LEGACY_SHARD_TOTAL_MAX 65535
%define LEGACY_SHARD_CTX_SIZE   256

%define SHARD_STATE_FREE          0
%define SHARD_STATE_ASSIGNED      1
%define SHARD_STATE_STARTING      2
%define SHARD_STATE_READY         3
%define SHARD_STATE_BACKOFF       4
%define SHARD_STATE_FATAL         5

%define SHARD_FLAG_SEQ_VALID       0x00000001
%define SHARD_FLAG_AWAITING_ACK    0x00000002
%define SHARD_FLAG_WS_HTTP         0x00000004
%define SHARD_FLAG_WS_OPEN         0x00000008
%define SHARD_FLAG_IDENTIFIED      0x00000010
%define SHARD_FLAG_READY           0x00000020
%define SHARD_FLAG_IDENTIFY_PENDING 0x00000040
%define SHARD_FLAG_RESUMING        0x00000080
%define SHARD_FLAG_CONNECT_ALLOWED  0x00000100

%define SHARD_OFF_ID              0
%define SHARD_OFF_TOTAL           4
%define SHARD_OFF_STATE           8
%define SHARD_OFF_SEQUENCE       12
%define SHARD_OFF_HEARTBEAT_MS   16
%define SHARD_OFF_FLAGS          20
%define SHARD_OFF_LEASE_EPOCH       24
%define SHARD_OFF_LAST_TICK         32
%define SHARD_OFF_SESSION_GEN       40
%define SHARD_OFF_HEARTBEAT_DEADLINE 48
%define SHARD_OFF_HEARTBEATS_SENT   56
%define SHARD_OFF_HEARTBEAT_ACKS    64
%define SHARD_OFF_HEARTBEAT_MISSES  72
%define SHARD_OFF_IDENTIFY_BUCKET   76
%define SHARD_OFF_TCP_CTX           80
%define SHARD_OFF_TLS_CTX           88
%define SHARD_OFF_WS_CTX            96
%define SHARD_OFF_DISCORD_CTX      104
%define SHARD_OFF_RX_BUF           112
%define SHARD_OFF_TX_BUF           120
%define SHARD_OFF_RX_LEN           128
%define SHARD_OFF_TX_LEN           132
%define SHARD_OFF_RECONNECTS       136
%define SHARD_OFF_LEASE_DEADLINE   144
%define SHARD_OFF_LAST_ERROR       152
%define SHARD_OFF_RECONNECT_DEADLINE 160
%define SHARD_OFF_SESSION_PTR       168
%define SHARD_OFF_RESERVED          176

legacy_shards_init64:
    cmp dword [rel shard_initialized], 1
    je .done
    mov dword [rel shard_total_global], 1
    mov dword [rel shard_local_start], 0
    mov dword [rel shard_local_count], 1
    mov dword [rel shard_active_count], 0
    mov dword [rel shard_resources_allocated], 0
    mov qword [rel shard_plan_generation], 1

    lea rdi, [rel shard_contexts]
    xor eax, eax
    mov ecx, (LEGACY_SHARD_MAX * LEGACY_SHARD_CTX_SIZE) / 8
    rep stosq

    call legacy_shards_apply_local_plan64

    mov dword [rel shard_initialized], 1
    lea rsi, [rel msg_shards_ready]
    call serial_puts64
.done:
    ret

legacy_shards_ensure_init64:
    cmp dword [rel shard_initialized], 1
    je .done
    call legacy_shards_init64
.done:
    ret

; apply a contiguous local lease plan. inputs live in shard_total_global /
; shard_local_start / shard_local_count. the controller will eventually update these
legacy_shards_apply_local_plan64:
    push rbx
    push r12
    push r13

    mov eax, [rel shard_total_global]
    test eax, eax
    jnz .total_nonzero
    mov eax, 1
    mov [rel shard_total_global], eax
.total_nonzero:
    cmp eax, LEGACY_SHARD_TOTAL_MAX
    jbe .total_ok
    mov eax, LEGACY_SHARD_TOTAL_MAX
    mov [rel shard_total_global], eax
.total_ok:

    mov r12d, [rel shard_local_start]
    cmp r12d, eax
    jb .start_ok
    xor r12d, r12d
    mov [rel shard_local_start], r12d
.start_ok:

    mov r13d, [rel shard_local_count]
    test r13d, r13d
    jnz .count_nonzero
    mov r13d, 1
    mov [rel shard_local_count], r13d
.count_nonzero:

    mov edx, eax
    sub edx, r12d
    cmp r13d, edx
    jbe .count_total_ok
    mov r13d, edx
    mov [rel shard_local_count], r13d
.count_total_ok:
    cmp r13d, LEGACY_SHARD_MAX
    jbe .count_max_ok
    mov r13d, LEGACY_SHARD_MAX
    mov [rel shard_local_count], r13d
.count_max_ok:

  ; clear the whole pool before applying the new lease generation.
    lea rdi, [rel shard_contexts]
    xor eax, eax
    mov ecx, (LEGACY_SHARD_MAX * LEGACY_SHARD_CTX_SIZE) / 8
    rep stosq

    xor ebx, ebx
.assign:
    cmp ebx, r13d
    jae .done

    mov eax, ebx
    shl rax, 8
    lea rdi, [rel shard_contexts]
    add rdi, rax

    mov eax, r12d
    add eax, ebx
    mov [rdi + SHARD_OFF_ID], eax

    mov eax, [rel shard_total_global]
    mov [rdi + SHARD_OFF_TOTAL], eax
    mov dword [rdi + SHARD_OFF_STATE], SHARD_STATE_ASSIGNED
    mov dword [rdi + SHARD_OFF_SEQUENCE], 0xFFFFFFFF
    mov rax, [rel shard_plan_generation]
    mov [rdi + SHARD_OFF_LEASE_EPOCH], rax
    mov eax, [rdi + SHARD_OFF_ID]
    xor edx, edx
    mov ecx, [rel shard_identify_concurrency]
    test ecx, ecx
    jnz .bucket_div
    mov ecx, 1
.bucket_div:
    div ecx
    mov [rdi + SHARD_OFF_IDENTIFY_BUCKET], edx

    inc ebx
    jmp .assign

.done:
    mov [rel shard_active_count], r13d
    mov qword [rel shard_identify_wave_deadline], 0
    mov qword [rel shard_connect_wave_deadline], 0
    lea rdi, [rel shard_identify_bucket_used]
    xor eax, eax
    mov ecx, 1024/8
    rep stosq
    pop r13
    pop r12
    pop rbx
    ret


; rcx=shard ctx. prefix one diagnostic line with the global shard id.
legacy_shard_log_prefix64:
    push rax
    push rbx
    push rcx
    push rsi
    mov rbx, rcx
    lea rsi, [rel msg_shard_log_prefix]
    call serial_puts64
    test rbx, rbx
    jz .zero
    mov eax, [rbx + SHARD_OFF_ID]
    jmp .id
.zero:
    xor eax, eax
.id:
    call serial_hex32_64
    lea rsi, [rel msg_shard_log_suffix]
    call serial_puts64
    pop rsi
    pop rcx
    pop rbx
    pop rax
    ret

; rcx=discord guild snowflake, eax=shard id for the current global shard
; count. discord routes guilds with (guild_id >> 22) % num_shards.
legacy_shard_for_guild64:
    mov rax, rcx
    shr rax, 22
    mov ecx, [rel shard_total_global]
    test ecx, ecx
    jz .zero
    xor edx, edx
    div rcx
    mov eax, edx
    ret
.zero:
    xor eax, eax
    ret

; ecx=global shard id, eax=local slot or 0xffffffff when this node does not
; own it.
legacy_shard_local_slot64:
    mov eax, ecx
    sub eax, [rel shard_local_start]
    jc .no
    cmp eax, [rel shard_local_count]
    jae .no
    ret
.no:
    mov eax, 0xFFFFFFFF
    ret

; ecx=global total, edx=local start, r8d=local count, r9=lease generation,
; r10d=discord identify max_concurrency. this is the single entry point a future controller
legacy_shards_set_plan64:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12d, ecx
    mov r13d, edx
    mov r14d, r8d
    mov r15d, r10d

    test r12d, r12d
    jz .bad
    cmp r12d, LEGACY_SHARD_TOTAL_MAX
    ja .bad
    cmp r13d, r12d
    jae .bad
    test r14d, r14d
    jz .bad
    cmp r14d, LEGACY_SHARD_MAX
    ja .bad
    mov eax, r12d
    sub eax, r13d
    cmp r14d, eax
    ja .bad
    test r15d, r15d
    jnz .conc_ok
    mov r15d, 1
.conc_ok:
    cmp r15d, 1024
    ja .bad

    mov [rel shard_total_global], r12d
    mov [rel shard_local_start], r13d
    mov [rel shard_local_count], r14d
    mov [rel shard_plan_generation], r9
    mov [rel shard_identify_concurrency], r15d

    cmp dword [rel shard_resources_allocated], 1
    je .live_replan

    call legacy_shards_apply_local_plan64
    xor eax, eax
    jmp .out

.live_replan:
  ; dynamic fleet rebalancing must not throw away allocated pages. reuse each
  ; local slot's private tcp/tls/ws/discord workspaces, invalidate any old resumable
    mov eax, [rel shard_network_enabled]
    mov [rel shard_replan_resume_network], eax
    mov dword [rel shard_network_enabled], 0
    mov eax, [rel shard_active_count]
    mov [rel shard_replan_old_count], eax

    mov edx, eax
    cmp edx, r14d
    jae .have_span
    mov edx, r14d
.have_span:
    mov [rel shard_replan_span], edx
    xor ebx, ebx

.replan_loop:
    cmp ebx, [rel shard_replan_span]
    jae .replan_done

    mov eax, ebx
    shl rax, 8
    lea r11, [rel shard_contexts]
    add r11, rax

    cmp ebx, [rel shard_replan_old_count]
    jae .new_slot
    mov rcx, r11
    call legacy_shard_session_invalidate64
    mov eax, ebx
    shl rax, 8
    lea r11, [rel shard_contexts]
    add r11, rax

.new_slot:
    cmp ebx, r14d
    jae .retire_slot

  ; publish the new ownership tuple before reset so the tcp local port and
  ; identify payload are rebuilt for the new
    mov eax, r13d
    add eax, ebx
    mov [r11 + SHARD_OFF_ID], eax
    mov [r11 + SHARD_OFF_TOTAL], r12d
    mov dword [r11 + SHARD_OFF_STATE], SHARD_STATE_ASSIGNED
    mov dword [r11 + SHARD_OFF_SEQUENCE], 0xFFFFFFFF
    mov dword [r11 + SHARD_OFF_FLAGS], 0
    mov qword [r11 + SHARD_OFF_HEARTBEAT_DEADLINE], 0
    mov dword [r11 + SHARD_OFF_HEARTBEAT_MISSES], 0
    mov qword [r11 + SHARD_OFF_RECONNECT_DEADLINE], 0
    mov rax, [rel shard_plan_generation]
    mov [r11 + SHARD_OFF_LEASE_EPOCH], rax

    mov eax, [r11 + SHARD_OFF_ID]
    xor edx, edx
    mov ecx, r15d
    div ecx
    mov [r11 + SHARD_OFF_IDENTIFY_BUCKET], edx

    cmp ebx, [rel shard_replan_old_count]
    jae .prepare_new
    mov rcx, r11
    call legacy_shard_connection_reset64
    test eax, eax
    jnz .replan_fail
    jmp .next

.prepare_new:
    mov rcx, r11
    call legacy_shard_connection_prepare64
    test eax, eax
    jnz .replan_fail
    jmp .next

.retire_slot:
    mov dword [r11 + SHARD_OFF_STATE], SHARD_STATE_FREE
    mov dword [r11 + SHARD_OFF_FLAGS], 0
    mov dword [r11 + SHARD_OFF_SEQUENCE], 0xFFFFFFFF
    mov rax, [r11 + SHARD_OFF_TCP_CTX]
    test rax, rax
    jz .next
    mov dword [rax + 0], 5

.next:
    inc ebx
    jmp .replan_loop

.replan_done:
    mov [rel shard_active_count], r14d
    mov qword [rel shard_identify_wave_deadline], 0
    mov qword [rel shard_connect_wave_deadline], 0
    lea rdi, [rel shard_identify_bucket_used]
    xor eax, eax
    mov ecx, 1024/8
    rep stosq

  ; carry an armed lease deadline into all newly assigned slots.
    mov rax, [rel shard_lease_deadline]
    test rax, rax
    jz .resume
    xor ebx, ebx
.lease_copy:
    cmp ebx, r14d
    jae .resume
    mov edx, ebx
    shl rdx, 8
    lea r11, [rel shard_contexts]
    add r11, rdx
    mov [r11 + SHARD_OFF_LEASE_DEADLINE], rax
    inc ebx
    jmp .lease_copy

.resume:
    cmp dword [rel shard_lease_expired], 1
    je .ok
    mov eax, [rel shard_replan_resume_network]
    mov [rel shard_network_enabled], eax
.ok:
    lea rsi, [rel msg_shards_replan_ok]
    call serial_puts64
    xor eax, eax
    jmp .out

.replan_fail:
    mov dword [rel shard_network_enabled], 0
    lea rsi, [rel msg_shards_replan_fail]
    call serial_puts64
.bad:
    mov eax, 1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rcx = local slot index (0..active_count-1), rax = ctx or zero.
legacy_shards_get_ctx64:
    mov eax, [rel shard_active_count]
    cmp ecx, eax
    jae .bad
    mov rax, rcx
    shl rax, 8
    lea rdx, [rel shard_contexts]
    add rax, rdx
    ret
.bad:
    xor eax, eax
    ret

; ap worker: count a strided subset of shard states. edx is the worker id
; assigned by the ap trampoline (1..n)
legacy_shards_health_worker64:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r15d, edx
    mov r14d, [rel ap_online_count]
    dec r14d
    jle .out

    mov r13d, r15d
    dec r13d
    xor ebx, ebx
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d

.scan:
    cmp r13d, [rel shard_active_count]
    jae .store
    mov eax, r13d
    shl rax, 8
    lea r12, [rel shard_contexts]
    add r12, rax
    mov eax, [r12 + SHARD_OFF_STATE]
    cmp eax, SHARD_STATE_READY
    je .ready
    cmp eax, SHARD_STATE_STARTING
    je .starting
    cmp eax, SHARD_STATE_BACKOFF
    je .backoff
    cmp eax, SHARD_STATE_FATAL
    je .fatal
    jmp .next
.ready:
    inc r8d
    jmp .next
.starting:
    inc r9d
    jmp .next
.backoff:
    inc r10d
    jmp .next
.fatal:
    inc r11d
.next:
    add r13d, r14d
    jmp .scan

.store:
    lea rax, [rel shard_worker_ready]
    mov [rax+r15*4], r8d
    lea rax, [rel shard_worker_starting]
    mov [rax+r15*4], r9d
    lea rax, [rel shard_worker_backoff]
    mov [rax+r15*4], r10d
    lea rax, [rel shard_worker_fatal]
    mov [rax+r15*4], r11d
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ap worker: run the full per-shard state machine over a disjoint strided
; subset of contexts. edx is the stable ap
legacy_shards_tick_worker64:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r15d, edx
    mov r14d, [rel ap_online_count]
    dec r14d
    jle .out

    mov r13d, r15d
    dec r13d
.scan:
    cmp r13d, [rel shard_active_count]
    jae .done

    mov eax, r13d
    shl rax, 8
    lea r12, [rel shard_contexts]
    add r12, rax

    mov rcx, r12
    call legacy_shard_lifecycle_tick64

    mov rcx, r12
    call legacy_shard_tcp_tick64
    mov rcx, r12
    call legacy_shard_tcp_rel_tick64

  ; shard crypto helpers are not re-entrant.
  ; shared scratch stays locked while tcp/lifecycle work stays parallel
.crypto_lock:
    xor eax, eax
    mov edx, 1
    lock cmpxchg dword [rel shard_crypto_lock], edx
    je .crypto_locked
    pause
    jmp .crypto_lock
.crypto_locked:
    mov rcx, r12
    call legacy_shard_tls_tick64

    mov rcx, r12
    call legacy_shard_discord_tick64
    mov dword [rel shard_crypto_lock], 0

    add r13d, r14d
    jmp .scan

.done:
    lea rax, [rel shard_worker_tick_count]
    lock inc qword [rax+r15*8]
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; refresh aggregate health using all online ap workers. eax=1 when aps
; supplied the snapshot, eax=0 when the machine is bsp-only.
legacy_shards_parallel_health64:
    cmp dword [rel ap_online_count], 1
    jbe .single

    lea rdi, [rel shard_worker_ready]
    xor eax, eax
    mov ecx, MAX_CPUS * 4 * 4 / 8
    rep stosq

    lea rcx, [rel legacy_shards_health_worker64]
    xor edx, edx
    call smp_dispatch_all64
    test eax, eax
    jz .single

    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    mov ecx, 1
.sum:
    cmp ecx, [rel ap_online_count]
    jae .store_sum
    lea rax, [rel shard_worker_ready]
    add r8d, [rax+rcx*4]
    lea rax, [rel shard_worker_starting]
    add r9d, [rax+rcx*4]
    lea rax, [rel shard_worker_backoff]
    add r10d, [rax+rcx*4]
    lea rax, [rel shard_worker_fatal]
    add r11d, [rax+rcx*4]
    inc ecx
    jmp .sum
.store_sum:
    mov [rel shard_health_ready], r8d
    mov [rel shard_health_starting], r9d
    mov [rel shard_health_backoff], r10d
    mov [rel shard_health_fatal], r11d
    mov eax, 1
    ret
.single:
    xor eax, eax
    ret

; main shard scheduler. global admission/identify arbitration remains on the
; bsp. when smp workers are healthy, the expensive per-shard lifecycle/tcp/tls/ heartbeat
legacy_shards_tick64:
    cmp dword [rel shard_initialized], 1
    jne .done
    inc qword [rel shard_scheduler_ticks]
    call legacy_shards_lease_tick64
    cmp dword [rel shard_network_enabled], 1
    jne .schedule_only

  ; these mutate shared concurrency-bucket state and intentionally stay on bsp.
    call legacy_shards_connect_admission_tick64
    call legacy_shard_discord_identify_tick64

    cmp dword [rel shard_parallel_enabled], 1
    jne .serial
    cmp dword [rel ap_online_count], 1
    jbe .serial

    lea rcx, [rel legacy_shards_tick_worker64]
    xor edx, edx
    call smp_dispatch_all64
    test eax, eax
    jz .parallel_failed

    cmp dword [rel shard_parallel_announced], 1
    je .schedule_only
    mov dword [rel shard_parallel_announced], 1
    lea rsi, [rel msg_shards_parallel_on]
    call serial_puts64
    jmp .schedule_only

.parallel_failed:
  ; do not serially repeat this tick: some aps may already have advanced their
  ; contexts. disable parallel mode and resume the
    mov dword [rel shard_parallel_enabled], 0
    lea rsi, [rel msg_shards_parallel_fail]
    call serial_puts64
    jmp .schedule_only

.serial:
    push rbx
    push r12
    xor ebx, ebx
.ctx_loop:
    cmp ebx, [rel shard_active_count]
    jae .ctx_done
    mov ecx, ebx
    call legacy_shards_get_ctx64
    test rax, rax
    jz .ctx_done
    mov r12, rax

    mov rcx, r12
    call legacy_shard_lifecycle_tick64

    mov rcx, r12
    call legacy_shard_tcp_tick64
    mov rcx, r12
    call legacy_shard_tcp_rel_tick64

    mov rcx, r12
    call legacy_shard_tls_tick64

    mov rcx, r12
    call legacy_shard_discord_tick64

    inc ebx
    jmp .ctx_loop
.ctx_done:
    pop r12
    pop rbx

.schedule_only:
    mov eax, [rel shard_active_count]
    test eax, eax
    jz .done
    mov ecx, [rel shard_scheduler_cursor]
    inc ecx
    cmp ecx, eax
    jb .store
    xor ecx, ecx
.store:
    mov [rel shard_scheduler_cursor], ecx
.done:
    ret


%define SHARD_CONNECT_WINDOW_MS 5500

; admit new gateway tcp connections in the same concurrency buckets used by
; identify. this prevents 128 sockets from receiving hello
legacy_shards_connect_admission_tick64:
    cmp dword [rel shard_network_enabled], 1
    jne .done
  ; never accumulate connect_allowed flags before the shared dns resolver has
  ; produced the gateway address. otherwise one new shard is admitted
    cmp dword [rel legacy_dns_state], LEGACY_DNS_READY
    jne .done
    mov rax, [rel tsc_cycles_per_ms]
    test rax, rax
    jz .done

    mov r8, [rel shard_connect_wave_deadline]
    test r8, r8
    jz .wave
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, r8
    jb .done

.wave:
    push rbx
    push r12
    push r13
    push r14
    push rdi

    lea rdi, [rel shard_connect_bucket_used]
    xor eax, eax
    mov ecx, 1024/8
    rep stosq

    mov r14d, [rel shard_identify_concurrency]
    test r14d, r14d
    jnz .cap
    mov r14d, 1
.cap:
    cmp r14d, 1024
    jbe .scan
    mov r14d, 1024

.scan:
    xor ebx, ebx
    xor r13d, r13d
.loop:
    cmp ebx, [rel shard_active_count]
    jae .deadline
    cmp r13d, r14d
    jae .deadline

    mov ecx, ebx
    call legacy_shards_get_ctx64
    test rax, rax
    jz .deadline
    mov r12, rax

    test dword [r12 + SHARD_OFF_FLAGS], SHARD_FLAG_CONNECT_ALLOWED
    jnz .next
    cmp dword [r12 + SHARD_OFF_STATE], SHARD_STATE_FATAL
    je .next

    mov r10, [r12 + SHARD_OFF_TCP_CTX]
    test r10, r10
    jz .next
    cmp dword [r10 + 0], 0
    jne .next

    mov eax, [r12 + SHARD_OFF_IDENTIFY_BUCKET]
    cmp eax, 1024
    jae .next
    lea r10, [rel shard_connect_bucket_used]
    cmp byte [r10+rax], 0
    jne .next

    mov byte [r10+rax], 1
    or dword [r12 + SHARD_OFF_FLAGS], SHARD_FLAG_CONNECT_ALLOWED
    inc r13d

    mov rcx, r12
    call legacy_shard_log_prefix64
    lea rsi, [rel msg_shards_connect_admit]
    call serial_puts64

.next:
    inc ebx
    jmp .loop

.deadline:
    mov rax, [rel tsc_cycles_per_ms]
    imul rax, SHARD_CONNECT_WINDOW_MS
    mov r8, rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    add rax, r8
    mov [rel shard_connect_wave_deadline], rax

    pop rdi
    pop r14
    pop r13
    pop r12
    pop rbx
.done:
    ret

; parses shardplan text.
; form: <total> <local-start> <local-count> [max-concurrency]
legacy_shards_configure_text64:
    push rbx
    push r12
    push r13
    push r14
    push r15

  ; initialize the shard subsystem before publishing a shell-supplied plan.
  ; otherwise the status print below performs the first lazy init and
    mov rbx, rcx
    call legacy_shards_ensure_init64
    mov rcx, rbx

    call legacy_shards_parse_u32_64
    jc .bad
    mov ebx, eax
    mov rcx, rdx
    call legacy_shards_parse_u32_64
    jc .bad
    mov r12d, eax
    mov rcx, rdx
    call legacy_shards_parse_u32_64
    jc .bad
    mov r13d, eax
    mov r14d, 1

    mov rcx, rdx
    call legacy_shards_skip_spaces64
    cmp byte [rax], 0
    je .safe_concurrency
    mov rcx, rax
    call legacy_shards_parse_u32_64
    jc .bad

.safe_concurrency:
  ; the shell command has no /gateway/bot result, so it cannot know discord's
  ; session_start_limit.max_concurrency. treat any optional fourth argument as advisory
    mov r14d, 1

.apply:
    mov r9, [rel shard_plan_generation]
    inc r9
    mov ecx, ebx
    mov edx, r12d
    mov r8d, r13d
    mov r10d, r14d
    call legacy_shards_set_plan64
    test eax, eax
    jnz .bad

    lea rsi, [rel msg_shards_plan_ok]
    call serial_puts64
    call legacy_shards_print64
    xor eax, eax
    jmp .out
.bad:
    lea rsi, [rel msg_shards_plan_bad]
    call serial_puts64
    mov eax, 1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rcx=text, rax=first non-space byte.
legacy_shards_skip_spaces64:
    mov rax, rcx
.loop:
    cmp byte [rax], ' '
    jne .done
    inc rax
    jmp .loop
.done:
    ret

; rcx=text, eax=value, rdx=next byte, carry on malformed/overflow.
legacy_shards_parse_u32_64:
    push rbx
    call legacy_shards_skip_spaces64
    mov rbx, rax
    xor eax, eax
    xor r8d, r8d
.loop:
    movzx ecx, byte [rbx]
    cmp ecx, '0'
    jb .done
    cmp ecx, '9'
    ja .done
    cmp eax, 429496729
    ja .bad
    imul eax, eax, 10
    sub ecx, '0'
    add eax, ecx
    jc .bad
    inc rbx
    inc r8d
    jmp .loop
.done:
    test r8d, r8d
    jz .bad
    mov rdx, rbx
    clc
    pop rbx
    ret
.bad:
    xor eax, eax
    mov rdx, rbx
    stc
    pop rbx
    ret


; ecx=lease seconds. zero clears lease enforcement (used by local shell
; tests). controller-driven nodes arm this after every successful check-in response.
legacy_shards_arm_lease64:
    test ecx, ecx
    jz .clear
    mov rax, [rel tsc_cycles_per_ms]
    test rax, rax
    jz .bad
    mov edx, ecx
    imul rdx, 1000
    imul rax, rdx
    mov r8, rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    add rax, r8
    mov [rel shard_lease_deadline], rax
    mov dword [rel shard_lease_expired], 0

    push rbx
    xor ebx, ebx
.loop:
    cmp ebx, [rel shard_active_count]
    jae .ok
    mov ecx, ebx
    call legacy_shards_get_ctx64
    test rax, rax
    jz .ok
    mov rdx, [rel shard_lease_deadline]
    mov [rax + SHARD_OFF_LEASE_DEADLINE], rdx
    inc ebx
    jmp .loop
.ok:
    pop rbx
    xor eax, eax
    ret
.clear:
    mov qword [rel shard_lease_deadline], 0
    mov dword [rel shard_lease_expired], 0
    xor eax, eax
    ret
.bad:
    mov eax, 1
    ret

; stop all shard-owned traffic when a controller lease expires. the singleton
; discord session remains untouched.
legacy_shards_expire_lease64:
    cmp dword [rel shard_lease_expired], 1
    je .done
    mov dword [rel shard_lease_expired], 1
    mov dword [rel shard_network_enabled], 0

    push rbx
    push r12
    xor ebx, ebx
.loop:
    cmp ebx, [rel shard_active_count]
    jae .log
    mov ecx, ebx
    call legacy_shards_get_ctx64
    test rax, rax
    jz .log
    mov r12, rax
    mov rcx, r12
    call legacy_shard_session_invalidate64
    mov rcx, r12
    call legacy_shard_tcp_abort64
    mov dword [r12 + SHARD_OFF_FLAGS], 0
    mov dword [r12 + SHARD_OFF_STATE], SHARD_STATE_ASSIGNED
.next:
    inc ebx
    jmp .loop
.log:
    lea rsi, [rel msg_shards_lease_expired]
    call serial_puts64
    pop r12
    pop rbx
.done:
    ret

legacy_shards_lease_tick64:
    cmp dword [rel shard_lease_expired], 1
    je .done
    mov r8, [rel shard_lease_deadline]
    test r8, r8
    jz .done
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, r8
    jb .done
    call legacy_shards_expire_lease64
.done:
    ret

legacy_shards_prepare_all64:
    call legacy_shards_ensure_init64
    push rbx
    xor ebx, ebx
.loop:
    cmp ebx, [rel shard_active_count]
    jae .ok
    mov ecx, ebx
    call legacy_shards_get_ctx64
    test rax, rax
    jz .bad
    mov rcx, rax
    call legacy_shard_connection_prepare64
    test eax, eax
    jnz .bad
    inc ebx
    jmp .loop
.ok:
    mov dword [rel shard_resources_allocated], 1
    xor eax, eax
    pop rbx
    ret
.bad:
    lea rsi, [rel msg_shards_prepare_slot]
    call serial_puts64
    mov eax, ebx
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64
    mov eax, 1
    pop rbx
    ret


; rcx=text after "shardreset". resets one local slot immediately and preserves
; resumable gateway session state when possible.

; rcx=text after "shardlease". decimal seconds; 0 disables lease enforcement.
legacy_shards_lease_text64:
    call legacy_shards_parse_u32_64
    jc .bad
    mov ecx, eax
    call legacy_shards_arm_lease64
    test eax, eax
    jnz .bad
    lea rsi, [rel msg_shards_lease_set]
    call serial_puts64
    xor eax, eax
    ret
.bad:
    lea rsi, [rel msg_shards_lease_bad]
    call serial_puts64
    mov eax, 1
    ret

legacy_shards_reset_text64:
    push rbx
    call legacy_shards_parse_u32_64
    jc .bad
    mov ebx, eax
    mov ecx, ebx
    call legacy_shards_get_ctx64
    test rax, rax
    jz .bad
    mov rcx, rax
    call legacy_shard_connection_reset64
    test eax, eax
    jnz .bad
    lea rsi, [rel msg_shards_reset_ok]
    call serial_puts64
    xor eax, eax
    pop rbx
    ret
.bad:
    lea rsi, [rel msg_shards_reset_bad]
    call serial_puts64
    mov eax, 1
    pop rbx
    ret


; ecx=lease seconds from the controller. this is the controller-facing start/
; renewal entrypoint: allocate once, rebuild connections after an expired lease
legacy_shards_accept_lease64:
    push rbx
    mov ebx, ecx
    test ebx, ebx
    jz .bad

    cmp dword [rel shard_resources_allocated], 1
    je .allocated
    call legacy_shards_prepare_all64
    test eax, eax
    jnz .bad
.allocated:
    cmp dword [rel shard_lease_expired], 1
    jne .arm

    push r12
    xor r12d, r12d
.reset_loop:
    cmp r12d, [rel shard_active_count]
    jae .reset_done
    mov ecx, r12d
    call legacy_shards_get_ctx64
    test rax, rax
    jz .reset_done
    mov rcx, rax
    call legacy_shard_connection_reset64
    test eax, eax
    jnz .reset_fail
    inc r12d
    jmp .reset_loop
.reset_done:
    pop r12
.arm:
    mov ecx, ebx
    call legacy_shards_arm_lease64
    test eax, eax
    jnz .bad
    mov dword [rel shard_network_enabled], 1
    xor eax, eax
    pop rbx
    ret
.reset_fail:
    pop r12
.bad:
    mov eax, 1
    pop rbx
    ret


; stop the hardware-proven singleton discord connection before starting the
; experimental shard pool. this prevents shard 0/1 tests from competing with
legacy_shards_takeover_singleton64:
    cmp dword [rel shard_singleton_taken_over], 1
    je .done

    cmp dword [rel legacy_tcp_state], LEGACY_TCP_UP
    jne .mark
    xor ecx, ecx
    xor edx, edx
    mov r8d, 0x14                    ; rst|ack
    call legacy_tcp_send_segment64
.mark:
    mov dword [rel legacy_tcp_state], LEGACY_TCP_CLOSED
    mov dword [rel legacy_tls_state], LEGACY_TLS_FAILED
    mov dword [rel discord_base_state], DISCORD_BASE_FAILED
    mov dword [rel shard_singleton_taken_over], 1
    lea rsi, [rel msg_shards_takeover]
    call serial_puts64
.done:
    xor eax, eax
    ret

; one-command two-shard bring-up preset for hardware validation. it
; deliberately uses max_concurrency=1 so shard 1 identifies in the next 5.5-second wave
legacy_shards_test2_64:
    call legacy_shards_ensure_init64
    cmp dword [rel legacy_config_ready], 1
    jne .bad_config

    mov ecx, 2
    xor edx, edx
    mov r8d, 2
    mov r9, [rel shard_plan_generation]
    inc r9
    mov r10d, 1
    call legacy_shards_set_plan64
    test eax, eax
    jnz .bad

    call legacy_shards_takeover_singleton64

  ; local test mode intentionally has no controller lease deadline.
    xor ecx, ecx
    call legacy_shards_arm_lease64

    call legacy_shards_prepare_all64
    test eax, eax
    jnz .bad
    mov dword [rel shard_network_enabled], 1
    lea rsi, [rel msg_shards_test2]
    call serial_puts64
    xor eax, eax
    ret

.bad_config:
    lea rsi, [rel msg_shards_test2_config]
    call serial_puts64
    mov eax, 1
    ret
.bad:
    lea rsi, [rel msg_shards_test2_fail]
    call serial_puts64
    mov eax, 1
    ret

; print a concise two-shard acceptance result. pass means both local slots are
; ready, their private tls sessions are up, and
legacy_shards_test_status64:
    push rbx
    push r12
    push r13
    push r14
    call legacy_shards_ensure_init64
    cmp dword [rel shard_active_count], 2
    jne .not_ready

    xor ecx, ecx
    call legacy_shards_get_ctx64
    test rax, rax
    jz .not_ready
    mov r12, rax
    mov ecx, 1
    call legacy_shards_get_ctx64
    test rax, rax
    jz .not_ready
    mov r13, rax

  ; structural isolation checks: the two sessions must not share any mutable
  ; transport/gateway workspace or tcp local port.
    cmp r12, r13
    je .isolation_fail
    mov rax, [r12 + SHARD_OFF_TCP_CTX]
    test rax, rax
    jz .not_ready
    cmp rax, [r13 + SHARD_OFF_TCP_CTX]
    je .isolation_fail
    mov r14, [r13 + SHARD_OFF_TCP_CTX]
    test r14, r14
    jz .not_ready
    mov edx, [rax + 20]
    cmp edx, [r14 + 20]
    je .isolation_fail

    mov rax, [r12 + SHARD_OFF_TLS_CTX]
    test rax, rax
    jz .not_ready
    cmp rax, [r13 + SHARD_OFF_TLS_CTX]
    je .isolation_fail
    mov rax, [r12 + SHARD_OFF_WS_CTX]
    test rax, rax
    jz .not_ready
    cmp rax, [r13 + SHARD_OFF_WS_CTX]
    je .isolation_fail
    mov rax, [r12 + SHARD_OFF_DISCORD_CTX]
    test rax, rax
    jz .not_ready
    cmp rax, [r13 + SHARD_OFF_DISCORD_CTX]
    je .isolation_fail

    cmp dword [r12 + SHARD_OFF_ID], 0
    jne .isolation_fail
    cmp dword [r13 + SHARD_OFF_ID], 1
    jne .isolation_fail
    cmp dword [r12 + SHARD_OFF_TOTAL], 2
    jne .isolation_fail
    cmp dword [r13 + SHARD_OFF_TOTAL], 2
    jne .isolation_fail

    xor ebx, ebx
.ready_loop:
    cmp ebx, 2
    jae .pass
    mov ecx, ebx
    call legacy_shards_get_ctx64
    test rax, rax
    jz .not_ready
    mov r14, rax
    cmp dword [r14 + SHARD_OFF_STATE], SHARD_STATE_READY
    jne .not_ready
    test dword [r14 + SHARD_OFF_FLAGS], SHARD_FLAG_READY
    jz .not_ready
    mov r11, [r14 + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .not_ready
    cmp dword [r11 + 0], LEGACY_TLS_UP
    jne .not_ready
    cmp qword [r14 + SHARD_OFF_HEARTBEAT_ACKS], 0
    je .not_ready
    cmp dword [r14 + SHARD_OFF_LAST_ERROR], 0
    jne .not_ready
    inc ebx
    jmp .ready_loop

.pass:
    lea rsi, [rel msg_shards_test_pass]
    call serial_puts64
    mov eax, 1
    jmp .out

.isolation_fail:
    lea rsi, [rel msg_shards_test_isolation]
    call serial_puts64
    xor eax, eax
    jmp .out

.not_ready:
    lea rsi, [rel msg_shards_test_wait]
    call serial_puts64
    call legacy_shards_print64
    xor eax, eax
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

legacy_shards_start_network64:
    call legacy_shards_ensure_init64

  ; do not kill the singleton transport until the shared resolver is ready.
  ; shard tcp start hard-requires legacy_dns_ready, so taking over
    cmp dword [rel legacy_dns_state], LEGACY_DNS_READY
    jne .dns_not_ready

    call legacy_shards_takeover_singleton64
    xor ecx, ecx
    call legacy_shards_arm_lease64
    call legacy_shards_prepare_all64
    test eax, eax
    jnz .bad
    mov dword [rel shard_network_enabled], 1
    lea rsi, [rel msg_shards_net_on]
    call serial_puts64
    xor eax, eax
    ret
.dns_not_ready:
    lea rsi, [rel msg_shards_dns_wait]
    call serial_puts64
    mov eax, 1
    ret
.bad:
    lea rsi, [rel msg_shards_prep_fail]
    call serial_puts64
    mov eax, 1
    ret

legacy_shards_stop_network64:
    mov dword [rel shard_network_enabled], 0
    push rbx
    xor ebx, ebx
.stop_loop:
    cmp ebx, [rel shard_active_count]
    jae .stopped
    mov ecx, ebx
    call legacy_shards_get_ctx64
    test rax, rax
    jz .stopped
    mov rcx, rax
    call legacy_shard_tcp_abort64
    inc ebx
    jmp .stop_loop
.stopped:
    pop rbx
    lea rsi, [rel msg_shards_net_off]
    call serial_puts64
    xor eax, eax
    ret

legacy_shards_print64:
    call legacy_shards_ensure_init64

  ; summarize lifecycle states first so large shard plans are readable at a
  ; glance.
    mov dword [rel shard_health_ready], 0
    mov dword [rel shard_health_starting], 0
    mov dword [rel shard_health_backoff], 0
    mov dword [rel shard_health_fatal], 0
    xor ebx, ebx
.count_loop:
    cmp ebx, [rel shard_active_count]
    jae .count_done
    mov ecx, ebx
    call legacy_shards_get_ctx64
    test rax, rax
    jz .count_done
    mov edx, [rax + SHARD_OFF_STATE]
    cmp edx, SHARD_STATE_READY
    je .count_ready
    cmp edx, SHARD_STATE_STARTING
    je .count_starting
    cmp edx, SHARD_STATE_BACKOFF
    je .count_backoff
    cmp edx, SHARD_STATE_FATAL
    je .count_fatal
    jmp .count_next
.count_ready:
    inc dword [rel shard_health_ready]
    jmp .count_next
.count_starting:
    inc dword [rel shard_health_starting]
    jmp .count_next
.count_backoff:
    inc dword [rel shard_health_backoff]
    jmp .count_next
.count_fatal:
    inc dword [rel shard_health_fatal]
.count_next:
    inc ebx
    jmp .count_loop
.count_done:
    lea rsi, [rel msg_shards_health]
    call serial_puts64
    mov eax, [rel shard_health_ready]
    call serial_hex32_64
    lea rsi, [rel msg_shards_health_start]
    call serial_puts64
    mov eax, [rel shard_health_starting]
    call serial_hex32_64
    lea rsi, [rel msg_shards_health_backoff]
    call serial_puts64
    mov eax, [rel shard_health_backoff]
    call serial_hex32_64
    lea rsi, [rel msg_shards_health_fatal]
    call serial_puts64
    mov eax, [rel shard_health_fatal]
    call serial_hex32_64
    lea rsi, [rel msg_crlf64]
    call serial_puts64

    lea rsi, [rel msg_shards_total]
    call serial_puts64
    mov eax, [rel shard_total_global]
    call serial_hex32_64

    lea rsi, [rel msg_shards_start]
    call serial_puts64
    mov eax, [rel shard_local_start]
    call serial_hex32_64

    lea rsi, [rel msg_shards_count]
    call serial_puts64
    mov eax, [rel shard_local_count]
    call serial_hex32_64

    lea rsi, [rel msg_shards_generation]
    call serial_puts64
    mov rax, [rel shard_plan_generation]
    call serial_hex64

    lea rsi, [rel msg_shards_ticks]
    call serial_puts64
    mov rax, [rel shard_scheduler_ticks]
    call serial_hex64

    lea rsi, [rel msg_crlf64]
    call serial_puts64

    xor ebx, ebx
.ctx_loop:
    cmp ebx, [rel shard_active_count]
    jae .done
    mov ecx, ebx
    call legacy_shards_get_ctx64
    test rax, rax
    jz .done
    mov r12, rax

    lea rsi, [rel msg_shard_slot]
    call serial_puts64
    mov eax, ebx
    call serial_hex32_64
    lea rsi, [rel msg_shard_id]
    call serial_puts64
    mov eax, [r12 + SHARD_OFF_ID]
    call serial_hex32_64
    lea rsi, [rel msg_shard_state]
    call serial_puts64
    mov eax, [r12 + SHARD_OFF_STATE]
    call serial_hex32_64
    lea rsi, [rel msg_shard_bucket]
    call serial_puts64
    mov eax, [r12 + SHARD_OFF_IDENTIFY_BUCKET]
    call serial_hex32_64
    lea rsi, [rel msg_shard_seq]
    call serial_puts64
    mov eax, [r12 + SHARD_OFF_SEQUENCE]
    call serial_hex32_64

    lea rsi, [rel msg_shard_tcp]
    call serial_puts64
    mov r11, [r12 + SHARD_OFF_TCP_CTX]
    test r11, r11
    jz .tcp_zero
    mov eax, [r11 + 0]
    jmp .tcp_print
.tcp_zero:
    xor eax, eax
.tcp_print:
    call serial_hex32_64

    lea rsi, [rel msg_shard_tls]
    call serial_puts64
    mov r11, [r12 + SHARD_OFF_TLS_CTX]
    test r11, r11
    jz .tls_zero
    mov eax, [r11 + 0]
    jmp .tls_print
.tls_zero:
    xor eax, eax
.tls_print:
    call serial_hex32_64

    lea rsi, [rel msg_shard_hb]
    call serial_puts64
    mov rax, [r12 + SHARD_OFF_HEARTBEATS_SENT]
    call serial_hex64
    lea rsi, [rel msg_shard_ack]
    call serial_puts64
    mov rax, [r12 + SHARD_OFF_HEARTBEAT_ACKS]
    call serial_hex64

    lea rsi, [rel msg_shard_recon]
    call serial_puts64
    mov rax, [r12 + SHARD_OFF_RECONNECTS]
    call serial_hex64
    lea rsi, [rel msg_shard_err]
    call serial_puts64
    mov eax, [r12 + SHARD_OFF_LAST_ERROR]
    call serial_hex32_64

    lea rsi, [rel msg_crlf64]
    call serial_puts64

    inc ebx
    jmp .ctx_loop
.done:
    ret

align 16
shard_initialized      dd 0
shard_total_global     dd 1
shard_local_start      dd 0
shard_local_count      dd 1
shard_active_count     dd 0
shard_network_enabled  dd 0
shard_resources_allocated dd 0
shard_identify_concurrency dd 1
shard_scheduler_cursor dd 0
shard_identify_wave_deadline dq 0
shard_connect_wave_deadline dq 0
shard_plan_generation  dq 1
shard_scheduler_ticks  dq 0
shard_parallel_enabled dd 0
shard_parallel_announced dd 0
shard_crypto_lock      dd 0
align 8
shard_worker_tick_count times MAX_CPUS dq 0
shard_lease_deadline   dq 0
shard_lease_expired    dd 0
shard_singleton_taken_over dd 0
shard_replan_old_count dd 0
shard_replan_span      dd 0
shard_replan_resume_network dd 0
shard_health_ready     dd 0
shard_health_starting  dd 0
shard_health_backoff   dd 0
shard_health_fatal     dd 0
align 16
shard_worker_ready     times MAX_CPUS dd 0
shard_worker_starting  times MAX_CPUS dd 0
shard_worker_backoff   times MAX_CPUS dd 0
shard_worker_fatal     times MAX_CPUS dd 0
shard_contexts         times (LEGACY_SHARD_MAX * LEGACY_SHARD_CTX_SIZE) db 0
; discord currently advertises max_concurrency values far below this cap, but
; 1024 keeps the scheduler independent of a particular deployment.
shard_identify_bucket_used times 1024 db 0
shard_connect_bucket_used times 1024 db 0

msg_shards_ready      db '[SHARD] context pool ready, max=0x00000080',13,10,0
msg_shards_net_on     db '[SHARD] shard TCP scheduler enabled (stable BSP mode)',13,10,0
msg_shards_dns_wait   db '[SHARD] not started: gateway DNS is not ready; singleton left untouched',13,10,0
msg_shards_parallel_on db '[SHARD] SMP shard workers active; contexts striped across APs',13,10,0
msg_shards_parallel_fail db '[SHARD] SMP shard dispatch failed; falling back to BSP shard ticks',13,10,0
msg_shards_net_off    db '[SHARD] shard scheduler stopped; reboot to return to singleton Gateway mode',13,10,0
msg_shards_prep_fail   db '[SHARD] could not allocate private connection state',13,10,0
msg_shards_prepare_slot db '[SHARD] private connection allocation failed at local slot 0x',0
msg_shards_lease_expired db '[SHARD] controller lease expired; shard traffic stopped',13,10,0
msg_shards_replan_ok   db '[SHARD] live shard ownership plan rebuilt',13,10,0
msg_shards_replan_fail db '[SHARD] live shard replan failed; scheduler stopped',13,10,0
msg_shards_takeover    db '[SHARD] singleton Gateway stopped; shard pool owns Discord transport now',13,10,0
msg_shards_test2       db '[SHARDTEST] two-shard bring-up started: shard 0 then shard 1',13,10,0
msg_shards_test2_config db '[SHARDTEST] token/config is not ready',13,10,0
msg_shards_test2_fail  db '[SHARDTEST] two-shard bring-up could not start',13,10,0
msg_shards_test_pass   db '[SHARDTEST] PASS: 2/2 isolated shards READY with TLS + heartbeat ACKs',13,10,0
msg_shards_test_isolation db '[SHARDTEST] FAIL: shard contexts are not isolated',13,10,0
msg_shards_test_wait   db '[SHARDTEST] not passed yet; current shard state follows',13,10,0
msg_shards_connect_admit db 'connection admitted for this Identify wave',13,10,0
msg_shards_plan_ok    db '[SHARD] local test plan applied; Identify concurrency forced to 1 until /gateway/bot is wired',13,10,0
msg_shards_plan_bad   db 'usage: shardplan <total> <start> <count> [max-concurrency]',13,10,0
msg_shards_reset_ok   db '[SHARD] local shard connection reset',13,10,0
msg_shards_reset_bad  db 'usage: shardreset <local-slot>',13,10,0
msg_shards_lease_set  db '[SHARD] lease deadline updated',13,10,0
msg_shards_lease_bad  db 'usage: shardlease <seconds>',13,10,0
msg_shards_health     db 'health ready=0x',0
msg_shards_health_start db ' starting=0x',0
msg_shards_health_backoff db ' backoff=0x',0
msg_shards_health_fatal db ' fatal=0x',0
msg_shards_total      db 'total=0x',0
msg_shards_start      db ' local-start=0x',0
msg_shards_count      db ' local-count=0x',0
msg_shards_generation db ' generation=0x',0
msg_shards_ticks      db ' ticks=0x',0
msg_shard_slot        db ' slot=0x',0
msg_shard_id          db ' shard=0x',0
msg_shard_state       db ' state=0x',0
msg_shard_bucket      db ' bucket=0x',0
msg_shard_seq         db ' seq=0x',0
msg_shard_tcp         db ' tcp=0x',0
msg_shard_tls         db ' tls=0x',0
msg_shard_hb          db ' hb=0x',0
msg_shard_ack         db ' ack=0x',0
msg_shard_recon       db ' reconn=0x',0
msg_shard_err         db ' err=0x',0
msg_shard_log_prefix  db '[SHARD 0x',0
msg_shard_log_suffix  db '] ',0


; shard-specific gateway helpers are compiled next to the context pool but are
; not wired into the proven singleton transport until
%include "legacy_shard_gateway.inc"
