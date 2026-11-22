#include "pb_internal.h"

/* One packet consumer owns all rewriting and injection. Only new-flow classification
 * runs on a worker; a pending flow holds its packets until its first verdict arrives.
 * No queue-full or lookup-pending path is allowed to invent a DIRECT verdict. */
#define PB_BATCH_COUNT 64
#define PB_BATCH_BYTES (256 * 1024)
#define PB_PENDING_BUCKETS 256
#define PB_PENDING_BYTES (16 * 1024 * 1024)
#define PB_PENDING_PACKETS 8192
#define PB_DIRECT_BUCKETS 16384
#define PB_DIRECT_WAYS 4

__declspec(thread) const PB_DECISION *pb_current_decision;
__declspec(thread) PB_DECISION *pb_resolving_decision;
__declspec(thread) const PB_PACKET_VIEW *pb_current_packet;

static ULONGLONG sample_begin(BOOL parser);
static void sample_end(BOOL parser, ULONGLONG begin);

static UINT32 flow_hash(const PB_FLOW_KEY *k)
{
    UINT32 h = 2166136261u;
    for (int i = 0; i < 16; i++) { h = (h ^ k->local[i]) * 16777619u; h = (h ^ k->remote[i]) * 16777619u; }
    h = (h ^ k->local_port) * 16777619u;
    h = (h ^ k->remote_port) * 16777619u;
    return (h ^ ((UINT32)k->ipv6 << 8) ^ k->protocol) * 16777619u;
}

void pb_packet_view(const void *packet, UINT len, PB_PACKET_VIEW *view)
{
    ULONGLONG sampled = sample_begin(TRUE);
    void *next = NULL; UINT remaining = 0;
    ZeroMemory(view, sizeof(*view));
    WinDivertHelperParsePacket(packet, len, &view->v4, &view->v6, NULL, NULL, NULL,
        &view->tcp, &view->udp, NULL, NULL, &next, &remaining);
    view->len = next ? (UINT)((const unsigned char *)next - (const unsigned char *)packet) : len;
    if ((!view->v4 && !view->v6) || (!view->tcp && !view->udp)) { sample_end(TRUE, sampled); return; }
    PB_FLOW_KEY *key = &view->key;
    key->ipv6 = view->v6 != NULL;
    memcpy(key->local, view->v6 ? (void *)view->v6->SrcAddr : (void *)&view->v4->SrcAddr, key->ipv6 ? 16 : 4);
    memcpy(key->remote, view->v6 ? (void *)view->v6->DstAddr : (void *)&view->v4->DstAddr, key->ipv6 ? 16 : 4);
    key->protocol = view->tcp ? IPPROTO_TCP : IPPROTO_UDP;
    key->local_port = ntohs(view->tcp ? view->tcp->SrcPort : view->udp->SrcPort);
    key->remote_port = ntohs(view->tcp ? view->tcp->DstPort : view->udp->DstPort);
    view->valid = TRUE;
    sample_end(TRUE, sampled);
}

BOOL pb_flow_key(const void *packet, UINT len, PB_FLOW_KEY *key)
{
    PB_PACKET_VIEW view; pb_packet_view(packet, len, &view);
    if (view.valid) *key = view.key;
    return view.valid;
}

typedef struct { PB_FLOW_KEY key; ULONGLONG until; } DIRECT_ENTRY;
static DIRECT_ENTRY g_direct[PB_DIRECT_BUCKETS][PB_DIRECT_WAYS];

BOOL pb_direct_cached(const PB_FLOW_KEY *key)
{
    ULONGLONG sampled = sample_begin(FALSE);
    DIRECT_ENTRY *bucket = g_direct[flow_hash(key) % PB_DIRECT_BUCKETS];
    ULONGLONG now = GetTickCount64();
    BOOL hit = FALSE;
    for (int i = 0; i < PB_DIRECT_WAYS; i++)
        if (bucket[i].until > now && memcmp(&bucket[i].key, key, sizeof(*key)) == 0) { hit = TRUE; break; }
    sample_end(FALSE, sampled);
    return hit;
}

void pb_direct_remember(const PB_FLOW_KEY *key)
{
    DIRECT_ENTRY *bucket = g_direct[flow_hash(key) % PB_DIRECT_BUCKETS];
    int slot = 0;
    for (int i = 0; i < PB_DIRECT_WAYS; i++) {
        if (memcmp(&bucket[i].key, key, sizeof(*key)) == 0) { slot = i; break; }
        if (bucket[i].until < bucket[slot].until) slot = i;
    }
    bucket[slot].key = *key;
    bucket[slot].until = GetTickCount64() + (key->protocol == IPPROTO_TCP ? CONNECTION_STALE_TIMEOUT_MS : UDP_DIRECT_TTL_MS);
}

void pb_direct_forget(const PB_FLOW_KEY *key)
{
    DIRECT_ENTRY *bucket = g_direct[flow_hash(key) % PB_DIRECT_BUCKETS];
    for (int i = 0; i < PB_DIRECT_WAYS; i++)
        if (memcmp(&bucket[i].key, key, sizeof(*key)) == 0) bucket[i].until = 0;
}

void pb_direct_reset(void) { ZeroMemory(g_direct, sizeof(g_direct)); }

typedef struct PACKET PACKET;
struct PACKET { PACKET *next; WINDIVERT_ADDRESS addr; UINT len; unsigned char data[1]; };
typedef struct PENDING PENDING;
struct PENDING {
    PENDING *hash_next, *job_next;
    PB_FLOW_KEY key;
    PACKET *head, *tail;
    PB_DECISION decision;
};
#include "pb_packet_io.h"

static DWORD WINAPI classify_worker(void *arg)
{
    PIPELINE *p = arg;
    for (;;) {
        if (p->stopping) break;
        AcquireSRWLockExclusive(&p->jobs_lock);
        PENDING *job = p->jobs_head;
        if (job) { p->jobs_head = job->job_next; if (!p->jobs_head) p->jobs_tail = NULL; }
        ReleaseSRWLockExclusive(&p->jobs_lock);
        if (!job) {
            if (p->stopping) break;
            WaitForSingleObject(p->work_event, INFINITE);
            continue;
        }
        PB_DECISION *d = &job->decision;
        pb_resolving_decision = d;
        if (job->key.protocol == IPPROTO_TCP && !job->key.ipv6) {
            PB_PACKET_VIEW view; pb_packet_view(job->head->data, job->head->len, &view);
            if (view.tcp && view.tcp->Syn && !view.tcp->Ack) {
                UINT32 local; memcpy(&local, job->key.local, 4);
                remove_cached_pid(local, job->key.local_port, FALSE);
            }
        }
        if (job->key.ipv6)
            d->action = check_process_rule_v6(job->key.local, job->key.local_port, job->key.remote,
                job->key.remote_port, job->key.protocol == IPPROTO_UDP, &d->pid, &d->proxy_id);
        else {
            UINT32 src, dst; memcpy(&src, job->key.local, 4); memcpy(&dst, job->key.remote, 4);
            d->action = check_process_rule(src, job->key.local_port, dst, job->key.remote_port,
                job->key.protocol == IPPROTO_UDP, &d->pid, &d->proxy_id);
        }
        d->rule_id = g_tl_rule_id; d->localhost = g_tl_rule_localhost;
        /* Also resolve the display name on this worker (the relay's auto-exempt PID
         * can return before the normal process-name lookup). */
        if (d->pid && !d->process[0]) get_process_name_from_pid(d->pid, d->process, sizeof(d->process));
        pb_resolving_decision = NULL;
        job->job_next = NULL;
        AcquireSRWLockExclusive(&p->jobs_lock);
        if (p->done_tail) p->done_tail->job_next = job; else p->done_head = job;
        p->done_tail = job;
        SetEvent(p->ready_event);
        ReleaseSRWLockExclusive(&p->jobs_lock);
    }
    return 0;
}

static void dispatch_packet(PIPELINE *p, const void *data, UINT len, const WINDIVERT_ADDRESS *addr, const PB_PACKET_VIEW *parsed);

static void drain_ready(PIPELINE *p)
{
    AcquireSRWLockExclusive(&p->jobs_lock);
    PENDING *done = p->done_head;
    p->done_head = p->done_tail = NULL;
    ResetEvent(p->ready_event);
    ReleaseSRWLockExclusive(&p->jobs_lock);
    while (done) {
        PENDING *next = done->job_next;
        UINT32 bucket = flow_hash(&done->key) % PB_PENDING_BUCKETS;
        PENDING **link = &p->pending[bucket];
        while (*link && *link != done) link = &(*link)->hash_next;
        if (*link) *link = done->hash_next;
        p->pending_flows--;
        PACKET *pkt = done->head;
        BOOL first = TRUE;
        while (pkt) {
            PACKET *following = pkt->next;
            p->pending_bytes -= pkt->len; p->pending_packets--;
            if (first) {
                pb_current_decision = &done->decision;
                pb_process_packet(pkt->data, pkt->len, &pkt->addr);
                pb_current_decision = NULL;
                first = FALSE;
            } else dispatch_packet(p, pkt->data, pkt->len, &pkt->addr, NULL);
            free(pkt); pkt = following;
        }
        free(done); done = next;
    }
}

static void dispatch_packet(PIPELINE *p, const void *data, UINT len, const WINDIVERT_ADDRESS *addr, const PB_PACKET_VIEW *parsed)
{
    PB_PACKET_VIEW local;
    if (!parsed) { pb_packet_view(data, len, &local); parsed = &local; }
    pb_current_packet = parsed;
    PB_FLOW_KEY key = parsed->key;
    if (!addr->Outbound || !parsed->valid) {
        pb_process_packet((void *)data, len, addr); pb_current_packet = NULL; return;
    }
    UINT32 bucket = flow_hash(&key) % PB_PENDING_BUCKETS;
    PENDING *job = p->pending[bucket];
    while (job && memcmp(&job->key, &key, sizeof(key)) != 0) job = job->hash_next;
    if (!job) {
        pb_process_packet((void *)data, len, addr); pb_current_packet = NULL; return;
    }
    pb_current_packet = NULL;
    pb_defer_packet(data, len, addr, &key);
}

BOOL pb_defer_packet(const void *data, UINT len, const WINDIVERT_ADDRESS *addr, const PB_FLOW_KEY *key)
{
    PIPELINE *p = g_pipeline;
    if (!p) return FALSE;  /* direct unit/API callers do not run the packet pipeline */
    UINT32 bucket = flow_hash(key) % PB_PENDING_BUCKETS;
    PENDING *job = p->pending[bucket];
    while (job && memcmp(&job->key, key, sizeof(*key)) != 0) job = job->hash_next;
    PACKET *pkt = malloc(offsetof(PACKET, data) + len);
    if (!pkt) {
        /* Allocation failure is fail-closed for a pending flow. TCP can retransmit;
         * forwarding an unclassified packet here would bypass PROXY/BLOCK rules. */
        log_message("Packet classification buffer allocation failed; packet dropped"); return TRUE;
    }
    pkt->next = NULL; pkt->addr = *addr; pkt->len = len; memcpy(pkt->data, data, len);
    if (job) { job->tail->next = pkt; job->tail = pkt; }
    else {
        job = calloc(1, sizeof(*job));
        if (!job) { free(pkt); log_message("Flow classification allocation failed; packet dropped"); return TRUE; }
        job->key = *key; job->head = job->tail = pkt;
        job->hash_next = p->pending[bucket]; p->pending[bucket] = job;
        p->pending_flows++;
        AcquireSRWLockExclusive(&p->jobs_lock);
        if (p->jobs_tail) p->jobs_tail->job_next = job; else p->jobs_head = job;
        p->jobs_tail = job;
        ReleaseSRWLockExclusive(&p->jobs_lock);
        SetEvent(p->work_event);
    }
    p->pending_bytes += len; p->pending_packets++;
    if (p->pending_bytes > p->stats.pending_peak_bytes) p->stats.pending_peak_bytes = p->pending_bytes;
    if (p->pending_packets > p->stats.pending_peak_packets) p->stats.pending_peak_packets = p->pending_packets;
    return TRUE;
}

DWORD WINAPI packet_processor(void *arg)
{
    (void)arg;
    PIPELINE *p = calloc(1, sizeof(*p));
    if (!p) goto finish;
    p->capture = windivert_handle;
    p->work_event = CreateEventW(NULL, FALSE, FALSE, NULL);
    p->ready_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!p->work_event || !p->ready_event || !io_init(p)) goto finish;
    p->worker = CreateThread(NULL, 0, classify_worker, p, 0, NULL);
    if (!p->worker) goto finish;
    g_pipeline = p;
    InterlockedExchange(&g_start_ok, 1);
    if (g_start_event) SetEvent(g_start_event);
    log_message("[Datapath v3.1] ordered bulk sender thread; small batches inline; summaries every 10s while active");
    while (running) {
        complete_send(p, FALSE);
        drain_ready(p);
        flush_send(p);
        report_stats(p, FALSE);
        if (!p->reading) {
            int result = post_receive(p);
            if (result < 0) break;
            if (!result) { Sleep(p->recv_fail_streak > 1000 ? 100 : 5); continue; }
        }
        RECEIVE_SLOT *slot = p->reading;
        if (slot->pending) {
            HANDLE waits[] = { slot->ov.hEvent, p->ready_event,
                p->inflight_offloaded ? p->send_done_event : p->send_ov.hEvent };
            DWORD w = WaitForMultipleObjects(p->inflight ? 3 : 2, waits, FALSE, INFINITE);
            if (w == WAIT_OBJECT_0 + 1 || w == WAIT_OBJECT_0 + 2) continue;
            if (w != WAIT_OBJECT_0) { log_message("Packet pipeline wait failed (%lu)", GetLastError()); break; }
            DWORD bytes = 0;
            BOOL ok = GetOverlappedResult(p->capture, &slot->ov, &bytes, FALSE);
            slot->pending = FALSE;
            if (!ok) {
                DWORD error = GetLastError();
                slot->output.leased = FALSE; p->reading = NULL; p->stats.rx_errors++;
                if (!running || error == ERROR_NO_DATA || error == ERROR_INVALID_HANDLE || error == ERROR_OPERATION_ABORTED) break;
                if (++p->recv_fail_streak == 1 || p->recv_fail_streak % 1000 == 0)
                    log_message("Packet batch completion failed (%lu)", error);
                Sleep(p->recv_fail_streak > 1000 ? 100 : 5); continue;
            }
            slot->bytes = bytes;
        }
        p->reading = NULL; p->recv_fail_streak = 0;
        UINT offset = 0, count = slot->addr_bytes / sizeof(WINDIVERT_ADDRESS);
        if (slot->addr_bytes % sizeof(WINDIVERT_ADDRESS) || count > PB_BATCH_COUNT || slot->bytes > PB_BATCH_BYTES) {
            p->stats.rx_errors++; log_message("Malformed receive batch metadata"); slot->output.leased = FALSE; continue;
        }
        p->stats.rx_batches++; p->stats.rx_packets += count; p->stats.rx_bytes += slot->bytes;
        /* The driver receives the next batch into different storage while this
         * thread parses/rewrites the current one and the previous send completes. */
        post_receive(p);
        /* Bound pending storage before starting a batch. A batch may overshoot by
         * at most PB_BATCH_COUNT packets/PB_BATCH_BYTES; never drain classified
         * heap packets into an active receive buffer's unprocessed region. */
        while (running && (p->pending_bytes >= PB_PENDING_BYTES || p->pending_packets >= PB_PENDING_PACKETS)) {
            drain_ready(p); flush_send(p);
            if (p->pending_bytes >= PB_PENDING_BYTES || p->pending_packets >= PB_PENDING_PACKETS) {
                ULONGLONG begin = perf_tick(); WaitForSingleObject(p->ready_event, 50);
                p->stats.classify_wait_ticks += perf_tick() - begin;
            }
        }
        p->building = &slot->output;
        ULONGLONG begin = perf_tick();
        for (UINT i = 0; i < count && offset < slot->bytes && running; i++) {
            PB_PACKET_VIEW view; pb_packet_view(slot->storage + offset, slot->bytes - offset, &view);
            UINT len = view.len;
            if (!len || len > slot->bytes - offset) { p->stats.rx_errors++; log_message("Malformed packet batch boundary"); break; }
            dispatch_packet(p, slot->storage + offset, len, &slot->addresses[i], &view);
            offset += len;
        }
        p->stats.work_ticks += perf_tick() - begin;
        flush_send(p);  /* no delay to accumulate an otherwise empty batch */
    }
finish:
    if (!g_pipeline && g_start_event) SetEvent(g_start_event);
    if (p) {
        if (g_pipeline) flush_send(p);
        io_destroy(p);  /* cancel/join I/O before releasing any packet/address storage */
        if (p->worker) {
            InterlockedExchange(&p->stopping, 1); SetEvent(p->work_event);
            WaitForSingleObject(p->worker, INFINITE); CloseHandle(p->worker);
            report_stats(p, TRUE);
        } else if (running) log_message("Packet pipeline initialization failed (%lu)", GetLastError());
        for (int i = 0; i < PB_PENDING_BUCKETS; i++) {
            PENDING *j = p->pending[i];
            while (j) {
                PENDING *n = j->hash_next; PACKET *pkt = j->head;
                while (pkt) { PACKET *pn = pkt->next; free(pkt); pkt = pn; }
                free(j); j = n;
            }
        }
        if (p->work_event) CloseHandle(p->work_event);
        if (p->ready_event) CloseHandle(p->ready_event);
        free(p);
    }
    g_pipeline = NULL;
    return 0;
}
