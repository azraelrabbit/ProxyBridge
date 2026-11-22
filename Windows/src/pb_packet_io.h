/* Private to pb_datapath.c. One send in flight preserves injection order.
 * Receive storage is loaned to the sender until completion, never recycled while
 * the driver can still read it. Deferred/classified packets use two copy buffers. */
#define PB_RECEIVE_SLOTS 3
#define PB_COPY_SLOTS 2
#define PB_STATS_INTERVAL_MS 10000
#define PB_BULK_MIN_BYTES (16 * 1024)
#define PB_BULK_MIN_PACKETS 8
#define PB_QUEUE_BUCKETS 12

typedef struct {
    unsigned char *data;
    UINT bytes, count, sent;
    BOOL leased;
    WINDIVERT_ADDRESS addr[PB_BATCH_COUNT];
    UINT lengths[PB_BATCH_COUNT];
} IO_BATCH;

typedef struct {
    IO_BATCH output;
    unsigned char storage[PB_BATCH_BYTES];
    WINDIVERT_ADDRESS addresses[PB_BATCH_COUNT];
    OVERLAPPED ov;
    UINT bytes, addr_bytes;
    BOOL pending;
} RECEIVE_SLOT;

typedef struct { IO_BATCH output; unsigned char storage[PB_BATCH_BYTES]; } COPY_SLOT;

typedef struct {
    UINT64 rx_batches, rx_packets, rx_bytes;
    UINT64 tx_batches, tx_packets, tx_bytes;
    UINT64 copied_bytes, reused_bytes, rx_errors, tx_errors;
    UINT64 work_ticks, submit_ticks, send_wait_ticks, classify_wait_ticks;
    UINT64 parse_calls, parse_samples, parse_ticks;
    UINT64 cache_calls, cache_samples, cache_ticks;
    UINT64 recv_submit_ticks, worker_batches, inline_batches;
    UINT64 queue_histogram[PB_QUEUE_BUCKETS];
    UINT pending_peak_bytes, pending_peak_packets;
} IO_STATS;

typedef struct {
    BOOL ok, queue_valid;
    UINT sent;
    DWORD error;
    ULONGLONG submit_ticks, oldest_queue_ticks;
} SEND_RESULT;

typedef struct {
    HANDLE capture, worker, work_event, ready_event;
    SRWLOCK jobs_lock;
    PENDING *jobs_head, *jobs_tail, *done_head, *done_tail;
    PENDING *pending[PB_PENDING_BUCKETS];
    volatile LONG stopping;
    UINT pending_bytes, pending_packets, pending_flows;
    RECEIVE_SLOT receives[PB_RECEIVE_SLOTS];
    COPY_SLOT copies[PB_COPY_SLOTS];
    RECEIVE_SLOT *reading;
    IO_BATCH *building, *inflight;
    OVERLAPPED send_ov;
    HANDLE send_thread, send_work_event, send_done_event, send_shutdown_event;
    IO_BATCH *send_job;
    SEND_RESULT send_result;
    BOOL inflight_offloaded;
    IO_STATS stats, reported;
    LARGE_INTEGER clock_frequency;
    ULONGLONG report_tick;
    DWORD recv_fail_streak;
} PIPELINE;

static const UINT g_queue_upper_us[PB_QUEUE_BUCKETS] = { 100, 250, 500, 1000, 2000, 4000, 8000, 16000, 32000, 64000, 128000, 0xffffffffu };

static __declspec(thread) PIPELINE *g_pipeline;
static HANDLE g_start_event;
static volatile LONG g_start_ok;

static ULONGLONG perf_tick(void)
{
    LARGE_INTEGER value; QueryPerformanceCounter(&value); return (ULONGLONG)value.QuadPart;
}

/* Sample timing once per 1024 calls, rather than adding two clock reads to
 * every packet's parser and cache lookup. Counters belong to the packet thread. */
static ULONGLONG sample_begin(BOOL parser)
{
    PIPELINE *p = g_pipeline;
    if (!p) return 0;
    UINT64 *calls = parser ? &p->stats.parse_calls : &p->stats.cache_calls;
    return ((++*calls & 1023) == 0) ? perf_tick() : 0;
}

static void sample_end(BOOL parser, ULONGLONG begin)
{
    if (!begin) return;
    PIPELINE *p = g_pipeline;
    if (parser) { p->stats.parse_ticks += perf_tick() - begin; p->stats.parse_samples++; }
    else { p->stats.cache_ticks += perf_tick() - begin; p->stats.cache_samples++; }
}

static void queue_percentile(const IO_STATS *s, const IO_STATS *old, UINT percentile, char text[24])
{
    UINT64 total = 0, cumulative = 0;
    for (UINT i = 0; i < PB_QUEUE_BUCKETS; i++) total += s->queue_histogram[i] - old->queue_histogram[i];
    if (!total) { strcpy_s(text, 24, "n/a"); return; }
    UINT64 wanted = (total * percentile + 99) / 100;
    for (UINT i = 0; i < PB_QUEUE_BUCKETS; i++) {
        cumulative += s->queue_histogram[i] - old->queue_histogram[i];
        if (cumulative >= wanted) {
            if (i == PB_QUEUE_BUCKETS - 1) strcpy_s(text, 24, ">128ms");
            else snprintf(text, 24, "<=%.2fms", g_queue_upper_us[i] / 1000.0);
            return;
        }
    }
}

static void note_submission(PIPELINE *p, const SEND_RESULT *result)
{
    p->stats.submit_ticks += result->submit_ticks;
    if (result->queue_valid) {
        double us = result->oldest_queue_ticks * 1000000.0 / p->clock_frequency.QuadPart;
        UINT bucket = 0;
        while (bucket + 1 < PB_QUEUE_BUCKETS && us > g_queue_upper_us[bucket]) bucket++;
        p->stats.queue_histogram[bucket]++;
    }
}

/* OVERLAPPED does not necessarily offload the driver's synchronous CPU work.
 * Small batches stay inline; bulk batches run on one actual sender thread. */
static SEND_RESULT submit_batch(PIPELINE *p, IO_BATCH *batch)
{
    SEND_RESULT result = {0};
    HANDLE event = p->send_ov.hEvent;
    ZeroMemory(&p->send_ov, sizeof(p->send_ov)); p->send_ov.hEvent = event;
    ResetEvent(event); batch->sent = 0;
    ULONGLONG begin = perf_tick(), oldest = begin;
    for (UINT i = 0; i < batch->count; i++) {
        LONGLONG timestamp = batch->addr[i].Timestamp;
        if (timestamp > 0 && (ULONGLONG)timestamp <= begin) {
            if ((ULONGLONG)timestamp < oldest) oldest = (ULONGLONG)timestamp;
            result.queue_valid = TRUE;
        }
    }
    result.oldest_queue_ticks = begin - oldest;
    result.ok = WinDivertSendEx(p->capture, batch->data, batch->bytes, &batch->sent, 0,
        batch->addr, batch->count * sizeof(WINDIVERT_ADDRESS), &p->send_ov);
    result.error = result.ok ? ERROR_SUCCESS : GetLastError();
    result.submit_ticks = perf_tick() - begin;
    result.sent = batch->sent;
    if (result.ok && result.sent != batch->bytes) result.error = ERROR_WRITE_FAULT;
    return result;
}

static DWORD WINAPI bulk_sender(void *argument)
{
    PIPELINE *p = argument;
    HANDLE waits[] = {p->send_work_event, p->send_shutdown_event};
    for (;;) {
        DWORD wake = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (wake != WAIT_OBJECT_0) break;
        IO_BATCH *batch = p->send_job;
        SEND_RESULT result = {0};
        if (WaitForSingleObject(p->send_shutdown_event, 0) == WAIT_OBJECT_0) result.error = ERROR_OPERATION_ABORTED;
        else {
            result = submit_batch(p, batch);
            if (!result.ok && result.error == ERROR_IO_PENDING) {
                HANDLE completion[] = {p->send_ov.hEvent, p->send_shutdown_event};
                if (WaitForMultipleObjects(2, completion, FALSE, INFINITE) != WAIT_OBJECT_0)
                    CancelIoEx(p->capture, &p->send_ov);
                DWORD sent = 0;
                result.ok = GetOverlappedResult(p->capture, &p->send_ov, &sent, TRUE);
                result.error = result.ok ? (sent == batch->bytes ? ERROR_SUCCESS : ERROR_WRITE_FAULT) : GetLastError();
                result.sent = sent;
            }
        }
        p->send_result = result;
        p->send_job = NULL;
        SetEvent(p->send_done_event);
    }
    return 0;
}

static void report_stats(PIPELINE *p, BOOL force)
{
    ULONGLONG now = GetTickCount64(), elapsed = now - p->report_tick;
    if (!force && elapsed < PB_STATS_INTERVAL_MS) return;
    IO_STATS *s = &p->stats, *old = &p->reported;
    UINT64 rx = s->rx_packets - old->rx_packets, tx = s->tx_packets - old->tx_packets;
    if ((rx || tx) && elapsed) {
        UINT64 rb = s->rx_batches - old->rx_batches, tb = s->tx_batches - old->tx_batches;
        UINT64 copied = s->copied_bytes - old->copied_bytes, reused = s->reused_bytes - old->reused_bytes;
        double ms_per_tick = 1000.0 / (double)p->clock_frequency.QuadPart;
        UINT64 parses = s->parse_samples - old->parse_samples, caches = s->cache_samples - old->cache_samples;
        char p95[24], p99[24]; queue_percentile(s, old, 95, p95); queue_percentile(s, old, 99, p99);
        log_message("[Datapath v3.1] %.1fs: rx=%llu packets avg=%.1f/batch; tx=%llu avg=%.1f/batch %.1f MiB/s; reused=%.1f%%; pending_peak=%u packets/%u KiB; errors rx=%llu tx=%llu",
            elapsed / 1000.0, rx, rb ? (double)rx / rb : 0, tx, tb ? (double)tx / tb : 0,
            (s->tx_bytes - old->tx_bytes) * 1000.0 / elapsed / (1024.0 * 1024.0),
            copied + reused ? reused * 100.0 / (copied + reused) : 0,
            s->pending_peak_packets, s->pending_peak_bytes / 1024,
            s->rx_errors - old->rx_errors, s->tx_errors - old->tx_errors);
        log_message("[Datapath v3.1] work=%.1fms submit=%.1fms send_wait=%.1fms classify_wait=%.1fms; sampled parse=%.2fus(%llu) cache=%.2fus(%llu); recv_submit=%.1fms bulk_worker=%llu inline=%llu; batch_oldest_capture_to_submit P95:%s P99:%s",
            (s->work_ticks - old->work_ticks) * ms_per_tick,
            (s->submit_ticks - old->submit_ticks) * ms_per_tick,
            (s->send_wait_ticks - old->send_wait_ticks) * ms_per_tick,
            (s->classify_wait_ticks - old->classify_wait_ticks) * ms_per_tick,
            parses ? (s->parse_ticks - old->parse_ticks) * ms_per_tick * 1000.0 / parses : 0, parses,
            caches ? (s->cache_ticks - old->cache_ticks) * ms_per_tick * 1000.0 / caches : 0, caches,
            (s->recv_submit_ticks - old->recv_submit_ticks) * ms_per_tick,
            s->worker_batches - old->worker_batches, s->inline_batches - old->inline_batches, p95, p99);
    }
    s->pending_peak_packets = p->pending_packets;
    s->pending_peak_bytes = p->pending_bytes;
    p->reported = *s; p->report_tick = now;
}

BOOL pb_packet_thread_start(HANDLE *thread)
{
    g_start_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_start_event) return FALSE;
    InterlockedExchange(&g_start_ok, 0);
    *thread = CreateThread(NULL, 0, packet_processor, NULL, 0, NULL);
    if (*thread) WaitForSingleObject(g_start_event, INFINITE);
    BOOL ok = *thread && g_start_ok;
    CloseHandle(g_start_event); g_start_event = NULL;
    return ok;
}

static BOOL io_init(PIPELINE *p)
{
    QueryPerformanceFrequency(&p->clock_frequency); p->report_tick = GetTickCount64();
    for (int i = 0; i < PB_RECEIVE_SLOTS; i++) {
        p->receives[i].output.data = p->receives[i].storage;
        p->receives[i].ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!p->receives[i].ov.hEvent) return FALSE;
    }
    for (int i = 0; i < PB_COPY_SLOTS; i++) p->copies[i].output.data = p->copies[i].storage;
    p->send_ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    p->send_work_event = CreateEventW(NULL, FALSE, FALSE, NULL);
    p->send_done_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    p->send_shutdown_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!p->send_ov.hEvent || !p->send_work_event || !p->send_done_event || !p->send_shutdown_event) return FALSE;
    p->send_thread = CreateThread(NULL, 0, bulk_sender, p, 0, NULL);
    return p->send_thread != NULL;
}

static void finish_send(PIPELINE *p, IO_BATCH *batch, BOOL ok, UINT sent, DWORD error)
{
    UINT prefix = 0, first = 0;
    while (first < batch->count && prefix < sent) prefix += batch->lengths[first++];
    if (prefix == sent) p->stats.tx_bytes += sent;
    if (!ok || sent != batch->bytes) {
        UINT64 n = ++p->stats.tx_errors;
        if (n <= 10 || n % 500 == 0)
            log_message("Packet batch injection incomplete (error %lu, %u/%u bytes, %llu failures)", error, sent, batch->bytes, n);
        /* Only a confirmed whole-packet suffix may be recovered. Never repeat an
         * already-injected prefix, and never recover a cancelled send on Stop. */
        if (prefix == sent && error != ERROR_OPERATION_ABORTED) {
            for (UINT i = first; i < batch->count; i++) {
                if (WinDivertSend(p->capture, batch->data + prefix, batch->lengths[i], NULL, &batch->addr[i]))
                    p->stats.tx_bytes += batch->lengths[i];
                else {
                    p->stats.tx_errors++;
                    if (n <= 10 || n % 500 == 0) log_message("Packet injection recovery failed (%lu)", GetLastError());
                }
                prefix += batch->lengths[i];
            }
        }
    }
    batch->bytes = batch->count = 0; batch->leased = FALSE;
}

static BOOL complete_send(PIPELINE *p, BOOL wait)
{
    if (!p->inflight) return TRUE;
    ULONGLONG begin = wait ? perf_tick() : 0;
    HANDLE completion = p->inflight_offloaded ? p->send_done_event : p->send_ov.hEvent;
    DWORD result = WaitForSingleObject(completion, wait ? INFINITE : 0);
    if (wait) p->stats.send_wait_ticks += perf_tick() - begin;
    if (result == WAIT_TIMEOUT) return FALSE;
    if (p->inflight_offloaded) {
        note_submission(p, &p->send_result);
        finish_send(p, p->inflight, p->send_result.ok, p->send_result.sent, p->send_result.error);
    } else {
        DWORD sent = 0;
        BOOL ok = GetOverlappedResult(p->capture, &p->send_ov, &sent, FALSE);
        DWORD error = ok ? (sent == p->inflight->bytes ? ERROR_SUCCESS : ERROR_WRITE_FAULT) : GetLastError();
        finish_send(p, p->inflight, ok, sent, error);
    }
    p->inflight = NULL;
    p->inflight_offloaded = FALSE;
    return TRUE;
}

static void flush_send(PIPELINE *p)
{
    IO_BATCH *batch = p->building;
    if (!batch) return;
    p->building = NULL;
    if (!batch->count) { batch->leased = FALSE; return; }
    complete_send(p, TRUE);  /* global submission order, including classified flows */
    p->stats.tx_batches++; p->stats.tx_packets += batch->count;
    if (batch->bytes >= PB_BULK_MIN_BYTES && batch->count >= PB_BULK_MIN_PACKETS) {
        p->stats.worker_batches++; p->inflight = batch; p->inflight_offloaded = TRUE;
        ResetEvent(p->send_done_event);
        p->send_job = batch;
        SetEvent(p->send_work_event);
    } else {
        p->stats.inline_batches++;
        SEND_RESULT result = submit_batch(p, batch);
        note_submission(p, &result);
        if (!result.ok && result.error == ERROR_IO_PENDING) p->inflight = batch;
        else finish_send(p, batch, result.ok, result.sent, result.error);
    }
}

static IO_BATCH *copy_batch(PIPELINE *p)
{
    for (int i = 0; i < PB_COPY_SLOTS; i++) {
        IO_BATCH *b = &p->copies[i].output;
        if (!b->leased) { b->leased = TRUE; b->bytes = b->count = 0; return b; }
    }
    complete_send(p, TRUE);
    for (int i = 0; i < PB_COPY_SLOTS; i++) {
        IO_BATCH *b = &p->copies[i].output;
        if (!b->leased) { b->leased = TRUE; b->bytes = b->count = 0; return b; }
    }
    return NULL;
}

BOOL pb_packet_send(const void *packet, UINT len, const WINDIVERT_ADDRESS *addr)
{
    PIPELINE *p = g_pipeline;
    if (!p) return WinDivertSend(windivert_handle, packet, len, NULL, addr);
    if (len > PB_BATCH_BYTES) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    if (p->building && (p->building->count == PB_BATCH_COUNT || p->building->bytes + len > PB_BATCH_BYTES)) flush_send(p);
    if (!p->building) p->building = copy_batch(p);
    if (!p->building) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    IO_BATCH *batch = p->building;
    unsigned char *destination = batch->data + batch->bytes;
    if (destination != packet) { memmove(destination, packet, len); p->stats.copied_bytes += len; }
    else p->stats.reused_bytes += len;
    batch->lengths[batch->count] = len; batch->addr[batch->count++] = *addr; batch->bytes += len;
    return TRUE;
}

/* There is one outstanding receive. It is posted before processing the previous
 * buffer, so no receive-order ambiguity is introduced by multiple read requests. */
static int post_receive(PIPELINE *p)
{
    if (p->reading) return 1;
    RECEIVE_SLOT *slot = NULL;
    for (int i = 0; i < PB_RECEIVE_SLOTS; i++)
        if (!p->receives[i].output.leased) { slot = &p->receives[i]; break; }
    if (!slot) { complete_send(p, TRUE); return 0; }
    slot->output.leased = TRUE; slot->output.bytes = slot->output.count = 0;
    slot->bytes = 0; slot->addr_bytes = sizeof(slot->addresses);
    HANDLE event = slot->ov.hEvent;
    ZeroMemory(&slot->ov, sizeof(slot->ov)); slot->ov.hEvent = event; ResetEvent(event);
    ULONGLONG begin = perf_tick();
    BOOL ok = WinDivertRecvEx(p->capture, slot->storage, sizeof(slot->storage), &slot->bytes, 0,
        slot->addresses, &slot->addr_bytes, &slot->ov);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    p->stats.recv_submit_ticks += perf_tick() - begin;
    if (ok || error == ERROR_IO_PENDING) {
        slot->pending = !ok; p->reading = slot; return 1;
    }
    slot->output.leased = FALSE; p->stats.rx_errors++;
    if (!running || error == ERROR_NO_DATA || error == ERROR_INVALID_HANDLE || error == ERROR_OPERATION_ABORTED) return -1;
    if (++p->recv_fail_streak == 1 || p->recv_fail_streak % 1000 == 0)
        log_message("Packet batch capture failed (%lu, %lu consecutive failures)", error, p->recv_fail_streak);
    return 0;
}

static void io_destroy(PIPELINE *p)
{
    for (int i = 0; i < PB_RECEIVE_SLOTS; i++) {
        RECEIVE_SLOT *slot = &p->receives[i];
        if (slot->pending) {
            DWORD ignored;
            CancelIoEx(p->capture, &slot->ov);
            GetOverlappedResult(p->capture, &slot->ov, &ignored, TRUE);
            slot->pending = FALSE;
        }
        if (slot->ov.hEvent) CloseHandle(slot->ov.hEvent);
    }
    if (p->send_shutdown_event) SetEvent(p->send_shutdown_event);
    if (p->inflight) {
        if (!running && !p->inflight_offloaded) CancelIoEx(p->capture, &p->send_ov);
        complete_send(p, TRUE);
    }
    if (p->send_thread) { WaitForSingleObject(p->send_thread, INFINITE); CloseHandle(p->send_thread); }
    if (p->send_work_event) CloseHandle(p->send_work_event);
    if (p->send_done_event) CloseHandle(p->send_done_event);
    if (p->send_shutdown_event) CloseHandle(p->send_shutdown_event);
    if (p->send_ov.hEvent) CloseHandle(p->send_ov.hEvent);
}
