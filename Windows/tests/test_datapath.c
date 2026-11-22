/* No driver is opened. Real packet parsing, rule snapshots and scheduler queues;
 * capture/injection and slow classification are replaced with deterministic stubs. */
#include "pb_internal.h"
#include "pbtest.h"

static BOOL fake_send_ex(HANDLE, const VOID *, UINT, UINT *, UINT64, const WINDIVERT_ADDRESS *, UINT, LPOVERLAPPED);
static BOOL fake_send(HANDLE, const VOID *, UINT, UINT *, const WINDIVERT_ADDRESS *);
static BOOL fake_recv_ex(HANDLE, VOID *, UINT, UINT *, UINT64, WINDIVERT_ADDRESS *, UINT *, LPOVERLAPPED);
static BOOL fake_result(HANDLE, LPOVERLAPPED, LPDWORD, BOOL);
static BOOL fake_cancel(HANDLE, LPOVERLAPPED);
static void fake_process(void *, UINT, const WINDIVERT_ADDRESS *);
static RuleAction fake_classify(UINT32, UINT16, UINT32, UINT16, BOOL, DWORD *, UINT32 *);
static RuleAction fake_classify6(const UINT8 *, UINT16, const UINT8 *, UINT16, BOOL, DWORD *, UINT32 *);
#define WinDivertSendEx fake_send_ex
#define WinDivertSend fake_send
#define WinDivertRecvEx fake_recv_ex
#define GetOverlappedResult fake_result
#define CancelIoEx fake_cancel
#define pb_process_packet fake_process
#define check_process_rule fake_classify
#define check_process_rule_v6 fake_classify6
#include "../src/pb_datapath.c"
#undef WinDivertSendEx
#undef WinDivertSend
#undef WinDivertRecvEx
#undef GetOverlappedResult
#undef CancelIoEx
#undef pb_process_packet
#undef check_process_rule
#undef check_process_rule_v6

static UINT g_batch_calls, g_single_calls, g_injected, g_partial;
static unsigned char g_order[128];
static UINT g_order_count;
static HANDLE g_class_entered, g_class_release;
static BOOL g_async_send, g_async_receive, g_loop_test;
static struct {
    LPOVERLAPPED ov;
    const unsigned char *data;
    const WINDIVERT_ADDRESS *addr;
    unsigned char snapshot[PB_BATCH_BYTES];
    WINDIVERT_ADDRESS addresses[PB_BATCH_COUNT];
    UINT len, packets;
    BOOL cancelled;
} g_pending_send;
static LPOVERLAPPED g_pending_receive;
static BOOL g_receive_cancelled;
static UINT g_recv_calls, g_cancel_calls;
static unsigned char *g_receive_storage[2];
static UINT64 g_loop_copied, g_loop_reused;
static HANDLE g_sender_entered, g_sender_release;
static BOOL g_hold_sender;
static DWORD g_last_submit_thread;
static void packet4(unsigned char *, UINT16, UINT16, unsigned char);
static BOOL fake_send_ex(HANDLE h, const VOID *data, UINT len, UINT *sent, UINT64 flags,
                         const WINDIVERT_ADDRESS *addr, UINT addr_len, LPOVERLAPPED ov)
{
    (void)h; (void)flags;
    g_last_submit_thread = GetCurrentThreadId();
    if (g_hold_sender) { SetEvent(g_sender_entered); WaitForSingleObject(g_sender_release, INFINITE); }
    g_batch_calls++;
    if (g_partial) { *sent = 40; g_injected++; SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (g_async_send) {
        CHECK(ov != NULL && g_pending_send.ov == NULL);
        g_pending_send.ov = ov; g_pending_send.data = data; g_pending_send.addr = addr;
        g_pending_send.len = len; g_pending_send.packets = addr_len / sizeof(*addr); g_pending_send.cancelled = FALSE;
        memcpy(g_pending_send.snapshot, data, len); memcpy(g_pending_send.addresses, addr, addr_len);
        *sent = 0;
        if (g_loop_test) {
            CHECK(g_batch_calls <= 2 && data == g_receive_storage[g_batch_calls - 1]);
            g_loop_copied = g_pipeline->stats.copied_bytes; g_loop_reused = g_pipeline->stats.reused_bytes;
            if (g_batch_calls == 2) SetEvent(ov->hEvent);
        }
        if (g_sender_entered) SetEvent(g_sender_entered);
        SetLastError(ERROR_IO_PENDING); return FALSE;
    }
    *sent = len; g_injected += addr_len / sizeof(*addr);
    CHECK(((const unsigned char *)data)[0] == 0x45);
    return TRUE;
}
static BOOL fake_recv_ex(HANDLE h, VOID *data, UINT len, UINT *received, UINT64 flags,
                        WINDIVERT_ADDRESS *addr, UINT *addr_len, LPOVERLAPPED ov)
{
    (void)h; (void)len; (void)flags;
    g_recv_calls++;
    if (g_async_receive) {
        g_pending_receive = ov; g_receive_cancelled = FALSE;
        SetLastError(ERROR_IO_PENDING); return FALSE;
    }
    if (g_loop_test && g_recv_calls <= 2) {
        packet4(data, 62000, 445, (unsigned char)g_recv_calls);
        *received = 40; *addr_len = sizeof(*addr); ZeroMemory(addr, sizeof(*addr)); addr->Outbound = TRUE;
        g_receive_storage[g_recv_calls - 1] = data;
        return TRUE;
    }
    SetLastError(ERROR_NO_DATA); return FALSE;
}
static BOOL fake_result(HANDLE h, LPOVERLAPPED ov, LPDWORD bytes, BOOL wait)
{
    (void)h; (void)wait;
    if (ov == g_pending_send.ov) {
        CHECK(!memcmp(g_pending_send.data, g_pending_send.snapshot, g_pending_send.len));
        CHECK(!memcmp(g_pending_send.addr, g_pending_send.addresses, g_pending_send.packets * sizeof(WINDIVERT_ADDRESS)));
        BOOL cancelled = g_pending_send.cancelled;
        *bytes = cancelled ? 0 : g_pending_send.len;
        if (!cancelled) g_injected += g_pending_send.packets;
        g_pending_send.ov = NULL;
        if (cancelled) SetLastError(ERROR_OPERATION_ABORTED);
        return !cancelled;
    }
    CHECK(ov == g_pending_receive && g_receive_cancelled);
    g_pending_receive = NULL; *bytes = 0; SetLastError(ERROR_OPERATION_ABORTED); return FALSE;
}
static BOOL fake_cancel(HANDLE h, LPOVERLAPPED ov)
{
    (void)h; g_cancel_calls++;
    if (ov == g_pending_send.ov) g_pending_send.cancelled = TRUE;
    else if (ov == g_pending_receive) g_receive_cancelled = TRUE;
    else { CHECK(FALSE); SetLastError(ERROR_NOT_FOUND); return FALSE; }
    SetEvent(ov->hEvent); return TRUE;
}
static BOOL fake_send(HANDLE h, const VOID *data, UINT len, UINT *sent, const WINDIVERT_ADDRESS *addr)
{
    (void)h; (void)addr; g_single_calls++; g_injected++;
    if (sent) *sent = len;
    CHECK(((const unsigned char *)data)[0] == 0x45);
    return TRUE;
}
static void fake_process(void *packet, UINT len, const WINDIVERT_ADDRESS *addr)
{
    PB_PACKET_VIEW view; pb_packet_view(packet, len, &view);
    if (!pb_current_decision && !pb_direct_cached(&view.key) && pb_defer_packet(packet, len, addr, &view.key)) return;
    g_order[g_order_count++] = ((unsigned char *)packet)[39];
    if (pb_current_decision && pb_current_decision->action == RULE_ACTION_DIRECT) pb_direct_remember(&view.key);
    if (g_loop_test) {
        CHECK(g_recv_calls >= ((unsigned char *)packet)[39] + 1u);
        if (((unsigned char *)packet)[39] == 2) {
            CHECK(g_pending_send.ov != NULL); SetEvent(g_pending_send.ov->hEvent);
        }
        pb_packet_send(packet, len, addr);
    }
}
static RuleAction fake_classify(UINT32 src, UINT16 sp, UINT32 dst, UINT16 dp, BOOL udp, DWORD *pid, UINT32 *proxy)
{
    (void)src; (void)sp; (void)dst; (void)udp;
    if (dp == 9001) { SetEvent(g_class_entered); WaitForSingleObject(g_class_release, INFINITE); }
    if (pid) *pid = GetCurrentProcessId(); if (proxy) *proxy = 7;
    g_tl_rule_id = 123; g_tl_rule_localhost = TRUE;
    return RULE_ACTION_DIRECT;
}
static RuleAction fake_classify6(const UINT8 *s, UINT16 sp, const UINT8 *d, UINT16 dp, BOOL udp, DWORD *pid, UINT32 *proxy)
{ (void)s; (void)d; return fake_classify(0, sp, 0, dp, udp, pid, proxy); }

static void packet4(unsigned char *data, UINT16 sp, UINT16 dp, unsigned char marker)
{
    ZeroMemory(data, 40);
    PWINDIVERT_IPHDR ip = (void *)data; PWINDIVERT_TCPHDR tcp = (void *)(data + 20);
    ip->Version = 4; ip->HdrLength = 5; ip->Length = htons(40); ip->Protocol = IPPROTO_TCP;
    inet_pton(AF_INET, "192.168.1.10", &ip->SrcAddr); inet_pton(AF_INET, "192.168.1.20", &ip->DstAddr);
    tcp->SrcPort = htons(sp); tcp->DstPort = htons(dp); tcp->HdrLength = 5; tcp->Ack = 1;
    data[39] = marker;
}

static void compare_matchers(void)
{
    const char *processes[] = {"chrome.exe", "C:\\Program Files\\App\\test.exe", "other.exe", "System"};
    const char *ips[] = {"192.168.1.1", "10.2.3.4", "8.8.8.8", "0.0.0.0"};
    UINT16 ports[] = {0, 53, 80, 443, 445, 65535};
    for (UINT a = 0; a < 4; a++) for (UINT b = 0; b < 4; b++) for (UINT c = 0; c < 6; c++) for (int udp = 0; udp < 2; udp++) {
        UINT32 ip, p1 = 0, p2 = 0; inet_pton(AF_INET, ips[b], &ip);
        AcquireSRWLockShared(&g_rules_lock);
        RuleAction expected = match_rule_inner(processes[a], ip, ports[c], udp, &p1);
        UINT32 rule = g_tl_rule_id; BOOL localhost = g_tl_rule_localhost;
        ReleaseSRWLockShared(&g_rules_lock);
        CHECK(match_rule(processes[a], ip, ports[c], udp, &p2) == expected && p1 == p2 &&
              g_tl_rule_id == rule && g_tl_rule_localhost == localhost);
    }
    UINT8 v6[16]; inet_pton(AF_INET6, "2001:db8::2", v6);
    for (UINT a = 0; a < 4; a++) for (UINT c = 0; c < 6; c++) {
        UINT32 p1 = 0, p2 = 0;
        AcquireSRWLockShared(&g_rules_lock);
        RuleAction expected = match_rule_v6_inner(processes[a], v6, ports[c], FALSE, &p1);
        UINT32 rule = g_tl_rule_id; BOOL localhost = g_tl_rule_localhost;
        ReleaseSRWLockShared(&g_rules_lock);
        CHECK(match_rule_v6(processes[a], v6, ports[c], FALSE, &p2) == expected && p1 == p2 &&
              g_tl_rule_id == rule && g_tl_rule_localhost == localhost);
    }
}

static void test_rules(void)
{
    dns_cache_init(); UINT32 ip; inet_pton(AF_INET, "8.8.8.8", &ip); dns_cache_store(ip, "api.example.com");
    UINT32 a = ProxyBridge_AddRule("*", "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_BLOCK, 1, FALSE);
    UINT32 b = ProxyBridge_AddRule("chrome.exe; \"C:\\Program Files\\App\\*.exe\"", "10.0.0.0/8;192.168.*.*;2001:db8::/32", "80,443;445-450", "*.example.com", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, 9, TRUE);
    UINT32 c = ProxyBridge_AddRule("ANY", "8.8.8.8;2001:db8::1-2001:db8::ff", "0;53;65535", "*", RULE_PROTOCOL_UDP, RULE_ACTION_DIRECT, 4, FALSE);
    CHECK(a && b && c); compare_matchers();
    ProxyBridge_MoveRuleToPosition(c, 1); compare_matchers();
    ProxyBridge_DisableRule(b); compare_matchers();
    ProxyBridge_EnableRule(b);
    ProxyBridge_EditRule(b, "chrome.exe", "10..0.1;1.2.3.4.5;192.168.1.0/24;::/0", "abc;-1;65535-70000", " ;*.example.com", RULE_PROTOCOL_BOTH, RULE_ACTION_DIRECT, 8, FALSE);
    compare_matchers();
    ProxyBridge_DeleteRule(a); ProxyBridge_DeleteRule(b); ProxyBridge_DeleteRule(c); compare_matchers();
}

static HANDLE g_log_entered, g_log_release;
static void slow_log(const char *message)
{ (void)message; SetEvent(g_log_entered); WaitForSingleObject(g_log_release, INFINITE); }

static void test_buffer_io(PIPELINE *p, const WINDIVERT_ADDRESS *addr)
{
    RECEIVE_SLOT *first = &p->receives[0], *second = &p->receives[1];
    packet4(first->storage, 63000, 445, 11);
    first->output.leased = TRUE; p->building = &first->output;
    UINT64 reused = p->stats.reused_bytes, copied = p->stats.copied_bytes;
    pb_packet_send(first->storage, 40, addr);
    CHECK(p->stats.reused_bytes == reused + 40 && p->stats.copied_bytes == copied);
    g_async_send = TRUE;
    flush_send(p);
    CHECK(p->inflight == &first->output && first->output.leased && g_pending_send.data == first->storage);
    CHECK(!complete_send(p, FALSE) && first->output.leased);
    packet4(second->storage, 63001, 445, 12);
    second->output.leased = TRUE; p->building = &second->output;
    pb_packet_send(second->storage, 40, addr);
    CHECK(g_pending_send.data[39] == 11 && p->building->data[39] == 12);
    SetEvent(p->send_ov.hEvent); flush_send(p);
    CHECK(!first->output.leased && second->output.leased && p->inflight == &second->output);
    SetEvent(p->send_ov.hEvent); CHECK(complete_send(p, FALSE) && !second->output.leased);
    g_async_send = FALSE;

    /* Mixed DIRECT/BLOCK/PROXY receive batch: compact only the surviving
     * packets, and keep each rewritten packet paired with its own address. */
    UINT32 rule = ProxyBridge_AddRule("*", "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_BLOCK, 0, FALSE);
    unsigned char expected[40];
    packet4(first->storage, 63002, 445, 13); memcpy(expected, first->storage, 40);
    packet4(first->storage + 40, 63003, 445, 14); packet4(first->storage + 80, 63004, 445, 15);
    first->output.leased = TRUE; p->building = &first->output;
    PB_DECISION decision = {0}; decision.pid = GetCurrentProcessId();
    RuleAction actions[] = {RULE_ACTION_DIRECT, RULE_ACTION_BLOCK, RULE_ACTION_PROXY};
    for (UINT i = 0; i < 3; i++) {
        PB_PACKET_VIEW view; pb_packet_view(first->storage + i * 40, 120 - i * 40, &view);
        WINDIVERT_ADDRESS packet_addr = *addr; packet_addr.Network.IfIdx = i + 1;
        decision.action = actions[i]; pb_current_decision = &decision; pb_current_packet = &view;
        pb_process_packet(first->storage + i * 40, 40, &packet_addr);
        pb_current_packet = NULL; pb_current_decision = NULL;
    }
    CHECK(first->output.count == 2 && first->output.bytes == 80 && !memcmp(first->storage, expected, 40));
    CHECK(first->output.addr[0].Network.IfIdx == 1 && first->output.addr[1].Network.IfIdx == 3);
    CHECK(ntohs(((PWINDIVERT_TCPHDR)(first->storage + 60))->DstPort) == g_local_relay_port);
    CHECK(!first->output.addr[1].Outbound);
    flush_send(p); CHECK(!first->output.leased); remove_connection(63004, FALSE, FALSE); ProxyBridge_DeleteRule(rule);

    /* Pending read and write both finish cancellation before their buffers can
     * be freed. A cancelled write must not be retried as fresh traffic. */
    PIPELINE *q = calloc(1, sizeof(*q)); CHECK(q && io_init(q));
    if (!q) return;
    g_pipeline = q; g_async_receive = g_async_send = TRUE;
    CHECK(post_receive(q) == 1 && q->reading->pending);
    unsigned char data[40]; packet4(data, 63005, 445, 16);
    pb_packet_send(data, 40, addr); flush_send(q); CHECK(q->inflight != NULL);
    UINT singles = g_single_calls, cancellations = g_cancel_calls;
    BOOL was_running = running; running = FALSE; io_destroy(q); running = was_running;
    CHECK(g_cancel_calls == cancellations + 2 && !q->inflight && !g_pending_receive && !g_pending_send.ov && singles == g_single_calls);
    free(q); g_pipeline = p; g_async_send = g_async_receive = FALSE;
}

static void test_receive_ahead(void)
{
    unsigned char data[40]; packet4(data, 62000, 445, 1);
    PB_FLOW_KEY key; pb_flow_key(data, 40, &key); pb_direct_remember(&key);
    g_batch_calls = g_injected = g_recv_calls = g_order_count = 0;
    g_loop_copied = g_loop_reused = 0;
    g_loop_test = g_async_send = TRUE; running = TRUE;
    packet_processor(NULL);
    running = FALSE; g_loop_test = g_async_send = FALSE;
    CHECK(g_order_count == 2 && g_order[0] == 1 && g_order[1] == 2 && g_injected == 2);
    CHECK(g_loop_reused == 80 && g_loop_copied == 0 && !g_pending_send.ov);
}

static void test_bulk_thread(PIPELINE *p, const WINDIVERT_ADDRESS *addr)
{
    g_sender_entered = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_sender_release = CreateEventW(NULL, TRUE, FALSE, NULL);
    DWORD packet_thread = GetCurrentThreadId();
    RECEIVE_SLOT *slot = &p->receives[0];
    slot->output.leased = TRUE; p->building = &slot->output;
    for (UINT i = 0; i < 16; i++) {
        unsigned char *data = slot->storage + i * 1500; ZeroMemory(data, 1500); packet4(data, 64000, 445, 20);
        ((PWINDIVERT_IPHDR)data)->Length = htons(1500);
        WINDIVERT_ADDRESS address = *addr; address.Timestamp = (LONGLONG)perf_tick();
        pb_packet_send(data, 1500, &address);
    }
    UINT64 workers = p->stats.worker_batches;
    g_hold_sender = TRUE; flush_send(p);
    CHECK(WaitForSingleObject(g_sender_entered, 3000) == WAIT_OBJECT_0);
    CHECK(p->inflight_offloaded && p->inflight == &slot->output && slot->output.leased);
    CHECK(g_last_submit_thread != packet_thread && !complete_send(p, FALSE));
    /* The driver-facing send call is still blocked, but the packet thread can
     * issue the next receive. This cannot be achieved by OVERLAPPED alone. */
    g_async_receive = TRUE;
    CHECK(post_receive(p) == 1 && p->reading->pending && p->reading != slot);
    DWORD ignored; fake_cancel(p->capture, &p->reading->ov); fake_result(p->capture, &p->reading->ov, &ignored, TRUE);
    p->reading->pending = FALSE; p->reading->output.leased = FALSE; p->reading = NULL; g_async_receive = FALSE;
    SetEvent(g_sender_release); CHECK(complete_send(p, TRUE));
    CHECK(!slot->output.leased && p->stats.worker_batches == workers + 1);
    g_hold_sender = FALSE;
    unsigned char latency_packet[40]; packet4(latency_packet, 64001, 445, 21);
    UINT64 inline_batches = p->stats.inline_batches;
    pb_packet_send(latency_packet, 40, addr); flush_send(p);
    CHECK(g_last_submit_thread == packet_thread && p->stats.inline_batches == inline_batches + 1);

    PIPELINE *q = calloc(1, sizeof(*q)); CHECK(q && io_init(q)); if (!q) return;
    g_pipeline = q; g_async_send = TRUE; ResetEvent(g_sender_entered);
    unsigned char bulk[1500] = {0}; packet4(bulk, 64002, 445, 22); ((PWINDIVERT_IPHDR)bulk)->Length = htons(1500);
    for (UINT i = 0; i < 16; i++) pb_packet_send(bulk, sizeof(bulk), addr);
    flush_send(q); CHECK(WaitForSingleObject(g_sender_entered, 3000) == WAIT_OBJECT_0 && q->inflight_offloaded);
    UINT singles = g_single_calls;
    BOOL was_running = running; running = FALSE; io_destroy(q); running = was_running;
    CHECK(!q->inflight && !g_pending_send.ov && singles == g_single_calls);
    free(q); g_pipeline = p; g_async_send = FALSE;
    CloseHandle(g_sender_entered); CloseHandle(g_sender_release); g_sender_entered = g_sender_release = NULL;

    IO_STATS synthetic = {0}, previous = {0}; char value[24];
    synthetic.queue_histogram[3] = 95; synthetic.queue_histogram[6] = 5;
    queue_percentile(&synthetic, &previous, 95, value); CHECK(!strcmp(value, "<=1.00ms"));
    queue_percentile(&synthetic, &previous, 99, value); CHECK(!strcmp(value, "<=8.00ms"));
}

int main(void)
{
    WSADATA ws; WSAStartup(MAKEWORD(2,2), &ws);
    test_rules();
    unsigned char data[40]; packet4(data, 50000, 445, 1);
    PB_FLOW_KEY key; CHECK(pb_flow_key(data, sizeof(data), &key));
    pb_direct_reset(); pb_direct_remember(&key); CHECK(pb_direct_cached(&key));
    PB_FLOW_KEY other = key; other.local[3]++; CHECK(!pb_direct_cached(&other));
    other = key; other.remote[3]++; CHECK(!pb_direct_cached(&other));
    other = key; other.ipv6 = TRUE; CHECK(!pb_direct_cached(&other));
    other = key; other.remote_port++; CHECK(!pb_direct_cached(&other));
    other = key; other.protocol = IPPROTO_UDP; CHECK(!pb_direct_cached(&other));
    pb_direct_forget(&key); CHECK(!pb_direct_cached(&key));

    PIPELINE *p = calloc(1, sizeof(*p)); CHECK(p != NULL); if (!p) return 1;
    CHECK(io_init(p));
    g_pipeline = p;
    WINDIVERT_ADDRESS addr = {0}; addr.Outbound = TRUE;
    for (int i = 0; i < 3; i++) pb_packet_send(data, sizeof(data), &addr);
    CHECK(g_batch_calls == 0); flush_send(p); CHECK(g_batch_calls == 1 && g_injected == 3 && (p->building ? p->building->count : 0) == 0);
    g_partial = 1; g_injected = g_single_calls = 0;
    for (int i = 0; i < 3; i++) pb_packet_send(data, sizeof(data), &addr);
    flush_send(p); CHECK(g_single_calls == 2 && g_injected == 3); g_partial = 0;
    test_buffer_io(p, &addr);
    test_bulk_thread(p, &addr);

    /* Exercise the shipping rewrite function too, with an already-resolved
     * verdict: DIRECT is byte-preserving, BLOCK injects nothing, PROXY keeps
     * the existing local-relay address/port translation. */
    UINT32 guard_rule = ProxyBridge_AddRule("*", "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_BLOCK, 0, FALSE);
    PB_DECISION decision = {0}; decision.pid = GetCurrentProcessId();
    pb_current_decision = &decision;
    unsigned char original[40];
    packet4(data, 61000, 445, 4); memcpy(original, data, sizeof(data));
    decision.action = RULE_ACTION_DIRECT;
    pb_process_packet(data, sizeof(data), &addr);
    pb_flow_key(original, sizeof(original), &key);
    CHECK((p->building ? p->building->count : 0) == 1 && !memcmp(data, original, sizeof(data)) && pb_direct_cached(&key));
    flush_send(p);
    ((PWINDIVERT_TCPHDR)(data + 20))->Fin = 1;
    pb_process_packet(data, sizeof(data), &addr); CHECK(!pb_direct_cached(&key)); flush_send(p);
    packet4(data, 61001, 445, 5); decision.action = RULE_ACTION_BLOCK;
    pb_process_packet(data, sizeof(data), &addr); CHECK((p->building ? p->building->count : 0) == 0);
    packet4(data, 61002, 445, 6); decision.action = RULE_ACTION_PROXY;
    pb_process_packet(data, sizeof(data), &addr);
    CHECK((p->building ? p->building->count : 0) == 1 && !p->building->addr[0].Outbound &&
          ntohs(((PWINDIVERT_TCPHDR)(data + 20))->DstPort) == g_local_relay_port &&
          is_connection_tracked(61002, FALSE, FALSE));
    flush_send(p); remove_connection(61002, FALSE, FALSE);
    pb_current_decision = NULL; ProxyBridge_DeleteRule(guard_rule);

    p->work_event = CreateEventW(NULL, FALSE, FALSE, NULL); p->ready_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_class_entered = CreateEventW(NULL, TRUE, FALSE, NULL); g_class_release = CreateEventW(NULL, TRUE, FALSE, NULL);
    p->worker = CreateThread(NULL, 0, classify_worker, p, 0, NULL);
    packet4(data, 50001, 9001, 1); dispatch_packet(p, data, sizeof(data), &addr, NULL);
    CHECK(WaitForSingleObject(g_class_entered, 3000) == WAIT_OBJECT_0);
    packet4(data, 50001, 9001, 2); dispatch_packet(p, data, sizeof(data), &addr, NULL);
    packet4(data, 50002, 445, 3); pb_flow_key(data, sizeof(data), &key); pb_direct_remember(&key);
    dispatch_packet(p, data, sizeof(data), &addr, NULL);
    CHECK(g_order_count == 1 && g_order[0] == 3 && p->pending_flows == 1 && p->pending_packets == 2);
    SetEvent(g_class_release); CHECK(WaitForSingleObject(p->ready_event, 3000) == WAIT_OBJECT_0); drain_ready(p);
    CHECK(g_order_count == 3 && g_order[1] == 1 && g_order[2] == 2 && p->pending_packets == 0 && p->pending_flows == 0);
    InterlockedExchange(&p->stopping, 1); SetEvent(p->work_event);
    CHECK(WaitForSingleObject(p->worker, 3000) == WAIT_OBJECT_0);
    CloseHandle(p->worker); CloseHandle(p->work_event); CloseHandle(p->ready_event);
    CloseHandle(g_class_entered); CloseHandle(g_class_release); io_destroy(p); free(p); g_pipeline = NULL;
    test_receive_ahead();

    /* A blocked activity consumer cannot block the producer. */
    g_log_entered = CreateEventW(NULL, TRUE, FALSE, NULL); g_log_release = CreateEventW(NULL, TRUE, FALSE, NULL);
    ProxyBridge_SetLogCallback(slow_log); CHECK(pb_events_start()); pb_emit_log("first");
    CHECK(WaitForSingleObject(g_log_entered, 3000) == WAIT_OBJECT_0);
    for (int i = 0; i < 2100; i++) pb_emit_log("queued");
    SetEvent(g_log_release); pb_events_stop(); ProxyBridge_SetLogCallback(NULL);
    CloseHandle(g_log_entered); CloseHandle(g_log_release);
    pb_rules_free(); WSACleanup();
    return pbtest_done("test_datapath");
}
