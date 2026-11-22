#include "pb_internal.h"

// Utilities: logging, string/IP helpers, token parsing, socket setup, base64.

/* Callbacks may perform synchronous pipe/console I/O. Keep that backpressure off
 * both the ordered packet consumer and the new-flow classifier. */
#define PB_EVENT_CAPACITY 2048
typedef struct {
    BOOL connection;
    DWORD pid;
    UINT16 port;
    char process[MAX_PROCESS_NAME], ip[64], info[128];
    char message[LOG_BUFFER_SIZE];
} PB_EVENT;
static SRWLOCK g_event_lock;
static PB_EVENT *g_events;
static UINT g_event_head, g_event_count;
static HANDLE g_event_thread, g_event_wake;
static BOOL g_event_stopping;
static volatile LONG g_event_dropped;

static DWORD WINAPI event_dispatcher(void *unused)
{
    (void)unused;
    for (;;) {
        PB_EVENT event;
        AcquireSRWLockExclusive(&g_event_lock);
        if (g_event_stopping) { ReleaseSRWLockExclusive(&g_event_lock); break; }
        if (!g_event_count) {
            ResetEvent(g_event_wake);
            ReleaseSRWLockExclusive(&g_event_lock);
            WaitForSingleObject(g_event_wake, INFINITE);
            continue;
        }
        event = g_events[g_event_head];
        g_event_head = (g_event_head + 1) % PB_EVENT_CAPACITY; g_event_count--;
        ReleaseSRWLockExclusive(&g_event_lock);
        LONG dropped = InterlockedExchange(&g_event_dropped, 0);
        if (dropped && g_log_callback) {
            char msg[128];
            snprintf(msg, sizeof(msg), "Activity log overloaded: %ld events omitted; traffic processing continued", dropped);
            g_log_callback(msg);
        }
        if (event.connection) {
            if (g_connection_callback) g_connection_callback(event.process, event.pid, event.ip, event.port, event.info);
        } else if (g_log_callback) g_log_callback(event.message);
    }
    return 0;
}

BOOL pb_events_start(void)
{
    if (g_event_thread) return TRUE;
    g_events = calloc(PB_EVENT_CAPACITY, sizeof(*g_events));
    g_event_wake = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_event_head = g_event_count = 0; g_event_stopping = FALSE; g_event_dropped = 0;
    if (g_events && g_event_wake) g_event_thread = CreateThread(NULL, 0, event_dispatcher, NULL, 0, NULL);
    if (g_event_thread) return TRUE;
    free(g_events); g_events = NULL;
    if (g_event_wake) CloseHandle(g_event_wake);
    g_event_wake = NULL;
    return FALSE;
}

void pb_events_stop(void)
{
    if (!g_event_thread) return;
    AcquireSRWLockExclusive(&g_event_lock);
    g_event_stopping = TRUE;
    SetEvent(g_event_wake);
    ReleaseSRWLockExclusive(&g_event_lock);
    /* Repeat cancellation to cover a callback entering WriteFile just after the
     * stop flag is set. Never leave callback code running after DLL unload. */
    do { CancelSynchronousIo(g_event_thread); }
    while (WaitForSingleObject(g_event_thread, 50) == WAIT_TIMEOUT);
    AcquireSRWLockExclusive(&g_event_lock);
    CloseHandle(g_event_thread); CloseHandle(g_event_wake);
    g_event_thread = g_event_wake = NULL;
    free(g_events); g_events = NULL; g_event_count = 0; g_event_stopping = FALSE;
    ReleaseSRWLockExclusive(&g_event_lock);
}

static BOOL queue_event(const PB_EVENT *event)
{
    BOOL queued = FALSE;
    AcquireSRWLockExclusive(&g_event_lock);
    if (g_events && !g_event_stopping) {
        if (g_event_count < PB_EVENT_CAPACITY) {
            g_events[(g_event_head + g_event_count) % PB_EVENT_CAPACITY] = *event;
            g_event_count++; SetEvent(g_event_wake);
        } else InterlockedIncrement(&g_event_dropped);
        queued = TRUE;
    } else if (g_event_stopping) queued = TRUE;
    ReleaseSRWLockExclusive(&g_event_lock);
    return queued;
}

void pb_emit_log(const char *msg)
{
    PB_EVENT event = {0};
    strncpy_s(event.message, sizeof(event.message), msg, _TRUNCATE);
    if (!queue_event(&event) && g_log_callback) g_log_callback(event.message);
}

void pb_emit_connection(const char *process, DWORD pid, const char *ip, UINT16 port, const char *info)
{
    PB_EVENT event = {0};
    event.connection = TRUE; event.pid = pid; event.port = port;
    strncpy_s(event.process, sizeof(event.process), process, _TRUNCATE);
    strncpy_s(event.ip, sizeof(event.ip), ip, _TRUNCATE);
    strncpy_s(event.info, sizeof(event.info), info, _TRUNCATE);
    if (!queue_event(&event) && g_connection_callback)
        g_connection_callback(event.process, pid, event.ip, port, event.info);
}

void log_message(const char *msg, ...)
{
    if (g_log_callback == NULL) return;
    char buffer[LOG_BUFFER_SIZE];
    va_list args;
    va_start(args, msg);
    vsnprintf(buffer, sizeof(buffer), msg, args);
    va_end(args);
    pb_emit_log(buffer);
}

// Extract filename from full path  C:\path\chrome.exe  >> chrome.exe
const char* extract_filename(const char* path)
{
    if (!path) return "";
    const char* last_backslash = strrchr(path, '\\');
    const char* last_slash = strrchr(path, '/');
    const char* last_separator = (last_backslash > last_slash) ? last_backslash : last_slash;
    return last_separator ? (last_separator + 1) : path;
}

char* skip_whitespace(char *str)
{
    while (*str == ' ' || *str == '\t')
        str++;
    return str;
}

void format_ip_address(UINT32 ip, char *buffer, size_t size)
{
    snprintf(buffer, size, "%d.%d.%d.%d",
        (ip >> 0) & 0xFF, (ip >> 8) & 0xFF,
        (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
}

BOOL parse_token_list(const char *list, const char *delimiters, token_match_func match_func, const void *match_data)
{
    if (list == NULL || list[0] == '\0' || strcmp(list, "*") == 0)
        return TRUE;

    // strtok_s needs a writable copy. Use a stack buffer for the common (short) case and
    // only fall back to malloc for unusually long lists - avoids a heap alloc on the
    // packet thread for every rule that has a specific host/port filter.
    char   stackbuf[256];
    size_t len    = strnlen_s(list, MAX_LIST_SIZE) + 1;
    size_t dstsz  = len;
    char  *list_copy;
    BOOL   on_heap = FALSE;
    if (len <= sizeof(stackbuf))
    {
        list_copy = stackbuf;
        dstsz     = sizeof(stackbuf);
    }
    else
    {
        list_copy = (char *)malloc(len);
        if (list_copy == NULL)
            return FALSE;
        on_heap = TRUE;
    }

    strncpy_s(list_copy, dstsz, list, _TRUNCATE);
    BOOL matched = FALSE;
    char *context = NULL;
    char *token = strtok_s(list_copy, delimiters, &context);
    while (token != NULL)
    {
        token = skip_whitespace(token);
        if (match_func(token, match_data))
        {
            matched = TRUE;
            break;
        }
        token = strtok_s(NULL, delimiters, &context);
    }
    if (on_heap)
        free(list_copy);
    return matched;
}

void configure_tcp_socket(SOCKET sock, int bufsize, DWORD timeout)
{
    int nodelay = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
}

// connect() with a bounded timeout. A blocking connect() to an unreachable host stalls
// for the OS SYN timeout (~21s on Windows), and the UDP relay runs on a single thread -
// so one dead/unreachable proxy config would freeze the whole relay (and delay real
// packets) while it waits. This does a non-blocking connect + select so a dead proxy
// fails in `timeout_ms` instead. Returns 0 on success, SOCKET_ERROR otherwise.
int connect_with_timeout(SOCKET s, const struct sockaddr *addr, int addrlen, int timeout_ms)
{
    u_long nonblock = 1;
    ioctlsocket(s, FIONBIO, &nonblock);

    int result = 0;
    if (connect(s, addr, addrlen) == SOCKET_ERROR)
    {
        if (WSAGetLastError() != WSAEWOULDBLOCK)
        {
            result = SOCKET_ERROR;
        }
        else
        {
            fd_set wfds, efds;
            FD_ZERO(&wfds); FD_SET(s, &wfds);
            FD_ZERO(&efds); FD_SET(s, &efds);
            struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
            int sel = select(0, NULL, &wfds, &efds, &tv);
            if (sel <= 0 || FD_ISSET(s, &efds))
            {
                result = SOCKET_ERROR;   // timed out or connect failed
            }
            else
            {
                int so_err = 0;
                int errlen = sizeof(so_err);
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_err, &errlen);
                if (so_err != 0)
                    result = SOCKET_ERROR;
            }
        }
    }

    u_long blocking = 0;
    ioctlsocket(s, FIONBIO, &blocking);   // restore blocking for the handshake reads
    return result;
}

void configure_udp_socket(SOCKET sock, int bufsize, DWORD timeout)
{
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

#ifdef _WIN32
    #ifndef SIO_UDP_CONNRESET
    #define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
    #endif
    BOOL bNewBehavior = FALSE;
    DWORD dwBytesReturned = 0;
    WSAIoctl(sock, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior), NULL, 0, &dwBytesReturned, NULL, NULL);
#endif
}

int send_all(SOCKET sock, const char *buf, int len)
{
    int sent = 0;
    while (sent < len) {
        int n = send(sock, buf + sent, len - sent, 0);
        if (n == SOCKET_ERROR) return SOCKET_ERROR;
        sent += n;
    }
    return sent;
}

// Read exactly n bytes, looping over partial TCP segments. SOCKS5/HTTP replies can be
// split across multiple segments (common on high-latency remote proxies); a single
// recv() may return fewer bytes than requested, so the fixed-length handshake reads
// must accumulate. Returns n on success, or SOCKET_ERROR on error / peer close.
int recv_n(SOCKET s, char *buf, int n)
{
    int got = 0;
    while (got < n) {
        int r = recv(s, buf + got, n - got, 0);
        if (r <= 0) return SOCKET_ERROR;  // 0 = peer closed, <0 = error/timeout
        got += r;
    }
    return n;
}

UINT32 parse_ipv4(const char *ip)
{
    unsigned int a, b, c, d;
    if (sscanf_s(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255)
        return 0;
    return (a << 0) | (b << 8) | (c << 16) | (d << 24);
}

// Resolve hostname to IPv4 address (supports both IP addresses and domain names)
UINT32 resolve_hostname(const char *hostname)
{
    if (hostname == NULL || hostname[0] == '\0')
        return 0;

    // First try to parse as IP address
    UINT32 ip = parse_ipv4(hostname);
    if (ip != 0)
        return ip;

    // Not an IP address, try DNS resolution
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  // IPv4 only
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0)
    {
        log_message("Failed to resolve hostname: %s", hostname);
        return 0;
    }

    if (result == NULL || result->ai_family != AF_INET)
    {
        if (result != NULL)
            freeaddrinfo(result);
        log_message("No IPv4 address found for hostname: %s", hostname);
        return 0;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)result->ai_addr;
    UINT32 resolved_ip = addr->sin_addr.s_addr;
    freeaddrinfo(result);

    log_message("Resolved %s to %d.%d.%d.%d", hostname,
        (resolved_ip >> 0) & 0xFF, (resolved_ip >> 8) & 0xFF,
        (resolved_ip >> 16) & 0xFF, (resolved_ip >> 24) & 0xFF);

    return resolved_ip;
}

void base64_encode(const char* input, char* output, size_t output_size)
{
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t input_len = strnlen_s(input, output_size * 2);
    size_t output_len = 0;

    for (size_t i = 0; i < input_len && output_len < output_size - 4; i += 3)
    {
        unsigned char b1 = input[i];
        unsigned char b2 = (i + 1 < input_len) ? input[i + 1] : 0;
        unsigned char b3 = (i + 2 < input_len) ? input[i + 2] : 0;

        output[output_len++] = base64_chars[b1 >> 2];
        output[output_len++] = base64_chars[((b1 & 0x03) << 4) | (b2 >> 4)];
        output[output_len++] = (i + 1 < input_len) ? base64_chars[((b2 & 0x0F) << 2) | (b3 >> 6)] : '=';
        output[output_len++] = (i + 2 < input_len) ? base64_chars[b3 & 0x3F] : '=';
    }
    output[output_len] = '\0';
}

