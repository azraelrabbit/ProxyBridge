/* Included by pb_rules.c after the legacy parsers. Keeping those parsers as the
 * fallback also preserves their handling of unusual/legacy profile entries. */
typedef struct { char *storage; char **item; UINT count; BOOL all; } PB_TOKENS;
typedef struct {
    UINT32 mask4, value4, low4, high4;
    UINT8 low6[16], high6[16];
    int kind4, kind6, prefix6;
} PB_IP_PATTERN;
typedef struct PB_RULE_PROGRAM {
    volatile LONG refs;
    PB_TOKENS process, hosts, ports, domains;
    PB_IP_PATTERN *ip;
    UINT8 port_bits[8192];
    BOOL wildcard_process, filtered_hosts, filtered_ports, filtered_domains, has_ip, has_domain;
} PB_RULE_PROGRAM;
typedef struct {
    PB_RULE_PROGRAM *program;
    UINT32 rule_id, proxy_id;
    RuleAction action;
    RuleProtocol protocol;
    BOOL enabled, localhost;
} PB_MATCH_RULE;
typedef struct { volatile LONG refs; UINT count; PB_MATCH_RULE rules[1]; } PB_RULE_SNAPSHOT;
static SRWLOCK g_snapshot_lock;
static PB_RULE_SNAPSHOT *g_snapshot;

static void tokens_free(PB_TOKENS *t) { free(t->storage); free(t->item); }
static BOOL tokens_compile(PB_TOKENS *t, const char *src, const char *delimiters, int mode)
{
    t->all = !src || !src[0] || strcmp(src, "*") == 0;
    if (t->all) return TRUE;
    size_t len = strlen(src);
    t->storage = _strdup(src);
    t->item = malloc((len + 1) * sizeof(char *));
    if (!t->storage || !t->item) return FALSE;
    char *context = NULL;
    for (char *token = strtok_s(t->storage, delimiters, &context); token; token = strtok_s(NULL, delimiters, &context)) {
        while (*token == ' ' || *token == '\t') token++;
        if (mode) {
            char *end = token + strlen(token);
            while (end > token && (end[-1] == ' ' || end[-1] == '\t')) *--end = 0;
        }
        if (mode == 1 && *token == '"' && strlen(token) > 1) {
            token++; char *quote = strchr(token, '"'); if (quote) *quote = 0;
        }
        if (mode != 2 || *token) t->item[t->count++] = token;
    }
    return TRUE;
}

static void program_release(PB_RULE_PROGRAM *p)
{
    if (!p || InterlockedDecrement(&p->refs)) return;
    tokens_free(&p->process); tokens_free(&p->hosts); tokens_free(&p->ports); tokens_free(&p->domains);
    free(p->ip); free(p);
}

static void ip_compile(PB_IP_PATTERN *out, const char *token)
{
    if (!strcmp(token, "*")) { out->kind4 = out->kind6 = 1; return; }
    int a, b, c, d, prefix, used = 0;
    if (sscanf_s(token, "%d.%d.%d.%d/%d%n", &a, &b, &c, &d, &prefix, &used) == 5 && !token[used] &&
        a >= 0 && a <= 255 && b >= 0 && b <= 255 && c >= 0 && c <= 255 && d >= 0 && d <= 255 && prefix >= 0 && prefix <= 32) {
        out->kind4 = 2; out->mask4 = prefix ? 0xffffffffu << (32 - prefix) : 0;
        out->value4 = ((UINT32)a << 24) | ((UINT32)b << 16) | ((UINT32)c << 8) | (UINT32)d;
    } else if (!strchr(token, '/') && !strchr(token, '-')) {
        /* Match the ordinary exact/wildcard form without parsing it on each flow.
         * Non-canonical legacy patterns retain the legacy parser's semantics. */
        char copy[256]; strncpy_s(copy, sizeof(copy), token, _TRUNCATE);
        char *ctx = NULL, *part = strtok_s(copy, ".", &ctx); int count = 0; BOOL valid = TRUE;
        while (part && count < 4) {
            if (strcmp(part, "*")) {
                int n = 0, consumed = 0;
                if (sscanf_s(part, "%d%n", &n, &consumed) != 1 || part[consumed] || n < 0 || n > 255) valid = FALSE;
                out->mask4 |= 0xffu << (24 - 8 * count);
                out->value4 |= (UINT32)n << (24 - 8 * count);
            }
            count++; part = strtok_s(NULL, ".", &ctx);
        }
        /* Empty octets are significant to the legacy parser. */
        if (valid && count == 4 && !part && token[0] != '.' && !strstr(token, "..") && token[strlen(token)-1] != '.') out->kind4 = 2;
    }
    if (strchr(token, ':')) {
        char copy[128]; strncpy_s(copy, sizeof(copy), token, _TRUNCATE);
        char *slash = strchr(copy, '/'), *dash = strchr(copy, '-');
        if (slash) {
            *slash = 0; prefix = atoi(slash + 1);
            if (prefix >= 0 && prefix <= 128 && inet_pton(AF_INET6, copy, out->low6) == 1) {
                out->kind6 = 2; out->prefix6 = prefix;
            }
        } else if (dash) {
            *dash = 0;
            if (inet_pton(AF_INET6, copy, out->low6) == 1 && inet_pton(AF_INET6, dash+1, out->high6) == 1) out->kind6 = 3;
        } else if (inet_pton(AF_INET6, token, out->low6) == 1) { out->kind6 = 2; out->prefix6 = 128; }
    }
    if (!out->kind4 && strchr(token, '-')) {
        /* Preserve the original range parser (including its permissive input)
         * but precompute ordinary IPv4 range endpoints. */
        char copy[128]; strncpy_s(copy, sizeof(copy), token, _TRUNCATE);
        char *dash = strchr(copy, '-');
        if (dash) {
            *dash = 0; struct in_addr lo, hi;
            if (inet_pton(AF_INET, copy, &lo) == 1 && inet_pton(AF_INET, dash+1, &hi) == 1) {
                out->kind4 = 3; out->low4 = ntohl(lo.s_addr); out->high4 = ntohl(hi.s_addr);
            }
        }
    }
}

static PB_RULE_PROGRAM *program_compile(const char *process, const char *hosts, const char *ports, const char *domains)
{
    PB_RULE_PROGRAM *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->refs = 1;
    p->wildcard_process = !strcmp(process, "*") || !strcmp(process, "ANY");
    p->filtered_hosts = strcmp(hosts, "*") != 0;
    p->filtered_ports = strcmp(ports, "*") != 0;
    p->has_ip = hosts[0] && strcmp(hosts, "*");
    p->has_domain = domains[0] && strcmp(domains, "*");
    p->filtered_domains = p->has_domain;
    if (!tokens_compile(&p->process, process, ",;", 1) || !tokens_compile(&p->hosts, hosts, ";", 0) ||
        !tokens_compile(&p->ports, ports, ",;", 0) || !tokens_compile(&p->domains, domains, ",;", 2)) goto fail;
    if (p->hosts.count) {
        p->ip = calloc(p->hosts.count, sizeof(*p->ip)); if (!p->ip) goto fail;
        for (UINT i = 0; i < p->hosts.count; i++) ip_compile(&p->ip[i], p->hosts.item[i]);
    }
    if (p->ports.all) memset(p->port_bits, 255, sizeof(p->port_bits));
    else for (UINT i = 0; i < p->ports.count; i++) {
        const char *t = p->ports.item[i], *dash = strchr(t, '-');
        if (!strcmp(t, "*")) { memset(p->port_bits, 255, sizeof(p->port_bits)); break; }
        int lo = atoi(t), hi = dash ? atoi(dash+1) : lo;
        if (lo < 0) lo = 0; if (hi > 65535) hi = 65535;
        for (int port = lo; port <= hi; port++) p->port_bits[port >> 3] |= (UINT8)(1u << (port & 7));
    }
    return p;
fail:
    program_release(p); return NULL;
}

static BOOL program_process(const PB_RULE_PROGRAM *p, const char *name)
{
    if (p->process.all) return TRUE;
    for (UINT i = 0; i < p->process.count; i++) if (match_process_pattern(p->process.item[i], name)) return TRUE;
    return FALSE;
}
static BOOL program_host(const PB_RULE_PROGRAM *p, const void *ip, BOOL ipv6, const char *domain)
{
    if (!p->has_ip && !p->has_domain) return TRUE;
    if (p->has_ip) {
        UINT32 be = ipv6 ? 0 : ntohl(*(const UINT32 *)ip);
        for (UINT i = 0; i < p->hosts.count; i++) {
            const PB_IP_PATTERN *pat = &p->ip[i]; BOOL hit;
            if (!ipv6) hit = pat->kind4 == 1 || (pat->kind4 == 2 && (be & pat->mask4) == (pat->value4 & pat->mask4)) ||
                (pat->kind4 == 3 && be >= pat->low4 && be <= pat->high4) ||
                (!pat->kind4 && match_ip_pattern(p->hosts.item[i], *(const UINT32 *)ip));
            else {
                hit = pat->kind6 == 1;
                if (pat->kind6 == 2) {
                    int bytes = pat->prefix6 / 8, bits = pat->prefix6 % 8;
                    hit = !memcmp(ip, pat->low6, bytes) && (!bits ||
                        ((((const UINT8 *)ip)[bytes] ^ pat->low6[bytes]) & (0xff << (8-bits))) == 0);
                } else if (pat->kind6 == 3) hit = memcmp(ip, pat->low6, 16) >= 0 && memcmp(ip, pat->high6, 16) <= 0;
                else if (!pat->kind6) hit = match_ip_pattern_v6(p->hosts.item[i], ip);
            }
            if (hit) return TRUE;
        }
    }
    if (p->has_domain && domain && *domain)
        for (UINT i = 0; i < p->domains.count; i++) if (match_domain_pattern(p->domains.item[i], domain)) return TRUE;
    return FALSE;
}

static void snapshot_release(PB_RULE_SNAPSHOT *s)
{
    if (!s || InterlockedDecrement(&s->refs)) return;
    for (UINT i = 0; i < s->count; i++) program_release(s->rules[i].program);
    free(s);
}
static PB_RULE_SNAPSHOT *snapshot_acquire(void)
{
    AcquireSRWLockShared(&g_snapshot_lock);
    PB_RULE_SNAPSHOT *s = g_snapshot; if (s) InterlockedIncrement(&s->refs);
    ReleaseSRWLockShared(&g_snapshot_lock);
    return s;
}
/* Caller holds g_rules_lock exclusive. A failed allocation installs NULL, so
 * matching falls back to the live locked list rather than using stale rules. */
static void snapshot_publish_locked(void)
{
    UINT count = 0; BOOL compiled = TRUE;
    for (PROCESS_RULE *r = rules_list; r; r = r->next) { count++; if (!r->program) compiled = FALSE; }
    PB_RULE_SNAPSHOT *s = compiled ? calloc(1, offsetof(PB_RULE_SNAPSHOT, rules) + count * sizeof(PB_MATCH_RULE)) : NULL;
    if (s) {
        s->refs = 1; s->count = count; UINT i = 0;
        for (PROCESS_RULE *r = rules_list; r; r = r->next) {
            PB_MATCH_RULE *v = &s->rules[i++];
            v->program = r->program; InterlockedIncrement(&v->program->refs);
            v->rule_id = r->rule_id; v->proxy_id = r->proxy_config_id; v->action = r->action;
            v->protocol = r->protocol; v->enabled = r->enabled; v->localhost = r->localhost_via_proxy;
        }
    }
    AcquireSRWLockExclusive(&g_snapshot_lock);
    PB_RULE_SNAPSHOT *old = g_snapshot; g_snapshot = s;
    ReleaseSRWLockExclusive(&g_snapshot_lock);
    snapshot_release(old);
}

static RuleAction snapshot_match(PB_RULE_SNAPSHOT *s, const char *process, const void *ip, BOOL ipv6,
                                UINT16 port, BOOL udp, UINT32 *proxy_id)
{
    char domain[256]; const char *host = NULL;
    if (g_has_domain_rules && (ipv6 ? dns_cache_lookup_v6(ip, domain, sizeof(domain)) :
        dns_cache_lookup(*(const UINT32 *)ip, domain, sizeof(domain)))) host = domain;
    const PB_MATCH_RULE *match = NULL, *fallback = NULL;
    for (UINT i = 0; i < s->count; i++) {
        const PB_MATCH_RULE *r = &s->rules[i]; const PB_RULE_PROGRAM *p = r->program;
        if (!r->enabled || (r->protocol != RULE_PROTOCOL_BOTH &&
            ((r->protocol == RULE_PROTOCOL_TCP && udp) || (r->protocol == RULE_PROTOCOL_UDP && !udp)))) continue;
        if (p->wildcard_process && !p->filtered_hosts && !p->filtered_ports && !p->filtered_domains) {
            if (!fallback) fallback = r;
            continue;
        }
        if ((p->wildcard_process || program_process(p, process)) &&
            (p->port_bits[port >> 3] & (1u << (port & 7))) && program_host(p, ip, ipv6, host)) { match = r; break; }
    }
    if (!match) match = fallback;
    g_tl_rule_id = match ? match->rule_id : 0;
    g_tl_rule_localhost = match ? match->localhost : FALSE;
    if (proxy_id) *proxy_id = match ? match->proxy_id : 0;
    return match ? match->action : RULE_ACTION_DIRECT;
}
