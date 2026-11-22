#ifndef PB_DATAPATH_H
#define PB_DATAPATH_H

/* Canonical packet identity. IPv4 addresses occupy the first four bytes. */
typedef struct {
    UINT8 local[16], remote[16];
    UINT16 local_port, remote_port;
    UINT8 ipv6, protocol;
} PB_FLOW_KEY;

typedef struct {
    RuleAction action;
    DWORD pid;
    UINT32 proxy_id, rule_id;
    BOOL localhost;
    char process[MAX_PATH * 4];
} PB_DECISION;

typedef struct {
    PB_FLOW_KEY key;
    PWINDIVERT_IPHDR v4;
    PWINDIVERT_IPV6HDR v6;
    PWINDIVERT_TCPHDR tcp;
    PWINDIVERT_UDPHDR udp;
    UINT len;
    BOOL valid;
} PB_PACKET_VIEW;

extern __declspec(thread) const PB_DECISION *pb_current_decision;
extern __declspec(thread) PB_DECISION *pb_resolving_decision;
extern __declspec(thread) const PB_PACKET_VIEW *pb_current_packet;

BOOL pb_flow_key(const void *packet, UINT len, PB_FLOW_KEY *key);
void pb_packet_view(const void *packet, UINT len, PB_PACKET_VIEW *view);
BOOL pb_direct_cached(const PB_FLOW_KEY *key);
void pb_direct_remember(const PB_FLOW_KEY *key);
void pb_direct_forget(const PB_FLOW_KEY *key);
void pb_direct_reset(void);
BOOL pb_packet_send(const void *packet, UINT len, const WINDIVERT_ADDRESS *addr);
void pb_process_packet(void *packet, UINT len, const WINDIVERT_ADDRESS *addr);
BOOL pb_packet_thread_start(HANDLE *thread);
BOOL pb_defer_packet(const void *packet, UINT len, const WINDIVERT_ADDRESS *addr, const PB_FLOW_KEY *key);

BOOL pb_events_start(void);
void pb_events_stop(void);
void pb_emit_log(const char *msg);
void pb_emit_connection(const char *process, DWORD pid, const char *ip, UINT16 port, const char *info);

#endif
