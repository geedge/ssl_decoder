#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include "stellar/stellar.h"
#include "stellar/session.h"
#include <stellar/session_mq.h>

void perf_resource_record_decode(struct ssl_message *ssl_msg);

#ifdef __cplusplus
}
#endif

struct stellar_packet
{
    size_t payload_sz;
    uint8_t payload[2048];
    struct session_addr addr;
    char *readable_addr;
    enum session_addr_type addr_type;
};

struct stellar *stellar_init(int worker_thread_num);

struct session *stellar_session_new(struct stellar *st, struct stellar_packet *cur_pkt, int tid);
void stellar_session_free(struct session *ss);

int session_mq_publish_message_by_name(struct session *ss, const char *topic_name, struct stellar_packet *msg);
