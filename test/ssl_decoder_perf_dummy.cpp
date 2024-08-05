#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "ssl_decoder_perf_dummy.h"

#define MAX_SUBSCRIBE_TOPIC_NUM 16
#define MAX_MESSGEA_TOPIC_NUM   16
#define MAX_STELLAR_PLUGIN_NUM  16

struct stellar_plugin
{
    void *plugin_env;
    void *per_session_ctx;
    session_ctx_new_func *session_ctx_new;
    session_ctx_free_func *session_ctx_free;
};

struct message_topic
{
    char *name;
    void *msg_free_arg;
    int on_msg_cb_idx;
    session_msg_free_cb_func *msg_free_cb;
    int on_msg_plugin_id[MAX_SUBSCRIBE_TOPIC_NUM];
    on_session_msg_cb_func *plugin_on_msg_cb[MAX_SUBSCRIBE_TOPIC_NUM];
};

struct stellar
{
    int topic_idx;
    int plugin_idx;
    int worker_thread_num;
    int udp_topic_id;
    int tcp_steam_topic_id;
    struct message_topic topic[MAX_MESSGEA_TOPIC_NUM];
    struct stellar_plugin plugin[MAX_STELLAR_PLUGIN_NUM];
};

struct session
{
    int tid;
    int topic_idx;
    int plugin_idx;
    struct message_topic *topic;
    struct stellar_plugin *plugin;
    struct stellar_packet *curr_msg;
    struct session_addr addr;
    char *readable_addr;
    enum session_addr_type addr_type;
};

const char *session_get0_current_payload(struct session *ss, size_t *payload_sz)
{
    if(ss->curr_msg==NULL)
    {
        *payload_sz=0;
        return NULL;
    }

    *payload_sz=ss->curr_msg->payload_sz;
    return (const char *)ss->curr_msg->payload;
}

int stellar_session_mq_create_topic(struct stellar *st, const char *topic_name, session_msg_free_cb_func *msg_free_cb, void *msg_free_arg)
{
    int topic_id=st->topic_idx++;
    st->topic[topic_id].name=strdup(topic_name);
    st->topic[topic_id].msg_free_cb=msg_free_cb;
    st->topic[topic_id].msg_free_arg=msg_free_arg;

    return topic_id;
}

int stellar_session_mq_get_topic_id(struct stellar *st, const char *topic_name)
{
    for(int i=0; i<st->topic_idx; i++)
    {
        if(strcmp(st->topic[i].name, topic_name)==0)
        {
            return i;
        }
    }

    return -1;
}

int stellar_session_mq_subscribe(struct stellar *st, int topic_id, on_session_msg_cb_func *plugin_on_msg_cb, int plugin_id)
{
    st->topic[topic_id].on_msg_plugin_id[st->topic[topic_id].on_msg_cb_idx]=plugin_id;
    st->topic[topic_id].plugin_on_msg_cb[st->topic[topic_id].on_msg_cb_idx]=plugin_on_msg_cb;
    st->topic[topic_id].on_msg_cb_idx++;

    return 0;
}

int session_mq_publish_message(struct session *ss, int topic_id, void *msg)
{
    for(int i=0; i<ss->topic[topic_id].on_msg_cb_idx; i++)
    {
        int plugin_id=ss->topic[topic_id].on_msg_plugin_id[i];
        ss->topic[topic_id].plugin_on_msg_cb[i](ss, topic_id, msg, ss->plugin[plugin_id].per_session_ctx, ss->plugin[plugin_id].plugin_env);
    }

    if(ss->topic[topic_id].msg_free_cb!=NULL)
    {
        ss->topic[topic_id].msg_free_cb(ss, msg, ss->topic[topic_id].msg_free_arg);
    }

    return 0;
}

int session_mq_publish_message_by_name(struct session *ss, const char *topic_name, struct stellar_packet *msg)
{
    for(int i=0; i<ss->topic_idx; i++)
    {
        if(strcmp(ss->topic[i].name, topic_name)==0)
        {
            ss->curr_msg=msg;
            session_mq_publish_message(ss, i, (void *)msg);
            break;
        }
    }

    return 0;
}

int stellar_session_mq_destroy_topic(struct stellar *st, int topic_id)
{
    return 0;
}

int stellar_session_plugin_register(struct stellar *st, session_ctx_new_func session_ctx_new, session_ctx_free_func session_ctx_free, void *plugin_env)
{
    int plugin_id=st->plugin_idx++;
    st->plugin[plugin_id].plugin_env=plugin_env;
    st->plugin[plugin_id].session_ctx_new=session_ctx_new;
    st->plugin[plugin_id].session_ctx_free=session_ctx_free;

    return plugin_id;
}

struct session *stellar_session_new(struct stellar *st, struct stellar_packet *cur_pkt, int tid)
{
    struct session *ss=(struct session *)malloc(sizeof(struct session));
    ss->tid=tid;
    ss->addr_type=cur_pkt->addr_type;
    ss->readable_addr=cur_pkt->readable_addr;
    memcpy(&(ss->addr), &(cur_pkt->addr), sizeof(struct session_addr));

    ss->plugin=st->plugin;
    ss->plugin_idx=st->plugin_idx;

    ss->topic=st->topic;
    ss->topic_idx=st->topic_idx;

    for(int i=0; i<ss->plugin_idx; i++)
    {
        ss->plugin[i].per_session_ctx=ss->plugin[i].session_ctx_new(ss, ss->plugin[i].plugin_env);
    }

    return ss;
}

int session_get_current_thread_id(struct session *ss)
{
    return ss->tid;
}

struct session_addr *session_get0_addr(struct session *ss, enum session_addr_type *addr_type)
{
    *addr_type=ss->addr_type;
    return &(ss->addr);
}


void stellar_session_plugin_dettach_current_session(struct session *ss)
{

}

int session_is_innermost(struct session *ss, uint64_t *flag)
{
    *flag=0;
    return 1;
}

enum session_state session_get_current_state(struct session *ss)
{
    return SESSION_STATE_ACTIVE;
}

const char *session_get0_readable_addr(struct session *ss)
{
    return ss->readable_addr;
}

void stellar_session_free(struct session *ss)
{
    for(int i=0; i<ss->plugin_idx; i++)
    {
        ss->plugin[i].session_ctx_free(ss, ss->plugin[i].per_session_ctx, ss->plugin[i].plugin_env);
    }
    
    free(ss);
}

struct stellar *stellar_init(int worker_thread_num)
{
    struct stellar *st=(struct stellar *)malloc(sizeof(struct stellar));
    st->topic_idx=0;
    st->plugin_idx=0;
    st->worker_thread_num=worker_thread_num;

    st->udp_topic_id=stellar_session_mq_create_topic(st, TOPIC_UDP, NULL, NULL);
    st->tcp_steam_topic_id=stellar_session_mq_create_topic(st, TOPIC_TCP_STREAM, NULL, NULL);

    return st;
}

int stellar_get_worker_thread_num(struct stellar *st)
{
    return st->worker_thread_num;
}

