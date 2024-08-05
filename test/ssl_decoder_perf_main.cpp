#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <arpa/inet.h>

#include "cJSON.h"
#include "fieldstat/fieldstat_easy.h"

#include <stellar/utils.h>
#include "stellar/stellar.h"
#include <stellar/session_mq.h>

#include "ssl_decoder.h"
#include "toml/toml.h"
#include "ssl_decoder_perf_dummy.h"

#define	ssl_DECODER_TEST_TOML_PATH "./etc/ssl/ssl_decoder.toml"

#define TIME_START()  struct timespec _start_time, _end_time;  clock_gettime(CLOCK_REALTIME, &_start_time)
#define TIME_DIFF()  \
    long long time_diff_ns;\
    do { \
        clock_gettime(CLOCK_REALTIME, &_end_time); \
        if (likely(_end_time.tv_sec == _start_time.tv_sec))\
        {\
            time_diff_ns = (_end_time.tv_nsec - _start_time.tv_nsec);\
        }else{\
            time_diff_ns = (_end_time.tv_sec * 1000 * 1000 * 1000 + _end_time.tv_nsec) - (_start_time.tv_sec * 1000 * 1000 * 1000 + _start_time.tv_nsec);\
        }\
    }while (0)

struct ssl_decoder_context;
struct ssl_decoder_plugin_env;

enum PERF_TAG
{
    PERF_TAG_QUESTION,
    PERF_TAG_RESOURCE_RECORD,
    PERF_TAG_MAX
};

struct fs_easy_schame
{
    int id[PERF_TAG_MAX];
    struct field tag[PERF_TAG_MAX];
    struct fieldstat_easy *handle;
};

struct perf_main_env
{
    int worker_thread_num;
    int *worker_thread_pid;
    int n_worker_thread_pid;
    struct fs_easy_schame fse;
    struct stellar *st;
    struct stellar_packet *response;
};

// form ssl_decoder_test.cpp
extern "C" void *ssl_decoder_test_init(struct stellar *st);
extern "C" void *ssl_decoder_init(struct stellar *st);

thread_local int local_worker_thread_id=-1;
int firewall_current_worker_thread_id_get(struct perf_main_env *main_env)
{
    if (local_worker_thread_id==-1)
    {
        pid_t my_pid = syscall(SYS_gettid);
        for(int i=0; i<main_env->n_worker_thread_pid; i++)
        {
            if (my_pid==main_env->worker_thread_pid[i])
            {
                local_worker_thread_id=i;
                return local_worker_thread_id;
            }
        }

        main_env->worker_thread_pid[main_env->n_worker_thread_pid]=my_pid;
        local_worker_thread_id=main_env->n_worker_thread_pid++;
    }

    return local_worker_thread_id;
}


extern "C" int commit_test_result_json(cJSON *node, const char *name)
{
    char *real_result_str=cJSON_Print(node);
    printf("%s\n", real_result_str);
    free(real_result_str);
    
    cJSON_Delete(node);

    return 0;
}

void *pthread_message_publish(void *arg)
{
    struct perf_main_env *main_env=(struct perf_main_env *)arg;
    int tid=firewall_current_worker_thread_id_get(main_env);
    struct session *ss=stellar_session_new(main_env->st, main_env->response, tid);

    while(1)
    {
        TIME_START();
        session_mq_publish_message_by_name(ss, TOPIC_UDP, main_env->response);
        TIME_DIFF();
        fieldstat_easy_histogram_record(main_env->fse.handle, tid, main_env->fse.id[PERF_TAG_QUESTION], &(main_env->fse.tag[PERF_TAG_QUESTION]), 1, time_diff_ns);
    }

    stellar_session_free(ss);
}

static void main_stat_init(struct perf_main_env *main_env)
{
    main_env->fse.handle=fieldstat_easy_new(main_env->worker_thread_num, "ssl_decoder_perf_test", NULL, 0);
    fieldstat_easy_enable_auto_output(main_env->fse.handle, "./metrics/ssl_decoder_perf_test.json", 1);

    main_env->fse.tag[PERF_TAG_QUESTION].key="question";
    main_env->fse.tag[PERF_TAG_QUESTION].type=FIELD_VALUE_DOUBLE;
    main_env->fse.tag[PERF_TAG_QUESTION].value_double=0.00001;
    main_env->fse.id[PERF_TAG_QUESTION]=fieldstat_easy_register_histogram(main_env->fse.handle, "question", 1, 99999999, 5);

    main_env->fse.tag[PERF_TAG_RESOURCE_RECORD].key="resource_record";
    main_env->fse.tag[PERF_TAG_RESOURCE_RECORD].type=FIELD_VALUE_DOUBLE;
    main_env->fse.tag[PERF_TAG_RESOURCE_RECORD].value_double=0.00001;
    main_env->fse.id[PERF_TAG_RESOURCE_RECORD]=fieldstat_easy_register_histogram(main_env->fse.handle, "resource-record", 1, 99999999, 5);
}

void display_packet(struct stellar_packet *cur_pkt)
{
    printf("query.payload_sz=%zu\n", cur_pkt->payload_sz);
    
    for(size_t i=0; i<cur_pkt->payload_sz; i++)
    {
        printf("%02x ", cur_pkt->payload[i]);
        if(i>0 && (i%16==0))
        {
            printf("\n");
        }
    }
    
    printf("\n");
}

size_t hex_string_to_byte_array(const char *hex_str, size_t hex_str_sz, unsigned char *byte_array, size_t byte_array_sz)
{
    size_t offset=0;
    for(size_t i=0; i<hex_str_sz; i+=2)
    {
        sscanf(hex_str+i, "%2hhx", &byte_array[offset++]);

    }

    return offset;
}

int32_t ssl_decoder_test_config_load(const char *cfg_path, struct perf_main_env *main_env)
{
    FILE *fp=fopen(cfg_path, "r");
    if (NULL==fp)
    {
        fprintf(stderr, "[%s:%d] Can't open config file: %s", __FUNCTION__, __LINE__, cfg_path);
        return -1;
    }

    int32_t ret=0;
    char errbuf[256]={0};

    toml_table_t *root=toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);

    toml_table_t *decoder_tbl=toml_table_in(root, "decoder");
    if(NULL==decoder_tbl)
    {
        fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder]", __FUNCTION__, __LINE__, cfg_path);
        toml_free(root);
        return -1;
    }

    toml_table_t *ssl_tbl=toml_table_in(decoder_tbl, "ssl");
    if(NULL==ssl_tbl)
    {
        fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl]", __FUNCTION__, __LINE__, cfg_path);
        toml_free(root);
        return -1;
    }

    toml_table_t *test_tbl=toml_table_in(ssl_tbl, "test");
    if(NULL==test_tbl)
    {
        fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl.test]", __FUNCTION__, __LINE__, cfg_path);
        toml_free(root);
        return -1;
    }

    toml_table_t *perf_tbl=toml_table_in(test_tbl, "perf");
    if(NULL==perf_tbl)
    {
        fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl.test.perf]", __FUNCTION__, __LINE__, cfg_path);
        toml_free(root);
        return -1;
    }
	
	toml_datum_t perf_worker_thread_num_val=toml_int_in(perf_tbl, "perf_worker_thread_num");
    if(perf_worker_thread_num_val.ok)
    {
        main_env->worker_thread_num=perf_worker_thread_num_val.u.i;
    }
    else
    {
         main_env->worker_thread_num=1;
        fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl.test.perf_worker_thread_num]", __FUNCTION__, __LINE__, cfg_path);
    }

	toml_free(root);
	
    return ret;
}

int main(int argc, char *argv[])
{
    struct perf_main_env *main_env=(struct perf_main_env *)calloc(1, sizeof(struct perf_main_env));
    ssl_decoder_test_config_load(ssl_DECODER_TEST_TOML_PATH, main_env);
    main_stat_init(main_env);
    main_env->st=stellar_init(main_env->worker_thread_num);
    ssl_decoder_init(main_env->st);
    ssl_decoder_test_init(main_env->st);
    main_env->n_worker_thread_pid=0;
    main_env->worker_thread_pid=(int *)calloc(main_env->worker_thread_num, sizeof(int));

    // Internet Protocol Version 6, Src=2001:503:231d::2:30 Dst=2001:da8:2008::10
    struct stellar_packet *response=(struct stellar_packet *)calloc(1, sizeof(struct stellar_packet));
    main_env->response=response;

    response->addr_type=SESSION_ADDR_TYPE_IPV6_UDP;
    response->readable_addr=(char *)("s=2001:503:231d::2:30.23856 d=2001:da8:2008::10.53");
    inet_pton(AF_INET6, "2001:da8:2008::10", response->addr.ipv6.daddr);
    inet_pton(AF_INET6, "2001:503:231d::2:30", response->addr.ipv6.saddr);
    response->addr.ipv6.dport=htons(53);
    response->addr.ipv6.sport=htons(23856);
    const char *response_hex_str="ce268000000100000006001404646174610862696c6963646e3203636f6d0000410001c011000200010002a300000c036e733305646e737635c01ac011000200010002a3000006036e7334c03320434b30504f4a4d473837344c4a5245463745464e38343330515649543842534dc01a003200010001518000230101000000146501a0c25720ee156f6c4e39636b3ada0312d92a000722000000000290c04d002e00010001518000b700320802000151806188b454617f5b5c3cbd03636f6d001f77dc4c5796eda9ced317925c67d91c52922152424c9dca024948c1169e8429053fdf50a23370d9c3dc79de909f2f79475b2c731d6060d1db7b5d294b8ee43c91a57b8a4afa06c25fb13127bfca3fb353c7d5a38eaf093e12ffa1e33bc80bd7118851ca730ed22bd27b6f16673b86b44898785c6e13b3dd3620750492e47bb8ca823ffa6e25225ffa5408184c25e4ff423497802deed0586629d78103b3e6e72039454d4644425347524c48514f4d4736515441534e534c4151343438454b4644c01a003200010001518000220101000000144bad0970b67bda0a716dcd12979d4451b22f7ac50006200000000012c160002e00010001518000b700320802000151806188bdde617f64e63cbd03636f6d00a9de4aee30c79978429e76969d02d2bd4c8942f1b4329a643e9d7703e9fd46dd9ab32c4feffe1f9fbed3418e40d42a00fe2c1c2cac66e1c718bf508c4f603171f9ea18e8e79a533d136c26907576ab033dc48e4ff3b355346c33ac54a359c9572c308c923f910e470315dd4de40bd3b443b7caa34309b22146dca1ed6f4758a476052fc8a33829216c5abe88f21981dfe8ae9b2b204958aac575bfaa9847af3ec02f000100010002a300000481d3b0d4c02f000100010002a3000004a20e12bcc02f000100010002a3000004a20e18fbc02f000100010002a3000004a20e19fbc02f000100010002a300000412c20289c02f000100010002a3000004b7c0c95ec02f000100010002a3000004dfa69710c02f001c00010002a300001024024e0014301102000091362b2bba61c02f000100010002a3000004344dee5cc02f000100010002a30000043d97b433c047000100010002a300000465e2dc0cc047000100010002a300000481d3b097c047000100010002a3000004a20e18f8c047000100010002a3000004a20e19f8c047000100010002a3000004b7c0a477c047000100010002a3000004dfa6977ec047001c00010002a300001024024e00102012640000913629b6fc32c047000100010002a300000434c69f92c047000100010002a30000043b2478930000291000000080000000"; 
    response->payload_sz=hex_string_to_byte_array(response_hex_str, strlen(response_hex_str), response->payload, sizeof(response->payload));
    //display_packet(response);

    for(int i=0; i<main_env->worker_thread_num; i++)
    {
        pthread_t ptid;
        pthread_create(&ptid, NULL, pthread_message_publish, (void *)main_env);
    }
    
    while(1)
    {
        sleep(1);
    }

    return 0;
}