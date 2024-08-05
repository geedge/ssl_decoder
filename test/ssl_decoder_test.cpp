#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>

#ifdef __cplusplus
extern "C"
{

#include "cJSON.h"
#include "ssl_decoder.h"
#include "toml/toml.h"

#include "stellar/stellar.h"
#include "stellar/session.h"
#include "stellar/session_exdata.h"
#include "stellar/session_mq.h"

}
#endif

#include "ssl_decoder.h"

#define	ssl_DECODER_TEST_TOML_PATH "./etc/ssl/ssl_decoder.toml"

struct ssl_decoder_test_plugin_env
{
	int plugin_id;
	int topic_id;
	int result_index;
	int commit_result_enable;
	int decode_resource_record_enable;
	int export_resource_record_enable;
};

extern "C" void perf_resource_record_decode(struct ssl_message *ssl_msg);
extern "C" int commit_test_result_json(cJSON *node, const char *name);

void ssl_real_result_write_file(char *result_str)
{
	FILE *fp=fopen("ssl_real_result.json", "a+");
	if(fp!=NULL)
	{
		fwrite(result_str, 1, strlen(result_str), fp);
		fclose(fp);
	}
}

void ssl_decoder_test_message_cb(struct session *ss, int topic_id, const void *msg, void *per_session_ctx, void *plugin_env_str)
{

}

void *ssl_decoder_test_per_session_context_new(struct session *sess, void *plugin_env)
{
    return NULL;
}

void ssl_decoder_test_per_session_context_free(struct session *sess, void *session_ctx, void *plugin_env)
{

}

int32_t ssl_decoder_test_config_load(const char *cfg_path, struct ssl_decoder_test_plugin_env *plugin_env)
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
	
	toml_datum_t commit_result_enable_val=toml_string_in(test_tbl, "commit_result_enable");
	if(commit_result_enable_val.ok==0)
	{
		plugin_env->commit_result_enable=0;
		fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl.test.commit_result_enable]", __FUNCTION__, __LINE__, cfg_path);
	}
	else
	{
		if(memcmp("no", commit_result_enable_val.u.s, strlen("no"))==0)
		{
			plugin_env->commit_result_enable=0;
		}
		else if(memcmp("yes", commit_result_enable_val.u.s, strlen("yes"))==0)
		{
			plugin_env->commit_result_enable=1;
		}
		else
		{
			plugin_env->commit_result_enable=1;
			fprintf(stderr, "[%s:%d] config file: %s key: [decoder.ssl.test.commit_result_enable] value is not yes or no", __FUNCTION__, __LINE__, cfg_path);
		}
	}

    toml_table_t *perf_tbl=toml_table_in(test_tbl, "perf");
    if(NULL==perf_tbl)
    {
        fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl.test.perf]", __FUNCTION__, __LINE__, cfg_path);
        toml_free(root);
        return -1;
    }

	// decode_resource_record_enable
	toml_datum_t decode_resource_record_enable_val=toml_string_in(perf_tbl, "decode_resource_record_enable");
	if(decode_resource_record_enable_val.ok==0)
	{
		plugin_env->decode_resource_record_enable=0;
		fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl.test.decode_resource_record_enable]", __FUNCTION__, __LINE__, cfg_path);
	}
	else
	{
		if(memcmp("no", decode_resource_record_enable_val.u.s, strlen("no"))==0)
		{
			plugin_env->decode_resource_record_enable=0;
		}
		else if(memcmp("yes", decode_resource_record_enable_val.u.s, strlen("yes"))==0)
		{
			plugin_env->decode_resource_record_enable=1;
		}
		else
		{
			plugin_env->decode_resource_record_enable=1;
			fprintf(stderr, "[%s:%d] config file: %s key: [decoder.ssl.test.decode_resource_record_enable] value is not yes or no", __FUNCTION__, __LINE__, cfg_path);
		}
	}

	// export_resource_record_enable
	toml_datum_t export_resource_record_enable_val=toml_string_in(perf_tbl, "export_resource_record_enable");
	if(export_resource_record_enable_val.ok==0)
	{
		plugin_env->export_resource_record_enable=0;
		fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl.test.export_resource_record_enable]", __FUNCTION__, __LINE__, cfg_path);
	}
	else
	{
		if(memcmp("no", export_resource_record_enable_val.u.s, strlen("no"))==0)
		{
			plugin_env->export_resource_record_enable=0;
		}
		else if(memcmp("yes", export_resource_record_enable_val.u.s, strlen("yes"))==0)
		{
			plugin_env->export_resource_record_enable=1;
		}
		else
		{
			plugin_env->export_resource_record_enable=1;
			fprintf(stderr, "[%s:%d] config file: %s key: [decoder.ssl.test.export_resource_record_enable] value is not yes or no", __FUNCTION__, __LINE__, cfg_path);
		}
	}

	toml_free(root);
	
    return ret;
}

extern "C" void *ssl_decoder_test_init(struct stellar *st)
{
	struct ssl_decoder_test_plugin_env *plugin_env=(struct ssl_decoder_test_plugin_env *)calloc(1, sizeof(struct ssl_decoder_test_plugin_env));

	plugin_env->result_index=1;
	ssl_decoder_test_config_load(ssl_DECODER_TEST_TOML_PATH, plugin_env);

    plugin_env->plugin_id=stellar_session_plugin_register(st, ssl_decoder_test_per_session_context_new, ssl_decoder_test_per_session_context_free, plugin_env);
    if(plugin_env->plugin_id<0)
    {
        printf("ssl_decoder_test_init: stellar_plugin_register failed !!!\n");
		exit(-1);
    }

	plugin_env->topic_id=stellar_session_mq_get_topic_id(st, SSL_DECODER_MESSAGE_TOPIC);
	if(plugin_env->topic_id<0)
	{
		printf("stellar_session_mq_get_topic_id failed, topic: %s \n", SSL_DECODER_MESSAGE_TOPIC);
		exit(-1);
	}

	stellar_session_mq_subscribe(st, plugin_env->topic_id, ssl_decoder_test_message_cb, plugin_env->plugin_id);

    return (void *)plugin_env;
}

extern "C" void ssl_decoder_test_exit(void *plugin_env_str)
{
	if(plugin_env_str!=NULL)
	{
		free(plugin_env_str);
	}
}
