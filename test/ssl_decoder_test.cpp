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
#include "yyjson/yyjson.h"
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

struct ssl_decoder_test_context
{
	yyjson_mut_doc *doc;
	yyjson_mut_val *ssl_object;
};

struct ssl_decoder_test_plugin_env
{
	int plugin_id;
	int topic_id;
	int result_index;
	int commit_result_enable;
};

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
	struct ssl_message *ssl_msg=(struct ssl_message *)msg;
	if(ssl_msg==NULL)
	{
		return;
	}

	struct ssl_decoder_test_context *per_ss_ctx=(struct ssl_decoder_test_context *)per_session_ctx;

	enum ssl_message_type msg_type=ssl_message_type_get(ssl_msg);
	switch(msg_type)
	{
		case	SSL_MESSAGE_CLIENT_HELLO:
			{
				yyjson_mut_obj_add_str(per_ss_ctx->doc ,per_ss_ctx->ssl_object, "ssl_client_version", ssl_message_readable_version_get0(ssl_msg));

				char *sni=NULL;
				size_t sni_sz=0;
				ssl_message_sni_get0(ssl_msg, &sni, &sni_sz);
				yyjson_mut_obj_add_strn(per_ss_ctx->doc ,per_ss_ctx->ssl_object, "ssl_sni", sni, sni_sz);

				char *ja3=NULL;
				size_t ja3_sz=0;
				ssl_message_ja3hash_get0(ssl_msg, &ja3, &ja3_sz);
				yyjson_mut_obj_add_strn(per_ss_ctx->doc ,per_ss_ctx->ssl_object, "ssl_ja3_hash", ja3, ja3_sz);

				int32_t esni_flag=ssl_message_esni_is_true(ssl_msg);
				yyjson_mut_obj_add_int(per_ss_ctx->doc ,per_ss_ctx->ssl_object, "ssl_esni", esni_flag);

				int32_t ech_flag=ssl_message_ech_is_true(ssl_msg);
				yyjson_mut_obj_add_int(per_ss_ctx->doc ,per_ss_ctx->ssl_object, "ssl_ech", ech_flag);
			}
			break;
		case	SSL_MESSAGE_SERVER_HELLO:
			{
				yyjson_mut_obj_add_str(per_ss_ctx->doc ,per_ss_ctx->ssl_object, "ssl_server_version", ssl_message_readable_version_get0(ssl_msg));

				char *ja3s=NULL;
				size_t ja3s_sz=0;
				ssl_message_ja3shash_get0(ssl_msg, &ja3s, &ja3s_sz);
				yyjson_mut_obj_add_strn(per_ss_ctx->doc ,per_ss_ctx->ssl_object, "ssl_ja3s_hash", ja3s, ja3s_sz);
			}
			break;
		case	SSL_MESSAGE_CERTIFICATE:
			break;
		case	SSL_PROTECTED_PAYLOAD:
			break;
		default:
			break;
	}
}

void *ssl_decoder_test_per_session_context_new(struct session *ss, void *plugin_env)
{
	struct ssl_decoder_test_context *per_ss_ctx=(struct ssl_decoder_test_context *)calloc(1, sizeof(struct ssl_decoder_test_context));
	per_ss_ctx->doc=yyjson_mut_doc_new(0);
	per_ss_ctx->ssl_object=yyjson_mut_obj(per_ss_ctx->doc);

    return (void *)per_ss_ctx;
}

void ssl_decoder_test_per_session_context_free(struct session *ss, void *per_session_ctx, void *plugin_env_str)
{
	struct ssl_decoder_test_plugin_env *plugin_env=(struct ssl_decoder_test_plugin_env *)plugin_env_str;
	struct ssl_decoder_test_context *per_ss_ctx=(struct ssl_decoder_test_context *)per_session_ctx;
	if(per_ss_ctx==NULL)
	{
		return;
	}

	yyjson_mut_doc_set_root(per_ss_ctx->doc, per_ss_ctx->ssl_object);
	char *json_str=yyjson_mut_write(per_ss_ctx->doc, 0, 0);
	yyjson_mut_doc_free(per_ss_ctx->doc);

	char result_name[16]="";
	sprintf(result_name, "SSL_RESULT_%d", plugin_env->result_index++);
	cJSON *real_result=cJSON_Parse(json_str);
	commit_test_result_json(real_result, result_name);

	free(json_str);
	free(per_ss_ctx);
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
