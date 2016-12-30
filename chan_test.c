/*
 * Copyright 2014-2016 The Wazo Authors  (see the AUTHORS file)
 */

#include <asterisk.h>
#include <asterisk/ari.h>
#include <asterisk/channel.h>
#include <asterisk/cli.h>
#include <asterisk/format.h>
#include <asterisk/format_cache.h>
#include <asterisk/format_cap.h>
#include <asterisk/module.h>
#include <asterisk/pbx.h>
#include <asterisk/stasis_channels.h>
#include <sys/timerfd.h>

#define ACTION_ANSWER_NOCHAN 1
#define ACTION_ANSWER_BADTECH 2
#define ACTION_ANSWER_BADSTATE 3

#define DEFAULT_CID_NAME "Alice"
#define DEFAULT_CID_NUM "555"
#define DEFAULT_PROTOCOL "Test"

static struct ast_frame ulaw_frame;
static unsigned int chan_idx = 0;

static struct ast_channel *create_channel(const char *exten, const char *context,
	const char *cid_num, const char *cid_name,
	const char *protocol, const char *prefix, const char *id,
	const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor,
	int autoanswer);

/* 20 ms frame of a 200 Hz tone */
static const unsigned char ulaw_data[] =
{
	0xff, 0xc5, 0xb7, 0xae, 0xa8, 0xa4, 0xa0, 0x9e, 0x9d, 0x9c,
	0x9c, 0x9c, 0x9d, 0x9e, 0xa0, 0xa4, 0xa8, 0xae, 0xb7, 0xc5,
	0xff, 0x45, 0x37, 0x2e, 0x28, 0x24, 0x20, 0x1e, 0x1d, 0x1c,
	0x1c, 0x1c, 0x1d, 0x1e, 0x20, 0x24, 0x28, 0x2e, 0x37, 0x45,
	0xff, 0xc5, 0xb7, 0xae, 0xa8, 0xa4, 0xa0, 0x9e, 0x9d, 0x9c,
	0x9c, 0x9c, 0x9d, 0x9e, 0xa0, 0xa4, 0xa8, 0xae, 0xb7, 0xc5,
	0xff, 0x45, 0x37, 0x2e, 0x28, 0x24, 0x20, 0x1e, 0x1d, 0x1c,
	0x1c, 0x1c, 0x1d, 0x1e, 0x20, 0x24, 0x28, 0x2e, 0x37, 0x45,
	0xff, 0xc5, 0xb7, 0xae, 0xa8, 0xa4, 0xa0, 0x9e, 0x9d, 0x9c,
	0x9c, 0x9c, 0x9d, 0x9e, 0xa0, 0xa4, 0xa8, 0xae, 0xb7, 0xc5,
	0xff, 0x45, 0x37, 0x2e, 0x28, 0x24, 0x20, 0x1e, 0x1d, 0x1c,
	0x1c, 0x1c, 0x1d, 0x1e, 0x20, 0x24, 0x28, 0x2e, 0x37, 0x45,
	0xff, 0xc5, 0xb7, 0xae, 0xa8, 0xa4, 0xa0, 0x9e, 0x9d, 0x9c,
	0x9c, 0x9c, 0x9d, 0x9e, 0xa0, 0xa4, 0xa8, 0xae, 0xb7, 0xc5,
	0xff, 0x45, 0x37, 0x2e, 0x28, 0x24, 0x20, 0x1e, 0x1d, 0x1c,
	0x1c, 0x1c, 0x1d, 0x1e, 0x20, 0x24, 0x28, 0x2e, 0x37, 0x45,
};

struct test_pvt {
	int timerfd;
	int autoanswer;
};

static struct test_pvt *test_pvt_create(int autoanswer)
{
	struct test_pvt *pvt;

	pvt = ast_calloc(1, sizeof(*pvt));
	if (!pvt) {
		return NULL;
	}

	pvt->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (pvt->timerfd == -1) {
		ast_log(LOG_ERROR, "test_pvt_create failed: %s\n", strerror(errno));
		ast_free(pvt);
		return NULL;
	}

	pvt->autoanswer = autoanswer;

	return pvt;
}

static void test_pvt_free(struct test_pvt *pvt)
{
	close(pvt->timerfd);
	ast_free(pvt);
}

static int test_pvt_start_timer(struct test_pvt *pvt)
{
	struct itimerspec timer;

	timer.it_interval.tv_sec = 0;
	timer.it_interval.tv_nsec = 20000000;	/* 20 ms */
	timer.it_value.tv_sec = 0;
	timer.it_value.tv_nsec = 20000000;

	if (timerfd_settime(pvt->timerfd, 0, &timer, NULL)) {
		return -1;
	}

	return 0;
}

static void answer_outbound_channel(struct ast_channel *channel)
{
	struct test_pvt *pvt = ast_channel_tech_pvt(channel);

	test_pvt_start_timer(pvt);
	ast_queue_control(channel, AST_CONTROL_ANSWER);
}

static struct ast_channel *channel_tech_requester(const char *type, struct ast_format_cap *cap, const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor, const char *addr, int *cause)
{
	char *options;
	int autoanswer = 0;
	const char *protocol = DEFAULT_PROTOCOL;

	options = strrchr(addr, '/');
	if (options) {
		*options++ = '\0';

		if (!strncmp(options, "autoanswer", 10)) {
			autoanswer = 1;
		}
	}

	return create_channel("s", "", DEFAULT_CID_NUM, DEFAULT_CID_NAME, protocol, addr, NULL, assignedids, requestor, autoanswer);
}

static int channel_tech_call(struct ast_channel *channel, const char *dest, int timeout)
{
	struct test_pvt *pvt = ast_channel_tech_pvt(channel);

	ast_setstate(channel, AST_STATE_RINGING);
	ast_queue_control(channel, AST_CONTROL_RINGING);

	if (pvt->autoanswer) {
		answer_outbound_channel(channel);
	}

	return 0;
}

static int channel_tech_hangup(struct ast_channel *channel)
{
	struct test_pvt *pvt = ast_channel_tech_pvt(channel);

	ast_setstate(channel, AST_STATE_DOWN);
	ast_channel_tech_pvt_set(channel, NULL);

	test_pvt_free(pvt);
	ast_module_unref(ast_module_info->self);

	return 0;
}

static int channel_tech_answer(struct ast_channel *channel)
{
	struct test_pvt *pvt = ast_channel_tech_pvt(channel);

	test_pvt_start_timer(pvt);

	ast_setstate(channel, AST_STATE_UP);

	return 0;
}

static struct ast_frame *channel_tech_read(struct ast_channel *channel)
{
	struct test_pvt *pvt = ast_channel_tech_pvt(channel);
	uint64_t value;

	read(pvt->timerfd, &value, sizeof(value));

	return &ulaw_frame;
}

static int channel_tech_write(struct ast_channel *channel, struct ast_frame *frame)
{
	return 0;
}

static int channel_tech_indicate(struct ast_channel *channel, int ind, const void *data, size_t datalen)
{
	return 0;
}

static struct ast_channel_tech test_tech = {
	.type = "Test",
	.description = "Test Channel Driver",
	.properties = AST_CHAN_TP_WANTSJITTER | AST_CHAN_TP_CREATESJITTER,
	.requester = channel_tech_requester,
	.call = channel_tech_call,
	.hangup = channel_tech_hangup,
	.answer = channel_tech_answer,
	.read = channel_tech_read,
	.write = channel_tech_write,
	.indicate = channel_tech_indicate,
};

static struct ast_channel *create_channel(const char *exten, const char *context,
	const char *cid_num, const char *cid_name,
	const char *protocol, const char *prefix, const char *id,
	const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor,
	int autoanswer)
{
	struct ast_format_cap *native_cap;
	struct ast_channel *channel;
	struct test_pvt *pvt;
	char buf[48] = "";
	sprintf(buf, "%08x", ast_atomic_fetchadd_int((int *)&chan_idx, +1));

	native_cap = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);
	if (!native_cap) {
		return NULL;
	}

	pvt = test_pvt_create(autoanswer);
	if (!pvt) {
		ao2_ref(native_cap, -1);
		return NULL;
	}

	channel = ast_channel_alloc(1, AST_STATE_DOWN, cid_num, cid_name, "", exten, context, assignedids, requestor, 0, "%s/%s-%s", protocol, prefix, id ? id : buf);
	if (!channel) {
		ao2_ref(native_cap, -1);
		test_pvt_free(pvt);
		return NULL;
	}

	ast_channel_stage_snapshot(channel);
	ast_channel_tech_set(channel, &test_tech);
	ast_channel_tech_pvt_set(channel, pvt);
	ast_channel_set_fd(channel, 0, pvt->timerfd);

	ast_format_cap_append(native_cap, ast_format_ulaw, 0);
	ast_channel_nativeformats_set(channel, native_cap);
	ast_channel_set_writeformat(channel, ast_format_ulaw);
	ast_channel_set_rawwriteformat(channel, ast_format_ulaw);
	ast_channel_set_readformat(channel, ast_format_ulaw);
	ast_channel_set_rawreadformat(channel, ast_format_ulaw);

	ast_channel_stage_snapshot_done(channel);
	ast_channel_unlock(channel);

	ast_module_ref(ast_module_info->self);

	return channel;
}

static int action_answer(const char *name)
{
	struct ast_channel *channel;
	int res = 0;

	channel = ast_channel_get_by_name(name);
	if (!channel) {
		ast_log(LOG_DEBUG, "can't answer channel: no such channel: %s\n", name);
		return ACTION_ANSWER_NOCHAN;
	}

	ast_channel_lock(channel);

	if (ast_channel_tech(channel) != &test_tech) {
		ast_log(LOG_DEBUG, "can't answer channel: not a chan_test channel\n");
		res = ACTION_ANSWER_BADTECH;
		goto unlock;
	}

	if (ast_channel_state(channel) != AST_STATE_RINGING) {
		ast_log(LOG_DEBUG, "can't answer channel: channel is not ringing\n");
		res = ACTION_ANSWER_BADSTATE;
		goto unlock;
	}

	answer_outbound_channel(channel);

unlock:
	ast_channel_unlock(channel);
	ast_channel_unref(channel);

	return res;
}

static int action_new(const char *exten, const char *context, const char *cid_num, const char *cid_name, const char *protocol, const char *id, char *res_uniqueid)
{
	struct ast_channel *channel;

	channel = create_channel(exten, context, cid_num, cid_name, protocol, "auto", id, NULL, NULL, 0);
	if (!channel) {
		ast_log(LOG_DEBUG, "can't create channel: create_channel failed\n");
		return -1;
	}

	if (res_uniqueid) {
		/* caller is responsible for buffer to be at least AST_MAX_UNIQUEID long */
		strcpy(res_uniqueid, ast_channel_uniqueid(channel));
	}

	ast_setstate(channel, AST_STATE_RING);
	ast_pbx_start(channel);

	return 0;
}

static int action_dtmf(const char *name, int digit)
{
	struct ast_frame frame = { .frametype = AST_FRAME_DTMF, };
	struct ast_channel *channel;

	channel = ast_channel_get_by_name(name);
	if (!channel) {
		ast_log(LOG_DEBUG, "can't answer channel: no such channel: %s\n", name);
		return -1;
	}

	/* no need to actually check the channel's, i.e. it's going to work for other tech too */
	frame.subclass.integer = digit;
	frame.src = "test";
	frame.len = 100;
	frame.offset = 0;
	frame.datalen = 0;
	ast_queue_frame(channel, &frame);

	ast_channel_unref(channel);

	return 0;
}

static char *cli_new(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	const char *cid_name = DEFAULT_CID_NAME;
	const char *cid_num = DEFAULT_CID_NUM;
	const char *protocol = DEFAULT_PROTOCOL;

	switch (cmd) {
	case CLI_INIT:
		e->command = "test new";
		e->usage =
				"Usage: test new <exten> <context> [cid_num] [cid_name] [protocol]\n"
				"       Create a new test channel.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc < 4) {
		return CLI_SHOWUSAGE;
	}

	if (a->argc > 4) {
		cid_num = a->argv[4];
	}

	if (a->argc > 5) {
		cid_name = a->argv[5];
	}

	if (a->argc > 6) {
		protocol = a->argv[6];
	}

	if (action_new(a->argv[2], a->argv[3], cid_num, cid_name, protocol, NULL, NULL)) {
		return CLI_FAILURE;
	}

	return CLI_SUCCESS;
}

static char *cli_newid(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	const char *cid_name = DEFAULT_CID_NAME;
	const char *cid_num = DEFAULT_CID_NUM;
	const char *protocol = DEFAULT_PROTOCOL;

	switch (cmd) {
	case CLI_INIT:
		e->command = "test newid";
		e->usage =
				"Usage: test newid <channelid> <exten> <context> [cid_num] [cid_name] [protocol]\n"
				"       Create a new test channel.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc < 5) {
		return CLI_SHOWUSAGE;
	}

	if (a->argc > 5) {
		cid_num = a->argv[5];
	}

	if (a->argc > 6) {
		cid_name = a->argv[6];
	}

	if (a->argc > 7) {
		protocol = a->argv[7];
	}

	if (action_new(a->argv[3], a->argv[4], cid_num, cid_name, protocol, a->argv[2], NULL)) {
		return CLI_FAILURE;
	}

	return CLI_SUCCESS;
}

static char *cli_answer(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "test answer";
		e->usage =
				"Usage: test answer <channel>\n"
				"       Answer a test channel.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc < 3) {
		return CLI_SHOWUSAGE;
	}

	if (action_answer(a->argv[2])) {
		return CLI_FAILURE;
	}

	return CLI_SUCCESS;
}

static char *cli_dtmf(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int digit;

	switch (cmd) {
	case CLI_INIT:
		e->command = "test dtmf";
		e->usage =
				"Usage: test dtmf <channel> <digit>\n"
				"       Add a DTMF to a channel's frame queue.\n";
		return NULL;
	case CLI_GENERATE:
		if (a->pos == 2) {
			return ast_complete_channels(a->line, a->word, a->pos, a->n, 2);
		}

		return NULL;
	}

	if (a->argc < 4) {
		return CLI_SHOWUSAGE;
	}

	if (strlen(a->argv[3]) != 1) {
		ast_cli(a->fd, "<digit> must be exactly 1 character\n");
		return CLI_FAILURE;
	}

	digit = a->argv[3][0];
	if (action_dtmf(a->argv[2], digit)) {
		return CLI_FAILURE;
	}

	return CLI_SUCCESS;
}
static struct ast_cli_entry cli_entries[] = {
	AST_CLI_DEFINE(cli_new, "Create a new test channel"),
	AST_CLI_DEFINE(cli_newid, "Create a new test channel with id"),
	AST_CLI_DEFINE(cli_answer, "Answer a test channel"),
	AST_CLI_DEFINE(cli_dtmf, "Add a DTMF to a channel's frame queue"),
};

static void ari_chan_test_answer_cb(
	struct ast_tcptls_session_instance *ser,
	struct ast_variable *get_params, struct ast_variable *path_vars,
	struct ast_variable *headers, struct ast_ari_response *response)
{
	struct ast_variable *i;
	const char *channel_id = NULL;

	for (i = get_params; i; i = i->next) {
		if (strcmp(i->name, "id") == 0) {
			channel_id = (i->value);
		}
	}

	if (!channel_id) {
		ast_ari_response_error(response, 400, "Bad Request", "id is required");
		return;
	}

	switch (action_answer(channel_id)) {
	case 0:
		ast_ari_response_no_content(response);
		break;
	case ACTION_ANSWER_NOCHAN:
		ast_ari_response_error(response, 400, "Bad Request", "No such channel");
		break;
	case ACTION_ANSWER_BADTECH:
		ast_ari_response_error(response, 400, "Bad Request", "Bad channel tech");
		break;
	case ACTION_ANSWER_BADSTATE:
		ast_ari_response_error(response, 400, "Bad Request", "Bad channel state");
		break;
	default:
		ast_ari_response_error(response, 500, "Internal Server Error", "Unexpected error");
		break;
	}
}

static void ari_chan_test_new_cb(
	struct ast_tcptls_session_instance *ser,
	struct ast_variable *get_params, struct ast_variable *path_vars,
	struct ast_variable *headers, struct ast_ari_response *response)
{
	struct ast_variable *i;
	const char *exten = NULL;
	const char *context = NULL;
	const char *cid_name = DEFAULT_CID_NAME;
	const char *cid_num = DEFAULT_CID_NUM;
	const char *protocol = DEFAULT_PROTOCOL;
	struct ast_json *json;
	char res_uniqueid[AST_MAX_UNIQUEID];

	for (i = get_params; i; i = i->next) {
		if (strcmp(i->name, "exten") == 0) {
			exten = (i->value);
		} else if (strcmp(i->name, "context") == 0) {
			context = (i->value);
		} else if (strcmp(i->name, "cid_name") == 0) {
			cid_name = (i->value);
		} else if (strcmp(i->name, "cid_num") == 0) {
			cid_num = (i->value);
		} else if (strcmp(i->name, "protocol") == 0) {
			protocol = (i->value);
		}
	}

	if (!exten) {
		ast_ari_response_error(response, 400, "Bad Request", "exten is required");
		return;
	} else if (!context) {
		ast_ari_response_error(response, 400, "Bad Request", "context is required");
		return;
	}

	switch (action_new(exten, context, cid_num, cid_name, protocol, NULL, res_uniqueid)) {
	case 0:
		json = ast_json_pack("{s: s}", "uniqueid", res_uniqueid);
		if (!json) {
			ast_ari_response_alloc_failed(response);
		} else {
			ast_ari_response_ok(response, json);
		}
		break;
	default:
		ast_ari_response_error(response, 500, "Internal Server Error", "Unexpected error");
		break;
	}
}

static struct stasis_rest_handlers ari_chan_test_answer = {
	.path_segment = "answer",
	.callbacks = {
		[AST_HTTP_POST] = ari_chan_test_answer_cb,
	},
	.num_children = 0,
	.children = {  }
};

static struct stasis_rest_handlers ari_chan_test_new = {
	.path_segment = "new",
	.callbacks = {
		[AST_HTTP_POST] = ari_chan_test_new_cb,
	},
	.num_children = 0,
	.children = {  }
};

static struct stasis_rest_handlers ari_chan_test = {
	.path_segment = "chan_test",
	.callbacks = {
	},
	.num_children = 2,
	.children = { &ari_chan_test_new,&ari_chan_test_answer }
};

static int register_test_tech(void)
{
	test_tech.capabilities = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);
	if (!test_tech.capabilities) {
		return -1;
	}

	ast_format_cap_append_by_type(test_tech.capabilities, AST_MEDIA_TYPE_AUDIO);

	return ast_channel_register(&test_tech);
}

static void unregister_test_tech(void)
{
	ast_channel_unregister(&test_tech);
	ao2_ref(test_tech.capabilities, -1);
}

static int load_module(void)
{
	ulaw_frame.frametype = AST_FRAME_VOICE;
	ulaw_frame.subclass.format = ao2_bump(ast_format_ulaw);
	ulaw_frame.datalen = 160;
	ulaw_frame.samples = 160;
	ulaw_frame.mallocd = 0;
	ulaw_frame.data.ptr = (void *) ulaw_data;
	ulaw_frame.len = 20;

	if (register_test_tech()) {
		ao2_ref(ulaw_frame.subclass.format, -1);
		return AST_MODULE_LOAD_DECLINE;
	}

	if (ast_ari_add_handler(&ari_chan_test)) {
		ast_log(LOG_ERROR, "could not add ARI handler\n");
	}

	ast_cli_register_multiple(cli_entries, ARRAY_LEN(cli_entries));

	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	ast_cli_unregister_multiple(cli_entries, ARRAY_LEN(cli_entries));

	ast_ari_remove_handler(&ari_chan_test);

	unregister_test_tech();

	return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Test Channel Driver",
	.load = load_module,
	.unload = unload_module,
	.load_pri = AST_MODPRI_CHANNEL_DRIVER,
	.nonoptreq = "res_ari",
);
