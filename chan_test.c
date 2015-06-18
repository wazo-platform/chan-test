#include <asterisk.h>
#include <asterisk/channel.h>
#include <asterisk/cli.h>
#include <asterisk/format.h>
#include <asterisk/format_cache.h>
#include <asterisk/format_cap.h>
#include <asterisk/module.h>
#include <asterisk/pbx.h>
#include <asterisk/stasis_channels.h>
#include <sys/timerfd.h>

#define DEFAULT_CID_NAME "Alice"
#define DEFAULT_CID_NUM "555"

static struct ast_frame ulaw_frame;
static unsigned int chan_idx = 0;

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
};

static struct test_pvt *test_pvt_create(void)
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

static int channel_tech_hangup(struct ast_channel *channel)
{
	struct test_pvt *pvt = ast_channel_tech_pvt(channel);

	ast_setstate(channel, AST_STATE_DOWN);
	ast_channel_tech_pvt_set(channel, NULL);

	test_pvt_free(pvt);

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
	.hangup = channel_tech_hangup,
	.answer = channel_tech_answer,
	.read = channel_tech_read,
	.write = channel_tech_write,
	.indicate = channel_tech_indicate,
};

static struct ast_channel *create_channel(const char *exten, const char *context, const char *cid_num, const char *cid_name, const char *id)
{
	struct ast_channel *channel;
	struct test_pvt *pvt;
	char buf[48] = "";
	sprintf(buf, "%08x", ast_atomic_fetchadd_int((int *)&chan_idx, +1));

	pvt = test_pvt_create();
	if (!pvt) {
		return NULL;
	}

	channel = ast_channel_alloc(1, AST_STATE_DOWN, cid_num, cid_name, "", exten, context, NULL, NULL, 0, "SIP/pouet-%s", id ? id : buf);
	if (!channel) {
		test_pvt_free(pvt);
		return NULL;
	}

	ast_channel_stage_snapshot(channel);
	ast_channel_tech_set(channel, &test_tech);
	ast_channel_tech_pvt_set(channel, pvt);
	ast_channel_set_fd(channel, 0, pvt->timerfd);

	ast_format_cap_append(ast_channel_nativeformats(channel), ast_format_ulaw, 0);
	ast_channel_set_writeformat(channel, ast_format_ulaw);
	ast_channel_set_rawwriteformat(channel, ast_format_ulaw);
	ast_channel_set_readformat(channel, ast_format_ulaw);
	ast_channel_set_rawreadformat(channel, ast_format_ulaw);

	ast_channel_stage_snapshot_done(channel);
	ast_channel_unlock(channel);

	return channel;
}

static char *cli_new(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct ast_channel *channel;
	const char *cid_name = DEFAULT_CID_NAME;
	const char *cid_num = DEFAULT_CID_NUM;

	switch (cmd) {
	case CLI_INIT:
		e->command = "test new";
		e->usage =
				"Usage: test new <exten> <context> [cid_num] [cid_name]\n"
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

	channel = create_channel(a->argv[2], a->argv[3], cid_num, cid_name, NULL);
	if (!channel) {
		return CLI_FAILURE;
	}

	ast_setstate(channel, AST_STATE_RING);
	ast_pbx_start(channel);

	return CLI_SUCCESS;
}

static char *cli_newid(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
    struct ast_channel *channel;
    const char *cid_name = DEFAULT_CID_NAME;
    const char *cid_num = DEFAULT_CID_NUM;

    switch (cmd) {
    case CLI_INIT:
        e->command = "test newid";
        e->usage =
                "Usage: test newid <channelid> <exten> <context> [cid_num] [cid_name]\n"
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
        cid_name = a->argv[7];
    }

    channel = create_channel(a->argv[3], a->argv[4], cid_num, cid_name, a->argv[2]);
    if (!channel) {
        return CLI_FAILURE;
    }

    ast_setstate(channel, AST_STATE_RING);
    ast_pbx_start(channel);

    return CLI_SUCCESS;
}

static struct ast_cli_entry cli_entries[] = {
	AST_CLI_DEFINE(cli_new, "Create a new test channel"),
    AST_CLI_DEFINE(cli_newid, "Create a new test channel with id"),
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

	ast_cli_register_multiple(cli_entries, ARRAY_LEN(cli_entries));

	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	ast_cli_unregister_multiple(cli_entries, ARRAY_LEN(cli_entries));

	unregister_test_tech();

	return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Test Channel Driver",
	.load = load_module,
	.unload = unload_module,
	.load_pri = AST_MODPRI_CHANNEL_DRIVER,
);
