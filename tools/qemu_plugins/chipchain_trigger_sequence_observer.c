/*
 * ChipChain Phase 9C Step 3A passive ARM trigger-sequence observer.
 *
 * This isolated plugin copies PC, instruction size, and instruction bytes
 * during translation, then emits an event only from the execution callback.
 * It never reads registers or guest memory and never mutates guest state.
 */

#include <glib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef struct InstructionMetadata {
    uint64_t pc;
    size_t size;
    uint8_t *bytes;
} InstructionMetadata;

static const char *const plugin_name =
    "chipchain-qemu-trigger-sequence-observer";
static FILE *trace_file;
static char *output_path;
static char *run_id;
static GMutex state_lock;
static GPtrArray *metadata_items;
static uint64_t next_sequence;
static bool trace_failed;

static void append_json_string(GString *record, const char *value)
{
    const unsigned char *cursor = (const unsigned char *)value;

    g_string_append_c(record, '"');
    while (*cursor != '\0') {
        switch (*cursor) {
        case '"':
            g_string_append(record, "\\\"");
            break;
        case '\\':
            g_string_append(record, "\\\\");
            break;
        case '\b':
            g_string_append(record, "\\b");
            break;
        case '\f':
            g_string_append(record, "\\f");
            break;
        case '\n':
            g_string_append(record, "\\n");
            break;
        case '\r':
            g_string_append(record, "\\r");
            break;
        case '\t':
            g_string_append(record, "\\t");
            break;
        default:
            if (*cursor < 0x20) {
                g_string_append_printf(record, "\\u%04x", *cursor);
            } else {
                g_string_append_c(record, (char)*cursor);
            }
        }
        cursor++;
    }
    g_string_append_c(record, '"');
}

static void free_instruction_metadata(gpointer value)
{
    InstructionMetadata *metadata = value;

    if (metadata != NULL) {
        g_free(metadata->bytes);
        g_free(metadata);
    }
}

static void write_record_locked(GString *record)
{
    g_string_append_c(record, '\n');
    if (fwrite(record->str, record->len, 1, trace_file) != 1 ||
        fflush(trace_file) != 0) {
        trace_failed = true;
        qemu_plugin_outs("chipchain trigger observer: trace write failed\n");
    }
}

static void emit_instruction(unsigned int vcpu_index, void *userdata)
{
    const InstructionMetadata *metadata = userdata;
    GString *record = g_string_new(NULL);
    size_t index;

    g_mutex_lock(&state_lock);
    g_string_append_printf(
        record,
        "{\"record_type\":\"event\",\"schema_version\":1,"
        "\"sequence_index\":%" PRIu64 ",\"vcpu_index\":%u,"
        "\"event_kind\":\"instruction_exec\","
        "\"pc\":{\"value\":\"0x%" PRIx64 "\"},"
        "\"instruction_size\":%zu,\"instruction_bytes\":\"",
        next_sequence++, vcpu_index, metadata->pc, metadata->size);
    for (index = 0; index < metadata->size; index++) {
        g_string_append_printf(record, "%02x", metadata->bytes[index]);
    }
    g_string_append(record, "\"}");
    write_record_locked(record);
    g_mutex_unlock(&state_lock);
    g_string_free(record, TRUE);
}

static void record_capture_failure(void)
{
    g_mutex_lock(&state_lock);
    trace_failed = true;
    g_mutex_unlock(&state_lock);
    qemu_plugin_outs(
        "chipchain trigger observer: instruction metadata copy failed\n");
}

static void translate_block(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t instruction_count = qemu_plugin_tb_n_insns(tb);
    size_t index;

    (void)id;
    for (index = 0; index < instruction_count; index++) {
        struct qemu_plugin_insn *instruction =
            qemu_plugin_tb_get_insn(tb, index);
        size_t size = qemu_plugin_insn_size(instruction);
        InstructionMetadata *metadata;

        if (size == 0 || size > 16) {
            record_capture_failure();
            continue;
        }
        metadata = g_new0(InstructionMetadata, 1);
        metadata->pc = qemu_plugin_insn_vaddr(instruction);
        metadata->size = size;
        metadata->bytes = g_malloc(size);
        if (qemu_plugin_insn_data(instruction, metadata->bytes, size) != size) {
            free_instruction_metadata(metadata);
            record_capture_failure();
            continue;
        }
        g_mutex_lock(&state_lock);
        g_ptr_array_add(metadata_items, metadata);
        g_mutex_unlock(&state_lock);
        qemu_plugin_register_vcpu_insn_exec_cb(
            instruction, emit_instruction, QEMU_PLUGIN_CB_NO_REGS, metadata);
    }
}

static void observer_exit(qemu_plugin_id_t id, void *userdata)
{
    GString *record = g_string_new(NULL);

    (void)id;
    (void)userdata;
    g_mutex_lock(&state_lock);
    g_string_append_printf(
        record,
        "{\"record_type\":\"end\",\"schema_version\":1,"
        "\"event_count\":%" PRIu64 ",\"last_sequence_index\":",
        next_sequence);
    if (next_sequence == 0) {
        g_string_append(record, "null");
    } else {
        g_string_append_printf(record, "%" PRIu64, next_sequence - 1);
    }
    g_string_append_printf(record, ",\"clean_shutdown\":%s}",
                           trace_failed ? "false" : "true");
    write_record_locked(record);
    fclose(trace_file);
    trace_file = NULL;
    g_mutex_unlock(&state_lock);
    g_string_free(record, TRUE);
    g_ptr_array_free(metadata_items, TRUE);
    metadata_items = NULL;
    g_free(output_path);
    g_free(run_id);
    g_mutex_clear(&state_lock);
}

static bool parse_options(int argc, char **argv)
{
    int index;

    for (index = 0; index < argc; index++) {
        if (g_str_has_prefix(argv[index], "out=")) {
            if (output_path != NULL || argv[index][4] == '\0') {
                return false;
            }
            output_path = g_strdup(argv[index] + 4);
        } else if (g_str_has_prefix(argv[index], "run_id=")) {
            if (run_id != NULL || argv[index][7] == '\0') {
                return false;
            }
            run_id = g_strdup(argv[index] + 7);
            if (strspn(run_id, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "abcdefghijklmnopqrstuvwxyz"
                               "0123456789._:-") != strlen(run_id)) {
                return false;
            }
        } else {
            return false;
        }
    }
    return output_path != NULL && run_id != NULL;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    GString *header;

    if (!info->system_emulation || strcmp(info->target_name, "arm") != 0 ||
        info->system.smp_vcpus != 1) {
        return 1;
    }
    if (!parse_options(argc, argv)) {
        g_free(output_path);
        g_free(run_id);
        output_path = NULL;
        run_id = NULL;
        return 1;
    }
    trace_file = fopen(output_path, "wb");
    if (trace_file == NULL) {
        g_free(output_path);
        g_free(run_id);
        output_path = NULL;
        run_id = NULL;
        return 1;
    }
    g_mutex_init(&state_lock);
    metadata_items = g_ptr_array_new_with_free_func(free_instruction_metadata);
    header = g_string_new(
        "{\"record_type\":\"header\","
        "\"format\":\"chipchain_qemu_trigger_sequence_trace\","
        "\"format_version\":1,\"plugin_name\":");
    append_json_string(header, plugin_name);
    g_string_append_printf(
        header,
        ",\"plugin_build_api_version\":%d,\"target_name\":",
        QEMU_PLUGIN_VERSION);
    append_json_string(header, info->target_name);
    g_string_append_printf(
        header,
        ",\"plugin_api_min\":%d,\"plugin_api_current\":%d,"
        "\"system_emulation\":true,\"smp_vcpus\":%d,\"max_vcpus\":%d,"
        "\"run_id\":",
        info->version.min, info->version.cur, info->system.smp_vcpus,
        info->system.max_vcpus);
    append_json_string(header, run_id);
    g_string_append_c(header, '}');
    g_mutex_lock(&state_lock);
    write_record_locked(header);
    g_mutex_unlock(&state_lock);
    g_string_free(header, TRUE);

    qemu_plugin_register_vcpu_tb_trans_cb(id, translate_block);
    qemu_plugin_register_atexit_cb(id, observer_exit, NULL);
    return 0;
}
