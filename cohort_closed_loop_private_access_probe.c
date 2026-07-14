#define _GNU_SOURCE

/*
 * Fixed setuid access probe for the structured TTT-RL private boundary.
 *
 * Installation contract (enforced again by the Python attester):
 *   root:41001, mode 04750, nlink 1, no ACL/xattr/file capabilities, and a
 *   suid-enabled mount.  The attester opens and hashes this binary once and
 *   executes that exact descriptor with fexecve(3).  This program then binds
 *   /proc/self/exe to the attester-supplied device/inode/size/SHA-256 before
 *   accepting its elevated credentials.
 *
 * This helper deliberately emits evidence only.  It grants no DGP, scorer,
 * model, launch, or operational authority.
 */

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/openat2.h>
#include <linux/securebits.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef CAP_LAST_CAP
#define CAP_LAST_CAP 40
#endif

#define ATTESTER_UID 41001U
#define PRIVATE_READ_GID 41016U
#define LOCKED_SECUREBITS                                                     \
  (SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP |          \
   SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_KEEP_CAPS |                       \
   SECBIT_KEEP_CAPS_LOCKED)
#define MAX_PAYLOAD_BYTES (1024U * 1024U)
#define MAX_CAPABILITY_BYTES 1024U
#define PRIVATE_ROOT_PREFIX                                                  \
  "/sensei-fs/private/zcai/TTT-RL/cohort-closed-loop-structured-state/"
#define CAPABILITY_ROOT                                                      \
  "/run/cohort-closed-loop-private-probe-capabilities"
#define CAPABILITY_SCHEMA                                                    \
  "cohort_closed_loop_private_probe_capability_v1"
#define CAPABILITY_BINDING_DOMAIN                                            \
  "cohort_closed_loop_private_probe_request_binding_v1"

/*
 * This stays zero until the separately audited root broker is installed.
 * Merely installing this setuid binary MUST NOT make private-path operations
 * reachable.  Enabling the provider requires changing this constant in a new
 * source commit together with the broker/attester integration and its audit.
 */
#define ROOT_CAPABILITY_BROKER_PROVIDER_AVAILABLE 0
#define INITIAL_PROTOCOL                                                     \
  "cohort_structured_private_context_initial_access_probe_v1"
#define SEALED_PROTOCOL                                                      \
  "cohort_structured_private_context_sealed_access_probe_v1"
#define INITIAL_STAGE "initial_registration_boundary"
#define SEALED_STAGE "sealed_prelaunch_boundary"
#define REGISTRAR_UID 41011U
#define PURE_SCORER_UID 41012U
#define PRIVATE_VALIDATOR_UID 41013U
#define LAUNCHER_UID 41014U
#define OPERATOR_UID 41015U

enum path_kind {
  PATH_PRIVATE_ROOT,
  PATH_TRANSIENT_PROBE,
  PATH_VALIDATOR_CREATE_PROBE,
  PATH_SCORER_CREATE_PROBE,
  PATH_REGISTERED_RECORD
};

enum private_stage_kind {
  PRIVATE_STAGE_SMOKE,
  PRIVATE_STAGE_INTERNAL,
  PRIVATE_STAGE_CONFIRMATION
};

struct probe_spec {
  const char *probe_id;
  const char *protocol;
  const char *stage;
  uid_t target_uid;
  gid_t target_gid;
  bool has_private_read_group;
  const char *operation;
  enum path_kind path_kind;
  bool payload_required;
};

#define SPEC(id, proto, boundary, uid, gid, reader, op, path_type, payload)   \
  {id, proto, boundary, uid, gid, reader, op, path_type, payload}

static const struct probe_spec probe_specs[] = {
    SPEC("01_registrar_create_probe", INITIAL_PROTOCOL, INITIAL_STAGE,
         REGISTRAR_UID, PRIVATE_READ_GID, false, "create_exact_probe",
         PATH_TRANSIENT_PROBE, true),
    SPEC("02_registrar_read_probe", INITIAL_PROTOCOL, INITIAL_STAGE,
         REGISTRAR_UID, PRIVATE_READ_GID, false, "read_exact_probe",
         PATH_TRANSIENT_PROBE, false),
    SPEC("03_private_validator_read_probe", INITIAL_PROTOCOL, INITIAL_STAGE,
         PRIVATE_VALIDATOR_UID, PRIVATE_VALIDATOR_UID, true,
         "read_exact_probe", PATH_TRANSIENT_PROBE, false),
    SPEC("04_private_validator_write_denied", INITIAL_PROTOCOL, INITIAL_STAGE,
         PRIVATE_VALIDATOR_UID, PRIVATE_VALIDATOR_UID, true,
         "write_exact_probe", PATH_TRANSIENT_PROBE, false),
    SPEC("05_private_validator_create_denied", INITIAL_PROTOCOL, INITIAL_STAGE,
         PRIVATE_VALIDATOR_UID, PRIVATE_VALIDATOR_UID, true, "create_record",
         PATH_VALIDATOR_CREATE_PROBE, false),
    SPEC("06_scorer_read_probe", INITIAL_PROTOCOL, INITIAL_STAGE,
         PURE_SCORER_UID, PURE_SCORER_UID, true, "read_exact_probe",
         PATH_TRANSIENT_PROBE, false),
    SPEC("07_scorer_write_denied", INITIAL_PROTOCOL, INITIAL_STAGE,
         PURE_SCORER_UID, PURE_SCORER_UID, true, "write_exact_probe",
         PATH_TRANSIENT_PROBE, false),
    SPEC("08_scorer_create_denied", INITIAL_PROTOCOL, INITIAL_STAGE,
         PURE_SCORER_UID, PURE_SCORER_UID, true, "create_record",
         PATH_SCORER_CREATE_PROBE, false),
    SPEC("09_launcher_enumerate", INITIAL_PROTOCOL, INITIAL_STAGE,
         LAUNCHER_UID, LAUNCHER_UID, false, "enumerate_root",
         PATH_PRIVATE_ROOT, false),
    SPEC("10_launcher_read_probe", INITIAL_PROTOCOL, INITIAL_STAGE,
         LAUNCHER_UID, LAUNCHER_UID, false, "read_exact_probe",
         PATH_TRANSIENT_PROBE, false),
    SPEC("11_operator_enumerate", INITIAL_PROTOCOL, INITIAL_STAGE, OPERATOR_UID,
         OPERATOR_UID, false, "enumerate_root", PATH_PRIVATE_ROOT, false),
    SPEC("12_operator_read_probe", INITIAL_PROTOCOL, INITIAL_STAGE,
         OPERATOR_UID, OPERATOR_UID, false, "read_exact_probe",
         PATH_TRANSIENT_PROBE, false),
    SPEC("13_registrar_remove_probe", INITIAL_PROTOCOL, INITIAL_STAGE,
         REGISTRAR_UID, PRIVATE_READ_GID, false, "remove_exact_probe",
         PATH_TRANSIENT_PROBE, false),
    SPEC("14_registrar_verify_no_leftover", INITIAL_PROTOCOL, INITIAL_STAGE,
         REGISTRAR_UID, PRIVATE_READ_GID, false, "verify_probe_absent",
         PATH_TRANSIENT_PROBE, false),
    SPEC("01_private_validator_read_record", SEALED_PROTOCOL, SEALED_STAGE,
         PRIVATE_VALIDATOR_UID, PRIVATE_VALIDATOR_UID, true,
         "read_registered_record", PATH_REGISTERED_RECORD, false),
    SPEC("02_scorer_read_record", SEALED_PROTOCOL, SEALED_STAGE,
         PURE_SCORER_UID, PURE_SCORER_UID, true, "read_registered_record",
         PATH_REGISTERED_RECORD, false),
    SPEC("03_registrar_read_record", SEALED_PROTOCOL, SEALED_STAGE,
         REGISTRAR_UID, PRIVATE_READ_GID, false, "read_registered_record",
         PATH_REGISTERED_RECORD, false),
    SPEC("04_launcher_enumerate", SEALED_PROTOCOL, SEALED_STAGE, LAUNCHER_UID,
         LAUNCHER_UID, false, "enumerate_root", PATH_PRIVATE_ROOT, false),
    SPEC("05_launcher_read_record", SEALED_PROTOCOL, SEALED_STAGE,
         LAUNCHER_UID, LAUNCHER_UID, false, "read_registered_record",
         PATH_REGISTERED_RECORD, false),
    SPEC("06_operator_enumerate", SEALED_PROTOCOL, SEALED_STAGE, OPERATOR_UID,
         OPERATOR_UID, false, "enumerate_root", PATH_PRIVATE_ROOT, false),
    SPEC("07_operator_read_record", SEALED_PROTOCOL, SEALED_STAGE,
         OPERATOR_UID, OPERATOR_UID, false, "read_registered_record",
         PATH_REGISTERED_RECORD, false),
    SPEC("08_registrar_create_denied", SEALED_PROTOCOL, SEALED_STAGE,
         REGISTRAR_UID, PRIVATE_READ_GID, false, "create_probe_record",
         PATH_TRANSIENT_PROBE, false),
    SPEC("09_registrar_write_denied", SEALED_PROTOCOL, SEALED_STAGE,
         REGISTRAR_UID, PRIVATE_READ_GID, false, "write_registered_record",
         PATH_REGISTERED_RECORD, false),
};

_Static_assert(sizeof(probe_specs) / sizeof(probe_specs[0]) == 23U,
               "the private probe allowlist must contain exactly 23 entries");

struct sha256_ctx {
  uint32_t state[8];
  uint64_t bit_count;
  unsigned char block[64];
  size_t used;
};

static const uint32_t sha256_k[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU,
    0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U,
    0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U,
    0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U,
    0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
    0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U,
    0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U, 0x1e376c08U,
    0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU,
    0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

static uint32_t rotr32(uint32_t x, unsigned int n) {
  return (x >> n) | (x << (32U - n));
}

static void sha256_transform(struct sha256_ctx *ctx,
                             const unsigned char block[64]) {
  uint32_t w[64];
  uint32_t a, b, c, d, e, f, g, h;
  unsigned int i;
  for (i = 0; i < 16; ++i) {
    w[i] = ((uint32_t)block[4U * i] << 24) |
           ((uint32_t)block[4U * i + 1U] << 16) |
           ((uint32_t)block[4U * i + 2U] << 8) |
           (uint32_t)block[4U * i + 3U];
  }
  for (i = 16; i < 64; ++i) {
    uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^
                  (w[i - 15] >> 3);
    uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^
                  (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];
  for (i = 0; i < 64; ++i) {
    uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t t1 = h + s1 + ch + sha256_k[i] + w[i];
    uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

static void sha256_init(struct sha256_ctx *ctx) {
  static const uint32_t initial[8] = {
      0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
      0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
  memcpy(ctx->state, initial, sizeof(initial));
  ctx->bit_count = 0;
  ctx->used = 0;
}

static void sha256_update(struct sha256_ctx *ctx, const unsigned char *data,
                          size_t length) {
  ctx->bit_count += (uint64_t)length * 8U;
  while (length > 0) {
    size_t available = 64U - ctx->used;
    size_t take = length < available ? length : available;
    memcpy(ctx->block + ctx->used, data, take);
    ctx->used += take;
    data += take;
    length -= take;
    if (ctx->used == 64U) {
      sha256_transform(ctx, ctx->block);
      ctx->used = 0;
    }
  }
}

static void sha256_final(struct sha256_ctx *ctx, unsigned char digest[32]) {
  unsigned int i;
  ctx->block[ctx->used++] = 0x80U;
  if (ctx->used > 56U) {
    while (ctx->used < 64U)
      ctx->block[ctx->used++] = 0;
    sha256_transform(ctx, ctx->block);
    ctx->used = 0;
  }
  while (ctx->used < 56U)
    ctx->block[ctx->used++] = 0;
  for (i = 0; i < 8U; ++i)
    ctx->block[63U - i] = (unsigned char)(ctx->bit_count >> (8U * i));
  sha256_transform(ctx, ctx->block);
  for (i = 0; i < 8U; ++i) {
    digest[4U * i] = (unsigned char)(ctx->state[i] >> 24);
    digest[4U * i + 1U] = (unsigned char)(ctx->state[i] >> 16);
    digest[4U * i + 2U] = (unsigned char)(ctx->state[i] >> 8);
    digest[4U * i + 3U] = (unsigned char)ctx->state[i];
  }
}

static void digest_hex(const unsigned char digest[32], char output[65]) {
  static const char alphabet[] = "0123456789abcdef";
  unsigned int i;
  for (i = 0; i < 32U; ++i) {
    output[2U * i] = alphabet[digest[i] >> 4];
    output[2U * i + 1U] = alphabet[digest[i] & 15U];
  }
  output[64] = '\0';
}

static int hash_fd(int fd, uint64_t expected_size, char output[65]) {
  struct sha256_ctx ctx;
  unsigned char buffer[65536];
  uint64_t offset = 0;
  sha256_init(&ctx);
  while (offset < expected_size) {
    size_t want = sizeof(buffer);
    ssize_t count;
    if (expected_size - offset < want)
      want = (size_t)(expected_size - offset);
    count = pread(fd, buffer, want, (off_t)offset);
    if (count <= 0)
      return -1;
    sha256_update(&ctx, buffer, (size_t)count);
    offset += (uint64_t)count;
  }
  {
    unsigned char digest[32];
    sha256_final(&ctx, digest);
    digest_hex(digest, output);
  }
  return 0;
}

struct options {
  const char *probe_id;
  uid_t target_uid;
  gid_t target_gid;
  gid_t target_groups[32];
  size_t target_group_count;
  const char *transition;
  const char *operation;
  const char *path;
  const char *protocol;
  const char *stage;
  const char *policy_sha;
  const char *adapter_sha;
  dev_t expected_device;
  ino_t expected_inode;
  uint64_t expected_size;
  const char *expected_sha;
  dev_t expected_private_root_device;
  ino_t expected_private_root_inode;
  char *private_root;
  const char *relative_path;
  const char *request_capability_path;
  const char *request_capability_sha;
  dev_t expected_capability_root_device;
  ino_t expected_capability_root_inode;
  uint64_t request_epoch;
  uint64_t request_ordinal;
  const char *request_nonce;
  uint64_t request_expiry_boottime_seconds;
  pid_t attester_parent_pid;
  uint64_t attester_parent_start_ticks;
  unsigned char *payload;
  size_t payload_size;
};

enum option_bit {
  OPTION_PROBE_ID = 1U << 0,
  OPTION_TARGET_UID = 1U << 1,
  OPTION_TARGET_GID = 1U << 2,
  OPTION_TARGET_GROUPS = 1U << 3,
  OPTION_TRANSITION = 1U << 4,
  OPTION_OPERATION = 1U << 5,
  OPTION_PATH = 1U << 6,
  OPTION_PROTOCOL = 1U << 7,
  OPTION_STAGE = 1U << 8,
  OPTION_POLICY_SHA = 1U << 9,
  OPTION_ADAPTER_SHA = 1U << 10,
  OPTION_DEVICE = 1U << 11,
  OPTION_INODE = 1U << 12,
  OPTION_SIZE = 1U << 13,
  OPTION_EXECUTABLE_SHA = 1U << 14,
  OPTION_PAYLOAD = 1U << 15,
  OPTION_PRIVATE_ROOT_DEVICE = 1U << 16,
  OPTION_PRIVATE_ROOT_INODE = 1U << 17,
  OPTION_REQUEST_CAPABILITY_PATH = 1U << 18,
  OPTION_REQUEST_CAPABILITY_SHA = 1U << 19,
  OPTION_CAPABILITY_ROOT_DEVICE = 1U << 20,
  OPTION_CAPABILITY_ROOT_INODE = 1U << 21,
  OPTION_REQUEST_EPOCH = 1U << 22,
  OPTION_REQUEST_ORDINAL = 1U << 23,
  OPTION_REQUEST_NONCE = 1U << 24,
  OPTION_REQUEST_EXPIRY = 1U << 25,
  OPTION_ATTESTER_PARENT_PID = 1U << 26,
  OPTION_ATTESTER_PARENT_START_TICKS = 1U << 27
};

#define REQUIRED_OPTION_MASK (((1U << 28) - 1U) & ~OPTION_PAYLOAD)

static void die(const char *message) {
  fprintf(stderr, "%s\n", message);
  exit(2);
}

static uint64_t parse_u64(const char *text, const char *label) {
  char *end = NULL;
  unsigned long long value;
  errno = 0;
  value = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0')
    die(label);
  return (uint64_t)value;
}

static uid_t parse_uid(const char *text) {
  uint64_t value = parse_u64(text, "invalid target uid");
  uid_t converted = (uid_t)value;
  if ((uint64_t)converted != value)
    die("target uid overflows uid_t");
  return converted;
}

static gid_t parse_gid(const char *text, const char *label) {
  uint64_t value = parse_u64(text, label);
  gid_t converted = (gid_t)value;
  if ((uint64_t)converted != value)
    die("target gid overflows gid_t");
  return converted;
}

static pid_t parse_pid(const char *text) {
  uint64_t value = parse_u64(text, "invalid attester parent pid");
  pid_t converted = (pid_t)value;
  if (value == 0U || converted <= 0 || (uint64_t)converted != value)
    die("attester parent pid overflows pid_t");
  return converted;
}

static void claim_option(uint32_t *seen, uint32_t bit) {
  if ((*seen & bit) != 0U)
    die("duplicate option");
  *seen |= bit;
}

static bool is_decimal_digit(char value) {
  return value >= '0' && value <= '9';
}

static bool valid_lower_sha256(const char *value) {
  size_t i;
  if (value == NULL || strlen(value) != 64U)
    return false;
  for (i = 0; i < 64U; ++i)
    if (!((value[i] >= '0' && value[i] <= '9') ||
          (value[i] >= 'a' && value[i] <= 'f')))
      return false;
  return true;
}

static void validate_capability_path(const struct options *options) {
  char expected[PATH_MAX];
  int length = snprintf(
      expected, sizeof(expected),
      CAPABILITY_ROOT "/epochs/%" PRIu64 "/next/%" PRIu64 "-%s.request",
      options->request_epoch, options->request_ordinal, options->request_nonce);
  if (length < 0 || (size_t)length >= sizeof(expected) ||
      strcmp(options->request_capability_path, expected) != 0)
    die("request capability path differs from fixed broker namespace");
}

static bool valid_attempt_component(const char *value) {
  return strlen(value) >= 11U && strncmp(value, "attempt-", 8U) == 0 &&
         is_decimal_digit(value[8]) && is_decimal_digit(value[9]) &&
         is_decimal_digit(value[10]);
}

static const char *parse_private_context_path(
    const char *path, enum private_stage_kind *stage_kind) {
  static const char private_context[] = "/private-context";
  const unsigned char *byte;
  const char *cursor;
  size_t path_length;
  size_t prefix_length = strlen(PRIVATE_ROOT_PREFIX);
  size_t i;

  if (path == NULL)
    die("missing probe path");
  path_length = strlen(path);
  if (path_length == 0U || path[0] != '/' || path[path_length - 1U] == '/' ||
      strstr(path, "//") != NULL || strstr(path, "/./") != NULL ||
      strstr(path, "/../") != NULL ||
      (path_length >= 2U && strcmp(path + path_length - 2U, "/.") == 0) ||
      (path_length >= 3U && strcmp(path + path_length - 3U, "/..") == 0))
    die("probe path is not normalized");
  for (byte = (const unsigned char *)path; *byte != '\0'; ++byte)
    if (*byte < 0x21U || *byte > 0x7eU)
      die("probe path must be printable ASCII without whitespace");
  if (strncmp(path, PRIVATE_ROOT_PREFIX, prefix_length) != 0)
    die("probe path escapes the fixed private root prefix");

  cursor = path + prefix_length;
  if (strlen(cursor) < 40U)
    die("probe path source commit is truncated");
  for (i = 0; i < 40U; ++i)
    if (!((cursor[i] >= '0' && cursor[i] <= '9') ||
          (cursor[i] >= 'a' && cursor[i] <= 'f')))
      die("probe path source commit differs");
  cursor += 40U;
  if (strncmp(cursor, "/attempts/", 10U) != 0)
    die("probe path experiment-attempt namespace differs");
  cursor += 10U;
  if (!valid_attempt_component(cursor) || cursor[11] != '/')
    die("probe path experiment attempt differs");
  cursor += 11U;
  if (strncmp(cursor, "/stages/", 8U) != 0)
    die("probe path stage namespace differs");
  cursor += 8U;
  if (strncmp(cursor, "smoke/", 6U) == 0) {
    *stage_kind = PRIVATE_STAGE_SMOKE;
    cursor += 6U;
  } else if (strncmp(cursor, "internal/", 9U) == 0) {
    *stage_kind = PRIVATE_STAGE_INTERNAL;
    cursor += 9U;
  } else if (strncmp(cursor, "confirmation/", 13U) == 0) {
    *stage_kind = PRIVATE_STAGE_CONFIRMATION;
    cursor += 13U;
  } else {
    die("probe path stage kind differs");
  }
  if (!valid_attempt_component(cursor) || cursor[11] != '/')
    die("probe path stage attempt differs");
  cursor += 11U;
  if (strncmp(cursor, private_context, sizeof(private_context) - 1U) != 0)
    die("probe path private-context suffix differs");
  cursor += sizeof(private_context) - 1U;
  if (*cursor != '\0' && *cursor != '/')
    die("probe path private-context boundary differs");
  return cursor;
}

static void validate_registered_record_path(
    const char *suffix, enum private_stage_kind stage_kind) {
  const char *stage_name;
  const char *cursor;
  unsigned int maximum_blocks;
  unsigned int maximum_items;
  unsigned int block_number;
  unsigned int item_number = 0U;
  size_t stage_length;

  if (stage_kind == PRIVATE_STAGE_SMOKE) {
    stage_name = "smoke";
    maximum_blocks = 1U;
    maximum_items = 5U;
  } else if (stage_kind == PRIVATE_STAGE_INTERNAL) {
    stage_name = "internal";
    maximum_blocks = 3U;
    maximum_items = 20U;
  } else {
    stage_name = "confirmation";
    maximum_blocks = 8U;
    maximum_items = 20U;
  }
  if (strncmp(suffix, "/records/", 9U) != 0)
    die("registered record path must begin under records");
  cursor = suffix + 9U;
  stage_length = strlen(stage_name);
  if (strncmp(cursor, stage_name, stage_length) != 0 ||
      strncmp(cursor + stage_length, "_block_", 7U) != 0)
    die("registered record block identity differs");
  cursor += stage_length + 7U;
  if (!is_decimal_digit(cursor[0]) || !is_decimal_digit(cursor[1]) ||
      cursor[2] != '/')
    die("registered record block number differs");
  block_number = (unsigned int)(cursor[0] - '0') * 10U +
                 (unsigned int)(cursor[1] - '0');
  if (block_number == 0U || block_number > maximum_blocks)
    die("registered record block exceeds stage shape");
  cursor += 3U;
  if (strncmp(cursor, "adaptation/", 11U) == 0)
    cursor += 11U;
  else if (strncmp(cursor, "held_out/", 9U) == 0)
    cursor += 9U;
  else
    die("registered record phase differs");
  if (cursor[0] < '1' || cursor[0] > '9')
    die("registered record item id is not canonical");
  while (is_decimal_digit(*cursor)) {
    item_number = item_number * 10U + (unsigned int)(*cursor - '0');
    if (item_number > maximum_items)
      die("registered record item exceeds stage shape");
    ++cursor;
  }
  if (strcmp(cursor, ".json") != 0 || item_number == 0U)
    die("registered record filename differs");
}

static const char *validate_probe_path(const struct probe_spec *spec,
                                       const char *path) {
  enum private_stage_kind stage_kind;
  const char *suffix = parse_private_context_path(path, &stage_kind);
  if (spec->path_kind == PATH_PRIVATE_ROOT) {
    if (*suffix != '\0')
      die("root probe path has a suffix");
  } else if (spec->path_kind == PATH_TRANSIENT_PROBE) {
    if (strcmp(suffix, "/.private-boundary-registration-probe") != 0)
      die("transient probe path differs");
  } else if (spec->path_kind == PATH_VALIDATOR_CREATE_PROBE) {
    if (strcmp(suffix, "/.private-boundary-validator-create-probe") != 0)
      die("validator create-probe path differs");
  } else if (spec->path_kind == PATH_SCORER_CREATE_PROBE) {
    if (strcmp(suffix, "/.private-boundary-scorer-create-probe") != 0)
      die("scorer create-probe path differs");
  } else {
    validate_registered_record_path(suffix, stage_kind);
  }
  return suffix;
}

static void validate_registered_probe(struct options *options) {
  const struct probe_spec *spec = NULL;
  size_t i;
  for (i = 0; i < sizeof(probe_specs) / sizeof(probe_specs[0]); ++i) {
    if (strcmp(options->probe_id, probe_specs[i].probe_id) == 0) {
      if (spec != NULL)
        die("duplicate probe id in compiled allowlist");
      spec = &probe_specs[i];
    }
  }
  if (spec == NULL)
    die("probe id is absent from the compiled allowlist");
  if (options->target_uid == 0U || options->target_uid != spec->target_uid ||
      options->target_gid != spec->target_gid ||
      strcmp(options->protocol, spec->protocol) != 0 ||
      strcmp(options->stage, spec->stage) != 0 ||
      strcmp(options->operation, spec->operation) != 0 ||
      options->target_group_count !=
          (spec->has_private_read_group ? 1U : 0U) ||
      (spec->has_private_read_group &&
       options->target_groups[0] != PRIVATE_READ_GID) ||
      spec->payload_required != (options->payload != NULL) ||
      (spec->payload_required && options->payload_size == 0U))
    die("probe request differs from the compiled allowlist");
  {
    const char *suffix = validate_probe_path(spec, options->path);
    size_t root_length = (size_t)(suffix - options->path);
    options->private_root = malloc(root_length + 1U);
    if (options->private_root == NULL)
      die("private root allocation failed");
    memcpy(options->private_root, options->path, root_length);
    options->private_root[root_length] = '\0';
    options->relative_path = *suffix == '/' ? suffix + 1 : suffix;
  }
}

static void close_unregistered_fds(void) {
  DIR *directory = opendir("/proc/self/fd");
  struct dirent *entry;
  int scan_descriptor;
  if (directory == NULL)
    die("cannot enumerate inherited descriptors");
  scan_descriptor = dirfd(directory);
  if (scan_descriptor < 0)
    die("cannot identify descriptor scan handle");
  while ((entry = readdir(directory)) != NULL) {
    char *end = NULL;
    long descriptor;
    errno = 0;
    descriptor = strtol(entry->d_name, &end, 10);
    if (errno != 0 || end == entry->d_name || *end != '\0')
      continue;
    if (descriptor > 2 && descriptor != scan_descriptor &&
        close((int)descriptor) != 0 && errno != EBADF)
      die("cannot close inherited descriptor");
  }
  if (closedir(directory) != 0)
    die("cannot close descriptor scan handle");
}

static unsigned int hex_nibble(char value) {
  if (value >= '0' && value <= '9')
    return (unsigned int)(value - '0');
  if (value >= 'a' && value <= 'f')
    return 10U + (unsigned int)(value - 'a');
  die("invalid lowercase hex");
  return 0;
}

static void parse_groups(char *text, struct options *options) {
  char *cursor = text;
  if (*cursor == '\0') {
    options->target_group_count = 0;
    return;
  }
  while (cursor != NULL) {
    char *comma = strchr(cursor, ',');
    if (options->target_group_count >= 32U)
      die("too many supplementary groups");
    if (comma != NULL)
      *comma = '\0';
    options->target_groups[options->target_group_count++] =
        parse_gid(cursor, "invalid supplementary gid");
    cursor = comma == NULL ? NULL : comma + 1;
  }
}

static void parse_payload(const char *hex, struct options *options) {
  size_t length = strlen(hex);
  size_t i;
  if ((length & 1U) != 0 || length / 2U > MAX_PAYLOAD_BYTES)
    die("invalid probe payload size");
  options->payload_size = length / 2U;
  options->payload = calloc(options->payload_size ? options->payload_size : 1U, 1U);
  if (options->payload == NULL)
    die("payload allocation failed");
  for (i = 0; i < options->payload_size; ++i)
    options->payload[i] =
        (unsigned char)((hex_nibble(hex[2U * i]) << 4) |
                        hex_nibble(hex[2U * i + 1U]));
}

static const char *required_value(int argc, char **argv, int *index) {
  if (*index + 1 >= argc)
    die("missing option value");
  ++*index;
  return argv[*index];
}

static void parse_options(int argc, char **argv, struct options *options) {
  int i;
  uint32_t seen = 0U;
  memset(options, 0, sizeof(*options));
  for (i = 1; i < argc; ++i) {
    const char *name = argv[i];
    const char *value = required_value(argc, argv, &i);
    if (strcmp(name, "--probe-id") == 0) {
      claim_option(&seen, OPTION_PROBE_ID);
      options->probe_id = value;
    } else if (strcmp(name, "--target-uid") == 0) {
      claim_option(&seen, OPTION_TARGET_UID);
      options->target_uid = parse_uid(value);
    } else if (strcmp(name, "--target-gid") == 0) {
      claim_option(&seen, OPTION_TARGET_GID);
      options->target_gid = parse_gid(value, "invalid target gid");
    } else if (strcmp(name, "--target-supplementary-gids") == 0) {
      claim_option(&seen, OPTION_TARGET_GROUPS);
      parse_groups((char *)value, options);
    } else if (strcmp(name, "--credential-transition") == 0) {
      claim_option(&seen, OPTION_TRANSITION);
      options->transition = value;
    } else if (strcmp(name, "--operation") == 0) {
      claim_option(&seen, OPTION_OPERATION);
      options->operation = value;
    } else if (strcmp(name, "--path") == 0) {
      claim_option(&seen, OPTION_PATH);
      options->path = value;
    } else if (strcmp(name, "--receipt-protocol") == 0) {
      claim_option(&seen, OPTION_PROTOCOL);
      options->protocol = value;
    } else if (strcmp(name, "--stage") == 0) {
      claim_option(&seen, OPTION_STAGE);
      options->stage = value;
    } else if (strcmp(name, "--access-policy-sha256") == 0) {
      claim_option(&seen, OPTION_POLICY_SHA);
      options->policy_sha = value;
    } else if (strcmp(name, "--adapter-sha256") == 0) {
      claim_option(&seen, OPTION_ADAPTER_SHA);
      options->adapter_sha = value;
    } else if (strcmp(name, "--expected-executable-device") == 0) {
      claim_option(&seen, OPTION_DEVICE);
      options->expected_device = (dev_t)parse_u64(value, "invalid device");
    } else if (strcmp(name, "--expected-executable-inode") == 0) {
      claim_option(&seen, OPTION_INODE);
      options->expected_inode = (ino_t)parse_u64(value, "invalid inode");
    } else if (strcmp(name, "--expected-executable-size-bytes") == 0) {
      claim_option(&seen, OPTION_SIZE);
      options->expected_size = parse_u64(value, "invalid executable size");
    } else if (strcmp(name, "--expected-executable-sha256") == 0) {
      claim_option(&seen, OPTION_EXECUTABLE_SHA);
      options->expected_sha = value;
    } else if (strcmp(name, "--expected-private-root-device") == 0) {
      claim_option(&seen, OPTION_PRIVATE_ROOT_DEVICE);
      options->expected_private_root_device =
          (dev_t)parse_u64(value, "invalid private root device");
    } else if (strcmp(name, "--expected-private-root-inode") == 0) {
      claim_option(&seen, OPTION_PRIVATE_ROOT_INODE);
      options->expected_private_root_inode =
          (ino_t)parse_u64(value, "invalid private root inode");
    } else if (strcmp(name, "--request-capability-path") == 0) {
      claim_option(&seen, OPTION_REQUEST_CAPABILITY_PATH);
      options->request_capability_path = value;
    } else if (strcmp(name, "--request-capability-sha256") == 0) {
      claim_option(&seen, OPTION_REQUEST_CAPABILITY_SHA);
      options->request_capability_sha = value;
    } else if (strcmp(name, "--expected-capability-root-device") == 0) {
      claim_option(&seen, OPTION_CAPABILITY_ROOT_DEVICE);
      options->expected_capability_root_device =
          (dev_t)parse_u64(value, "invalid capability root device");
    } else if (strcmp(name, "--expected-capability-root-inode") == 0) {
      claim_option(&seen, OPTION_CAPABILITY_ROOT_INODE);
      options->expected_capability_root_inode =
          (ino_t)parse_u64(value, "invalid capability root inode");
    } else if (strcmp(name, "--request-capability-epoch") == 0) {
      claim_option(&seen, OPTION_REQUEST_EPOCH);
      options->request_epoch = parse_u64(value, "invalid request epoch");
    } else if (strcmp(name, "--request-capability-ordinal") == 0) {
      claim_option(&seen, OPTION_REQUEST_ORDINAL);
      options->request_ordinal = parse_u64(value, "invalid request ordinal");
    } else if (strcmp(name, "--request-capability-nonce") == 0) {
      claim_option(&seen, OPTION_REQUEST_NONCE);
      options->request_nonce = value;
    } else if (strcmp(name, "--request-expiry-boottime-seconds") == 0) {
      claim_option(&seen, OPTION_REQUEST_EXPIRY);
      options->request_expiry_boottime_seconds =
          parse_u64(value, "invalid request expiry");
    } else if (strcmp(name, "--attester-parent-pid") == 0) {
      claim_option(&seen, OPTION_ATTESTER_PARENT_PID);
      options->attester_parent_pid = parse_pid(value);
    } else if (strcmp(name, "--attester-parent-start-ticks") == 0) {
      claim_option(&seen, OPTION_ATTESTER_PARENT_START_TICKS);
      options->attester_parent_start_ticks =
          parse_u64(value, "invalid attester parent start ticks");
    } else if (strcmp(name, "--probe-payload-hex") == 0) {
      claim_option(&seen, OPTION_PAYLOAD);
      parse_payload(value, options);
    } else {
      die("unknown option");
    }
  }
  if ((seen & REQUIRED_OPTION_MASK) != REQUIRED_OPTION_MASK ||
      options->expected_size == 0U ||
      strcmp(options->transition,
             "setgroups_then_setresgid_then_setresuid_no_active_capabilities") !=
          0 ||
      !valid_lower_sha256(options->policy_sha) ||
      !valid_lower_sha256(options->adapter_sha) ||
      !valid_lower_sha256(options->expected_sha) ||
      !valid_lower_sha256(options->request_capability_sha) ||
      !valid_lower_sha256(options->request_nonce) ||
      options->request_epoch == 0U || options->request_ordinal == 0U ||
      options->request_expiry_boottime_seconds == 0U ||
      options->attester_parent_start_ticks == 0U ||
      strcmp(options->adapter_sha, options->expected_sha) != 0)
    die("incomplete or unsafe option set");
  validate_capability_path(options);
  validate_registered_probe(options);
}

static size_t current_groups(gid_t *groups, size_t capacity) {
  int count = getgroups(0, NULL);
  if (count < 0 || (size_t)count > capacity)
    die("cannot inspect supplementary groups");
  if (count > 0 && getgroups(count, groups) != count)
    die("cannot read supplementary groups");
  return (size_t)count;
}

static void verify_self(const struct options *options) {
  struct stat metadata;
  char digest[65];
  int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
  if (fd < 0 || fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
      metadata.st_nlink != 1 || metadata.st_dev != options->expected_device ||
      metadata.st_ino != options->expected_inode ||
      (uint64_t)metadata.st_size != options->expected_size ||
      hash_fd(fd, options->expected_size, digest) != 0 ||
      strcmp(digest, options->expected_sha) != 0) {
    if (fd >= 0)
      close(fd);
    die("/proc/self/exe does not match verified descriptor");
  }
  close(fd);
}

static void verify_pre_transition(void) {
  uid_t ruid, euid, suid;
  gid_t rgid, egid, sgid;
  gid_t groups[32];
  size_t count;
  if (getresuid(&ruid, &euid, &suid) != 0 ||
      getresgid(&rgid, &egid, &sgid) != 0)
    die("cannot inspect pre-transition credentials");
  count = current_groups(groups, 32U);
  if (ruid != ATTESTER_UID || euid != 0U || suid != 0U ||
      rgid != ATTESTER_UID || egid != ATTESTER_UID || sgid != ATTESTER_UID ||
      count != 1U || groups[0] != PRIVATE_READ_GID)
    die("pre-transition setuid credential proof failed");
}

/*
 * Required root-broker contract (provider intentionally absent in this source
 * commit):
 *
 *   - CAPABILITY_ROOT is a preregistered root:root 0700 directory whose
 *     device/inode equal --expected-capability-root-{device,inode}.  Every
 *     ancestor and descendant used below is root owned and not group/other
 *     writable, has no ACL/xattr/file capability, and is opened with openat2
 *     NO_SYMLINKS.  UID 41001 cannot list, read, create, rename, or unlink it.
 *   - The only pending request is the exact normalized path
 *       epochs/<epoch>/next/<ordinal>-<nonce>.request
 *     below that descriptor.  It is root:root 0400, regular, nlink=1, on the
 *     capability-root device, and hashes to --request-capability-sha256.
 *   - Its canonical manifest binds CAPABILITY_BINDING_DOMAIN plus every
 *     request tuple member (probe id, target uid/gid/groups, credential
 *     transition, operation, absolute path, protocol, stage, policy digest,
 *     adapter identity, expected private-root identity), payload size/SHA-256,
 *     epoch, ordinal, 256-bit nonce, CLOCK_BOOTTIME expiry, capability-root
 *     identity, and attester parent PID/start ticks.  Fields are hashed as
 *       <ASCII-name> "=" <decimal-byte-length> ":" <ASCII-value> "\n"
 *     in the fixed order documented by the future broker module.
 *   - Before claim, the helper opens a pidfd for getppid(), proves that it is
 *     exactly the bound PID owned by UID 41001, reads the bound field-22 start
 *     ticks through that /proc process descriptor, and proves the pidfd live.
 *   - Claim is fail-stop and one-shot: renameat2(RENAME_NOREPLACE) moves the
 *     pending request to epochs/<epoch>/consumed/, then moves the root-owned
 *     sequence marker <ordinal>.next to <ordinal>.consumed.  Ordinal 1 is the
 *     only genesis; later ordinals additionally require the immediately prior
 *     consumed marker.  Any missing/mismatched/replayed/out-of-order artifact,
 *     expiry, rename, fsync, or parent-liveness failure poisons the attempt.
 *
 * Until an audited root broker implements all of the above atomically, this
 * helper must hard-fail.  Do not replace this function with argv-only checks:
 * UID 41001 controls argv and can directly pathname-exec a setuid binary.
 */
static void claim_root_capability_or_die(const struct options *options) {
  (void)options;
  die("root capability broker claim protocol is not implemented");
}

static void clear_capability_sets(void) {
  struct __user_cap_header_struct header;
  struct __user_cap_data_struct data[2];
  memset(&header, 0, sizeof(header));
  memset(data, 0, sizeof(data));
  header.version = _LINUX_CAPABILITY_VERSION_3;
  header.pid = 0;
  if (syscall(SYS_capset, &header, data) != 0)
    die("capset zero failed");
}

static void transition_credentials(const struct options *options) {
  int capability;
  if (prctl(PR_SET_SECUREBITS, LOCKED_SECUREBITS, 0, 0, 0) != 0)
    die("cannot lock securebits");
  for (capability = 0; capability <= CAP_LAST_CAP; ++capability) {
    if (prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 && errno != EINVAL)
      die("cannot clear capability bounding set");
  }
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    die("cannot set no_new_privs");
  if (setgroups(options->target_group_count, options->target_groups) != 0)
    die("setgroups failed");
  if (setresgid(options->target_gid, options->target_gid, options->target_gid) !=
      0)
    die("setresgid failed");
  if (setresuid(options->target_uid, options->target_uid, options->target_uid) !=
      0)
    die("setresuid failed");
  clear_capability_sets();
}

static bool capability_status_zero(void) {
  FILE *stream = fopen("/proc/self/status", "re");
  char *line = NULL;
  size_t capacity = 0;
  unsigned int seen = 0;
  bool ok = true;
  if (stream == NULL)
    return false;
  while (getline(&line, &capacity, stream) >= 0) {
    static const char *names[] = {"CapInh:", "CapPrm:", "CapEff:", "CapBnd:",
                                  "CapAmb:"};
    unsigned int i;
    for (i = 0; i < 5U; ++i) {
      if (strncmp(line, names[i], strlen(names[i])) == 0) {
        char *value = line + strlen(names[i]);
        while (*value == ' ' || *value == '\t')
          ++value;
        if (strtoull(value, NULL, 16) != 0ULL)
          ok = false;
        seen |= 1U << i;
      }
    }
  }
  free(line);
  fclose(stream);
  return ok && seen == 0x1fU;
}

static void verify_post_transition(const struct options *options) {
  uid_t ruid, euid, suid;
  gid_t rgid, egid, sgid;
  gid_t groups[32];
  size_t count, i;
  if (getresuid(&ruid, &euid, &suid) != 0 ||
      getresgid(&rgid, &egid, &sgid) != 0)
    die("cannot inspect post-transition credentials");
  count = current_groups(groups, 32U);
  if (ruid != options->target_uid || euid != options->target_uid ||
      suid != options->target_uid || rgid != options->target_gid ||
      egid != options->target_gid || sgid != options->target_gid ||
      count != options->target_group_count)
    die("post-transition credential proof failed");
  for (i = 0; i < count; ++i)
    if (groups[i] != options->target_groups[i])
      die("post-transition group proof failed");
  if (!capability_status_zero() || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
      prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) != LOCKED_SECUREBITS)
    die("post-transition privilege proof failed");
}

static int strict_openat2(int directory_fd, const char *path, int flags,
                          mode_t mode, uint64_t resolve) {
  struct open_how how;
  memset(&how, 0, sizeof(how));
  how.flags = (uint64_t)flags;
  how.mode = (uint64_t)mode;
  how.resolve = resolve;
  return (int)syscall(SYS_openat2, directory_fd, path, &how, sizeof(how));
}

static void verify_private_root_anchor(const struct options *options,
                                       int root_fd) {
  struct stat metadata;
  if (fstat(root_fd, &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
      metadata.st_dev != options->expected_private_root_device ||
      metadata.st_ino != options->expected_private_root_inode)
    die("private-context root descriptor identity differs");
}

static int open_private_root_anchor(const struct options *options) {
  int fd = strict_openat2(
      AT_FDCWD, options->private_root, O_PATH | O_DIRECTORY | O_CLOEXEC, 0,
      RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS);
  if (fd < 0)
    die("cannot anchor exact private-context root");
  verify_private_root_anchor(options, fd);
  return fd;
}

static int anchored_open(int root_fd, const char *relative_path, int flags,
                         mode_t mode) {
  const char *path = *relative_path == '\0' ? "." : relative_path;
  return strict_openat2(root_fd, path, flags | O_CLOEXEC, mode,
                        RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
                            RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV);
}

static void require_single_component_mutation(const char *relative_path) {
  if (*relative_path == '\0' || strchr(relative_path, '/') != NULL ||
      strcmp(relative_path, ".") == 0 || strcmp(relative_path, "..") == 0)
    die("mutation path is not a single anchored component");
}

struct outcome {
  bool allowed;
  bool absence;
  int raw_errno;
  bool has_content_sha;
  char content_sha[65];
};

static void hash_payload(const unsigned char *payload, size_t size, char output[65]) {
  struct sha256_ctx ctx;
  unsigned char digest[32];
  sha256_init(&ctx);
  sha256_update(&ctx, payload, size);
  sha256_final(&ctx, digest);
  digest_hex(digest, output);
}

static void perform_operation(const struct options *options, int root_fd,
                              struct outcome *outcome) {
  int fd = -1;
  memset(outcome, 0, sizeof(*outcome));
  verify_private_root_anchor(options, root_fd);
  errno = 0;
  if (strcmp(options->operation, "create_exact_probe") == 0) {
    size_t offset = 0;
    if (options->payload == NULL)
      die("create probe requires payload");
    require_single_component_mutation(options->relative_path);
    umask(0);
    fd = anchored_open(root_fd, options->relative_path,
                       O_WRONLY | O_CREAT | O_EXCL, 0440);
    if (fd >= 0) {
      while (offset < options->payload_size) {
        ssize_t count = write(fd, options->payload + offset,
                              options->payload_size - offset);
        if (count <= 0)
          die("probe write failed");
        offset += (size_t)count;
      }
      if (fchmod(fd, 0440) != 0 || fsync(fd) != 0)
        die("probe durability failed");
      close(fd);
      outcome->allowed = true;
      outcome->raw_errno = 0;
      outcome->has_content_sha = true;
      hash_payload(options->payload, options->payload_size, outcome->content_sha);
    } else
      outcome->raw_errno = errno;
  } else if (strcmp(options->operation, "read_exact_probe") == 0 ||
             strcmp(options->operation, "read_registered_record") == 0) {
    struct stat metadata;
    fd = anchored_open(root_fd, options->relative_path, O_RDONLY, 0);
    if (fd >= 0 && fstat(fd, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
        hash_fd(fd, (uint64_t)metadata.st_size, outcome->content_sha) == 0) {
      outcome->allowed = true;
      outcome->raw_errno = 0;
      outcome->has_content_sha = true;
      close(fd);
    } else {
      outcome->raw_errno = errno == 0 ? EIO : errno;
      if (fd >= 0)
        close(fd);
    }
  } else if (strcmp(options->operation, "remove_exact_probe") == 0) {
    require_single_component_mutation(options->relative_path);
    if (unlinkat(root_fd, options->relative_path, 0) == 0) {
      outcome->allowed = true;
      outcome->raw_errno = 0;
    } else
      outcome->raw_errno = errno;
  } else if (strcmp(options->operation, "verify_probe_absent") == 0) {
    struct stat metadata;
    require_single_component_mutation(options->relative_path);
    outcome->absence = true;
    if (fstatat(root_fd, options->relative_path, &metadata,
                AT_SYMLINK_NOFOLLOW) != 0)
      outcome->raw_errno = errno;
    else
      outcome->raw_errno = 0;
  } else if (strcmp(options->operation, "enumerate_root") == 0) {
    fd = anchored_open(root_fd, options->relative_path,
                       O_RDONLY | O_DIRECTORY, 0);
    if (fd >= 0) {
      outcome->allowed = true;
      outcome->raw_errno = 0;
      close(fd);
    } else
      outcome->raw_errno = errno;
  } else if (strcmp(options->operation, "write_exact_probe") == 0 ||
             strcmp(options->operation, "write_registered_record") == 0) {
    fd = anchored_open(root_fd, options->relative_path, O_WRONLY, 0);
    if (fd >= 0) {
      outcome->allowed = true;
      outcome->raw_errno = 0;
      close(fd);
    } else
      outcome->raw_errno = errno;
  } else if (strcmp(options->operation, "create_record") == 0 ||
             strcmp(options->operation, "create_probe_record") == 0) {
    struct stat metadata;
    require_single_component_mutation(options->relative_path);
    fd = anchored_open(root_fd, options->relative_path,
                       O_WRONLY | O_CREAT | O_EXCL, 0440);
    if (fd >= 0) {
      outcome->allowed = true;
      outcome->raw_errno = 0;
      if (close(fd) != 0)
        die("unexpected-success create descriptor close failed");
      if (unlinkat(root_fd, options->relative_path, 0) != 0)
        die("unexpected-success create cleanup unlink failed");
      errno = 0;
      if (fstatat(root_fd, options->relative_path, &metadata,
                  AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT)
        die("unexpected-success create cleanup verification failed");
    } else
      outcome->raw_errno = errno;
  } else
    die("unknown operation");
  verify_private_root_anchor(options, root_fd);
}

static void json_string(const char *value) {
  const unsigned char *cursor = (const unsigned char *)value;
  putchar('"');
  while (*cursor != '\0') {
    unsigned char byte = *cursor++;
    if (byte == '"' || byte == '\\') {
      putchar('\\');
      putchar((int)byte);
    } else if (byte >= 0x20U && byte <= 0x7eU) {
      putchar((int)byte);
    } else {
      printf("\\u%04x", (unsigned int)byte);
    }
  }
  putchar('"');
}

static void json_groups(const gid_t *groups, size_t count) {
  size_t i;
  putchar('[');
  for (i = 0; i < count; ++i) {
    if (i != 0)
      putchar(',');
    printf("%u", (unsigned int)groups[i]);
  }
  putchar(']');
}

static void emit_receipt(const struct options *options,
                         const struct outcome *outcome) {
  /* Key order is deliberately canonical ASCII lexicographic order. */
  putchar('{');
  if (outcome->absence)
    printf("\"absent\":%s,", outcome->raw_errno == ENOENT ? "true" : "false");
  printf("\"access_policy_sha256\":");
  json_string(options->policy_sha);
  printf(",\"adapter_sha256\":");
  json_string(options->adapter_sha);
  if (!outcome->absence) {
    printf(",\"allowed\":%s,\"content_sha256\":",
           outcome->allowed ? "true" : "false");
    if (outcome->has_content_sha)
      json_string(outcome->content_sha);
    else
      printf("null");
  }
  printf(",\"credential_transition\":");
  json_string(options->transition);
  printf(",\"invoking_uid_before_transition\":%u", ATTESTER_UID);
  printf(",\"observed_active_capabilities_empty\":true");
  printf(",\"observed_all_capability_sets_zero\":true");
  printf(",\"observed_effective_gid\":%u", (unsigned int)options->target_gid);
  printf(",\"observed_effective_uid\":%u", (unsigned int)options->target_uid);
  printf(",\"observed_no_new_privs\":true");
  printf(",\"observed_real_gid\":%u", (unsigned int)options->target_gid);
  printf(",\"observed_real_uid\":%u", (unsigned int)options->target_uid);
  printf(",\"observed_saved_gid\":%u", (unsigned int)options->target_gid);
  printf(",\"observed_saved_uid\":%u", (unsigned int)options->target_uid);
  printf(",\"observed_securebits\":%u", (unsigned int)LOCKED_SECUREBITS);
  printf(",\"observed_supplementary_gids\":");
  json_groups(options->target_groups, options->target_group_count);
  printf(",\"operation\":");
  json_string(options->operation);
  printf(",\"path\":");
  json_string(options->path);
  printf(",\"pre_transition_effective_gid\":%u", ATTESTER_UID);
  printf(",\"pre_transition_effective_uid\":0");
  printf(",\"pre_transition_real_gid\":%u", ATTESTER_UID);
  printf(",\"pre_transition_real_uid\":%u", ATTESTER_UID);
  printf(",\"pre_transition_saved_gid\":%u", ATTESTER_UID);
  printf(",\"pre_transition_saved_uid\":0");
  printf(",\"private_context_root_device\":%" PRIuMAX,
         (uintmax_t)options->expected_private_root_device);
  printf(",\"private_context_root_inode\":%" PRIuMAX,
         (uintmax_t)options->expected_private_root_inode);
  printf(",\"private_context_root_path\":");
  json_string(options->private_root);
  printf(",\"probe_id\":");
  json_string(options->probe_id);
  printf(",\"protocol\":");
  json_string(options->protocol);
  printf(",\"raw_errno\":%d", outcome->raw_errno);
  printf(",\"relative_path\":");
  json_string(options->relative_path);
  printf(",\"schema_version\":2");
  printf(",\"self_executable_device\":%" PRIuMAX,
         (uintmax_t)options->expected_device);
  printf(",\"self_executable_inode\":%" PRIuMAX,
         (uintmax_t)options->expected_inode);
  printf(",\"self_executable_sha256\":");
  json_string(options->expected_sha);
  printf(",\"self_executable_size_bytes\":%" PRIu64, options->expected_size);
  printf(",\"stage\":");
  json_string(options->stage);
  printf(",\"target_gid\":%u", (unsigned int)options->target_gid);
  printf(",\"target_supplementary_gids\":");
  json_groups(options->target_groups, options->target_group_count);
  printf(",\"target_uid\":%u}", (unsigned int)options->target_uid);
}

int main(int argc, char **argv) {
  struct options options;
  struct outcome outcome;
  int private_root_fd;
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  parse_options(argc, argv, &options);
  close_unregistered_fds();
  verify_self(&options);
  verify_pre_transition();
  if (ROOT_CAPABILITY_BROKER_PROVIDER_AVAILABLE != 1)
    die("root capability broker provider is unavailable");
  claim_root_capability_or_die(&options);
  private_root_fd = open_private_root_anchor(&options);
  transition_credentials(&options);
  verify_post_transition(&options);
  perform_operation(&options, private_root_fd, &outcome);
  emit_receipt(&options, &outcome);
  if (close(private_root_fd) != 0)
    die("cannot close private-context root descriptor");
  free(options.payload);
  free(options.private_root);
  return 0;
}
