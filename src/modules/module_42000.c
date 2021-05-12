/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"

#ifdef DEBUG
  #define DEBUG_PRINTF(fmt, args...) printf(fmt, args)
#else
  #define DEBUG_PRINTF(fmt, args...) do {} while (0)
#endif

#define BSWAP32_ARR(src, target) \
  do { \
    for (size_t i = 0; i < sizeof((src))/sizeof((src)[0]); i++) { \
      (target)[i] = byte_swap_32 ((src)[i]); \
    } \
  } while (0)

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_CIPHER_KPA;
static const char *HASH_NAME      = "Generic AES-128-ECB PBKDF2-HMAC-SHA1";
static const u64   KERN_TYPE      = 42000;
static const u32   OPTI_TYPE      = 0;
static const u64   OPTS_TYPE      = OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_ST_HEX;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
//                                    <sig> <rounds>           <salt>                       <ciphertext>        <plaintext header>
static const char *ST_HASH        = "$aespbkdf$42*6abdfbf8a052190f4d1837a19e64b541*77313871ceabe746e9c06ed53abe1cfb*53514c6974";

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }


typedef struct
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[32];
  u32 out[32];
} pbkdf2_sha1_tmp_t;

typedef struct
{
  u32 first_block[4];
  u32 known_header[4];
  u32 header_mask[4];
} aes_target_t;

static const char SIGNATURE_AESPBKDF[] = "$aespbkdf$";

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return sizeof (pbkdf2_sha1_tmp_t);
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return sizeof (aes_target_t);
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  aes_target_t *aes_target = (aes_target_t *) esalt_buf;
  u32 *digest = (u32 *) digest_buf;

  token_t token;
  token.token_cnt         = 5;
  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_AESPBKDF;

  token.len[0]     = sizeof(SIGNATURE_AESPBKDF)-1;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // iterations
  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // salt
  token.sep[2]     = '*';
  token.len_min[2] = SALT_MIN * 2;
  token.len_max[2] = SALT_MAX * 2;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // first AES block
  token.sep[3]     = '*';
  token.len_min[3] = 16 * 2;  // 128bit / 16byte
  token.len_max[3] = 16 * 2;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // known header
  token.sep[4]     = '*';
  token.len_min[4] = 1 * 2;   // 1-16 bytes
  token.len_max[4] = 16 * 2;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);


  // iterations
  const u8 *iter_pos = token.buf[1];
  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);
  salt->salt_iter = iter - 1;   // pbkdf2 init round counts as well, loop fewer times

  // salt
  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];
  const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);
  if (parse_rc == false) return (PARSER_SALT_LENGTH);
  BSWAP32_ARR(salt->salt_buf, salt->salt_buf);
  DEBUG_PRINTF("sb0: %08x, sb1: %08x, sb2: %08x, sb3: %08x (len: %d)\n", salt->salt_buf[0], salt->salt_buf[1], salt->salt_buf[2], salt->salt_buf[3], salt->salt_len);

  // first block
  const u8 *first_block_pos = token.buf[3];
  aes_target->first_block[0] = hex_to_u32 (first_block_pos +  0);
  aes_target->first_block[1] = hex_to_u32 (first_block_pos +  8);
  aes_target->first_block[2] = hex_to_u32 (first_block_pos + 16);
  aes_target->first_block[3] = hex_to_u32 (first_block_pos + 24);
  DEBUG_PRINTF("fb0: %08x, fb1: %08x, fb2: %08x, fb3: %08x\n", aes_target->first_block[0], aes_target->first_block[1], aes_target->first_block[2], aes_target->first_block[3]);

  // known header: up to 16 bytes (one AES block)
  const u8 *header_pos = token.buf[4];
  const u32 header_hexlen = token.len[4];
  if (header_hexlen % 2 != 0) {
    return (PARSER_TOKEN_LENGTH);
  }
  u8 parse_buf[32] = {0};
  memcpy(parse_buf, header_pos, header_hexlen);
  aes_target->known_header[0] = hex_to_u32 (parse_buf +  0);
  aes_target->known_header[1] = hex_to_u32 (parse_buf +  8);
  aes_target->known_header[2] = hex_to_u32 (parse_buf + 16);
  aes_target->known_header[3] = hex_to_u32 (parse_buf + 24);
  DEBUG_PRINTF("kh0: %08x, kh1: %08x, kh2: %08x, kh3: %08x\n", aes_target->known_header[0], aes_target->known_header[1], aes_target->known_header[2], aes_target->known_header[3]);


  // header mask
  const i32 header_bytes = header_hexlen / 2;
#define BYTE_MASK(n) ((n) >= 4 ? 0 : (0xffffffff >> (8 * MAX(0, n))))
  aes_target->header_mask[0] = BYTE_MASK( 4 - header_bytes);
  aes_target->header_mask[1] = BYTE_MASK( 8 - header_bytes);
  aes_target->header_mask[2] = BYTE_MASK(12 - header_bytes);
  aes_target->header_mask[3] = BYTE_MASK(16 - header_bytes);
#undef BYTE_MASK
  DEBUG_PRINTF("mask0: %08x, mask1: %08x, mask2: %08x, mask3: %08x\n", aes_target->header_mask[0], aes_target->header_mask[1], aes_target->header_mask[2], aes_target->header_mask[3]);

  // fake hash
  digest[0] = aes_target->first_block[0] ^ salt->salt_buf[0];
  digest[1] = aes_target->first_block[1] ^ salt->salt_buf[1];
  digest[2] = aes_target->first_block[2] ^ salt->salt_buf[2];
  digest[3] = aes_target->first_block[3] ^ salt->salt_buf[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  aes_target_t *aes_target = (aes_target_t *)esalt_buf;
  int line_len = snprintf (line_buf, line_size, "%s%d*",
    SIGNATURE_AESPBKDF,
    salt->salt_iter + 1
  );

  u8 tmp_salt[sizeof(salt->salt_buf)];
  BSWAP32_ARR(salt->salt_buf, (u32 *) tmp_salt);

  line_len += generic_salt_encode (hashconfig, (const u8 *) tmp_salt, (const int) salt->salt_len, ((u8 *) line_buf) + line_len);

  line_len += snprintf (line_buf + line_len, line_size - line_len, "*%08x%08x%08x%08x*%08x%08x%08x%08x",
    byte_swap_32 (aes_target->first_block[0]),
    byte_swap_32 (aes_target->first_block[1]),
    byte_swap_32 (aes_target->first_block[2]),
    byte_swap_32 (aes_target->first_block[3]),

    byte_swap_32 (aes_target->known_header[0]),
    byte_swap_32 (aes_target->known_header[1]),
    byte_swap_32 (aes_target->known_header[2]),
    byte_swap_32 (aes_target->known_header[3])
  );

  for (int i = 0, off = line_len - 4*8; i < 4; i++) {
    u32 mask = aes_target->header_mask[i];
    for (int b = 0; b < 4; b++, off += 2) {
      if ((mask & (0xff << (b * 8))) == 0) {
        line_buf[off] = '\0';
        line_len = off;
        return line_len;
      }
    }
  }

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = MODULE_DEFAULT;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = MODULE_DEFAULT;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
