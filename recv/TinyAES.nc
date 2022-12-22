#include "TinyAES.h"

interface TinyAES {
    command void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
    command void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
    command void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
    command void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
    command void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);
    command void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, uint32_t length);
    command void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf,  uint32_t length);
}
