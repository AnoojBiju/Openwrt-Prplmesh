#include "hmac_wrapper.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/params.h>
#endif

#include <mapf/common/logger.h>

hmac_wrapper::hmac_wrapper(const uint8_t *key, size_t key_length)
    :
#if OPENSSL_VERSION_NUMBER < 0x30000000L
      m_ctx(nullptr, &HMAC_CTX_free)
#else
      m_ctx(nullptr, &EVP_MAC_CTX_free)
#endif
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    HMAC_CTX *raw_ctx = HMAC_CTX_new();
#else
    EVP_MAC_CTX *raw_ctx = EVP_MAC_CTX_new(EVP_MAC_fetch(nullptr, "HMAC", nullptr));
#endif

    if (!raw_ctx) {
        MAPF_ERR("HMAC_CTX_new failed");
        return;
    }
    m_ctx.reset(raw_ctx);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (!HMAC_Init_ex(raw_ctx, key, key_length, EVP_sha256(), nullptr)) {
        m_ctx.reset();
        MAPF_ERR("HMAC_Init_ex failed");
        return;
    }
#else
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!EVP_MAC_init(raw_ctx, key, key_length, params)) {
        m_ctx.reset();
        MAPF_ERR("EVP_MAC_init failed");
        return;
    }
#endif
}

bool hmac_wrapper::update(const uint8_t *message, size_t message_length)
{
    if (!m_ctx) {
        MAPF_ERR("HMAC context not initialized");
        return false;
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (!HMAC_Update(m_ctx.get(), message, message_length)) {
        MAPF_ERR("HMAC_Update failed");
        return false;
    }
#else
    if (!EVP_MAC_update(m_ctx.get(), message, message_length)) {
        MAPF_ERR("EVP_MAC_update failed");
        return false;
    }
#endif

    return true;
}

bool hmac_wrapper::digest(uint8_t *digest, size_t digest_length)
{
    if (!m_ctx) {
        MAPF_ERR("HMAC context not initialized");
        return false;
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    auto len = static_cast<unsigned int>(digest_length);
    if (!HMAC_Final(m_ctx.get(), digest, &len)) {
        MAPF_ERR("HMAC_Final failed");
        return false;
    }
#else
    if (!EVP_MAC_final(m_ctx.get(), digest, &digest_length, digest_length)) {
        MAPF_ERR("EVP_MAC_final failed");
        return false;
    }
#endif

    return true;
}
