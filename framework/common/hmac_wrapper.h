#ifndef HMAC_WRAPPER_H
#define HMAC_WRAPPER_H

#include <memory>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#include <openssl/hmac.h>
#endif

class hmac_wrapper {
public:
    hmac_wrapper(const uint8_t *key, size_t key_length);
    ~hmac_wrapper() = default;

    bool update(const uint8_t *message, size_t message_length);
    bool digest(uint8_t *digest, size_t digest_length);

private:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    std::unique_ptr<HMAC_CTX, decltype(&HMAC_CTX_free)> m_ctx;
#else
    std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> m_ctx;
#endif
};

#endif // HMAC_WRAPPER_H
