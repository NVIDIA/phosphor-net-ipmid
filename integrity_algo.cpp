#include "integrity_algo.hpp"

#include "message_parsers.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

namespace cipher
{

namespace integrity
{

namespace
{

/**
 * @brief Constant-time comparison of a locally computed HMAC against the
 *        AuthCode received from the network.
 *
 * The integrity check is the authentication gate for every post-session RMCP+
 * command on a network-exposed service (UDP/623). A byte-by-byte comparison
 * such as std::equal()/memcmp() returns as soon as it finds the first
 * mismatching byte, so its execution time reveals how many leading bytes of the
 * candidate AuthCode are correct. A network-adjacent attacker can exploit that
 * timing oracle to reconstruct a valid HMAC one byte at a time and forge
 * authenticated packets without knowing the session integrity key K1
 * (CWE-208).
 *
 * CRYPTO_memcmp() always inspects the full buffer regardless of where the
 * first difference is, so the comparison time does not depend on the secret.
 * The length check below is not secret-dependent (the AuthCode length is fixed
 * by the negotiated algorithm and controlled by the attacker anyway), so
 * short-circuiting on it leaks nothing.
 */
bool constantTimeEqual(const std::vector<uint8_t>& computed,
                       std::vector<uint8_t>::const_iterator receivedBegin,
                       std::vector<uint8_t>::const_iterator receivedEnd)
{
    if (receivedEnd < receivedBegin)
    {
        return false;
    }
    if (computed.size() != static_cast<size_t>(receivedEnd - receivedBegin))
    {
        return false;
    }
    if (computed.empty())
    {
        return true;
    }
    return CRYPTO_memcmp(computed.data(), &*receivedBegin, computed.size()) ==
           0;
}

} // namespace

AlgoSHA1::AlgoSHA1(const std::vector<uint8_t>& sik) :
    Interface(SHA1_96_AUTHCODE_LENGTH)
{
    k1 = generateKn(sik, rmcp::const_1);
}

std::vector<uint8_t> AlgoSHA1::generateHMAC(const uint8_t* input,
                                            const size_t len) const
{
    std::vector<uint8_t> output(SHA_DIGEST_LENGTH);
    unsigned int mdLen = 0;

    if (HMAC(EVP_sha1(), k1.data(), k1.size(), input, len, output.data(),
             &mdLen) == NULL)
    {
        throw std::runtime_error("Generating integrity data failed");
    }

    // HMAC generates Message Digest to the size of SHA_DIGEST_LENGTH, the
    // AuthCode field length is based on the integrity algorithm. So we are
    // interested only in the AuthCode field length of the generated Message
    // digest.
    output.resize(authCodeLength);

    return output;
}

bool AlgoSHA1::verifyIntegrityData(
    const std::vector<uint8_t>& packet, const size_t length,
    std::vector<uint8_t>::const_iterator integrityDataBegin,
    std::vector<uint8_t>::const_iterator integrityDataEnd) const
{
    auto output = generateHMAC(
        packet.data() + message::parser::RMCP_SESSION_HEADER_SIZE, length);

    // Verify if the generated integrity data for the packet and the received
    // integrity data matches, using a constant-time comparison so the check
    // cannot be turned into an HMAC-recovery timing oracle (CWE-208).
    return constantTimeEqual(output, integrityDataBegin, integrityDataEnd);
}

std::vector<uint8_t> AlgoSHA1::generateIntegrityData(
    const std::vector<uint8_t>& packet) const
{
    return generateHMAC(
        packet.data() + message::parser::RMCP_SESSION_HEADER_SIZE,
        packet.size() - message::parser::RMCP_SESSION_HEADER_SIZE);
}

std::vector<uint8_t> AlgoSHA1::generateKn(const std::vector<uint8_t>& sik,
                                          const rmcp::Const_n& const_n) const
{
    unsigned int mdLen = 0;
    std::vector<uint8_t> Kn(sik.size());

    // Generated Kn for the integrity algorithm with the additional key keyed
    // with SIK.
    if (HMAC(EVP_sha1(), sik.data(), sik.size(), const_n.data(), const_n.size(),
             Kn.data(), &mdLen) == NULL)
    {
        throw std::runtime_error("Generating KeyN for integrity "
                                 "algorithm failed");
    }
    return Kn;
}

AlgoSHA256::AlgoSHA256(const std::vector<uint8_t>& sik) :
    Interface(SHA256_128_AUTHCODE_LENGTH)
{
    k1 = generateKn(sik, rmcp::const_1);
}

std::vector<uint8_t> AlgoSHA256::generateHMAC(const uint8_t* input,
                                              const size_t len) const
{
    std::vector<uint8_t> output(SHA256_DIGEST_LENGTH);
    unsigned int mdLen = 0;

    if (HMAC(EVP_sha256(), k1.data(), k1.size(), input, len, output.data(),
             &mdLen) == NULL)
    {
        throw std::runtime_error("Generating HMAC_SHA256_128 failed");
    }

    // HMAC generates Message Digest to the size of SHA256_DIGEST_LENGTH, the
    // AuthCode field length is based on the integrity algorithm. So we are
    // interested only in the AuthCode field length of the generated Message
    // digest.
    output.resize(authCodeLength);

    return output;
}

bool AlgoSHA256::verifyIntegrityData(
    const std::vector<uint8_t>& packet, const size_t length,
    std::vector<uint8_t>::const_iterator integrityDataBegin,
    std::vector<uint8_t>::const_iterator integrityDataEnd) const
{
    auto output = generateHMAC(
        packet.data() + message::parser::RMCP_SESSION_HEADER_SIZE, length);

    // Verify if the generated integrity data for the packet and the received
    // integrity data matches, using a constant-time comparison so the check
    // cannot be turned into an HMAC-recovery timing oracle (CWE-208).
    return constantTimeEqual(output, integrityDataBegin, integrityDataEnd);
}

std::vector<uint8_t> AlgoSHA256::generateIntegrityData(
    const std::vector<uint8_t>& packet) const
{
    return generateHMAC(
        packet.data() + message::parser::RMCP_SESSION_HEADER_SIZE,
        packet.size() - message::parser::RMCP_SESSION_HEADER_SIZE);
}

std::vector<uint8_t> AlgoSHA256::generateKn(const std::vector<uint8_t>& sik,
                                            const rmcp::Const_n& const_n) const
{
    unsigned int mdLen = 0;
    std::vector<uint8_t> Kn(sik.size());

    // Generated Kn for the integrity algorithm with the additional key keyed
    // with SIK.
    if (HMAC(EVP_sha256(), sik.data(), sik.size(), const_n.data(),
             const_n.size(), Kn.data(), &mdLen) == NULL)
    {
        throw std::runtime_error("Generating KeyN for integrity "
                                 "algorithm HMAC_SHA256 failed");
    }
    return Kn;
}

} // namespace integrity

} // namespace cipher
