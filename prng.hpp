#include <openssl/rand.h>

#include <stdexcept>

namespace crypto
{

struct prng
{
    static unsigned int rand()
    {
        unsigned int v;
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&v), sizeof(v)) != 1)
        {
            throw std::runtime_error(
                "RAND_bytes failed to generate random number");
        }
        return v;
    }
};

} // namespace crypto
