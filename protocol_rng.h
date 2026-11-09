#ifndef PROTOCOL_RNG_H
#define PROTOCOL_RNG_H

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>
#if defined(__linux__)
#include <fcntl.h>
#include <unistd.h>
#endif
#include "Algorithm/pairing_3.h"

// Owns the MIRACL CSPRNG and seeds it exclusively from the operating system.
class ProtocolRng {
public:
    ProtocolRng() : initialized_(false) {
        std::vector<char> seed(64);
        auto wipe = [](char *p, size_t n) { volatile char *v = reinterpret_cast<volatile char *>(p); while (n--) *v++ = 0; };
#if defined(__linux__)
        int fd = ::open("/dev/urandom", O_RDONLY);
        if (fd < 0) throw std::runtime_error("cannot open /dev/urandom");
        size_t off = 0;
        while (off < seed.size()) {
            ssize_t n = ::read(fd, seed.data() + off, seed.size() - off);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { ::close(fd); wipe(seed.data(), seed.size()); throw std::runtime_error("cannot read OS entropy"); }
            off += static_cast<size_t>(n);
        }
        ::close(fd);
#else
        throw std::runtime_error("ProtocolRng requires an OS entropy source");
#endif
        strong_init(&rng_, static_cast<int>(seed.size()), seed.data(), 0);
        wipe(seed.data(), seed.size());
        initialized_ = true;
    }
    ProtocolRng(const ProtocolRng&) = delete;
    ProtocolRng& operator=(const ProtocolRng&) = delete;
    ~ProtocolRng() { if (initialized_) strong_kill(&rng_); volatile char *v = reinterpret_cast<volatile char *>(&rng_); for (size_t i = 0; i < sizeof(rng_); ++i) v[i] = 0; }
    csprng* get() { return &rng_; }
private:
    csprng rng_{};
    bool initialized_;
};

#endif
