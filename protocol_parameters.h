#ifndef PROTOCOL_PARAMETERS_H
#define PROTOCOL_PARAMETERS_H
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>
#include "Algorithm/pairing_3.h"
struct ProtocolParameters { std::string version; size_t attribute_count; std::string binding; };
inline std::string protocolFrame(const std::string&s){std::string o(8,'\0');uint64_t n=s.size();for(int i=7;i>=0;--i){o[i]=char(n&255);n>>=8;}return o+s;}
inline std::string protocolSha256(const std::string&s){sha256 h;shs256_init(&h);for(unsigned char c:s)shs256_process(&h,c);char d[32];shs256_hash(&h,d);return std::string(d,32);}
inline std::string protocolHex(const std::string&s){static const char*x="0123456789abcdef";std::string o;for(unsigned char c:s){o+=x[c>>4];o+=x[c&15];}return o;}
inline std::string protocolU64(uint64_t n){std::string o(8,'\0');for(int i=7;i>=0;--i){o[i]=char(n&255);n>>=8;}return o;}
inline size_t protocolCoordinateWidth(PFC* p) {
    if (!p || !p->mod) throw std::invalid_argument("null PFC");
    return (bits(*p->mod) + 7) / 8;
}
inline std::string protocolBig(const Big& v, size_t w) {
    if (!w || v < Big(0) || static_cast<size_t>(bits(v)) > w * 8)
        throw std::invalid_argument("invalid fixed-width integer");
    std::string o(w, '\0'); to_binary(v, static_cast<int>(w), &o[0], TRUE); return o;
}
inline std::string protocolEncodeG1(const G1&p,PFC*f){size_t w=protocolCoordinateWidth(f);if(p.g.iszero())return std::string(1,'\0');Big x,y;G1 q=p;q.g.get(x,y);return std::string(1,'\1')+protocolBig(x,w)+protocolBig(y,w);}
inline std::string protocolEncodeG2(const G2&p,PFC*f){size_t w=protocolCoordinateWidth(f);if(p.g.iszero())return std::string(1,'\0');ZZn2 x,y;G2 q=p;q.g.get(x,y);ZZn a,b,c,d;x.get(a,b);y.get(c,d);return std::string(1,'\1')+protocolBig((Big)a,w)+protocolBig((Big)b,w)+protocolBig((Big)c,w)+protocolBig((Big)d,w);}
inline bool protocolScalarValid(const Big&v,PFC*p,bool nz=false){if(!p||!p->ord||v<Big(0)||v>=p->order())return false;return !nz||!v.iszero();}
inline Big protocolRandomScalar(PFC* p, bool nz = false) {
    if (!p || !p->ord || p->order() <= Big(1)) throw std::invalid_argument("invalid scalar domain");
    Big v;
    const int order_bits = bits(p->order());
    do {
        if (p->RNG) {
            const int byte_count = (order_bits + 7) / 8;
            std::string candidate(static_cast<size_t>(byte_count), '\0');
            for (int i = 0; i < byte_count; ++i)
                candidate[static_cast<size_t>(i)] = static_cast<char>(strong_rng(p->RNG));
            const int excess = byte_count * 8 - order_bits;
            if (excess) candidate[0] = static_cast<char>(static_cast<unsigned char>(candidate[0]) & (0xffU >> excess));
            v = from_binary(byte_count, &candidate[0]);
        } else {
            throw std::runtime_error("protocol RNG is not initialized");
        }
    } while (!protocolScalarValid(v, p, nz));
    return v;
}
inline bool protocolValidG1(const G1&p,PFC*f,bool nz=true){if(!f||!f->ord)return false;if(p.g.iszero())return !nz;Big x,y;G1 q=p;q.g.get(x,y);ECn e;if(!e.set(x,y))return false;e*=f->order();return e.iszero();}
inline bool protocolValidG2(const G2&p,PFC*f,bool nz=true){if(!f||!f->ord)return false;if(p.g.iszero())return !nz;ZZn2 x,y;G2 q=p;q.g.get(x,y);ECn2 e;if(!e.set(x,y))return false;e*=f->order();return e.iszero();}
inline ProtocolParameters makeProtocolParameters(PFC* f, const G1& g1, const G2& g2, size_t k) {
    if (!f || !f->mod || !f->ord || !f->B || !f->x || f->order() <= Big(1) || !k ||
        !protocolValidG1(g1, f) || !protocolValidG2(g2, f))
        throw std::invalid_argument("invalid protocol parameters");
    ProtocolParameters p;
    p.version = "multi-issuer-deniable-cred-v2";
    p.attribute_count = k;
    size_t w = protocolCoordinateWidth(f);
    bool neg = *f->x < Big(0);
    Big ax = neg ? -*f->x : *f->x;
    std::string d = protocolFrame(p.version) + protocolFrame("MIRACL-BN-TypeIII-SHA256-hash-v2") +
        protocolFrame(protocolBig(*f->mod, w)) + protocolFrame(protocolBig(f->order(), w)) +
        protocolFrame(protocolBig(*f->B, w)) +
        protocolFrame(std::string(1, char(neg)) + protocolBig(ax, w)) +
        protocolFrame(protocolEncodeG1(g1, f)) + protocolFrame(protocolEncodeG2(g2, f)) +
        protocolFrame(protocolU64(k));
    p.binding = protocolSha256(d);
    return p;
}
inline Big protocolHashScalar(const std::string&s,PFC*p){if(!p)throw std::invalid_argument("null PFC");std::string h=protocolSha256(s);return from_binary(32,&h[0])%p->order();}
inline G2 protocolHashToG2(const ProtocolParameters&p,const std::string&ctx,PFC*f){if(!f)throw std::invalid_argument("null PFC");std::string b=protocolFrame("domain_nym")+protocolFrame(p.binding)+protocolFrame(ctx);for(uint64_t i=0;;++i){std::string h=protocolHex(protocolSha256(b+protocolFrame(protocolU64(i))));std::vector<char> z(h.begin(),h.end());z.push_back(0);G2 q;f->hash_and_map(q,&z[0]);if(!q.g.iszero())return q;}}
#endif
