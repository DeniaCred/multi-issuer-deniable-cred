#include <algorithm>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>

#include "Algorithm/pairing_3.h"

using Clock = std::chrono::steady_clock;

namespace {

struct NullBuffer : std::streambuf {
    int overflow(int c) override { return c; }
};

class CoutSilencer {
public:
    explicit CoutSilencer(bool enabled) : enabled_(enabled), old_(nullptr) {
        if (enabled_) {
            old_ = std::cout.rdbuf(&null_);
        }
    }

    ~CoutSilencer() {
        if (enabled_) {
            std::cout.rdbuf(old_);
        }
    }

private:
    bool enabled_;
    std::streambuf* old_;
    NullBuffer null_;
};

struct Summary {
    std::string unit_id;
    std::string unit_name;
    std::string operation;
    int samples;
    int iterations;
    double mean_ms;
    double median_ms;
    double std_ms;
    double min_ms;
    double max_ms;
    std::string notes;
};

double median(std::vector<double> values) {
    std::sort(values.begin(), values.end());
    const size_t n = values.size();
    if (n == 0) return 0.0;
    if (n % 2 == 1) return values[n / 2];
    return (values[n / 2 - 1] + values[n / 2]) / 2.0;
}

double stddev(const std::vector<double>& values, double mean) {
    if (values.size() < 2) return 0.0;
    double acc = 0.0;
    for (double value : values) {
        const double delta = value - mean;
        acc += delta * delta;
    }
    return std::sqrt(acc / static_cast<double>(values.size() - 1));
}

template <typename Fn>
Summary measure(
    const std::string& unit_id,
    const std::string& unit_name,
    const std::string& operation,
    int samples,
    int iterations,
    bool suppress_cout,
    const std::string& notes,
    Fn fn
) {
    std::vector<double> per_op_ms;
    per_op_ms.reserve(samples);

    CoutSilencer silencer(suppress_cout);
    for (int i = 0; i < std::min(iterations, 5); ++i) {
        fn(i);
    }

    for (int sample = 0; sample < samples; ++sample) {
        const auto start = Clock::now();
        for (int i = 0; i < iterations; ++i) {
            fn(i + sample * iterations);
        }
        const auto end = Clock::now();
        const double total_ms = std::chrono::duration<double, std::milli>(end - start).count();
        per_op_ms.push_back(total_ms / static_cast<double>(iterations));
    }

    const double mean = std::accumulate(per_op_ms.begin(), per_op_ms.end(), 0.0)
        / static_cast<double>(per_op_ms.size());
    const auto minmax = std::minmax_element(per_op_ms.begin(), per_op_ms.end());

    return Summary{
        unit_id,
        unit_name,
        operation,
        samples,
        iterations,
        mean,
        median(per_op_ms),
        stddev(per_op_ms, mean),
        *minmax.first,
        *minmax.second,
        notes,
    };
}

std::string format_double(double value) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(9) << value;
    return out.str();
}

Big random_nonzero_scalar(PFC& pfc) {
    Big value;
    do {
        pfc.random_ord(value);
    } while (value == Big(0));
    return value;
}

void print_tsv(const std::vector<Summary>& rows) {
    std::cout << "BEGIN_UNIT_COSTS_TSV\n";
    std::cout
        << "unit_id\tunit_name\toperation\tsamples\titerations_per_sample\t"
        << "mean_ms\tmedian_ms\tstd_ms\tmin_ms\tmax_ms\tnotes\n";
    for (const auto& row : rows) {
        std::cout
            << row.unit_id << '\t'
            << row.unit_name << '\t'
            << row.operation << '\t'
            << row.samples << '\t'
            << row.iterations << '\t'
            << format_double(row.mean_ms) << '\t'
            << format_double(row.median_ms) << '\t'
            << format_double(row.std_ms) << '\t'
            << format_double(row.min_ms) << '\t'
            << format_double(row.max_ms) << '\t'
            << row.notes << '\n';
    }
    std::cout << "END_UNIT_COSTS_TSV\n";
}

}  // namespace

int main(int argc, char** argv) {
    int samples = 15;
    if (argc >= 2) {
        samples = std::max(3, std::atoi(argv[1]));
    }

    PFC pfc(128);
    std::vector<Big> scalars;
    std::vector<std::string> ids;
    scalars.reserve(64);
    ids.reserve(64);
    for (int i = 0; i < 64; ++i) {
        scalars.push_back(random_nonzero_scalar(pfc));
        ids.push_back("unit-benchmark-" + std::to_string(i));
    }

    G1 g1_base;
    G2 g2_base;
    pfc.random(g1_base);
    pfc.random(g2_base);

    std::vector<G1> g1_pool(8);
    std::vector<G2> g2_pool(8);
    for (int i = 0; i < 8; ++i) {
        g1_pool[i] = pfc.mult(g1_base, scalars[i]);
        g2_pool[i] = pfc.mult(g2_base, scalars[i + 8]);
    }

    GT gt_base;
    {
        CoutSilencer silencer(true);
        gt_base = pfc.pairing(g2_base, g1_base);
    }

    Big sink_big;
    G1 sink_g1;
    G2 sink_g2;
    GT sink_gt;

    std::vector<Summary> rows;
    rows.push_back(measure("T_RZ", "random scalar", "pfc.random_ord(Big)", samples, 3000, false, "Zp random scalar generation", [&](int i) {
        Big value;
        pfc.random_ord(value);
        sink_big = value;
        (void)i;
    }));

    rows.push_back(measure("T_ZADD", "scalar add mod p", "(a+b) mod order", samples, 30000, false, "Usually negligible; included for SPS-EQ set-commitment estimates", [&](int i) {
        Big a = scalars[i % scalars.size()];
        Big b = scalars[(i + 1) % scalars.size()];
        sink_big = (a + b) % pfc.order();
    }));

    rows.push_back(measure("T_ZMUL", "scalar multiply mod p", "modmult(a,b,order)", samples, 30000, false, "Usually negligible; included for polynomial and exponent aggregation estimates", [&](int i) {
        Big a = scalars[i % scalars.size()];
        Big b = scalars[(i + 1) % scalars.size()];
        sink_big = modmult(a, b, pfc.order());
    }));

    rows.push_back(measure("T_INVZ", "scalar inverse mod p", "pfc.Zpinverse(x)", samples, 3000, false, "Scalar inverse in the group order field", [&](int i) {
        Big a = scalars[i % scalars.size()];
        sink_big = pfc.Zpinverse(a);
    }));

    rows.push_back(measure("T_R1", "random G1 element", "pfc.random(G1)", samples, 500, false, "Random curve point in G1", [&](int i) {
        G1 value;
        pfc.random(value);
        sink_g1 = value;
        (void)i;
    }));

    rows.push_back(measure("T_R2", "random G2 element", "pfc.random(G2)", samples, 200, false, "Random curve point in G2", [&](int i) {
        G2 value;
        pfc.random(value);
        sink_g2 = value;
        (void)i;
    }));

    rows.push_back(measure("T_E1", "G1 scalar multiplication", "pfc.mult(G1, scalar)", samples, 1000, false, "Used for BBS/BBS+/PS/SPS-EQ G1 exponentiation terms", [&](int i) {
        sink_g1 = pfc.mult(g1_pool[i % g1_pool.size()], scalars[i % scalars.size()]);
    }));

    rows.push_back(measure("T_E2", "G2 scalar multiplication", "pfc.mult(G2, scalar)", samples, 400, false, "Used for public-key and verifier-side exponentiation terms", [&](int i) {
        sink_g2 = pfc.mult(g2_pool[i % g2_pool.size()], scalars[i % scalars.size()]);
    }));

    rows.push_back(measure("T_ET", "GT exponentiation", "pfc.power(GT, scalar)", samples, 400, false, "Used when a proof equation is represented as exponentiation in GT", [&](int i) {
        sink_gt = pfc.power(gt_base, scalars[i % scalars.size()]);
    }));

    rows.push_back(measure("T_P", "single pairing", "pfc.pairing(G2,G1)", samples, 80, true, "The library prints each pairing internally; output is suppressed in this benchmark", [&](int i) {
        sink_gt = pfc.pairing(g2_pool[i % g2_pool.size()], g1_pool[i % g1_pool.size()]);
    }));

    auto multi_pairing_op = [&](int width, int i) {
        std::vector<G2*> g2_ptrs(width);
        std::vector<G1*> g1_ptrs(width);
        for (int j = 0; j < width; ++j) {
            g2_ptrs[j] = &g2_pool[(i + j) % g2_pool.size()];
            g1_ptrs[j] = &g1_pool[(i + j) % g1_pool.size()];
        }
        sink_gt = pfc.multi_pairing(width, g2_ptrs.data(), g1_ptrs.data());
    };

    rows.push_back(measure("T_MP2", "2-term pairing product", "pfc.multi_pairing(2)", samples, 60, true, "Useful for BBS/PS verification equations with two pairings", [&](int i) {
        multi_pairing_op(2, i);
    }));
    rows.push_back(measure("T_MP6", "6-term pairing product", "pfc.multi_pairing(6)", samples, 25, true, "Useful for SPS-EQ VerifyR-style pairing-product estimates", [&](int i) {
        multi_pairing_op(6, i);
    }));
    rows.push_back(measure("T_MP8", "8-term pairing product", "pfc.multi_pairing(8)", samples, 20, true, "Useful for SPS-EQ show verification upper-bound estimates", [&](int i) {
        multi_pairing_op(8, i);
    }));

    rows.push_back(measure("T_H", "Fiat-Shamir hash to scalar", "start_hash/add_to_hash/finish_hash_to_group", samples, 3000, false, "Hashes one G1, one G2, one GT, one scalar, and one label", [&](int i) {
        pfc.start_hash();
        pfc.add_to_hash(g1_pool[i % g1_pool.size()]);
        pfc.add_to_hash(g2_pool[i % g2_pool.size()]);
        pfc.add_to_hash(gt_base);
        pfc.add_to_hash(scalars[i % scalars.size()]);
        pfc.add_to_hash(const_cast<char*>(ids[i % ids.size()].c_str()));
        sink_big = pfc.finish_hash_to_group();
    }));

    rows.push_back(measure("T_H2G1", "hash and map to G1", "pfc.hash_and_map(G1,char*)", samples, 500, false, "Used when generators are derived on demand instead of precomputed", [&](int i) {
        G1 value;
        pfc.hash_and_map(value, const_cast<char*>(ids[i % ids.size()].c_str()));
        sink_g1 = value;
    }));

    rows.push_back(measure("T_H2G2", "hash and map to G2", "pfc.hash_and_map(G2,char*)", samples, 100, false, "Included for completeness; most formulas here do not require it directly", [&](int i) {
        G2 value;
        pfc.hash_and_map(value, const_cast<char*>(ids[i % ids.size()].c_str()));
        sink_g2 = value;
    }));

    print_tsv(rows);

    if (sink_big == Big(-1)) {
        std::cerr << "unreachable sink guard\n";
    }
    return 0;
}
