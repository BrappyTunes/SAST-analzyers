// test-modern-cpp.cpp: modern C++ syntax that should produce zero flawfinder hits.
// Exercises binary literals, hex literals, hex floats, digit separators,
// C++11/14/17 keywords, and lambdas inside function calls.

// Binary literals with digit separators (C++14)
int bin1 = 0b1010'0101;
long bin2 = 0b1111'1111'0000'0000;

// Hex literals with alpha digits and digit separators
unsigned hex1 = 0xDEAD'BEEF;
unsigned long hex2 = 0xCAFE'BABE;
unsigned long long hex3 = 0xFFFF'FFFF'FFFF'FFFFull;

// Hex float literals (C99 / C++17)
double hf1 = 0x1.fp+3;
float  hf2 = 0x1.8p-2f;
double hf3 = 0x1p+0;

// Decimal floats with digit separators
long   million = 1'000'000;
double pi      = 3.141'592'653;
double lead    = .5;

// constexpr functions and variables
constexpr int square(int x) { return x * x; }
constexpr double tau = 6.283'185'307;

// noexcept, thread_local, decltype (none are in the ruleset)
void safe_func() noexcept {}
thread_local int tl_counter = 0;
int base_val = 42;
decltype(base_val) other_val = base_val;

// static_assert with string literal
static_assert(sizeof(int) >= 4, "int must be at least 32 bits");

// alignas / alignof (use int to avoid the char-array hit)
alignas(16) int aligned_buf[16];

// Lambda in argument: exercises curlylevel tracking in extract_c_parameters
void invoke(int (*fn)(int, int)) { (void)fn; }
void use_lambda() {
    invoke([](int a, int b) -> int { return a + b; });
}

// Nested template arguments (>> disambiguation)
#include <vector>
#include <map>
void nested_template() {
    std::vector<std::map<int, int>> vm;
    (void)vm;
}
