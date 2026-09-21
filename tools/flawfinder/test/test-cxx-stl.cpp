// Tests for C++ STL false-positive fixes.

// Bug 28: enum members named mismatch/equal/is_permutation should not warn.
class Foo {
public:
    enum MatchState {
        invalid,
        mismatch,      // should NOT warn - not a function call
        exact_match,
    };
};

// Bug 29: std::ranges:: versions are safe (C++20) and should not warn.
// The legacy three-iterator forms should still warn.
void stl_test(int* a, int* b, int n) {
    std::ranges::equal(a, a+n, b, b+n);        // should NOT warn
    std::ranges::mismatch(a, a+n, b, b+n);     // should NOT warn
    std::ranges::is_permutation(a, a+n, b, b+n); // should NOT warn
    std::equal(a, a+n, b);                     // SHOULD warn (3-iterator form)
    std::mismatch(a, a+n, b);                  // SHOULD warn (3-iterator form)
    std::is_permutation(a, a+n, b);            // SHOULD warn (3-iterator form)
}
