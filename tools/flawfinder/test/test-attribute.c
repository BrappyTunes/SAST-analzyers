// test-attribute.c: __attribute__((format(printf,...))) must not produce
// false positives; real printf calls outside attributes must still be flagged.

// --- These should produce NO hits ---

// GCC format attribute: 'printf' here is a specifier keyword, not a call.
#define ZT_FORMAT_PRINTF(a, b) __attribute__((format(printf, a, b)))

// Attribute directly on a declaration.
void my_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

// Nested parens inside attribute argument.
void my_warn(const char *fmt, ...) __attribute__((format(printf, 1, 2), noinline));

// --- These SHOULD still produce hits ---

void real_call(const char *name) {
    printf(name);  // non-constant format: real hit
}
