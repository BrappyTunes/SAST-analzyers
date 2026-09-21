// test-member-calls.cpp: member calls via '.' and '->' must not produce
// false positives; global calls must still be flagged.

struct Stream {
    int read(void *buf, unsigned n) { (void)buf; (void)n; return 0; }
    int write(const void *buf, unsigned n) { (void)buf; (void)n; return 0; }
};

// --- These should produce NO hits ---

void no_hits(Stream *ptr, Stream &obj, void *buf) {
    // Member call via dot operator
    obj.read(buf, 10);
    obj.write(buf, 10);
    // Member call via arrow operator
    ptr->read(buf, 10);
    ptr->write(buf, 10);
}

// --- These SHOULD still produce hits ---

void hits(void *buf) {
    // Bare global call — must be flagged
    read(0, buf, 10);
    // Explicit global scope — must still be flagged
    ::system("echo hello");
}
