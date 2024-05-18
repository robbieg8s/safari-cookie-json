#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    EXIT_CODE_OK = 0,
    EXIT_CODE_BAD_INVOCATION,
    EXIT_CODE_BAD_OPEN,
    EXIT_CODE_BAD_CLOSE,
    EXIT_CODE_BAD_STAT,
    EXIT_CODE_BAD_MMAP,
    EXIT_CODE_BAD_MUNMAP,
    EXIT_CODE_BAD_EOF,
    EXIT_CODE_BAD_MAGIC,
    EXIT_CODE_BAD_PARSE,
};

const char BINARY_COOKIE_MAGIC[] = { 'c', 'o', 'o', 'k' } ;
const char COOKIE_PAGE_TAG[] = { 0, 0, 1, 0 } ;
const char COOKIE_PAGE_HEADER_END[] = { 0, 0, 0, 0 } ;
const char BINARY_COOKIE_FOOTER[] = { 0x07, 0x17, 0x20, 0x05 } ;

uint32_t read32Hi(const char ** data) {
    uint32_t result = 0;
    for (int i = 0; i < sizeof(uint32_t); ++i) {
        result <<= CHAR_BIT;
        const uint8_t byte = (*data)[i];
        result += byte;
    }
    (*data) += sizeof(uint32_t);
    return result;
}

uint32_t read32Lo(const char ** data) {
    uint32_t result = 0;
    for (int i = 0; i < sizeof(uint32_t); ++i) {
        const uint8_t byte = (*data)[i];
        result += ((uint32_t)byte) << (i * CHAR_BIT);
    }
    (*data) += sizeof(uint32_t);
    return result;
}

uint64_t read64Lo(const char ** data) {
    uint64_t result = 0;
    for (int i = 0; i < sizeof(uint64_t); ++i) {
        const uint8_t byte = (*data)[i];
        result += ((uint64_t)byte) << (i * CHAR_BIT);
    }
    (*data) += sizeof(uint64_t);
    return result;
}

double readDouble(const char ** data) {
    uint64_t raw = read64Lo(data);
    return *((double*)&raw);
}

void emitJsonBeginArray() {
    putchar('[');
}

void emitJsonBeginObject() {
    putchar('{');
}

void emitJsonEndArray() {
    putchar(']');
}

void emitJsonEndObject() {
    putchar('}');
}

void emitJsonNameSeparator() {
    putchar(':');
}

void emitJsonValueSeparator() {
    putchar(',');
}

void emitJsonValueFalse() {
    printf("false");
}

void emitJsonValueNull() {
    printf("null");
}

void emitJsonValueTrue() {
    printf("true");
}

void emitJsonNumberInt(int value) {
    printf("%d", value);
}

void emitJsonNumberDouble(double value) {
    printf("%.17lg", value);
}

void emitJsonCharEscapedPretty(char value) {
    putchar('\\');
    putchar(value);
}

void emitJsonCharEscapedUgly(uint8_t value) {
    printf("\\u%04X", value);
}

void emitJsonString(const char * value) {
    putchar('"');

    // I'm ignoring encodings here - i guess i hope the cookies are in UTF8, and maybe that goes through
    // clean because a control character can't occur in the non-first bytes for UTF8 ?
    // RFC 8259 section 7 says
    // All Unicode characters may be placed within the quotation marks, except for the characters that MUST
    // be escaped: quotation mark, reverse solidus, and the control characters (U+0000 through U+001F).

    for(const char * cursor = value; *cursor; ++cursor) {
        uint8_t byte = *cursor;
        switch(byte) {
            // Be pretty where we can be - NB this is the order in the spec
            case '"': emitJsonCharEscapedPretty('\"'); break;
            case '\\': emitJsonCharEscapedPretty('\\'); break;
            // But let's not escape solidus / because we don't need to
            case 0x08: emitJsonCharEscapedPretty('b'); break; // backspace
            case 0x0C: emitJsonCharEscapedPretty('f'); break; // form feed
            case 0x0A: emitJsonCharEscapedPretty('n'); break; // line feed
            case 0x0D: emitJsonCharEscapedPretty('r'); break; // carriage return
            case 0x09: emitJsonCharEscapedPretty('t'); break; // tab
            default: {
                if (byte < 0x20) {
                    emitJsonCharEscapedUgly(byte);
                } else {
                    putchar(byte);
                }
                break;
            }
        }
    }

    putchar('"');
}

void emitJsonNamedValueInt(const char * name, int value) {
    emitJsonString(name);
    emitJsonNameSeparator();
    emitJsonNumberInt(value);
}

void emitJsonSeparatedNamedValueInt(const char * name, int value) {
    emitJsonValueSeparator();
    emitJsonNamedValueInt(name, value);
}

void emitJsonSeparatedNamedValueDouble(const char * name, double value) {
    emitJsonValueSeparator();
    emitJsonString(name);
    emitJsonNameSeparator();
    emitJsonNumberDouble(value);
}

void emitJsonOptionalSeparatedNamedValueString(int present, const char * name, const char * value) {
    if (present) {
        emitJsonValueSeparator();
        emitJsonString(name);
        emitJsonNameSeparator();
        emitJsonString(value);
    }
}

int printCookiesFromMmap(off_t length, const char * data) {
    if (length < sizeof(BINARY_COOKIE_MAGIC) + sizeof(uint32_t)) {
        fprintf(stderr, "File too short, when checking magic and page count\n");
        return EXIT_CODE_BAD_EOF;
    } else if (memcmp(data, BINARY_COOKIE_MAGIC, sizeof(BINARY_COOKIE_MAGIC))) {
        fprintf(stderr, "Bad magic - is this a cookie file?\n");
        return EXIT_CODE_BAD_MAGIC;
    } else {
        uint32_t checkSum = 0;
        const char * pageSizeBase = data + sizeof(BINARY_COOKIE_MAGIC);
        const uint32_t pageCount = read32Hi(&pageSizeBase);
        const char * pageBase = pageSizeBase + pageCount * sizeof(uint32_t);
        if (data + length < pageBase) {
            fprintf(stderr, "File too short, when checking page sizes in header\n");
            return EXIT_CODE_BAD_EOF;
        } else {
            // Separators are fenceposts not terminators
            int first = 1;
            emitJsonBeginObject();
            emitJsonString("cookies");
            emitJsonNameSeparator();
            emitJsonBeginArray();
            for(int pageIdx = 0; pageIdx < pageCount; ++pageIdx) {
                uint32_t pageSize = read32Hi(&pageSizeBase);
                const char * pageEnd = pageBase + pageSize;
                if (data + length < pageEnd) {
                    fprintf(stderr, "File too short, incomplete page %d\n", pageIdx);
                    return EXIT_CODE_BAD_EOF;
                } else if (pageSize < sizeof(COOKIE_PAGE_TAG) + sizeof(uint32_t)) {
                    fprintf(stderr, "Page %d too short for page tag and cookie count\n", pageIdx);
                    return EXIT_CODE_BAD_PARSE;
                } else if (memcmp(pageBase, COOKIE_PAGE_TAG, sizeof(COOKIE_PAGE_TAG))) {
                    fprintf(stderr, "Bad page tag - is this a cookie file?\n");
                    return EXIT_CODE_BAD_MAGIC;
                } else {
                    // Process page
                    const char * cookieOffsetBase = pageBase + sizeof(COOKIE_PAGE_TAG);
                    const uint32_t cookieCount = read32Lo(&cookieOffsetBase);
                    const char * cookiePageHeaderEnd = cookieOffsetBase + cookieCount * sizeof(uint32_t);
                    if (pageEnd < cookiePageHeaderEnd + sizeof(COOKIE_PAGE_HEADER_END)) {
                        fprintf(stderr, "Page %d too short for cookie offsets\n", pageIdx);
                        return EXIT_CODE_BAD_PARSE;
                    } else if (memcmp(cookiePageHeaderEnd, COOKIE_PAGE_HEADER_END, sizeof(COOKIE_PAGE_HEADER_END))) {
                        fprintf(stderr, "Bad page header end - is this a cookie file?\n");
                        return EXIT_CODE_BAD_MAGIC;
                    } else {
                        for(int cookieIdx = 0; cookieIdx < cookieCount; ++cookieIdx) {
                            const char * cookieBase = pageBase + read32Lo(&cookieOffsetBase);
                            const char * cookieCursor = cookieBase;
                            // Check enough space for the mandatory fields read below
                            if (data + length < cookieCursor + 10 * sizeof(uint32_t) + 2 * sizeof(uint64_t)) {
                                fprintf(stderr, "Cookie %d in Page %d too short for cookie header\n", cookieIdx, pageIdx);
                                return EXIT_CODE_BAD_PARSE;
                            } else {
                                // The size of the cookie record, which we use just for validation
                                const uint32_t cookieSize = read32Lo(&cookieCursor);
                                const uint32_t version = read32Lo(&cookieCursor);
                                const uint32_t flags = read32Lo(&cookieCursor);
                                const uint32_t hasPort = read32Lo(&cookieCursor); // extra field below ?
                                const uint32_t domain = read32Lo(&cookieCursor);
                                const uint32_t name = read32Lo(&cookieCursor);
                                const uint32_t path = read32Lo(&cookieCursor);
                                const uint32_t value = read32Lo(&cookieCursor);
                                const uint32_t comment = read32Lo(&cookieCursor);
                                const uint32_t commentUrl = read32Lo(&cookieCursor);
                                const double expiry = readDouble(&cookieCursor);
                                const double creation = readDouble(&cookieCursor);
                                // if hasPort, maybe there us a uint15_t port here ?
                                const char * cookieEnd = cookieBase + cookieSize;
                                if (pageEnd < cookieEnd) {
                                    fprintf(stderr,
                                        "Cookie %d in Page %d has end past end of page\n",
                                        cookieIdx, pageIdx);
                                    return EXIT_CODE_BAD_PARSE;
                                } else if (0 != *(cookieEnd - 1)) {
                                    fprintf(stderr,
                                        "Cookie %d in Page %d does not end with null terminated string\n",
                                        cookieIdx, pageIdx);
                                    return EXIT_CODE_BAD_PARSE;
                                } else if (cookieEnd < cookieBase + domain) {
                                    fprintf(stderr, "Cookie %d in Page %d domain out of range\n", cookieIdx, pageIdx);
                                    return EXIT_CODE_BAD_PARSE;
                                } else if (cookieEnd < cookieBase + name) {
                                    fprintf(stderr, "Cookie %d in Page %d name out of range\n", cookieIdx, pageIdx);
                                    return EXIT_CODE_BAD_PARSE;
                                } else if (cookieEnd < cookieBase + path) {
                                    fprintf(stderr, "Cookie %d in Page %d path out of range\n", cookieIdx, pageIdx);
                                    return EXIT_CODE_BAD_PARSE;
                                } else if (cookieEnd < cookieBase + value) {
                                    fprintf(stderr, "Cookie %d in Page %d value out of range\n", cookieIdx, pageIdx);
                                    return EXIT_CODE_BAD_PARSE;
                                } else if (cookieEnd < cookieBase + comment) {
                                    fprintf(stderr, "Cookie %d in Page %d comment out of range\n", cookieIdx, pageIdx);
                                    return EXIT_CODE_BAD_PARSE;
                                } else if (cookieEnd < cookieBase + commentUrl) {
                                    fprintf(stderr, "Cookie %d in Page %d commentUrl out of range\n", cookieIdx, pageIdx);
                                    return EXIT_CODE_BAD_PARSE;
                                } else {
                                    if (first) {
                                        first = 0;
                                    } else {
                                        emitJsonValueSeparator();
                                    }
                                    emitJsonBeginObject();
                                    emitJsonNamedValueInt("version", version);
                                    // Treating flags as an integer for now
                                    emitJsonSeparatedNamedValueInt("flags", flags);
                                    emitJsonOptionalSeparatedNamedValueString(domain, "domain", cookieBase + domain);
                                    emitJsonOptionalSeparatedNamedValueString(name, "name", cookieBase + name);
                                    emitJsonOptionalSeparatedNamedValueString(path, "path", cookieBase + path);
                                    emitJsonOptionalSeparatedNamedValueString(value, "value", cookieBase + value);
                                    emitJsonOptionalSeparatedNamedValueString(comment, "comment", cookieBase + comment);
                                    emitJsonOptionalSeparatedNamedValueString(commentUrl, "commentUrl", cookieBase + commentUrl);
                                    emitJsonSeparatedNamedValueDouble("expiry", expiry);
                                    emitJsonSeparatedNamedValueDouble("creation", creation);
                                    emitJsonEndObject();
                                }
                            }
                        }
                    }
                    // Incorporate the page checksum into the running total. Yes the loop steps four bytes, but
                    // only one byte is included each time. This works in my examples, and matches my understanding
                    // of the swift version.
                    for(const char * pageCursor = pageBase; pageCursor < pageEnd; pageCursor += sizeof(uint32_t)) {
                        const uint8_t byte = *pageCursor;
                        checkSum += byte;
                    }
                    pageBase = pageEnd;
                }
            }
            if (data + length < pageBase + sizeof(uint32_t) + sizeof(BINARY_COOKIE_FOOTER) + sizeof(uint32_t)) {
                fprintf(stderr, "File too short, for checksum, footer, and plist size\n");
                return EXIT_CODE_BAD_EOF;
            } else {
                uint32_t savedCheckSum = read32Hi(&pageBase);
                if (savedCheckSum != checkSum) {
                    fprintf(stderr, "Bad file checksum\n");
                    return EXIT_CODE_BAD_PARSE;
                } else
                if (memcmp(pageBase, BINARY_COOKIE_FOOTER, sizeof(BINARY_COOKIE_FOOTER))) {
                    fprintf(stderr, "Bad file footer - is this a cookie file?\n");
                    return EXIT_CODE_BAD_MAGIC;
                } else {
                    pageBase += sizeof(BINARY_COOKIE_FOOTER);
                    const uint32_t plistSize = read32Hi(&pageBase);
                    if (data + length != pageBase + plistSize) {
                        fprintf(stderr, "File length and plist data length mismatch\n");
                        return EXIT_CODE_BAD_PARSE;
                    } else {
                        // It's not worth parsing the binary plist - it my experiment it contains
                        // the NSHTTPCookieAcceptPolicy value

                        // It's very ugly having these here
                        emitJsonEndArray();
                        emitJsonEndObject();

                        return EXIT_CODE_OK;
                    }
                }
            }
        }
    }
}

int printCookiesFromFd(int fd) {
    struct stat statResult;
    if (fstat(fd, &statResult)) {
        perror("Cannot stat file");
        return EXIT_CODE_BAD_STAT;
    }

    const off_t length = statResult.st_size;

    void * data = mmap(0, length, PROT_READ, MAP_PRIVATE | MAP_NOCACHE, fd, 0);
    if (MAP_FAILED == data) {
        perror("Cannot mmap file");
        return EXIT_CODE_BAD_MMAP;
    } else {
        int exitCode = printCookiesFromMmap(length, data);
        if (munmap(data, length)) {
            perror("Cannot munmap file");
            return exitCode ? exitCode : EXIT_CODE_BAD_MUNMAP;
        } else {
            return exitCode;
        }
    }
}

int main(int argc, const char **argv) {
    if (2 != argc) {
        fprintf(stderr, "Usage: %s FILENAME\n", *argv);
        fprintf(stderr, "  For example,\n");
        fprintf(stderr,
            "  %s \"${HOME}\"/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies\n",
            *argv);
        return EXIT_CODE_BAD_INVOCATION;
    }

    const char * filename = argv[1];
    const int fd = open(filename, O_RDONLY);
    if (-1 == fd) {
        perror("Cannot open file");
        return EXIT_CODE_BAD_OPEN;
    } else {
        const int exitCode = printCookiesFromFd(fd);
        if (close(fd)) {
            // Not much we can actually do, but interesting to know maybe
            perror("Cannot close file");
            return exitCode ? exitCode : EXIT_CODE_BAD_CLOSE;
        } else {
            return exitCode;
        }
    }
}
