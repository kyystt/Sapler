#include "../include/sv.h"
#include <string.h>

StringView sv(const char *cstr)
{
    return (StringView){.data = cstr, .count = strlen(cstr)};
}

char *sv_to_cstr(StringView *sv)
{
    char *res = (char *)malloc(sv->count + 1);
    memcpy(res, sv->data, sv->count);
    res[sv->count] = '\0';

    return res;
}

int sv_eq(StringView a, StringView b)
{
    return a.count == b.count && memcmp(a.data, b.data, a.count) == 0;
}

int sv_eq_ignore_case(StringView a, StringView b)
{
    if (a.count != b.count)
        return 0;

    for (size_t i = 0; i < a.count; ++i)
        if (tolower(a.data[i]) != tolower(b.data[i]))
            return 0;

    return 1;
}

int sv_eq_cstr(StringView sv, const char *cstr)
{
    size_t clen = strlen(cstr);
    return sv.count == clen && memcmp(sv.data, cstr, clen) == 0;
}

int sv_eq_cstr_ignore_case(StringView sv, const char *cstr)
{
    size_t clen = strlen(cstr);
    if (sv.count != clen)
        return 0;

    for (size_t i = 0; i < clen; ++i)
        if (tolower(sv.data[i]) != tolower(cstr[i]))
            return 0;

    return 1;
}

void sv_chop_left(StringView *sv, size_t n)
{
    if (sv->count < n)
        n = sv->count;
    sv->data += n;
    sv->count -= n;
}

void sv_chop_right(StringView *sv, size_t n)
{
    if (sv->count < n)
        n = sv->count;
    sv->count -= n;
}

void sv_trim_left(StringView *sv)
{
    while (sv->count > 0 && isspace(sv->data[0]))
        sv_chop_left(sv, 1);
}

void sv_trim_right(StringView *sv)
{
    while (sv->count > 0 && isspace(sv->data[sv->count - 1]))
        sv_chop_right(sv, 1);
}

void sv_trim(StringView *sv)
{
    sv_trim_left(sv);
    sv_trim_right(sv);
}

StringView sv_chop_by_delim(StringView *sv, char delim)
{
    size_t i = 0;

    while (i < sv->count && sv->data[i] != delim)
        ++i;

    if (i < sv->count) {
        StringView result = {.data = sv->data, .count = i};

        sv_chop_left(sv, i + 1);

        return result;
    }

    StringView result = *sv;
    sv_chop_left(sv, sv->count);

    return result;
}

StringView sv_chop_by_type(StringView *sv, int (*istype)(int))
{
    size_t i = 0;

    while (i < sv->count && !istype(sv->data[i]))
        ++i;

    if (i < sv->count) {
        StringView result = {.data = sv->data, .count = i};

        sv_chop_left(sv, i + 1);

        return result;
    }

    StringView result = *sv;
    sv_chop_left(sv, sv->count);

    return result;
}

int sv_get_str_literal_doubleq(StringView src, StringView *dst)
{
    size_t i = 0;

    while (i < src.count && src.data[i] != '"')
        ++i;

    StringView str_literal = {.data = src.data + i, .count = src.count - i};

    if (str_literal.data[str_literal.count - 1] != '"')
        return -1;

    *dst = str_literal;
    return 1;
}

void sv_remove_comment(StringView *sv)
{
    int in_quote = 0;

    for (size_t i = 0; i < sv->count; ++i) {
        char c = sv->data[i];

        if (in_quote && c == '\\' && i + 1 < sv->count) {
            ++i;
            continue;
        }

        if (c == '"') {
            in_quote = !in_quote;
        } else if (c == ';' && !in_quote) {
            sv_chop_right(sv, sv->count - i);
            return;
        }
    }
}

void sv_remove_doubleq(StringView *sv)
{
    if (sv->data[0] != '"' || sv->data[sv->count - 1] != '"')
        return;

    sv_chop_left(sv, 1);
    sv_chop_right(sv, 1);
}
