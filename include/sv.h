#ifndef SV_H
#define SV_H

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define SV_FMT "%.*s"
#define SV_ARGS(sv) (int)(sv).count, (sv).data

#define SV_IMPLEMENTATION

typedef struct {
    const char *data;
    size_t count;
} StringView;

StringView sv(const char *);
char *sv_to_cstr(StringView *);
int sv_eq(StringView, StringView);
int sv_eq_ignore_case(StringView, StringView);
int sv_eq_cstr(StringView, const char *);
int sv_eq_cstr_ignore_case(StringView, const char *);
void sv_chop_left(StringView *, size_t);
void sv_chop_right(StringView *, size_t);
void sv_trim_left(StringView *);
void sv_trim_right(StringView *);
void sv_trim(StringView *);
StringView sv_chop_by_delim(StringView *, char);
StringView sv_chop_by_type(StringView *, int (*)(int));
void sv_remove_comment(StringView *);
void sv_remove_doubleq(StringView *);

#endif // SV_H
