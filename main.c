#include <ctype.h>
#include <errno.h>

#include "include/dynamic.h"
#include "include/isa.h"
#include "include/portio.h"
#include "include/sv.h"

#define FAILURE(line_num, line, str)                                           \
    do {                                                                       \
        fprintf(stderr, "line %zu: " str " -> " SV_FMT "\n", line_num,         \
                SV_ARGS(line));                                                \
        exit(EXIT_FAILURE);                                                    \
    } while (0)

typedef struct {
    StringView name;
    uint16_t addr;
} Symbol;

typedef struct {
    Symbol *items;
    size_t count;
    size_t capacity;
} SymbolTable;

int symbol_contains(const SymbolTable *symtab, const StringView name)
{
    for (size_t i = 0; i < symtab->count; ++i) {
        if (sv_eq_ignore_case(symtab->items[i].name, name)) {
            return 1;
        }
    }

    return 0;
}

static inline void remove_doubleq(char *str)
{
    size_t len = strlen(str);
    if (len >= 2 && *str == '"' && str[len - 1] == '"') {
        memmove(str, str + 1, len - 2);
        str[len - 2] = '\0';
        return;
    }

    fprintf(stderr, "not a double quoted string");
    exit(EXIT_FAILURE);
}

static inline void remove_comment(char *str)
{
    str[strcspn(str, ";")] = '\0';
}

static void trim_left(char **str)
{
    while (isspace(**str))
        (*str)++;
}

static void trim_right(char **str)
{
    size_t len = strlen(*str);

    while (len > 0 && isspace((*str)[len - 1]))
        (*str)[--len] = '\0';
}

static void _trim(char **str)
{
    trim_left(str);
    trim_right(str);
}

#define trim(str) _trim(&str)

static inline void print_usage()
{
    fprintf(stderr, "usage: ./sapler [file]\n");
}

char *get_str_until(const char *str, int delim, size_t *out_size)
{
    const char *p = strchr(str, delim);

    if (!p) {
        if (out_size != NULL)
            *out_size = 0;
        return NULL;
    }

    size_t size = (size_t)(p - str);

    char *segment = malloc(size + 1);

    if (!segment) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    strncpy(segment, str, size);
    segment[size] = '\0';

    if (out_size != NULL)
        *out_size = size;

    return segment;
}

char *get_str_until_func(const char *str, int (*comp)(int), size_t *out_size)
{
    const char *p = str;

    while (*p && !comp(*p))
        ++p;

    if (!p) {
        if (out_size != NULL)
            *out_size = 0;
        return NULL;
    }

    size_t size = (size_t)(p - str);

    char *segment = malloc(size + 1);

    if (!segment) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    strncpy(segment, str, size);
    segment[size] = '\0';

    if (out_size != NULL)
        *out_size = size;

    return segment;
}

#define get_next_field(str, out_size) get_str_until_func(str, isspace, out_size)

AddressingFlags check_instr_addr_mode(const char *cursor, const char *mnemonic)
{
    switch (*cursor) {
    case '\0':
        return 0;
        break;
    case '@':
        return MODE_IDIR;
        break;
    case '#':
        if (!strcmp(mnemonic, "LDS"))
            return MODE_IMM16;
        else
            return MODE_IMM;
        break;
    default:
        return MODE_DIR;
        break;
    }
}

static const char *get_addr_mode_name(AddressingFlags addr)
{
    switch (addr) {
    case MODE_IDIR:
        return "Indirect";
    case MODE_DIR:
        return "Direct";
    case MODE_IMM:
        return "Immediate";
    case MODE_IMM16:
        return "Immediate 16 bits";
    default:
        return "No operands";
    }
}

typedef enum { OK = 0, ERRBASE, ERRVAL } parse_err;

parse_err parse_number(char *operand, size_t operand_size, long *val)
{
    char l = operand[operand_size - 1];

    int base;
    if (isdigit(l)) {
        base = 10;
    } else {
        if (l == 'b') {
            base = 2;
        } else if (l == 'h') {
            base = 16;
        } else {
            return ERRBASE;
        }
        operand[operand_size - 1] = '\0';
    }

    char *end;
    errno = 0;
    *val = strtol(operand, &end, base);

    if (end == operand || *end != '\0' || errno == ERANGE || *val < 0 ||
        *val > UINT16_MAX)
        return ERRVAL;

    return OK;
}

int is_valid(StringView symbol)
{
    if (isdigit(symbol.data[0]))
        return 0;

    for (size_t i = 1; i < symbol.count; ++i) {
        char c = symbol.data[i];

        if (!isalnum(c) && c != '_')
            return 0;
    }

    return 1;
}

int main(int argc, char **argv)
{

    if (argc != 2) {
        print_usage();
        exit(1);
    }

    // extract target file
    const char *path = argv[1];

    FILE *fp = fopen(path, "r");

    if (!fp) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    size_t file_size;
    char *file_buffer = read_entire_file(path, &file_size);

    StringView file = sv(file_buffer);

    // first pass -- goal: find labels
    SymbolTable SYMTAB = {0};
    uint32_t LOCCTR = 0;
    size_t line_num = 0;
    while (file.count > 0) {
        line_num++;
        StringView line = sv_chop_by_delim(&file, '\n');
        sv_remove_comment(&line);
        sv_trim_left(&line);

        printf("processing line %zu: " SV_FMT, line_num, SV_ARGS(line));
        if (line.count == 0)
            continue;

        StringView symbol = sv_chop_by_delim(&line, ';');

        if (symbol.count == 0) {
            FAILURE(line_num, line, "label must have a identifier");
        }

        if (LOCCTR > UINT16_MAX) {
            FAILURE(line_num, line, "label exceeds address space");
        }

        if (symbol_contains(&SYMTAB, symbol)) {
            FAILURE(line_num, line, "duplicate label");
        }

        if (is_valid(symbol)) {
            FAILURE(line_num, line, "invalid label name");
        }

        Symbol label = {.name = symbol, .addr = LOCCTR};
        da_append(SYMTAB, label);

        sv_trim_left(&line);
        if (line.count == 0)
            continue;

        // read next token (mnemonic or directive)
        StringView tag = sv_chop_by_type(&line, isspace);
        sv_trim_left(&line);

        AddressingFlags mode = check_instr_addr_mode(cursor, tag);

        if (sv_eq_cstr_ignore_case(tag, "ORG")) {
            size_t operand_size;
            char *operand = get_next_field(cursor, &operand_size);

            if (operand == NULL || operand_size == 0) {
                FAILURE(line_num, line, "Missing operand");
            }
            cursor += operand_size;

            if (*cursor != '\0') {
                FAILURE(line_num, line, "Unknown field");
            }

            long val;

            switch (parse_number(operand, operand_size, &val)) {
            case ERRVAL:
                FAILURE(line_num, line, "invalid value");
            case ERRBASE:
                FAILURE(line_num, line, "invalid base");
            case OK:
            default:
                break;
            }

            LOCCTR = val;
            free(operand);
            free(tag);
            continue;
        }

        if (!strcasecmp(tag, "DS")) { // define storage
            size_t imed_size;
            char *imed = get_next_field(cursor, &imed_size);

            if (imed == NULL || imed_size == 0)
                FAILURE(line_num, line, "expected value");

            long imed_val;
            switch (parse_number(imed, imed_size, &imed_val)) {
            case ERRVAL:
                FAILURE(line_num, line, "invalid value");
            case ERRBASE:
                FAILURE(line_num, line, "invalid base");
            case OK:
            default:
                break;
            }

            if (LOCCTR + imed_val > UINT16_MAX + 1) {
                FAILURE(line_num, line, "directive exceeds address space");
            }

            LOCCTR += imed_val;
            continue;
        } else if (!strcasecmp(tag, "DB")) { // define byte
            size_t count = 0;
            char *next = NULL;
            size_t next_size;

            for (;;) {
                next = get_next_field(cursor, &next_size);
                if (next == NULL || next_size == 0)
                    FAILURE(line_num, line, "expected value, but got none");

                if (!next || next_size == 0)
                    break;
                cursor += next_size;
                trim_left(&cursor);

                free(next);
                ++count;
            }

            if (LOCCTR + count > UINT16_MAX + 1) {
                FAILURE(line_num, line, "directive exceeds address space");
            }

            LOCCTR += count;
            continue;
        } else if (!strcasecmp(tag, "DW")) { // define word
            size_t count = 0;
            char *next = NULL;
            size_t next_size;

            for (;;) {
                next = get_next_field(cursor, &next_size);
                printf("next: %p\n", next);

                if (!next || next_size == 0)
                    break;
                cursor += next_size;
                trim_left(&cursor);

                free(next);
                ++count;
            }

            if (LOCCTR + 2 * count > UINT16_MAX + 1) {
                FAILURE(line_num, line, "directive exceeds address space");
            }

            LOCCTR += 2 * count;
            continue;
        } else if (!strcasecmp(tag, "STR")) { // define string
            size_t str_len;
            char *str = get_next_field(cursor, &str_len);
            remove_doubleq(str);
            str_len = strlen(str);

            printf("string defined: %s | len: %zu\n", str, str_len);

            free(str);

            if (LOCCTR + str_len > UINT16_MAX + 1) {
                FAILURE(line_num, line, "directive exceeds address space");
            }

            LOCCTR += str_len;
            continue;
        }

        size_t i;
        for (i = 0; i < SAPIENS_INSTRUCTION_COUNT; ++i) {
            const Instruction n = SAPIENS_INSTRUCTIONS[i];

            if (!strcmp(tag, n.mnemonic)) {
                uint8_t is_valid;

                // NOP has supported_modes == 0, we have to check that case
                if (mode == 0) {
                    is_valid = n.supported_modes == 0;
                } else {
                    is_valid = (n.supported_modes & mode) != 0;
                }
                if (is_valid) {
                    size_t instr_size = get_instr_size(&n, mode);

                    if (LOCCTR + instr_size > UINT16_MAX + 1) {
                        FAILURE(line_num, line,
                                "instruction exceeds address space");
                    }

                    LOCCTR += instr_size;
                } else {
                    FAILURE(line_num, line, "Incorrect addressing mode");
                }
                break;
            }
        }

        if (i == SAPIENS_INSTRUCTION_COUNT) {
            FAILURE(line_num, line, "Unknown instruction");
        }

        memset(line, 0, sizeof(line));
        free(tag);
    }

    for (size_t i = 0; i < SYMTAB.count; ++i)
        printf("%s @ %d\n", SYMTAB.arr[i].name, SYMTAB.arr[i].addr);

    // pass 2
    puts("starting pass 2 phase");
    rewind(fp);
    LOCCTR = 0;
    line_num = 0;
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        printf("processing line %zu: %s", line_num, line);

        char *cursor = line;
        remove_comment(cursor);
        trim(cursor);
        if (*cursor == '\0')
            continue;

        char *cl = strchr(cursor, ':');

        if (cl != NULL) {
            cursor = cl + 1;
            trim_left(&cursor);
        }

        if (*cursor == '\0')
            continue; // label only line

        // read next token (mnemonic or directive)
        size_t tag_size;
        char *tag = get_str_until_func(cursor, isspace, &tag_size);
        cursor += tag_size;
        trim_left(&cursor);

        AddressingFlags mode = check_instr_addr_mode(cursor, tag);

        printf("instruction: %s \n", tag);
    }

    for (size_t i = 0; i < SYMTAB.count; ++i)
        free(SYMTAB.arr[i].name);

    free(SYMTAB.arr);
    fclose(fp);
    return 0;
}
