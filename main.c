#include <ctype.h>
#include <errno.h>

#include "dynamic.h"
#include "isa.h"
#include "portio.h"
#include "sv.h"

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

static inline void print_usage()
{
    fprintf(stderr, "usage: ./sapler [file]\n");
}

AddressingFlags check_instr_addr_mode(const StringView mnemonic)
{
    switch (mnemonic.data[0]) {
    case '\0':
        return 0;
        break;
    case '@':
        return MODE_IDIR;
        break;
    case '#':
        if (sv_eq_cstr_ignore_case(mnemonic, "LDS"))
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

parse_err parse_number(StringView *operand, long *val)
{
    char l = operand->data[operand->count - 1];

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
        sv_chop_right(operand, 1);
    }

    char *cstr = sv_to_cstr(operand);

    char *end;
    errno = 0;
    *val = strtol(cstr, &end, base);

    if (end == cstr || *end != '\0' || errno == ERANGE || *val < 0 ||
        *val > UINT16_MAX) {
        free(cstr);
        return ERRVAL;
    }

    free(cstr);
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
        StringView raw_line = sv_chop_by_delim(&file, '\n');
        StringView line = raw_line;

        sv_remove_comment(&line);
        sv_trim(&line);

        printf("processing line %zu: " SV_FMT "\n", line_num, SV_ARGS(line));
        if (line.count == 0)
            continue;

        size_t line_count = line.count;
        StringView symbol = sv_chop_by_delim(&line, ':');

        if (symbol.count == line_count) { // theres no label
            line = symbol;
        } else {
            if (symbol.count == 0) {
                FAILURE(line_num, raw_line, "label must have a identifier");
            }

            if (LOCCTR > UINT16_MAX) {
                FAILURE(line_num, raw_line, "label exceeds address space");
            }

            if (symbol_contains(&SYMTAB, symbol)) {
                FAILURE(line_num, raw_line, "duplicate label");
            }

            if (!is_valid(symbol)) {
                FAILURE(line_num, raw_line, "invalid label name");
            }

            Symbol label = {.name = symbol, .addr = LOCCTR};
            da_append(SYMTAB, label);
        }

        sv_trim_left(&line);
        if (line.count == 0)
            continue;

        // read next token (mnemonic or directive)
        StringView tag = sv_chop_by_type(&line, isspace);

        AddressingFlags mode = check_instr_addr_mode(tag);

        if (sv_eq_cstr_ignore_case(tag, "ORG")) {
            StringView operand = sv_chop_by_type(&line, isspace);

            if (operand.count == 0)
                FAILURE(line_num, line, "Missing operand");

            sv_trim_left(&line);

            if (line.count != 0)
                FAILURE(line_num, line, "Unknown field");

            long val;
            switch (parse_number(&operand, &val)) {
            case ERRVAL:
                FAILURE(line_num, line, "invalid value");
            case ERRBASE:
                FAILURE(line_num, line, "invalid base");
            case OK:
            default:
                break;
            }

            LOCCTR = val;
            continue;
        }

        if (sv_eq_cstr_ignore_case(tag, "DS")) { // define storage
            StringView imed = sv_chop_by_type(&line, isspace);

            if (imed.count == 0)
                FAILURE(line_num, line, "expected value");

            long imed_val;
            switch (parse_number(&imed, &imed_val)) {
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
        } else if (sv_eq_cstr_ignore_case(tag, "DB")) { // define byte
            size_t count = 1;
            StringView next = sv_chop_by_type(&line, isspace);

            if (next.count == 0)
                FAILURE(line_num, line, "expected value, but got none");

            for (;;) {
                next = sv_chop_by_type(&line, isspace);
                if (next.count == 0)
                    break;

                sv_trim_left(&line);

                ++count;
            }

            if (LOCCTR + count > UINT16_MAX + 1) {
                FAILURE(line_num, line, "directive exceeds address space");
            }

            LOCCTR += count;
            continue;
        } else if (sv_eq_cstr_ignore_case(tag, "DW")) { // define word
            size_t count = 1;
            StringView next = sv_chop_by_type(&line, isspace);

            if (next.count == 0)
                FAILURE(line_num, line, "expected value, but got none");

            for (;;) {
                next = sv_chop_by_type(&line, isspace);

                if (next.count == 0)
                    break;

                sv_trim_left(&line);

                ++count;
            }

            if (LOCCTR + 2 * count > UINT16_MAX + 1) {
                FAILURE(line_num, line, "directive exceeds address space");
            }

            LOCCTR += 2 * count;
            continue;
        } else if (sv_eq_cstr_ignore_case(tag, "STR")) { // define string
            StringView str = sv_chop_by_type(&line, isspace);
            sv_remove_doubleq(&str);

            printf("removed double quoted string: " SV_FMT "\n", SV_ARGS(str));

            if (LOCCTR + str.count > UINT16_MAX + 1) {
                FAILURE(line_num, line, "directive exceeds address space");
            }

            LOCCTR += str.count;
            continue;
        }

        size_t i;
        for (i = 0; i < SAPIENS_INSTRUCTION_COUNT; ++i) {
            const Instruction n = SAPIENS_INSTRUCTIONS[i];

            if (!sv_eq_cstr_ignore_case(tag, n.mnemonic)) {
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
    }

    for (size_t i = 0; i < SYMTAB.count; ++i)
        printf(SV_FMT " @ %d\n", SV_ARGS(SYMTAB.items[i].name),
               SYMTAB.items[i].addr);

    // pass 2
    puts("starting pass 2 phase");

    file = sv(file_buffer);
    LOCCTR = 0;
    line_num = 0;
    while (file.count > 0) {
        line_num++;
        StringView line = sv_chop_by_delim(&file, '\n');
        sv_remove_comment(&line);
        sv_trim(&line);

        printf("processing line %zu: " SV_FMT "\n", line_num, SV_ARGS(line));
        if (line.count == 0)
            continue;

        StringView symbol = sv_chop_by_delim(&line, ':');

        if (line.count == 0)
            continue; // label only line

        // read next token (mnemonic or directive)
        StringView tag = sv_chop_by_type(&line, isspace);

        AddressingFlags mode = check_instr_addr_mode(tag);
    }

    free(file_buffer);
    free(SYMTAB.items);
    fclose(fp);
    return 0;
}
