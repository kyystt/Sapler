#include <errno.h>
#include <stdint.h>

#include "dynamic.h"
#include "isa.h"
#include "portio.h"
#include "sv.h"

#define FAILURE(line_num, line, ...)                                           \
    do {                                                                       \
        fprintf(stderr, "line %zu: ", line_num);                               \
        fprintf(stderr, __VA_ARGS__);                                          \
        fprintf(stderr, " -> " SV_FMT "\n", SV_ARGS(line));                    \
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

const Symbol *symbol_find(const SymbolTable *symtab, const StringView name)
{
    for (size_t i = 0; i < symtab->count; ++i) {
        if (sv_eq_ignore_case(symtab->items[i].name, name)) {
            return &symtab->items[i];
        }
    }

    return 0;
}

static inline void print_usage(void)
{
    fprintf(stderr, "usage: ./sapler [file]\n");
}

AddressingFlags check_instr_addr_mode(const StringView instruction,
                                      const StringView operand)
{
    if (sv_eq_cstr_ignore_case(instruction, "NOP") ||
        sv_eq_cstr_ignore_case(instruction, "HLT")) {
        if (operand.count != 0)
            return ERR_INVALID;

        return MODE_NO_OPERAND;
    }

    if (operand.count == 0)
        return ERR_NO_OPERAND;

    switch (operand.data[0]) {
    case '@':
        return MODE_IDIR;
        break;
    case '#':
        if (sv_eq_cstr_ignore_case(instruction, "LDS"))
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

    if (end == cstr || *end != '\0' || errno == ERANGE) {
        free(cstr);
        return ERRVAL;
    }

    free(cstr);
    return OK;
}

int is_valid(StringView symbol)
{
    if (symbol.count == 0 ||
        (!isalpha(symbol.data[0]) && symbol.data[0] != '_'))
        return 0;

    for (size_t i = 1; i < symbol.count; ++i) {
        char c = symbol.data[i];

        if (!isalnum(c) && c != '_')
            return 0;
    }

    return 1;
}

int has_label(StringView line)
{
    StringView first_keyword = sv_chop_by_type(&line, isspace);
    size_t keyword_count = first_keyword.count;

    if (sv_chop_by_delim(&first_keyword, ':').count == keyword_count)
        return 0;

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

        StringView symbol = {0};

        if (has_label(line)) {
            symbol = sv_chop_by_delim(&line, ':');

            printf("SYMBOL FOUND: " SV_FMT "\n", SV_ARGS(symbol));

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

        if (line.count == 0)
            continue;

        // read next token (mnemonic or directive)
        StringView tag = sv_next_token(&line);

        if (sv_eq_cstr_ignore_case(tag, "ORG")) {
            StringView imed = sv_chop_by_type(&line, isspace);

            if (imed.count == 0)
                FAILURE(line_num, raw_line, "Missing operand");

            sv_trim_left(&line);

            if (line.count != 0)
                FAILURE(line_num, raw_line, "Unknown field");

            long val;
            parse_err rc = parse_number(&imed, &val);
            if (rc == ERRVAL) {
                if (val < 0 || val > UINT16_MAX) {
                    FAILURE(line_num, raw_line, "value must be >= 0 and <= %d",
                            INT16_MAX);
                } else {
                    FAILURE(line_num, raw_line, "invalid value");
                }
            } else if (rc == ERRBASE) {
                FAILURE(line_num, raw_line, "invalid base");
            }

            LOCCTR = val;
            continue;
        }

        if (sv_eq_cstr_ignore_case(tag, "DS")) { // define storage
            StringView imed = sv_chop_by_type(&line, isspace);

            if (imed.count == 0)
                FAILURE(line_num, raw_line, "expected value");

            long val;
            parse_err rc = parse_number(&imed, &val);
            if (rc == ERRVAL) {
                if (val < 0 || val > UINT16_MAX) {
                    FAILURE(line_num, raw_line, "value must be >= 0 and <= %d",
                            INT16_MAX);
                } else {
                    FAILURE(line_num, raw_line, "invalid value");
                }
            } else if (rc == ERRBASE) {
                FAILURE(line_num, raw_line, "invalid base");
            }

            if (LOCCTR + val > UINT16_MAX + 1) {
                FAILURE(line_num, raw_line, "directive exceeds address space");
            }

            LOCCTR += val;
            continue;
        } else if (sv_eq_cstr_ignore_case(tag, "DB")) { // define byte
            size_t count = 1;
            StringView next = sv_chop_by_type(&line, isspace);

            if (next.count == 0)
                FAILURE(line_num, raw_line, "expected value, but got none");

            for (;;) {
                next = sv_chop_by_type(&line, isspace);
                if (next.count == 0)
                    break;

                sv_trim_left(&line);

                ++count;
            }

            if (LOCCTR + count > UINT16_MAX + 1) {
                FAILURE(line_num, raw_line, "directive exceeds address space");
            }

            LOCCTR += count;
            continue;
        } else if (sv_eq_cstr_ignore_case(tag, "DW")) { // define word
            size_t count = 1;
            StringView next = sv_chop_by_type(&line, isspace);

            if (next.count == 0)
                FAILURE(line_num, raw_line, "expected value, but got none");

            for (;;) {
                next = sv_chop_by_type(&line, isspace);

                if (next.count == 0)
                    break;

                sv_trim_left(&line);

                ++count;
            }

            if (LOCCTR + 2 * count > UINT16_MAX + 1) {
                FAILURE(line_num, raw_line, "directive exceeds address space");
            }

            LOCCTR += 2 * count;
            continue;
        } else if (sv_eq_cstr_ignore_case(tag, "STR")) { // define string
            StringView str = {0};
            int rc = sv_get_str_literal_doubleq(line, &str);

            if (rc != 1) {
                FAILURE(line_num, raw_line, "expected string literal");
            }

            sv_remove_doubleq(&str);

            printf("line: " SV_FMT "\n", SV_ARGS(line));
            printf("string found: " SV_FMT "\n", SV_ARGS(str));

            if (LOCCTR + str.count > UINT16_MAX + 1) {
                FAILURE(line_num, raw_line, "directive exceeds address space");
            }

            LOCCTR += str.count;
            continue;
        }

        size_t i;
        for (i = 0; i < SAPIENS_INSTRUCTION_COUNT; ++i) {
            const Instruction n = SAPIENS_INSTRUCTIONS[i];

            if (sv_eq_cstr_ignore_case(tag, n.mnemonic)) {
                printf("mnemonic found: %s\n", n.mnemonic);
                uint8_t is_valid;

                StringView operand = sv_chop_by_type(&line, isspace);
                AddressingFlags mode = check_instr_addr_mode(tag, operand);

                if (mode == ERR_NO_OPERAND)
                    FAILURE(line_num, raw_line, "expected operando found none");

                if (mode == ERR_INVALID)
                    FAILURE(line_num, raw_line, "invalid operand");

                printf("Operand: " SV_FMT "\n", SV_ARGS(operand));
                printf("mode found for %s: %s\n", n.mnemonic,
                       get_addr_mode_name(mode));

                // NOP and HLT has supported_modes == 0, we have to check that
                // case
                if (mode == MODE_NO_OPERAND) {
                    is_valid = n.supported_modes == 0;
                } else {
                    is_valid = (n.supported_modes & mode) != 0;
                }

                if (is_valid) {
                    size_t instr_size = get_instr_size(&n, mode);

                    if (LOCCTR + instr_size > UINT16_MAX + 1) {
                        FAILURE(line_num, raw_line,
                                "instruction exceeds address space");
                    }

                    LOCCTR += instr_size;
                } else {
                    FAILURE(line_num, raw_line, "Incorrect addressing mode");
                }
                break;
            }
        }

        if (i == SAPIENS_INSTRUCTION_COUNT) {
            FAILURE(line_num, raw_line, "Unknown instruction");
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
        StringView raw_line = sv_chop_by_delim(&file, '\n');
        StringView line = raw_line;
        sv_remove_comment(&line);
        sv_trim(&line);

        printf("processing line %zu: " SV_FMT "\n", line_num, SV_ARGS(line));
        if (line.count == 0)
            continue;

        if (has_label(line))
            (void)sv_chop_by_delim(&line, '"');

        sv_trim_left(&line);
        if (line.count == 0)
            continue; // label only line

        // read next token (mnemonic or directive)
        StringView tag = sv_chop_by_type(&line, isspace);
        StringView operand = sv_chop_by_type(&line, isspace);
        AddressingFlags mode = check_instr_addr_mode(tag, operand);

        if (mode == ERR_NO_OPERAND)
            FAILURE(line_num, raw_line, "expected operand found none");

        if (mode == ERR_INVALID)
            FAILURE(line_num, raw_line, "invalid operand");
    }

    free(file_buffer);
    free(SYMTAB.items);
    fclose(fp);
    return 0;
}
