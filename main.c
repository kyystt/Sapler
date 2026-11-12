#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "dynamic.h"

#define _ISA_IMPLEMENTATION
#include "include/isa.h"

#define FAILURE(line_num, line, str) \
    do { \
        fprintf(stderr, "line %zu: "str" -> %s\n", line_num, line); \
        exit(EXIT_FAILURE); \
    } while (0)

typedef struct {
    char *name;
    uint16_t addr;
} Label;

typedef struct {
    Label *arr;
    size_t count;
    size_t capacity;
} Labels;

#ifdef _WIN32
    #define strcasecmp _stricmp
#else
    #include <strings.h>
#endif

int array_contains_str(Labels *ls, const char *name) {
    for(size_t i = 0; i < ls->count; ++i) {
        if (!strcasecmp(ls->arr[i].name, name)) return 1;
    }
    return 0;
}

static inline void remove_comment(char *str)
{
    str[strcspn(str, ";")] = '\0';
}

static void trim_left(char **str)
{
    while(isspace(**str)) (*str)++;
}

static void trim_right(char **str)
{
    size_t len = strlen(*str);

    while (len > 0 && isspace((*str)[len - 1])) (*str)[--len] = '\0';
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

char* get_str_until(const char *str, int delim, size_t *out_size)
{
    const char *p = strchr(str, delim);

    if (!p) {
        *out_size = 0;
        return NULL;
    }

    *out_size = (size_t)(p - str);

    char *segment = malloc(*out_size + 1);

    if (!segment) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    strncpy(segment, str, *out_size);
    segment[*out_size] = '\0';

    return segment;
}

char* get_str_until_func(const char *str, int (*comp)(int), size_t *out_size)
{
    const char *p = str;

    while (*p && !comp(*p)) ++p;

    if (!p) {
        *out_size = 0;
        return NULL;
    }

    *out_size = (size_t)(p - str);

    char *segment = malloc(*out_size + 1);

    if (!segment) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    strncpy(segment, str, *out_size);
    segment[*out_size] = '\0';

    return segment;
}

#define get_next_field(str, out_size) get_str_until_func(str, isspace, out_size)

AddressingFlags check_instr_addr_mode(const char *cursor, const char *mnemonic)
{
    switch(*cursor) {
        case '\0':
            return 0;
            break;
        case '@':
            return MODE_IDIR;
            break;
        case '#':
            if(!strcmp(mnemonic, "LDS")) return MODE_IMM16;
            else return MODE_IMM;
            break;
        default:
            return MODE_DIR;
            break;
    }
}

static const char* get_addr_mode_name(AddressingFlags addr)
{
    switch(addr) {
        case MODE_IDIR: return "Indirect";
        case MODE_DIR: return "Direct";
        case MODE_IMM: return "Immediate";
        case MODE_IMM16: return "Immediate 16 bits";
        default: return "No operands";
    }
}

typedef enum {
    OK = 0,
    ERRBASE,
    ERRVAL
} parse_err;

parse_err parse_number(char *operand, size_t operand_size, long *val)
{
    char l = operand[operand_size-1];

    int base;
    if (isdigit(l)) {
        base = 10;
    } else {
        if(l == 'b') {
            base = 2;
        } else if (l == 'h') {
            base = 16;
        } else {
            return ERRBASE;
        }
        operand[operand_size-1] = '\0';
    }

    char *end;
    errno = 0;
    *val = strtol(operand, &end, base);

    if (end == operand || *end != '\0' || errno == ERANGE || *val < 0 || *val > UINT16_MAX)
        return ERRVAL;

    return OK;
}

int is_valid_label(const char *label)
{
    if (isdigit(*label)) return 0;

    for(; *label; ++label) {
        if(!isalnum(*label) && *label != '_') return 0;
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

    char line[100];

    // first pass -- goal: find labels
    Labels ls = {0};
    uint32_t LOCCNTR = 0;
    size_t line_num = 0;
    while(fgets(line, sizeof(line), fp)) {
        line_num++;
        printf("processing line %zu: %s", line_num, line);

        char *cursor = line;

        remove_comment(cursor);
        trim(cursor);
        if (*cursor == '\0') continue;

        size_t name_len;
        char *name = get_str_until(cursor, ':', &name_len);

        if (name != NULL) {
            if (name_len == 0) {
                free(name);
                FAILURE(line_num, line, "label must have a identifier");
            }

            if (LOCCNTR > UINT16_MAX) {
                free(name);
                FAILURE(line_num, line, "label exceeds address space");
            }

            if (array_contains_str(&ls, name)) {
                free(name);
                FAILURE(line_num, line, "duplicate label");
            }

            if (!is_valid_label(name)) {
                free(name);
                FAILURE(line_num, line, "invalid label name");
            }

            Label label = {.name = name, .addr = LOCCNTR};
            da_append(ls, label);

            cursor += name_len + 1;
            trim_left(&cursor);
        }
        if (*cursor == '\0') continue;

        // read next token (mnemonic or directive)
        size_t tag_size;
        char *tag = get_str_until_func(cursor, isspace, &tag_size);
        cursor += tag_size;
        trim_left(&cursor);

        AddressingFlags mode = check_instr_addr_mode(cursor, tag);

        printf("tag: %s | cursor: %s | mode: %s\n", tag, cursor, get_addr_mode_name(mode));

        if (!strcmp(tag, "ORG")) {
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

            switch(parse_number(operand, operand_size, &val)) {
                case ERRVAL:
                    FAILURE(line_num, line, "invalid value");
                case ERRBASE:
                    FAILURE(line_num, line, "invalid base");
                case OK:
                default:
                    break;
            }

            LOCCNTR = val;
            free(operand);
            free(tag);
            continue;
        }

        size_t i;
        for(i = 0; i < SAPIENS_INSTRUCTION_COUNT; ++i) {
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

                    if (LOCCNTR + instr_size > UINT16_MAX + 1) {
                        FAILURE(line_num, line, "instruction exceeds address space");
                    }

                    LOCCNTR += instr_size;
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

    for (size_t i = 0; i < ls.count; ++i)
        printf("%s @ %d\n", ls.arr[i].name, ls.arr[i].addr);

    for (size_t i = 0; i < ls.count; ++i)
        free(ls.arr[i].name);

    free(ls.arr);
    fclose(fp);
    return 0;
}
