#include "../include/portio.h"

char *read_entire_file(const char *path, size_t *out_size)
{
    FILE *fp = fopen(path, "rb");

    if (!fp) {
        perror("fopen");
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    if (portable_fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    file_offset_t size = portable_ftell(fp);
    if (size < 0 || (uint64_t)size > SIZE_MAX - 1) {
        perror("ftell");
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    if (portable_fseek(fp, 0, SEEK_SET) != 0) {
        perror("fseek");
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    char *buffer = (char *)malloc(size + 1);

    if (!buffer) {
        perror("malloc");
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    size_t bytes_read = fread(buffer, 1, size, fp);
    if (bytes_read != (size_t)size) {
        perror("fread");
        free(buffer);
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    fclose(fp);

    buffer[size] = '\0';

    if (out_size)
        *out_size = size;

    return buffer;
}
