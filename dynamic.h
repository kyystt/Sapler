#ifndef H_DYNAMIC
#define H_DYNAMIC

#define da_append(xs, x) \
    do { \
        if(xs.count >= xs.capacity) { \
            if (xs.capacity == 0) xs.capacity = 256; else xs.capacity *= 2; \
            xs.arr = realloc(xs.arr, sizeof(*xs.arr) * xs.capacity); \
        } \
        xs.arr[xs.count++] = x; \
    } while (0)

#endif // H_DYNAMIC
