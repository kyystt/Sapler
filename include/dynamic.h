#ifndef H_DYNAMIC
#define H_DYNAMIC

#define da_append(xs, x) \
    do { \
        if((xs).count >= (xs).capacity) { \
            (xs).capacity = (xs).capacity == 0 ? 64 : (xs).capacity * 2; \
            (xs).items = realloc((xs).items, sizeof(*(xs).items) * (xs).capacity); \
        } \
        (xs).items[(xs).count++] = (x); \
    } while (0)

#define da_find(xs, x, out_addr) \
    do { \
        *(out_addr) = -1; \
        for (size_t i = 0; i < xs.count; ++i) { \
            if (sv_eq((xs).items[i].name, (x).name)) { \
                *(out_addr) = (xs).items[i].addr; \
                break; \
            } \
        } \
    } while(0)

#endif // H_DYNAMIC
