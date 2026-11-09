/* test_scale.c — dynamic ARM64, test realistic libc subset.
 * Each section prints + returns unique code on failure:
 *   10 = strlen wrong
 *   11 = malloc NULL
 *   12 = malloc buffer write broken
 */
extern int puts(const char *);
extern unsigned long strlen(const char *);
extern void *malloc(unsigned long);
extern void free(void *);

int main(void) {
    puts("t1: puts OK");

    unsigned long n = strlen("hello");
    if (n != 5) return 10;
    puts("t2: strlen OK");

    char *p = malloc(16);
    if (!p) return 11;
    p[0] = 'A'; p[1] = 'B'; p[2] = '\0';
    puts(p);
    free(p);
    puts("t3: malloc/free OK");

    return 0;
}
