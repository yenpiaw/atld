#include <stdio.h>
#include <string.h>
int main(void) {
    char buf[128];
    snprintf(buf, sizeof(buf), "len=%zu", strlen("hello"));
    puts(buf);
    return 0;
}
