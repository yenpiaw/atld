#include <unistd.h>
int main(void) {
    write(1, "hello glibc\n", 12);
    return 0;
}
