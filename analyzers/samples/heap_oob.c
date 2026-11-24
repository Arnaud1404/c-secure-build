/* Smoke sample for analyzers/test.sh: one heap write past the end, line 12. */
#include <stdlib.h>

int main(void)
{
    int *a = malloc(4 * sizeof *a);

    if (a == NULL) {
        return 1;
    }
    for (int i = 0; i <= 4; i++) {
        a[i] = i;
    }
    int last = a[3];
    free(a);
    return last;
}
