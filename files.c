#include <unistd.h>
#include <stdio.h>

int main() {

    while (1) {
        FILE *file = fopen("demo.txt", "w");
        if (file == NULL) {
            perror("fopen");
            return 1;
        }
        fprintf(file, "Hello World!\n");

        fclose(file);
    }

    return 0;
}