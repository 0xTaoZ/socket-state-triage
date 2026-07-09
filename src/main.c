#include <stdio.h>
#include <string.h>

#define LINE_MAX_LEN 1024

int main(void) {
    char line[LINE_MAX_LEN];
    int listening = 0;

    while (fgets(line, sizeof(line), stdin) != NULL) {
        char netid[32];
        char state[32];

        if (sscanf(line, "%31s %31s", netid, state) != 2) {
            continue;
        }

        if (strcmp(state, "LISTEN") == 0) {
            listening++;
        }
    }

    printf("listening sockets: %d\n", listening);
    return 0;
}
