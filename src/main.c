#include <stdio.h>
#include <string.h>

#define LINE_MAX_LEN 1024

int main(void) {
    char line[LINE_MAX_LEN];
    int listening = 0;
    int broad_ipv4 = 0;

    while (fgets(line, sizeof(line), stdin) != NULL) {
        char netid[32];
        char state[32];
        char recvq[32];
        char sendq[32];
        char local[128];

        if (sscanf(line, "%31s %31s %31s %31s %127s", netid, state, recvq, sendq, local) != 5) {
            continue;
        }

        if (strcmp(state, "LISTEN") == 0) {
            listening++;
            if (strncmp(local, "0.0.0.0:", 8) == 0) {
                broad_ipv4++;
            }
        }
    }

    printf("listening sockets: %d\n", listening);
    printf("broad IPv4 binds: %d\n", broad_ipv4);
    return 0;
}
