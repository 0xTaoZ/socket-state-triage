#include <stdio.h>
#include <string.h>

#define LINE_MAX_LEN 1024

static int analyze_stream(FILE *input) {
    char line[LINE_MAX_LEN];
    int listening = 0;
    int broad_ipv4 = 0;
    int broad_ipv6 = 0;
    int tcp = 0;
    int udp = 0;

    while (fgets(line, sizeof(line), input) != NULL) {
        char netid[32];
        char state[32];
        char recvq[32];
        char sendq[32];
        char local[128];

        if (sscanf(line, "%31s %31s %31s %31s %127s", netid, state, recvq, sendq, local) != 5) {
            continue;
        }

        if (strcmp(netid, "tcp") == 0) {
            tcp++;
        } else if (strcmp(netid, "udp") == 0) {
            udp++;
        }

        if (strcmp(state, "LISTEN") == 0) {
            listening++;
            if (strncmp(local, "0.0.0.0:", 8) == 0) {
                broad_ipv4++;
                printf("review: %s listener on %s\n", netid, local);
            }
            if (strncmp(local, "[::]:", 5) == 0) {
                broad_ipv6++;
                printf("review: %s listener on %s\n", netid, local);
            }
        }
    }

    printf("listening sockets: %d\n", listening);
    printf("tcp sockets: %d\n", tcp);
    printf("udp sockets: %d\n", udp);
    printf("broad IPv4 binds: %d\n", broad_ipv4);
    printf("broad IPv6 binds: %d\n", broad_ipv6);
    return 0;
}

int main(int argc, char **argv) {
    FILE *input = stdin;

    if (argc > 2) {
        fprintf(stderr, "usage: socket-state-triage [ss-output-file]\n");
        return 2;
    }

    if (argc == 2) {
        input = fopen(argv[1], "r");
        if (input == NULL) {
            perror(argv[1]);
            return 1;
        }
    }

    int result = analyze_stream(input);

    if (input != stdin) {
        fclose(input);
    }

    return result;
}
