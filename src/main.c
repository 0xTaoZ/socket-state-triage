#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_MAX_LEN 1024

static int is_broad_ipv4_bind(const char *local) {
    return strncmp(local, "0.0.0.0:", 8) == 0;
}

static int is_broad_ipv6_bind(const char *local) {
    return strncmp(local, "[::]:", 5) == 0;
}

static int parse_local_port(const char *local) {
    const char *separator = strrchr(local, ':');
    char *end = NULL;
    long port;

    if (separator == NULL || separator[1] == '\0') {
        return -1;
    }

    port = strtol(separator + 1, &end, 10);
    if (end == separator + 1 || *end != '\0' || port < 0 || port > 65535) {
        return -1;
    }

    return (int)port;
}

static int analyze_stream(FILE *input) {
    char line[LINE_MAX_LEN];
    int listening = 0;
    int broad_ipv4 = 0;
    int broad_ipv6 = 0;
    int privileged_broad = 0;
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
        }

        int is_broad = is_broad_ipv4_bind(local) || is_broad_ipv6_bind(local);
        int port = parse_local_port(local);

        if (is_broad_ipv4_bind(local)) {
            broad_ipv4++;
            printf("review: %s broad bind on %s\n", netid, local);
        }
        if (is_broad_ipv6_bind(local)) {
            broad_ipv6++;
            printf("review: %s broad bind on %s\n", netid, local);
        }
        if (is_broad && port >= 0 && port < 1024) {
            privileged_broad++;
            printf("review: %s privileged broad bind on %s\n", netid, local);
        }
    }

    printf("listening sockets: %d\n", listening);
    printf("tcp sockets: %d\n", tcp);
    printf("udp sockets: %d\n", udp);
    printf("broad IPv4 binds: %d\n", broad_ipv4);
    printf("broad IPv6 binds: %d\n", broad_ipv6);
    printf("privileged broad binds: %d\n", privileged_broad);
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
