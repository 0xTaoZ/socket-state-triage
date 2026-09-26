#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_MAX_LEN 1024

struct analysis_options {
    int review_limit;
};

struct analysis_state {
    int review_lines;
};

static void print_review(const struct analysis_options *options, struct analysis_state *state, const char *message,
                         const char *netid, const char *address) {
    if (options->review_limit >= 0 && state->review_lines >= options->review_limit) {
        return;
    }
    printf("review: %s %s %s\n", netid, message, address);
    state->review_lines++;
}

static int is_broad_ipv4_bind(const char *local) {
    return strncmp(local, "0.0.0.0:", 8) == 0;
}

static int is_broad_ipv6_bind(const char *local) {
    return strncmp(local, "[::]:", 5) == 0;
}

static int is_loopback_bind(const char *local) {
    return strncmp(local, "127.", 4) == 0 || strncmp(local, "[::1]:", 6) == 0;
}

static int is_non_private_ipv4_peer(const char *peer) {
    int a;
    int b;
    int c;
    int d;
    int port;

    if (sscanf(peer, "%d.%d.%d.%d:%d", &a, &b, &c, &d, &port) != 5) {
        return 0;
    }
    if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255 || port < 0 ||
        port > 65535) {
        return 0;
    }
    if (a == 10 || a == 127 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) ||
        (a == 169 && b == 254)) {
        return 0;
    }

    return 1;
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

static int analyze_stream(FILE *input, const struct analysis_options *options) {
    char line[LINE_MAX_LEN];
    struct analysis_state review_state = {0};
    int listening = 0;
    int established = 0;
    int broad_ipv4 = 0;
    int broad_ipv6 = 0;
    int loopback_only = 0;
    int privileged_broad = 0;
    int remote_established = 0;
    int non_private_peers = 0;
    int tcp = 0;
    int udp = 0;

    while (fgets(line, sizeof(line), input) != NULL) {
        char netid[32];
        char state[32];
        char recvq[32];
        char sendq[32];
        char local[128];
        char peer[128];
        int fields;

        peer[0] = '\0';
        fields = sscanf(line, "%31s %31s %31s %31s %127s %127s", netid, state, recvq, sendq, local, peer);
        if (fields < 5) {
            continue;
        }

        if (strcmp(netid, "tcp") == 0) {
            tcp++;
        } else if (strcmp(netid, "udp") == 0) {
            udp++;
        }

        if (strcmp(state, "LISTEN") == 0) {
            listening++;
        } else if (strcmp(state, "ESTAB") == 0) {
            established++;
        }

        int is_broad = is_broad_ipv4_bind(local) || is_broad_ipv6_bind(local);
        int port = parse_local_port(local);

        if (is_broad_ipv4_bind(local)) {
            broad_ipv4++;
            print_review(options, &review_state, "broad bind on", netid, local);
        }
        if (is_broad_ipv6_bind(local)) {
            broad_ipv6++;
            print_review(options, &review_state, "broad bind on", netid, local);
        }
        if (is_loopback_bind(local)) {
            loopback_only++;
        }
        if (is_broad && port >= 0 && port < 1024) {
            privileged_broad++;
            print_review(options, &review_state, "privileged broad bind on", netid, local);
        }
        if (strcmp(netid, "tcp") == 0 && strcmp(state, "ESTAB") == 0 && !is_loopback_bind(local)) {
            remote_established++;
            print_review(options, &review_state, "remote established socket on", "tcp", local);
        }
        if (strcmp(netid, "tcp") == 0 && strcmp(state, "ESTAB") == 0 && is_non_private_ipv4_peer(peer)) {
            non_private_peers++;
            print_review(options, &review_state, "non-private peer on", "tcp", peer);
        }
    }

    printf("listening sockets: %d\n", listening);
    printf("established sockets: %d\n", established);
    printf("tcp sockets: %d\n", tcp);
    printf("udp sockets: %d\n", udp);
    printf("broad IPv4 binds: %d\n", broad_ipv4);
    printf("broad IPv6 binds: %d\n", broad_ipv6);
    printf("loopback-only binds: %d\n", loopback_only);
    printf("privileged broad binds: %d\n", privileged_broad);
    printf("remote established sockets: %d\n", remote_established);
    printf("non-private established peers: %d\n", non_private_peers);
    return 0;
}

int main(int argc, char **argv) {
    FILE *input = stdin;
    struct analysis_options options = {-1};
    const char *path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--limit") == 0) {
            char *end = NULL;
            long limit;

            if (i + 1 >= argc) {
                fprintf(stderr, "usage: socket-state-triage [--limit N | --summary-only] [ss-output-file]\n");
                return 2;
            }
            limit = strtol(argv[++i], &end, 10);
            if (end == argv[i] || *end != '\0' || limit < 0 || limit > 1000000) {
                fprintf(stderr, "error: --limit expects a non-negative number\n");
                return 2;
            }
            options.review_limit = (int)limit;
        } else if (strcmp(argv[i], "--summary-only") == 0) {
            options.review_limit = 0;
        } else if (path == NULL) {
            path = argv[i];
        } else {
            fprintf(stderr, "usage: socket-state-triage [--limit N | --summary-only] [ss-output-file]\n");
            return 2;
        }
    }

    if (path != NULL) {
        input = fopen(path, "r");
        if (input == NULL) {
            perror(path);
            return 1;
        }
    }

    int result = analyze_stream(input, &options);

    if (input != stdin) {
        fclose(input);
    }

    return result;
}
