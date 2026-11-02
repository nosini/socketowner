/* Native UDP loopback send/receive iterations; no Wine identity or relay lookup hit.
 * Build: cc -O2 -Wall -Wextra native-cost.c -o native-cost
 * Run: taskset -c CPU ./native-cost 4|6 PAYLOAD_BYTES ROUND_TRIPS
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static void check(int result, const char *what)
{
    if (result < 0) { perror(what); exit(1); }
}

int main(int argc, char **argv)
{
    if (argc != 4) return 2;
    int family = atoi(argv[1]) == 6 ? AF_INET6 : AF_INET;
    int bytes = atoi(argv[2]), count = atoi(argv[3]);
    if (bytes < 1 || bytes > 65507 || count < 1) return 2;
    char *buffer = calloc(1, bytes);
    if (!buffer) return 1;
    int server = socket(family, SOCK_DGRAM, 0);
    int client = socket(family, SOCK_DGRAM, 0);
    check(server, "server"); check(client, "client");
    struct sockaddr_storage address = {0};
    socklen_t size;
    if (family == AF_INET6) {
        struct sockaddr_in6 *a = (void *)&address;
        a->sin6_family = family; a->sin6_addr = in6addr_loopback;
        size = sizeof(*a);
    } else {
        struct sockaddr_in *a = (void *)&address;
        a->sin_family = family; a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        size = sizeof(*a);
    }
    check(bind(server, (void *)&address, size), "bind");
    check(getsockname(server, (void *)&address, &size), "getsockname");
    check(connect(client, (void *)&address, size), "connect");
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < count; i++) {
        check(send(client, buffer, bytes, 0), "send");
        check(recv(server, buffer, bytes, 0), "recv");
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double ns = (end.tv_sec-start.tv_sec)*1e9 + end.tv_nsec-start.tv_nsec;
    printf("%.2f\n", ns/count);
    close(client); close(server); free(buffer);
}
