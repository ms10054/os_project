/*
 * ============================================================================
 *  portscan.c  -  A simple TCP port scanner (OS course project)
 * ============================================================================
 *  Purpose:
 *    Scan a target device on our Wi-Fi lab and classify each port as
 *    OPEN, CLOSED, or FILTERED -- the same three states nmap reports.
 *    This reproduces, in our own C code, the key finding of our project:
 *      - Windows  -> all FILTERED  (firewall silently drops probes)
 *      - Android  -> all CLOSED    (host actively refuses, no services)
 *      - a device running a service -> that port shows OPEN (attack surface)
 *
 *  How it tells them apart (this is the clever bit):
 *    - open     : connect() succeeds                      -> service listening
 *    - closed   : connect() is refused (ECONNREFUSED)     -> RST sent back
 *    - filtered : connect() gets NO reply before timeout  -> firewall drop
 *
 *  Concepts used (all standard OS / systems programming):
 *    sockets, non-blocking connect(), select() for timeouts, getsockopt().
 *
 *  ETHICAL USE: run ONLY against your own devices on your own lab network.
 *
 *  Build:  gcc -o portscan portscan.c
 *  Run:    ./portscan 192.168.18.103            (scans a default port list)
 *          ./portscan 192.168.18.103 1 1024     (scans a port range)
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define TIMEOUT_SEC 1          /* how long to wait for a reply, in seconds */

/*
 * scan_port: try to connect to one TCP port and decide its state.
 * Returns a string: "open", "closed", or "filtered".
 */
const char *scan_port(const char *ip, int port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);   /* make a TCP socket */
    if (sock < 0)
        return "error";

    /* Put the socket in NON-BLOCKING mode so connect() returns immediately
       instead of hanging. We then time the attempt ourselves with select(),
       which is what lets us tell "no reply" (filtered) from "refused"
       (closed). */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    /* Fill in the target address (IP + port). */
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(port);                /* host->network byte order */
    inet_pton(AF_INET, ip, &target.sin_addr);     /* text IP -> binary */

    const char *state;
    int res = connect(sock, (struct sockaddr *)&target, sizeof(target));

    if (res == 0) {
        /* Connected instantly (rare on a network) -> port is open. */
        state = "open";
    } else if (errno == EINPROGRESS) {
        /* Normal case for non-blocking: the connection is being attempted.
           Wait up to TIMEOUT_SEC for the socket to become writable. */
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(sock, &wset);
        struct timeval tv;
        tv.tv_sec = TIMEOUT_SEC;
        tv.tv_usec = 0;

        int sel = select(sock + 1, NULL, &wset, NULL, &tv);
        if (sel == 0) {
            /* select() timed out: nothing ever came back.
               => a firewall is silently dropping our probe = FILTERED. */
            state = "filtered";
        } else {
            /* The attempt finished. Ask the socket whether it succeeded
               or errored, using SO_ERROR. */
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error == 0)
                state = "open";                   /* handshake completed */
            else if (so_error == ECONNREFUSED)
                state = "closed";                 /* host sent a RST */
            else
                state = "filtered";               /* other error */
        }
    } else if (errno == ECONNREFUSED) {
        state = "closed";
    } else {
        state = "filtered";
    }

    close(sock);
    return state;
}

int main(int argc, char *argv[])
{
    /* A default list of "interesting" ports if the user gives no range.
       These cover the services that matter for our OS comparison:
       22=SSH, 80=HTTP, 135/139/445=Windows SMB/RPC/NetBIOS,
       443=HTTPS, 3389=RDP, 5900=VNC/Screen-Sharing. */
    int default_ports[] = {21, 22, 23, 25, 53, 80, 110, 135, 139,
                           143, 443, 445, 993, 3389, 5900, 8080};
    int n_default = sizeof(default_ports) / sizeof(default_ports[0]);

    if (argc < 2) {
        printf("Usage: %s <target-ip> [start-port end-port]\n", argv[0]);
        printf("  e.g. %s 192.168.18.103\n", argv[0]);
        printf("       %s 192.168.18.103 1 1024\n", argv[0]);
        return 1;
    }

    const char *ip = argv[1];
    int open_count = 0, closed_count = 0, filtered_count = 0;

    printf("\nScanning %s ...\n", ip);
    printf("%-8s %s\n", "PORT", "STATE");
    printf("-------------------\n");

    if (argc == 4) {
        /* Range mode: scan every port from start to end. */
        int start = atoi(argv[2]);
        int end = atoi(argv[3]);
        for (int p = start; p <= end; p++) {
            const char *st = scan_port(ip, p);
            /* Only print open/closed to avoid thousands of "filtered" lines;
               still count everything for the summary. */
            if (strcmp(st, "open") == 0)        open_count++;
            else if (strcmp(st, "closed") == 0) closed_count++;
            else                                filtered_count++;
            if (strcmp(st, "filtered") != 0)
                printf("%-8d %s\n", p, st);
        }
    } else {
        /* Default mode: scan the common-ports list and print each one. */
        for (int i = 0; i < n_default; i++) {
            int p = default_ports[i];
            const char *st = scan_port(ip, p);
            printf("%-8d %s\n", p, st);
            if (strcmp(st, "open") == 0)        open_count++;
            else if (strcmp(st, "closed") == 0) closed_count++;
            else                                filtered_count++;
        }
    }

    /* Summary + interpretation (matches how we read the nmap output). */
    printf("-------------------\n");
    printf("Summary: %d open, %d closed, %d filtered\n",
           open_count, closed_count, filtered_count);

    if (open_count > 0) {
        printf("=> This host EXPOSES attack surface (open service ports).\n");
    } else if (filtered_count > 0 && closed_count == 0) {
        printf("=> All FILTERED: a firewall is silently dropping probes "
               "(stealth, e.g. Windows Public profile).\n");
    } else if (closed_count > 0 && filtered_count == 0) {
        printf("=> All CLOSED: host actively refuses (RST). No listening "
               "services, no silent-drop firewall (e.g. Android).\n");
    } else {
        printf("=> Mixed result: see per-port states above.\n");
    }

    return 0;
}