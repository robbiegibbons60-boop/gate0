#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "src/gate0.h"
#include "shadow.h"

#define SOCKET_PATH "/data/data/com.termux/files/home/gate0/gate0.sock"
#define TCP_PORT 4200
#define MAX_EVENTS 64
#define CMD_BUF_LEN 512
#define EVICT_INTERVAL_NS 2000000000ULL

static int unix_fd = -1;
static int tcp_fd = -1;
static int epoll_fd = -1;

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}static int init_unix_socket(void) {
    unlink(SOCKET_PATH);
    unix_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (unix_fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path)-1);
    if (bind(unix_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        return -1;
    if (listen(unix_fd, 8) < 0) return -1;
    return 0;
}

static int init_tcp_socket(void) {
    tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd < 0) return -1;
    int opt = 1;
    setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(TCP_PORT);
    if (bind(tcp_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        return -1;
    if (listen(tcp_fd, 8) < 0) return -1;
    return 0;
}static void handle_tcp_client(void) {
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    int cfd = accept(tcp_fd, (struct sockaddr*)&peer, &plen);
    if (cfd < 0) return;
    uint8_t buf[CMD_BUF_LEN];
    ssize_t n = recv(cfd, buf, sizeof(buf), 0);
    if (n < (ssize_t)sizeof(SignedCommand)) {
        ShadowEntry *se = shadow_lookup(&peer);
        if (!se) se = shadow_register(&peer, ATTACK_MALFORMED);
        else se->attempt_count++;
        if (se) shadow_feed_decoy(se);
        send(cfd, se ? se->shadow_envelope : buf,
             sizeof(((ShadowEntry*)0)->shadow_envelope), 0);
        close(cfd);
        return;
    }
    SignedCommand *cmd = (SignedCommand*)buf;
    GateOResult rc = evaluate_command(cmd, NULL, NULL, now_ns());
    if (rc == GO_SEQUENCE_INVALID) {
        ShadowEntry *se = shadow_lookup(&peer);
        if (!se) se = shadow_register(&peer, ATTACK_REPLAY);
        else se->attempt_count++;
        if (se) shadow_feed_decoy(se);
        send(cfd, se->shadow_envelope,
             sizeof(se->shadow_envelope), 0);
        close(cfd);
        return;
    }
    if (rc == GO_SIGNATURE_INVALID) {
        ShadowEntry *se = shadow_lookup(&peer);
        if (!se) se = shadow_register(&peer, ATTACK_SIG_FLOOD);
        else se->attempt_count++;
        if (se) shadow_feed_decoy(se);
        send(cfd, se->shadow_envelope,
             sizeof(se->shadow_envelope), 0);
        close(cfd);
        return;
    }
    uint8_t ok = (uint8_t)GO_OK;
    send(cfd, &ok, 1, 0);
    close(cfd);
}int main(void) {
    shadow_init();
    if (init_unix_socket() < 0) {
        perror("[-] UNIX socket init failed");
        return 1;
    }
    if (init_tcp_socket() < 0) {
        perror("[-] TCP socket init failed");
        return 1;
    }
    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("[-] epoll_create1 failed");
        return 1;
    }
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = unix_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, unix_fd, &ev);
    ev.data.fd = tcp_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tcp_fd, &ev);
    printf("[+] GATE0 DAEMON: UNIX=%s TCP=%d\n",
           SOCKET_PATH, TCP_PORT);
    struct epoll_event events[MAX_EVENTS];
    uint64_t last_evict = now_ns();
    while (1) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 2000);
        uint64_t t = now_ns();
        if (t - last_evict >= EVICT_INTERVAL_NS) {
            shadow_evict_expired(t);
            last_evict = t;
        }
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == tcp_fd)
                handle_tcp_client();
            else if (events[i].data.fd == unix_fd) {
                int cfd = accept(unix_fd, NULL, NULL);
                if (cfd >= 0) close(cfd);
            }
        }
    }
    close(unix_fd);
    close(tcp_fd);
    close(epoll_fd);
    unlink(SOCKET_PATH);
    return 0;
}
