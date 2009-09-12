#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#ifdef __cplusplus
};
#endif

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string>

static struct flock lock_it, unlock_it;
static int lock_fd = -1;
static int nchildren;
static pid_t *pids;
static SV* handler;

extern "C" {
void run(int port, int _nchildren, SV *_handler);
}

// Sudden death error handling for system calls.
#define SYS_ASSERT(expression)  {                                       \
        if ((expression) < 0) {                                             \
            debug("%s: %s", #expression, strerror(errno));                      \
            abort();                                                          \
        }                                                                   \
    }



#define croak(x) perror((x))
#define debug(...) fprintf(stderr, __VA_ARGS__)

void
my_lock_init(const char *pathname)
{
    char lock_file[1024];

    strncpy(lock_file, pathname, sizeof(lock_file));
    mkstemp(lock_file);

    lock_fd = open(lock_file, O_CREAT | O_WRONLY);
    unlink(lock_file);

    lock_it.l_type = F_WRLCK;
    lock_it.l_whence = SEEK_SET;
    lock_it.l_start = 0;
    lock_it.l_len = 0;

    unlock_it.l_type = F_UNLCK;
    unlock_it.l_whence = SEEK_SET;
    unlock_it.l_start = 0;
    unlock_it.l_len = 0;
}

void
my_lock_wait()
{
    int rc;
    while ( (rc = fcntl(lock_fd, F_SETLKW, &lock_it)) < 0 ) {
        if (errno == EINTR) {
            continue;
        } else {
            croak("fcntl error for my_lock_wait");
            exit(1);
        }
    }
}

void
my_lock_release()
{
    if (fcntl(lock_fd, F_SETLKW, &unlock_it) < 0) {
        perror("fcntl error for my_lock_release");
        exit(1);
    }
}

std::string read_line(int fd, size_t max_len) {
    std::string line;
    int prev_char = -1;
    int ch;
    while (read(fd, &ch, 1) == 1) {
        line += ch;
        if ((ch == '\n') || line.size() == max_len) {
            debug("HOT\n");
            break;
        }
        prev_char = ch;
    }
    return line;
}


void do_handle(int connfd)
{
    debug("DO HANDLE\n");

    // parse GET / HTTP/1.0
    std::string status_line = read_line(connfd, 1024);
    int first = status_line.find(' ');
    std::string method = status_line.substr(0, first);
    int second = status_line.find(' ', first+1);
    std::string path = status_line.substr(first, second-first);
    std::string protocol = status_line.substr(second+6, 3);
    debug("num: %d, %d\n", first, second);
    debug("method: %s\n", method.c_str());
    debug("path: %s\n", path.c_str());
    debug("protocol: %s\n", protocol.c_str());

    HV * env = newHV();

    // parse headers
    for (;;) {
        std::string line = read_line(connfd, 1024);
        int pos = line.find(':');
        std::string key = line.substr(0, pos);
        std::string val = line.substr(pos+1, line.size()-(pos+1));
        while (val[0] == ' ') {
            val = val.substr(1, val.size()-1);
        }
        while (val[val.size()-1] == '\r' || val[val.size()-1]=='\n' || val[val.size()-1]==' ') {
            val = val.substr(0, val.size()-1);
        }
        debug("headers: '%s' '%s'\n", key.c_str(), val.c_str());
    }
    send(connfd, "OK\n", 3, 0);
}

void
child_main(int i, int listenfd)
{
    int connfd;
    socklen_t clilen;
    struct sockaddr_in cliaddr;
    
    printf("child %ld starting\n", (long)getpid());
    
    for (;;) {
        clilen = sizeof(cliaddr);
        my_lock_wait();
            connfd = accept(listenfd, (struct sockaddr*)&cliaddr, &clilen);
        my_lock_release();
    
        debug("accept : pid = %ld, ip = %s, port = %d\n",
            (long)getpid(),
            inet_ntoa(cliaddr.sin_addr),
            ntohs(cliaddr.sin_port));

        do_handle(connfd);

        debug("done : pid = %ld, ip = %s, port = %d\n",
            (long)getpid(),
            inet_ntoa(cliaddr.sin_addr),
            ntohs(cliaddr.sin_port));

        close(connfd);
    }
}

pid_t
child_make(int i, int listenfd)
{
    pid_t pid;
    if ( (pid = fork()) > 0 ) {
        return pid;//Parent
    }
    child_main(i, listenfd);
}

void
sig_int(int signo)
{
    int i;
    for (i = 0; i < nchildren; i++) {
        debug("killing %d\n", i);
        kill(pids[i], SIGTERM);
    }
    while (wait(NULL) > 0) { 1; }
    if (errno != ECHILD) {
        perror("wait error");
        exit(1);
    }
    exit(0);
}

void ignore_sigpipe() {
    // Set signal handler to ignore SIGPIPE.
    struct sigaction sa = {};  // Zero-clear.
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    SYS_ASSERT(sigaction(SIGPIPE, &sa, NULL));
}

// nchildren meanse 'the numbers of children'
void run(int port, int _nchildren, SV *_handler) {
    nchildren = _nchildren;
    handler = _handler;

    ignore_sigpipe();

    int listenfd = socket(AF_INET, SOCK_STREAM, 0);

    int reuse;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

    struct sockaddr_in client;
    client.sin_family = AF_INET;
    client.sin_port = htons(port);
    client.sin_addr.s_addr = htonl(INADDR_ANY);

    bind(listenfd, (struct sockaddr*)&client, sizeof(client));

    listen(listenfd, 64);

    pids = (pid_t*)calloc(nchildren, sizeof(pid_t));
    my_lock_init("/tmp/lock.XXXXXXXXXXXXXX");

    int i;
    for (i = 0; i < nchildren; i++) {
        pids[i] = child_make(i, listenfd);
    }

    signal(SIGINT, sig_int);

    debug("access http://0.0.0.0:%d/\n", port);

    for (;;) {
        pause();
    }
}

#ifdef STANDALONE
int
main()
{
    run(8000, 10, NULL);
    return 0;
}
#endif

