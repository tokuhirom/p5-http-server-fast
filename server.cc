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
#ifdef PREFORK
static pid_t *pids;
#endif
static SV* handler;

#define ASSERT_HTTP(x) do { \
            if (!x) { \
                http_error_500(connfd, protocol, "assertion failed"); \
                return; \
            } \
        } while (0)

// 500KB is good enough
#define BUFSIZ 500000

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
    char prev_char = -1;
    char ch;
    while (read(fd, &ch, 1) == 1) {
        line += ch;
        if ((ch == '\n') || line.size() == max_len) {
            break;
        }
        prev_char = ch;
    }
    return line;
}

void to_cgi_name(std::string &src) {
    for (unsigned int i=0; i<src.size(); i++) {
        if (islower(src[i])) {
            src[i] = toupper(src[i]);
        } else if (src[i] == '-') {
            src[i] = '_';
        }
    }
    if (src != "CONTENT_TYPE" && src != "CONTENT_LENGTH") {
        src = "HTTP_" + src;
    }
}

void send_status_line(int connfd, const char *protocol, int status) {
    debug("sending status line\r\n");
    char buf[1024];
    int size = snprintf(buf, 1024, "HTTP/%s %d %d\r\n", protocol, status, status);
    send(connfd, buf, size, 0);
}

static void http_error(int fd, const char *protocol, int status, const char *message) {
    send_status_line(fd, protocol, status);
    // TODO: send message body
}

static void http_error_500(int fd, const char * protocol, const char *internal_reason) {
    debug("%s\n", internal_reason);
    http_error(fd, protocol, 500, "internal server error");
}

static void send_body(int connfd, const char *protocol, AV*res) {
    // sending body
    SV ** body_ref = av_fetch(res, 2, 0);
    ASSERT_HTTP(body_ref);
    ASSERT_HTTP(SvROK(*body_ref));
    SV* body = SvRV(*body_ref);
    if (SvTYPE(body) == SVt_PVAV) {
        debug("ready to send body %d\n", av_len((AV*)body));
        for (int i=0; i<av_len((AV*)body)+1; ++i) {
            debug("sending body %d\n", i);
            STRLEN elem_len;
            SV ** elem_sv = av_fetch((AV*)body, i, 0);
            ASSERT_HTTP(elem_sv);
            const char * elem_c = SvPV(*elem_sv, elem_len);
            send(connfd, elem_c, elem_len, 0);
        }
    } else {
        http_error_500(connfd, protocol, "this server doesn't support ->getline thing");
        return;
    }
}

static void send_response(int connfd, const char *protocol, SV*res_ref) {
    if (!SvROK(res_ref) || SvTYPE(SvRV(res_ref))!=SVt_PVAV) {
        http_error_500(connfd, protocol, "handler should return arrayref");
        return;
    }

    AV* res = (AV*)SvRV(res_ref);

    SV ** status_ref = av_fetch(res, 0, 0);
    if (!status_ref) {
        http_error_500(connfd, protocol, "cannot get status");
        return;
    }
    SV * status_sv = *status_ref;
    int status = SvIV(status_sv);
    send_status_line(connfd, protocol, status);

    SV ** v = av_fetch(res, 1, 0);
    if (!v) {
        http_error_500(connfd, protocol, "cannot get header");
        return;
    }
    AV * headers = (AV*)SvRV(*v);
    debug("ready to send headers %d\n", av_len((AV*)headers));
    SV* val;
    for (int i=0; i<av_len(headers)+1; i+=2) {
        STRLEN key_len;
        SV ** key_sv = av_fetch(headers, i, 0);
        ASSERT_HTTP(key_sv);
        char * key_c = SvPV(*key_sv, key_len);
        STRLEN val_len;
        SV ** val_sv = av_fetch(headers, i+1, 0);
        ASSERT_HTTP(val_sv);
        char * val_c = SvPV(*val_sv, val_len);

        char * buf;
        Newx(buf, key_len + val_len + 4, char);
        strcpy(buf, key_c);
        strcpy(buf+key_len, ":");
        strcpy(buf+key_len+1, val_c);
        strcpy(buf+key_len+1+val_len, "\r\n");
        debug("sending header '%s'\n", buf);
        send(connfd, buf, key_len+1+val_len+2, 0);
        Safefree(buf);
    }
    send(connfd, "\r\n", 2, 0);

    send_body(connfd, protocol, res);
}

void do_handle(int connfd)
{
    debug("DO HANDLE\n");

    // parse GET / HTTP/1.0
    std::string status_line = read_line(connfd, 1024);
    if (status_line[status_line.size()-1] != '\n') {
        http_error(connfd, "1.0", 400, "bad request");
        debug("invalid request");
        return;
    }
    debug("status line: %s\n", status_line.c_str());
    int first = status_line.find(' ');
    std::string method = status_line.substr(0, first);
    int second = status_line.find(' ', first+1);
    debug("num: %d, %d\n", first, second);
    std::string path_query = status_line.substr(first+1, second-first-1);
    std::string protocol = status_line.substr(second+6, 3);
    debug("method: %s\n", method.c_str());
    debug("path_query: %s\n", path_query.c_str());
    debug("protocol: %s\n", protocol.c_str());
    int pqq = path_query.find('?');
    std::string path_info = pqq >= 0 ? path_query.substr(0, pqq) : path_query;
    std::string query_string = pqq >= 0 ? path_query.substr(pqq+1, path_query.size()-(pqq+1)) : "";

    HV * env = newHV();
#define SET(k, v) hv_store(env, k, strlen(k), newSVpv((v).c_str(), (v).size()), 0);
    SET("REQUEST_METHOD", method);
    SET("PATH_INFO", path_info);
    SET("QUERY_STRING", query_string);
    SET("SERVER_PROTOCOL", protocol);
#undef SET

    // parse headers
    for (;;) {
        std::string line = read_line(connfd, 1024);
        if (line == "\r\n") {
            debug("REACH TO END");
            break;
        }
        int pos = line.find(':');
        std::string key = line.substr(0, pos);
        std::string val = line.substr(pos+1, line.size()-(pos+1));
        while (val[0] == ' ') {
            val = val.substr(1, val.size()-1);
        }
        while (val[val.size()-1] == '\r' || val[val.size()-1]=='\n' || val[val.size()-1]==' ') {
            val = val.substr(0, val.size()-1);
        }
        to_cgi_name(key);
        debug("headers: '%s' '%s'\n", key.c_str(), val.c_str());
        hv_store(env, key.c_str(), key.size(), newSVpv(val.c_str(), val.size()), 0);
    }

    // set input file handle
    {
        PerlIO *input = PerlIO_fdopen(connfd, "r");
        GV *gv = newGVgen("HTTP::Server::Fast::_sock"); // so bad, we don't need to use glob
        if (input && do_open(gv, "+<&", 3, FALSE, 0, 0, input)) {
            SV * input_sv = sv_2mortal(newSViv(0));
            sv_setsv(input_sv, sv_bless(newRV((SV*)gv), gv_stashpv("HTTP::Server::Fast::_sock",1)));
            (void) hv_store(env, "psgi.input", strlen("psgi.input"), input_sv, 0);
        }
    }

    debug("READY TO CALLBACK\n");

    // see perlcall.pod
    dSP;

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv_2mortal(newRV_inc((SV*)env)));
    PUTBACK;

    int count = call_sv(handler, G_SCALAR);

    SPAGAIN;


    if (count != 1) {
        http_error_500(connfd, protocol.c_str(), "handler should return single arrayref");
        return;
    }

    SV * res_ref = POPs;
    debug("ready for send response\n");
    send_response(connfd, protocol.c_str(), res_ref);
    debug("finished to send response\n");

    FREETMPS;
    LEAVE;
}

void
child_main(int listenfd)
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
child_make(int listenfd)
{
    pid_t pid;
    if ( (pid = fork()) > 0 ) {
        return pid;//Parent
    }
    child_main(listenfd);
    return -1;
}

#ifdef PREFORK
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
#endif

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

    my_lock_init("/tmp/lock.XXXXXXXXXXXXXX");

#ifdef PREFORK
    pids = (pid_t*)calloc(nchildren, sizeof(pid_t));

    int i;
    for (i = 0; i < nchildren; i++) {
        pids[i] = child_make(listenfd);
    }

    signal(SIGINT, sig_int);
    debug("access http://0.0.0.0:%d/\n", port);

    for (;;) {
        pause();
    }
#else
    child_main(listenfd);
#endif
}

#ifdef STANDALONE
int
main()
{
    run(8000, 10, NULL);
    return 0;
}
#endif

