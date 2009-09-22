#include "picohttpparser/picohttpparser.c"
#include "xs_assert.h"

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
#include <sstream>

#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#ifdef __cplusplus
};
#endif

/*
 * TODO: request timeout
 * TODO: sendfile support
 * TODO: keep-alive support
 */

static struct flock lock_it, unlock_it;
static int lock_fd = -1;
static int nchildren;
#ifdef PREFORK
static pid_t *pids;
#endif
static SV* handler;

#define ASSERT_HTTP(x) do { \
            if (!x) { \
                http_error_500(connfd, minor_version, "assertion failed"); \
                return; \
            } \
        } while (0)

// 500KB is good enough
#define HTTP_BUFSIZ 500000

static void http_error_500(int fd, int minor_version, const char *internal_reason);
static void http_error_400(int fd, int minor_version, const char *internal_reason);

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


#ifdef DEBUG
#define debug(...) fprintf(stderr, __VA_ARGS__)
#else
#define debug(...)
#endif

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

std::string make_status_line(int minor_version, int status) {
    debug("making status line\r\n");
    char buf[1024];
    int size = snprintf(buf, 1024, "HTTP/1.%d %d %d\r\n", minor_version, status, status);
    return std::string(buf, size);
}

void send_status_line(int connfd, int minor_version, int status) {
    debug("sending status line\r\n");
    std::string buf = make_status_line(minor_version, status);
    send(connfd, buf.c_str(), buf.size(), 0);
}

static void send_body(int connfd, int minor_version, AV*res) {
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
        http_error_500(connfd, minor_version, "this server doesn't support ->getline thing");
        return;
    }
}

static void http_error(int fd, int minor_version, int status, const char *message) {
    std::stringstream buf;
    buf << make_status_line(minor_version, status);
    buf << "Content-Type: text/plain\r\n";
    buf << "Content-Length: ";
    buf << strlen(message);
    buf << "\r\n";
    buf << "\r\n";
    buf << message;
    send(fd, buf.str().c_str(), buf.str().size(), 0);
}

static void http_error_500(int fd, int minor_version, const char *internal_reason) {
    debug("%s\n", internal_reason);
    http_error(fd, minor_version, 500, "internal server error");
}

static void http_error_400(int fd, int minor_version, const char *internal_reason) {
    debug("400 bad request: %s\n", internal_reason);
    http_error(fd, minor_version, 400, "Bad Request");
}

static void send_response(int connfd, int minor_version, SV*res_ref) {
    if (!SvROK(res_ref) || SvTYPE(SvRV(res_ref))!=SVt_PVAV) {
        http_error_500(connfd, minor_version, "handler should return arrayref!");
        return;
    }

    AV* res = (AV*)SvRV(res_ref);

    SV ** status_ref = av_fetch(res, 0, 0);
    if (!status_ref) {
        http_error_500(connfd, minor_version, "cannot get status");
        return;
    }
    SV * status_sv = *status_ref;
    int status = SvIV(status_sv);
    std::string res_buf;
    res_buf.reserve(5000);
    res_buf += make_status_line(minor_version, status);

    SV ** v = av_fetch(res, 1, 0);
    if (!v) {
        http_error_500(connfd, minor_version, "cannot get header");
        return;
    }
    AV * headers = (AV*)SvRV(*v);
    debug("ready to send headers %d\n", av_len((AV*)headers));
    for (int i=0; i<av_len(headers)+1; i+=2) {
        STRLEN key_len;
        SV ** key_sv = av_fetch(headers, i, 0);
        ASSERT_HTTP(key_sv);
        char * key_c = SvPV(*key_sv, key_len);
        STRLEN val_len;
        SV ** val_sv = av_fetch(headers, i+1, 0);
        ASSERT_HTTP(val_sv);
        char * val_c = SvPV(*val_sv, val_len);

        res_buf.append(key_c, key_len);
        res_buf.append(":", 1);
        res_buf.append(val_c, val_len);
        res_buf.append("\r\n", 2);
    }
    res_buf.append("\r\n", 2);
    send(connfd, res_buf.c_str(), res_buf.size(), 0);

    send_body(connfd, minor_version, res);
}

void do_handle(int connfd)
{
    debug("DO HANDLE\n");
    char *buf;
    int bufsiz = 500 * 1000; // 500KB
    ssize_t read_cnt = 0;
    Newxz(buf, bufsiz, char);
    const char* method;
    size_t method_len;
    const char* path;
    size_t path_len;
    int minor_version;
    struct phr_header headers[10];
    size_t num_headers = 10;

    while (1) {
        debug("-- looping \n");
        ssize_t cur_read_cnt = read(connfd, buf+read_cnt, bufsiz);
        debug("cur_read_cnt is %d\n", cur_read_cnt);
        if (cur_read_cnt == 0) {
            debug("** eof ** %d, %d\n", bufsiz, bufsiz);
            free(buf);
            return;
        } else if (cur_read_cnt == -1) {
            perror("reading error");
            free(buf);
            return;
        }
        read_cnt += cur_read_cnt;
        int ret = phr_parse_request(buf, read_cnt, &method, &method_len, &path, &path_len, &minor_version, headers, &num_headers, 0);
        if (ret >= 0) {
            // got request
            HV * env = newHV();
#define SET(k, v, vlen) hv_store(env, k, sizeof(k)-1, newSVpv((v), (vlen)), 0);
            SET("REQUEST_METHOD", method, method_len);
            {
                std::string path_query(path, path_len);
                int pqq = path_query.find('?');
                std::string path_info = pqq >= 0 ? path_query.substr(0, pqq) : path_query;
                std::string query_string = pqq >= 0 ? path_query.substr(pqq+1, path_query.size()-(pqq+1)) : "";
                SET("PATH_INFO", path_info.c_str(), path_info.size());
                SET("QUERY_STRING", query_string.c_str(), query_string.size());
            }
            {
                char protocol[4];
                protocol[0]='1'; protocol[1] = '.'; protocol[2] = '0'+minor_version; protocol[3] = '\0';
                SET("SERVER_PROTOCOL", protocol, 3);
            }
#undef SET

            for (size_t i=0; i<num_headers; i++) {
                std::string name(headers[i].name, headers[i].name_len);
                to_cgi_name(name);
                hv_store(env, name.c_str(), name.size(), newSVpv(headers[i].value, headers[i].value_len), 0);
            }

            // set input file handle
            GV *gv = (GV*)SvREFCNT_inc(newGVgen("HTTP::Server::Fast"));
            if (gv) {
                PerlIO *input = PerlIO_fdopen(connfd, "r");
                hv_delete(GvSTASH(gv), GvNAME(gv), GvNAMELEN(gv), G_DISCARD);
                if (input && do_open(gv, "+<&", 3, FALSE, 0, 0, input)) {
                    if (ret != read_cnt) {
                        PerlIO_unread(input, buf+ret, bufsiz+ret);
                    }
                    (void) hv_store(env, "psgi.input", sizeof("psgi.input")-1, newRV((SV*)gv), 0);
                }
            }

            debug("READY TO CALLBACK\n");

            // see perlcall.pod
            dSP;

            ENTER;
            SAVETMPS;

            PUSHMARK(SP);
            XPUSHs(sv_2mortal(newRV_noinc((SV*)env)));
            PUTBACK;

            int count = call_sv(handler, G_SCALAR);

            SPAGAIN;

            if (count != 1) {
                http_error_500(connfd, minor_version, "handler should return single arrayref");
                free(buf);
                return;
            }

            SV * res_ref = POPs;
            debug("ready for send response\n");
            send_response(connfd, minor_version, res_ref);
            debug("finished to send response\n");

            FREETMPS;
            LEAVE;
            free(buf);
            return;
        } else if (ret == -2) {
            // partial request.
            if (cur_read_cnt != 0) {
                debug("realloc\n");
                bufsiz *= 2;
                Renew(buf, bufsiz, char);
            }
        } else if (ret == -1) {
            // failed.
            http_error_400(connfd, minor_version, "picohttpparser returns -1");
            debug("--- failed\n");
            debug(buf);
            debug("\n--- failed\n");
            free(buf);
            return;
        }
    }
    abort(); // should not reach here.
}

void
child_main(int listenfd)
{
    int connfd;
    socklen_t clilen;
    struct sockaddr_in cliaddr;

    printf("child %ld starting\n", (long)getpid());

#ifdef LIMIT_RUNNING
    for (int i=0; i < LIMIT_RUNNING; i++) {
#else
    for (;;) {
#endif
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

void
sig_int(int signo)
{
#ifdef PREFORK
    int i;
    for (i = 0; i < nchildren; i++) {
        debug("killing %d\n", i);
        if (kill(pids[i], SIGTERM) != 0) {
            perror("kill");
        }
    }
    debug("waiting\n");
    while (wait(NULL) > 0) {  }
    if (errno != ECHILD) {
        perror("wait error");
        exit(1);
    }
#endif
    debug("--FINISHED--\n");
    exit(0);
}

void ignore_sigpipe() {
    // Set signal handler to ignore SIGPIPE.
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
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

    int reuse = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

    struct sockaddr_in client;
    client.sin_family = AF_INET;
    client.sin_port = htons(port);
    client.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listenfd, (struct sockaddr*)&client, sizeof(client)) == -1) {
        Perl_croak(aTHX_ "bind: %s", strerror(errno));
        return;
    }

    if (listen(listenfd, 64) == -1) {
        Perl_croak(aTHX_ "listen: %s", strerror(errno));
        return;
    }

    my_lock_init("/tmp/lock.XXXXXXXXXXXXXX");

#ifdef PREFORK
    pids = (pid_t*)calloc(nchildren, sizeof(pid_t));

    int i;
    for (i = 0; i < nchildren; i++) {
        pids[i] = child_make(listenfd);
    }

    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);
    debug("access http://0.0.0.0:%d/\n", port);

    for (;;) {
        pause();
    }
#else
    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);
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

