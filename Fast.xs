#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"
#ifdef __cplusplus
void run(int port, int nchild, SV*cb);
};
#endif

MODULE = HTTP::Server::Fast PACKAGE = HTTP::Server::Fast

PROTOTYPES: DISABLED

void run(int port, int nchild, SV*cb);

