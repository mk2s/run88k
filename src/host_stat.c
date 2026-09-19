/* Portable host stat/fstat shim for run88k.
 *
 * Exposes a fixed-layout result struct so the Zig side does not depend on the
 * host's struct stat layout. The Zig dispatcher translates these fields into
 * the guest's (SysV/88) struct stat. */

#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

struct r88k_stat {
    unsigned long long size;
    unsigned int mode;   /* st_mode (host bits; S_IF* are portable) */
    unsigned int nlink;
    unsigned int uid;
    unsigned int gid;
    unsigned int dev;
    unsigned int rdev;
    unsigned int ino;
    long atime;
    long mtime;
    long ctime;
    int ok;              /* 1 on success, 0 on error (errno set) */
    int err;             /* errno on failure */
};

static void fill(struct r88k_stat *out, const struct stat *st) {
    out->size = (unsigned long long)st->st_size;
    out->mode = (unsigned int)st->st_mode;
    out->nlink = (unsigned int)st->st_nlink;
    out->uid = (unsigned int)st->st_uid;
    out->gid = (unsigned int)st->st_gid;
    out->dev = (unsigned int)st->st_dev;
    out->rdev = (unsigned int)st->st_rdev;
    out->ino = (unsigned int)st->st_ino;
    out->atime = (long)st->st_atime;
    out->mtime = (long)st->st_mtime;
    out->ctime = (long)st->st_ctime;
    out->ok = 1;
    out->err = 0;
}

void r88k_fstat(int fd, struct r88k_stat *out) {
    struct stat st;
    if (fstat(fd, &st) == 0) {
        fill(out, &st);
    } else {
        out->ok = 0;
        out->err = errno;
    }
}

void r88k_stat(const char *path, struct r88k_stat *out) {
    struct stat st;
    if (stat(path, &st) == 0) {
        fill(out, &st);
    } else {
        out->ok = 0;
        out->err = errno;
    }
}

/* Portable S_IF* accessors so the Zig side can classify without hardcoding
 * host bit values (they happen to be standard, but be explicit). */
unsigned int r88k_s_ifchr(void) { return S_IFCHR; }
unsigned int r88k_s_ifreg(void) { return S_IFREG; }
unsigned int r88k_s_ifdir(void) { return S_IFDIR; }
unsigned int r88k_s_ifmt(void)  { return S_IFMT; }
