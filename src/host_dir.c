/* Portable directory-stream shim for run88k.
 *
 * Modern hosts forbid read(2) on a directory fd, and the guest uses getdents,
 * so we back guest directory reads with opendir/readdir/closedir keyed by a
 * small integer handle. Supports one-entry pushback so getdents can stop at a
 * buffer boundary and re-emit the entry on the next call. */

#include <dirent.h>
#include <stddef.h>
#include <string.h>

#define MAX_DIRS 64

static DIR *g_dirs[MAX_DIRS];
/* Pushback: when set, the next r88k_dirread for this handle returns the saved
 * entry instead of advancing. */
static int g_pushback[MAX_DIRS];
static unsigned long g_pb_ino[MAX_DIRS];
static char g_pb_name[MAX_DIRS][256];

int r88k_diropen(const char *path) {
    for (int h = 0; h < MAX_DIRS; h++) {
        if (g_dirs[h] == NULL) {
            DIR *d = opendir(path);
            if (!d) return -1;
            g_dirs[h] = d;
            g_pushback[h] = 0;
            return h;
        }
    }
    return -1;
}

/* Returns 1 and fills ino_out/name_out on success, 0 at end of directory,
 * -1 on a bad handle. */
int r88k_dirread(int h, unsigned long *ino_out, char *name_out) {
    if (h < 0 || h >= MAX_DIRS || g_dirs[h] == NULL) return -1;
    if (g_pushback[h]) {
        g_pushback[h] = 0;
        *ino_out = g_pb_ino[h];
        strcpy(name_out, g_pb_name[h]);
        return 1;
    }
    struct dirent *e = readdir(g_dirs[h]);
    if (!e) return 0;
    *ino_out = (unsigned long)e->d_ino;
    strncpy(name_out, e->d_name, 255);
    name_out[255] = 0;
    /* Remember for possible pushback. */
    g_pb_ino[h] = *ino_out;
    strcpy(g_pb_name[h], name_out);
    return 1;
}

/* Re-emit the last-read entry on the next r88k_dirread. */
void r88k_dirpushback(int h) {
    if (h >= 0 && h < MAX_DIRS && g_dirs[h] != NULL) g_pushback[h] = 1;
}

void r88k_dirclose(int h) {
    if (h >= 0 && h < MAX_DIRS && g_dirs[h] != NULL) {
        closedir(g_dirs[h]);
        g_dirs[h] = NULL;
        g_pushback[h] = 0;
    }
}
