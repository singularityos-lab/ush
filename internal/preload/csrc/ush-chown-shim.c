#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>

static int is_ro_error(int e) {
    // EPERM/EACCES/EROFS are typical FS errors.
    // EINVAL is returned by chown() when the target UID/GID is not mapped in the namespace.
    // ENOENT must remain visible: faking success for missing files corrupts dpkg's
    // unpack/restore flow (for example when replacing /usr/bin/perl).
    return e == EPERM || e == EACCES || e == EROFS || e == EINVAL;
}

static int is_write_flags(int flags) {
    return (flags & O_CREAT) || (flags & O_TRUNC) || (flags & O_APPEND) ||
           ((flags & O_ACCMODE) == O_WRONLY) || ((flags & O_ACCMODE) == O_RDWR);
}

static char *redirect_path(const char *path) {
    // Path redirection is disabled: dpkg installs with --instdir=/ so writes go
    // through the /usr fuse-overlayfs, which also covers execve. This shim now
    // does identity (uid/gid) remapping only.
    (void)path;
    return NULL;
}

static void ensure_parent_dirs(const char *path) {
    if (!path) return;

    char tmp[PATH_MAX];
    size_t len = strlen(path);
    if (len >= sizeof(tmp)) return;
    memcpy(tmp, path, len + 1);

    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        syscall(SYS_mkdir, tmp, 0755);
        *p = '/';
    }
}

static uid_t get_host_uid() {
    const char *mode = getenv("USH_PRELOAD_IDENTITY");
    if (!mode || strcmp(mode, "host") != 0) return 0;

    static uid_t host_uid = -1;
    if (host_uid == (uid_t)-1) {
        const char *s = getenv("USH_HOST_UID");
        if (s) host_uid = atoi(s);
        else host_uid = 0;
    }
    return host_uid;
}

static gid_t get_host_gid() {
    const char *mode = getenv("USH_PRELOAD_IDENTITY");
    if (!mode || strcmp(mode, "host") != 0) return 0;

    static gid_t host_gid = -1;
    if (host_gid == (gid_t)-1) {
        const char *s = getenv("USH_HOST_GID");
        if (s) host_gid = atoi(s);
        else host_gid = 0;
    }
    return host_gid;
}

/*
 * Identity shims - only active when USH_PRELOAD_IDENTITY=host, where they make
 * the process believe it's running as the host user instead of root (UID 0)
 * inside the single-UID secure namespace, so Electron/Chromium use their
 * namespace sandbox instead of the failing setuid one. Otherwise these pass
 * through to the REAL id: the secure guest is genuinely UID 0, and the dev
 * (dsh) guest is genuinely the user's real UID, and lying there would break
 * tools like distrobox that key off the reported id.
 */

static int identity_host(void) {
    const char *mode = getenv("USH_PRELOAD_IDENTITY");
    return mode && strcmp(mode, "host") == 0;
}

/*
 * Fake-root gate. When USH_FAKE_ROOT=1, the id getters report uid/gid 0.
 * ush sets this ONLY in the env of the dpkg/apt invocation (runApt), so it
 * reaches dpkg and its maintainer-script children but never the interactive
 * guest or dsh, which keep their real keep-id identity. Maintainer helpers
 * (addgroup/adduser/useradd, the shadow tools) gate on a NUMERIC geteuid()==0
 * check; the guest already holds the namespace capabilities (they come from
 * owning the userns, not from the id number), so clearing the numeric check
 * grants no privilege the guest lacks -- it only stops the check from rejecting
 * an install that is otherwise permitted. Kept independent of identity_host
 * (that gate fakes the HOST uid for Electron sandboxing; opposite direction).
 */
static int fake_root(void) {
    const char *m = getenv("USH_FAKE_ROOT");
    return m && strcmp(m, "1") == 0;
}

uid_t getuid(void) {
    if (fake_root()) return 0;
    return identity_host() ? get_host_uid() : (uid_t)syscall(SYS_getuid);
}

uid_t geteuid(void) {
    if (fake_root()) return 0;
    return identity_host() ? get_host_uid() : (uid_t)syscall(SYS_geteuid);
}

gid_t getgid(void) {
    if (fake_root()) return 0;
    return identity_host() ? get_host_gid() : (gid_t)syscall(SYS_getgid);
}

gid_t getegid(void) {
    if (fake_root()) return 0;
    return identity_host() ? get_host_gid() : (gid_t)syscall(SYS_getegid);
}

int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid) {
    if (fake_root()) {
        if (ruid) *ruid = 0;
        if (euid) *euid = 0;
        if (suid) *suid = 0;
        return 0;
    }
    if (!identity_host()) return syscall(SYS_getresuid, ruid, euid, suid);
    uid_t h = get_host_uid();
    if (ruid) *ruid = h;
    if (euid) *euid = h;
    if (suid) *suid = h;
    return 0;
}

int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid) {
    if (fake_root()) {
        if (rgid) *rgid = 0;
        if (egid) *egid = 0;
        if (sgid) *sgid = 0;
        return 0;
    }
    if (!identity_host()) return syscall(SYS_getresgid, rgid, egid, sgid);
    gid_t h = get_host_gid();
    if (rgid) *rgid = h;
    if (egid) *egid = h;
    if (sgid) *sgid = h;
    return 0;
}

/*
 * stat family: keep the faked identity consistent. When USH_PRELOAD_IDENTITY
 * is "host", getuid()/geteuid() report the host UID, but every file in the
 * single-UID guest namespace is really owned by UID 0. Apps that verify a path
 * is owned by their own UID (tmpdir/config security checks, which Node and Bun
 * do and otherwise refuse to start) would see owner 0 != euid. We
 * rewrite the reported owner of UID-0 files to the host UID so that getuid()
 * equals st_uid again. When IDENTITY is not "host" (pkg/dpkg mode)
 * get_host_uid() returns 0 and these wrappers are pure pass-through, so apt and
 * dpkg still observe the real on-disk owners.
 */

static void remap_owner(uid_t *uid, gid_t *gid) {
    uid_t h = get_host_uid();
    gid_t hg = get_host_gid();
    if (h != 0 && uid && *uid == 0) *uid = h;
    if (hg != 0 && gid && *gid == 0) *gid = hg;
}

static void remap_stat(struct stat *st) {
    if (st) remap_owner(&st->st_uid, &st->st_gid);
}

int stat(const char *path, struct stat *buf) {
    int (*real)(const char *, struct stat *) = dlsym(RTLD_NEXT, "stat");
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(path, buf);
    if (r == 0) remap_stat(buf);
    return r;
}

int lstat(const char *path, struct stat *buf) {
    int (*real)(const char *, struct stat *) = dlsym(RTLD_NEXT, "lstat");
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(path, buf);
    if (r == 0) remap_stat(buf);
    return r;
}

int fstat(int fd, struct stat *buf) {
    int (*real)(int, struct stat *) = dlsym(RTLD_NEXT, "fstat");
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(fd, buf);
    if (r == 0) remap_stat(buf);
    return r;
}

int fstatat(int dirfd, const char *path, struct stat *buf, int flags) {
    int (*real)(int, const char *, struct stat *, int) = dlsym(RTLD_NEXT, "fstatat");
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(dirfd, path, buf, flags);
    if (r == 0) remap_stat(buf);
    return r;
}

#ifdef STATX_TYPE
int statx(int dirfd, const char *path, int flags, unsigned int mask, struct statx *buf) {
    int (*real)(int, const char *, int, unsigned int, struct statx *) = dlsym(RTLD_NEXT, "statx");
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(dirfd, path, flags, mask, buf);
    if (r == 0 && buf) {
        uid_t u = buf->stx_uid; gid_t g = buf->stx_gid;
        remap_owner(&u, &g);
        buf->stx_uid = u; buf->stx_gid = g;
    }
    return r;
}
#endif

#ifdef __GLIBC__
/*
 * glibc large-file and legacy versioned stat entry points. Apps built with
 * _FILE_OFFSET_BITS=64 (and anything compiled against glibc < 2.33) reach the
 * kernel through these symbols rather than the bare names above, so they need
 * the same remap to stay consistent.
 */
int stat64(const char *path, struct stat64 *buf) {
    int (*real)(const char *, struct stat64 *) = dlsym(RTLD_NEXT, "stat64");
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(path, buf);
    if (r == 0 && buf) remap_owner(&buf->st_uid, &buf->st_gid);
    return r;
}
int lstat64(const char *path, struct stat64 *buf) {
    int (*real)(const char *, struct stat64 *) = dlsym(RTLD_NEXT, "lstat64");
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(path, buf);
    if (r == 0 && buf) remap_owner(&buf->st_uid, &buf->st_gid);
    return r;
}
int fstat64(int fd, struct stat64 *buf) {
    int (*real)(int, struct stat64 *) = dlsym(RTLD_NEXT, "fstat64");
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(fd, buf);
    if (r == 0 && buf) remap_owner(&buf->st_uid, &buf->st_gid);
    return r;
}
int fstatat64(int dirfd, const char *path, struct stat64 *buf, int flags) {
    int (*real)(int, const char *, struct stat64 *, int) = dlsym(RTLD_NEXT, "fstatat64");
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(dirfd, path, buf, flags);
    if (r == 0 && buf) remap_owner(&buf->st_uid, &buf->st_gid);
    return r;
}

int __xstat(int ver, const char *path, struct stat *buf) {
    int (*real)(int, const char *, struct stat *) = dlsym(RTLD_NEXT, "__xstat");
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(ver, path, buf);
    if (r == 0) remap_stat(buf);
    return r;
}
int __lxstat(int ver, const char *path, struct stat *buf) {
    int (*real)(int, const char *, struct stat *) = dlsym(RTLD_NEXT, "__lxstat");
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(ver, path, buf);
    if (r == 0) remap_stat(buf);
    return r;
}
int __fxstat(int ver, int fd, struct stat *buf) {
    int (*real)(int, int, struct stat *) = dlsym(RTLD_NEXT, "__fxstat");
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(ver, fd, buf);
    if (r == 0) remap_stat(buf);
    return r;
}
int __fxstatat(int ver, int dirfd, const char *path, struct stat *buf, int flags) {
    int (*real)(int, int, const char *, struct stat *, int) = dlsym(RTLD_NEXT, "__fxstatat");
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(ver, dirfd, path, buf, flags);
    if (r == 0) remap_stat(buf);
    return r;
}
int __xstat64(int ver, const char *path, struct stat64 *buf) {
    int (*real)(int, const char *, struct stat64 *) = dlsym(RTLD_NEXT, "__xstat64");
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(ver, path, buf);
    if (r == 0 && buf) remap_owner(&buf->st_uid, &buf->st_gid);
    return r;
}
int __lxstat64(int ver, const char *path, struct stat64 *buf) {
    int (*real)(int, const char *, struct stat64 *) = dlsym(RTLD_NEXT, "__lxstat64");
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(ver, path, buf);
    if (r == 0 && buf) remap_owner(&buf->st_uid, &buf->st_gid);
    return r;
}
int __fxstat64(int ver, int fd, struct stat64 *buf) {
    int (*real)(int, int, struct stat64 *) = dlsym(RTLD_NEXT, "__fxstat64");
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(ver, fd, buf);
    if (r == 0 && buf) remap_owner(&buf->st_uid, &buf->st_gid);
    return r;
}
int __fxstatat64(int ver, int dirfd, const char *path, struct stat64 *buf, int flags) {
    int (*real)(int, int, const char *, struct stat64 *, int) = dlsym(RTLD_NEXT, "__fxstatat64");
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(ver, dirfd, path, buf, flags);
    if (r == 0 && buf) remap_owner(&buf->st_uid, &buf->st_gid);
    return r;
}
#endif /* __GLIBC__ */

/*
 * chown family (unmapped GIDs in user namespace cause EINVAL/EPERM).
 * dpkg calls these when unpacking .deb archives.
 */

typedef int (*chown_fn)(const char *, uid_t, gid_t);
typedef int (*lchown_fn)(const char *, uid_t, gid_t);
typedef int (*fchown_fn)(int, uid_t, gid_t);
typedef int (*fchownat_fn)(int, const char *, uid_t, gid_t, int);

int chown(const char *path, uid_t owner, gid_t group) {
    chown_fn real = (chown_fn)dlsym(RTLD_NEXT, "chown");
    if (!real) return -1;
    int r = real(path, owner, group);
    if (r == -1 && is_ro_error(errno)) return 0;
    return r;
}

int lchown(const char *path, uid_t owner, gid_t group) {
    lchown_fn real = (lchown_fn)dlsym(RTLD_NEXT, "lchown");
    if (!real) return -1;
    int r = real(path, owner, group);
    if (r == -1 && is_ro_error(errno)) return 0;
    return r;
}

int fchown(int fd, uid_t owner, gid_t group) {
    fchown_fn real = (fchown_fn)dlsym(RTLD_NEXT, "fchown");
    if (!real) return -1;
    int r = real(fd, owner, group);
    if (r == -1 && is_ro_error(errno)) return 0;
    return r;
}

int fchownat(int dirfd, const char *path, uid_t owner, gid_t group, int flags) {
    fchownat_fn real = (fchownat_fn)dlsym(RTLD_NEXT, "fchownat");
    if (!real) return -1;
    int r = real(dirfd, path, owner, group, flags);
    if (r == -1 && is_ro_error(errno)) return 0;
    return r;
}

/*
 * chmod family, maintainer scripts chmod on RO bind mounts.
 * Also fails in user namespace for unmapped UIDs.
 */

typedef int (*chmod_fn)(const char *, mode_t);
typedef int (*fchmod_fn)(int, mode_t);
typedef int (*fchmodat_fn)(int, const char *, mode_t, int);

int chmod(const char *path, mode_t mode) {
    chmod_fn real = (chmod_fn)dlsym(RTLD_NEXT, "chmod");
    if (!real) return -1;
    int r = real(path, mode);
    if (r == -1 && is_ro_error(errno)) return 0;
    return r;
}

int fchmod(int fd, mode_t mode) {
    fchmod_fn real = (fchmod_fn)dlsym(RTLD_NEXT, "fchmod");
    if (!real) return -1;
    int r = real(fd, mode);
    if (r == -1 && is_ro_error(errno)) return 0;
    return r;
}

int fchmodat(int dirfd, const char *path, mode_t mode, int flags) {
    fchmodat_fn real = (fchmodat_fn)dlsym(RTLD_NEXT, "fchmodat");
    if (!real) return -1;
    int r = real(dirfd, path, mode, flags);
    if (r == -1 && is_ro_error(errno)) return 0;
    return r;
}

/*
 * unlink family, maintainer scripts try to remove files from RO /usr/bin
 * during update-alternatives, fontconfig, ca-certificates, etc.
 */

typedef int (*unlink_fn)(const char *);
typedef int (*unlinkat_fn)(int, const char *, int);
typedef int (*rmdir_fn)(const char *);

int unlink(const char *path) {
    unlink_fn real = (unlink_fn)dlsym(RTLD_NEXT, "unlink");
    if (!real) return -1;
    int r = real(path);
    if (r == -1 && is_ro_error(errno)) {
        char *rp = redirect_path(path);
        if (rp) {
            r = real(rp);
            int saved = errno;
            free(rp);
            if (r == 0 || saved == ENOENT) return 0;
            errno = saved;
        }
        return 0;
    }
    return r;
}

int unlinkat(int dirfd, const char *path, int flags) {
    unlinkat_fn real = (unlinkat_fn)dlsym(RTLD_NEXT, "unlinkat");
    if (!real) return -1;
    int r = real(dirfd, path, flags);
    if (r == -1 && is_ro_error(errno)) {
        char *rp = redirect_path(path);
        if (rp) {
            r = real(AT_FDCWD, rp, flags);
            int saved = errno;
            free(rp);
            if (r == 0 || saved == ENOENT) return 0;
            errno = saved;
        }
        return 0;
    }
    return r;
}

int rmdir(const char *path) {
    rmdir_fn real = (rmdir_fn)dlsym(RTLD_NEXT, "rmdir");
    if (!real) return -1;
    int r = real(path);
    if (r == -1 && is_ro_error(errno)) return 0;
    return r;
}

/*
 * symlink / link, maintainer scripts create symlinks in RO /usr/bin
 * (update-alternatives, xdg-utils postinst, etc.)
 */

typedef int (*symlink_fn)(const char *, const char *);
typedef int (*symlinkat_fn)(const char *, int, const char *);
typedef int (*link_fn)(const char *, const char *);
typedef int (*linkat_fn)(int, const char *, int, const char *, int);

int symlink(const char *target, const char *linkpath) {
    symlink_fn real = (symlink_fn)dlsym(RTLD_NEXT, "symlink");
    if (!real) return -1;
    int r = real(target, linkpath);
    if (r == -1 && is_ro_error(errno)) {
        char *rp = redirect_path(linkpath);
        if (rp) {
            char *rt = redirect_path(target);
            ensure_parent_dirs(rp);
            r = real(rt ? rt : target, rp);
            int saved = errno;
            if (r == -1 && saved == EEXIST) {
                unlink_fn ureal = (unlink_fn)dlsym(RTLD_NEXT, "unlink");
                if (ureal) {
                    ureal(rp);
                    r = real(rt ? rt : target, rp);
                    saved = errno;
                }
            }
            if (rt) free(rt);
            free(rp);
            if (r == 0 || saved == EEXIST) return 0;
            errno = saved;
        }
        return 0;
    }
    return r;
}

int symlinkat(const char *target, int dirfd, const char *linkpath) {
    symlinkat_fn real = (symlinkat_fn)dlsym(RTLD_NEXT, "symlinkat");
    if (!real) return -1;
    int r = real(target, dirfd, linkpath);
    if (r == -1 && is_ro_error(errno)) {
        char *rp = redirect_path(linkpath);
        if (rp) {
            char *rt = redirect_path(target);
            ensure_parent_dirs(rp);
            r = real(rt ? rt : target, AT_FDCWD, rp);
            int saved = errno;
            if (r == -1 && saved == EEXIST) {
                unlink_fn ureal = (unlink_fn)dlsym(RTLD_NEXT, "unlink");
                if (ureal) {
                    ureal(rp);
                    r = real(rt ? rt : target, AT_FDCWD, rp);
                    saved = errno;
                }
            }
            if (rt) free(rt);
            free(rp);
            if (r == 0 || saved == EEXIST) return 0;
            errno = saved;
        }
        return 0;
    }
    return r;
}

int link(const char *oldpath, const char *newpath) {
    link_fn real = (link_fn)dlsym(RTLD_NEXT, "link");
    if (!real) return -1;
    int r = real(oldpath, newpath);
    if (r == -1 && is_ro_error(errno)) {
        char *rp = redirect_path(newpath);
        if (rp) {
            ensure_parent_dirs(rp);
            r = real(oldpath, rp);
            int saved = errno;
            free(rp);
            if (r == 0 || saved == EEXIST) return 0;
            errno = saved;
        }
        return 0;
    }
    return r;
}

int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
    linkat_fn real = (linkat_fn)dlsym(RTLD_NEXT, "linkat");
    if (!real) return -1;
    int r = real(olddirfd, oldpath, newdirfd, newpath, flags);
    if (r == -1 && is_ro_error(errno)) {
        char *rp = redirect_path(newpath);
        if (rp) {
            ensure_parent_dirs(rp);
            r = real(olddirfd, oldpath, AT_FDCWD, rp, flags);
            int saved = errno;
            free(rp);
            if (r == 0 || saved == EEXIST) return 0;
            errno = saved;
        }
        return 0;
    }
    return r;
}

/*
 * rename, cross-filesystem or RO source fails with EXDEV/EROFS/EPERM.
 * update-alternatives, fontconfig, etc. try this.
 */

typedef int (*rename_fn)(const char *, const char *);
typedef int (*renameat_fn)(int, const char *, int, const char *);
typedef int (*renameat2_fn)(int, const char *, int, const char *, unsigned int);

int rename(const char *oldpath, const char *newpath) {
    rename_fn real = (rename_fn)dlsym(RTLD_NEXT, "rename");
    if (!real) return -1;
    int r = real(oldpath, newpath);
    if (r == -1 && (is_ro_error(errno) || errno == EXDEV)) {
        char *ro = redirect_path(oldpath);
        char *rp = redirect_path(newpath);
        if (ro || rp) {
            const char *src = ro ? ro : oldpath;
            const char *dst = rp ? rp : newpath;
            if (rp) ensure_parent_dirs(rp);
            r = real(src, dst);
            int saved = errno;
            if (ro) free(ro);
            if (rp) free(rp);
            if (r == 0) return 0;
            errno = saved;
        } else if (rp) {
            ensure_parent_dirs(rp);
            r = real(oldpath, rp);
            int saved = errno;
            free(rp);
            if (r == 0) return 0;
            errno = saved;
        }
        return 0;
    }
    return r;
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    renameat_fn real = (renameat_fn)dlsym(RTLD_NEXT, "renameat");
    if (!real) return -1;
    int r = real(olddirfd, oldpath, newdirfd, newpath);
    if (r == -1 && (is_ro_error(errno) || errno == EXDEV)) {
        char *ro = redirect_path(oldpath);
        char *rp = redirect_path(newpath);
        if (ro || rp) {
            const char *src = ro ? ro : oldpath;
            const char *dst = rp ? rp : newpath;
            if (rp) ensure_parent_dirs(rp);
            r = real(ro ? AT_FDCWD : olddirfd, src, rp ? AT_FDCWD : newdirfd, dst);
            int saved = errno;
            if (ro) free(ro);
            if (rp) free(rp);
            if (r == 0) return 0;
            errno = saved;
        } else if (rp) {
            ensure_parent_dirs(rp);
            r = real(olddirfd, oldpath, AT_FDCWD, rp);
            int saved = errno;
            free(rp);
            if (r == 0) return 0;
            errno = saved;
        }
        return 0;
    }
    return r;
}

int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
    renameat2_fn real = (renameat2_fn)dlsym(RTLD_NEXT, "renameat2");
    if (!real) return -1;
    int r = real(olddirfd, oldpath, newdirfd, newpath, flags);
    if (r == -1 && (is_ro_error(errno) || errno == EXDEV)) {
        char *ro = redirect_path(oldpath);
        char *rp = redirect_path(newpath);
        if (ro || rp) {
            const char *src = ro ? ro : oldpath;
            const char *dst = rp ? rp : newpath;
            if (rp) ensure_parent_dirs(rp);
            r = real(ro ? AT_FDCWD : olddirfd, src, rp ? AT_FDCWD : newdirfd, dst, flags);
            int saved = errno;
            if (ro) free(ro);
            if (rp) free(rp);
            if (r == 0) return 0;
            errno = saved;
        } else if (rp) {
            ensure_parent_dirs(rp);
            r = real(olddirfd, oldpath, AT_FDCWD, rp, flags);
            int saved = errno;
            free(rp);
            if (r == 0) return 0;
            errno = saved;
        }
        return 0;
    }
    return r;
}

/*
 * mkdir / mkdirat, some postinst scripts mkdir in RO paths.
 */

typedef int (*mkdir_fn)(const char *, mode_t);
typedef int (*mkdirat_fn)(int, const char *, mode_t);

int mkdir(const char *path, mode_t mode) {
    mkdir_fn real = (mkdir_fn)dlsym(RTLD_NEXT, "mkdir");
    if (!real) return -1;
    int r = real(path, mode);
    if (r == -1 && is_ro_error(errno)) {
        char *rp = redirect_path(path);
        if (rp) {
            ensure_parent_dirs(rp);
            r = real(rp, mode);
            int saved = errno;
            free(rp);
            if (r == 0 || saved == EEXIST) return 0;
            errno = saved;
        }
        return 0;
    }
    return r;
}

int mkdirat(int dirfd, const char *path, mode_t mode) {
    mkdirat_fn real = (mkdirat_fn)dlsym(RTLD_NEXT, "mkdirat");
    if (!real) return -1;
    int r = real(dirfd, path, mode);
    if (r == -1 && is_ro_error(errno)) {
        char *rp = redirect_path(path);
        if (rp) {
            ensure_parent_dirs(rp);
            r = real(AT_FDCWD, rp, mode);
            int saved = errno;
            free(rp);
            if (r == 0 || saved == EEXIST) return 0;
            errno = saved;
        }
        return 0;
    }
    return r;
}

/*
 * creat, open with O_CREAT|O_WRONLY|O_TRUNC on RO path.
 */

typedef int (*creat_fn)(const char *, mode_t);

int creat(const char *path, mode_t mode) {
    creat_fn real = (creat_fn)dlsym(RTLD_NEXT, "creat");
    if (!real) return -1;
    int r = real(path, mode);
    if (r == -1 && is_ro_error(errno)) {
        char *rp = redirect_path(path);
        if (rp) {
            ensure_parent_dirs(rp);
            r = real(rp, mode);
            int saved = errno;
            free(rp);
            if (r != -1) return r;
            errno = saved;
        }
    }
    return r;
}

typedef int (*open_fn)(const char *, int, ...);
typedef int (*openat_fn)(int, const char *, int, ...);

int open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    open_fn real = (open_fn)dlsym(RTLD_NEXT, "open");
    if (!real) return -1;

    int r = (flags & O_CREAT) ? real(path, flags, mode) : real(path, flags);
    if (r == -1 && is_write_flags(flags) && is_ro_error(errno)) {
        char *rp = redirect_path(path);
        if (rp) {
            ensure_parent_dirs(rp);
            r = (flags & O_CREAT) ? real(rp, flags, mode) : real(rp, flags);
            int saved = errno;
            free(rp);
            if (r != -1) return r;
            errno = saved;
        }
    }
    return r;
}

int open64(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    open_fn real = (open_fn)dlsym(RTLD_NEXT, "open64");
    if (!real) return open(path, flags, mode);

    int r = (flags & O_CREAT) ? real(path, flags, mode) : real(path, flags);
    if (r == -1 && is_write_flags(flags) && is_ro_error(errno)) {
        char *rp = redirect_path(path);
        if (rp) {
            ensure_parent_dirs(rp);
            r = (flags & O_CREAT) ? real(rp, flags, mode) : real(rp, flags);
            int saved = errno;
            free(rp);
            if (r != -1) return r;
            errno = saved;
        }
    }
    return r;
}

int openat(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    openat_fn real = (openat_fn)dlsym(RTLD_NEXT, "openat");
    if (!real) return -1;

    int r = (flags & O_CREAT) ? real(dirfd, path, flags, mode) : real(dirfd, path, flags);
    if (r == -1 && is_write_flags(flags) && is_ro_error(errno)) {
        char *rp = redirect_path(path);
        if (rp) {
            ensure_parent_dirs(rp);
            r = (flags & O_CREAT) ? real(AT_FDCWD, rp, flags, mode) : real(AT_FDCWD, rp, flags);
            int saved = errno;
            free(rp);
            if (r != -1) return r;
            errno = saved;
        }
    }
    return r;
}

int openat64(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    openat_fn real = (openat_fn)dlsym(RTLD_NEXT, "openat64");
    if (!real) return openat(dirfd, path, flags, mode);

    int r = (flags & O_CREAT) ? real(dirfd, path, flags, mode) : real(dirfd, path, flags);
    if (r == -1 && is_write_flags(flags) && is_ro_error(errno)) {
        char *rp = redirect_path(path);
        if (rp) {
            ensure_parent_dirs(rp);
            r = (flags & O_CREAT) ? real(AT_FDCWD, rp, flags, mode) : real(AT_FDCWD, rp, flags);
            int saved = errno;
            free(rp);
            if (r != -1) return r;
            errno = saved;
        }
    }
    return r;
}
