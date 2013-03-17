/* Meta-tile optimised file storage
 *
 * Instead of storing each individual tile as a file,
 * bundle the 8x8 meta tile into a special meta-file.
 * This reduces the Inode usage and more efficient
 * utilisation of disk space.
 */

#include "config.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#define HAVE_LIBRADOS 1
#ifdef HAVE_LIBMEMCACHED
#include <rados/librados.h>
#endif

#include "store.h"
#include "metatile.h"
#include "render_config.h"
#include "protocol.h"


#ifdef HAVE_LIBRADOS

struct rados_ctx {
    char * pool;
    rados_t cluster;
    rados_ioctx_t io;
};

static char * rados_xyz_to_storagekey(const char *xmlconfig, int x, int y, int z, char * key) {
    int mask;

    mask = METATILE - 1;
    x &= ~mask;
    y &= ~mask;

    snprintf(key, PATH_MAX - 1, "%s/%d/%d/%d.meta", xmlconfig, x, y, z);

    return key;
}


static int rados_tile_read(struct storage_backend * store, const char *xmlconfig, int x, int y, int z, char *buf, size_t sz, int * compressed, char * log_msg) {

    char meta_path[PATH_MAX];
    struct rados_ctx * ctx = (struct rados_ctx *)store->storage_ctx;
    int meta_offset;
    unsigned int pos;
    unsigned int header_len = sizeof(struct meta_layout) + METATILE*METATILE*sizeof(struct entry);
    struct meta_layout *m = (struct meta_layout *)malloc(header_len);
    size_t file_offset, tile_size;
    int mask;
    size_t len;
    int err;
    char * buf_raw = malloc(header_len);

    mask = METATILE - 1;
    meta_offset = (x & mask) * METATILE + (y & mask);

    rados_xyz_to_storagekey(xmlconfig, x, y, z, meta_path);
    err = rados_read(ctx->io, meta_path, buf_raw, header_len, 0);

    if (err < 0) {
        free(buf_raw);
        free(m);
        fprintf(stderr, "cannot read pool %s: %s\n", ctx->pool, strerror(-err));
        return -1;
    }

    memcpy(m, buf_raw + sizeof(struct stat_info), header_len);

    if (memcmp(m->magic, META_MAGIC, strlen(META_MAGIC))) {
        if (memcmp(m->magic, META_MAGIC_COMPRESSED, strlen(META_MAGIC_COMPRESSED))) {
            snprintf(log_msg,1024, "Meta file header magic mismatch\n");
            free(buf_raw);
            free(m);
            return -4;
        } else {
            *compressed = 1;
        }
    } else *compressed = 0;

    // Currently this code only works with fixed metatile sizes (due to xyz_to_meta above)
    if (m->count != (METATILE * METATILE)) {
        snprintf(log_msg, 1024, "Meta file header bad count %d != %d\n", m->count, METATILE * METATILE);
        free(buf_raw);
        free(m);
        return -5;
    }

    file_offset = m->index[meta_offset].offset + sizeof(struct stat_info);
    tile_size   = m->index[meta_offset].size;

    free(m);

    if (tile_size > sz) {
        snprintf(log_msg, 1024, "Truncating tile %zd to fit buffer of %zd\n", tile_size, sz);
        tile_size = sz;
        return -6;
    }

    err = rados_read(((struct rados_ctx *)store->storage_ctx)->io, meta_path, buf, tile_size, file_offset);

    if (err < 0) {
        free(m);
        return -1;
    }
    free(buf_raw);
    return tile_size;
}

static struct stat_info rados_tile_stat(struct storage_backend * store, const char *xmlconfig, int x, int y, int z) {
    struct stat_info tile_stat;
    struct rados_ctx * ctx = (struct rados_ctx *)store->storage_ctx;
    char meta_path[PATH_MAX];
    unsigned int header_len = sizeof(struct meta_layout) + METATILE*METATILE*sizeof(struct entry);
    struct meta_layout *m = (struct meta_layout *)malloc(header_len);
    char * buf = malloc(header_len);
    size_t len;
    int err;
    int offset, mask;

    mask = METATILE - 1;
    offset = (x & mask) * METATILE + (y & mask);

    rados_xyz_to_storagekey(xmlconfig, x, y, z, meta_path);

    err = rados_read(ctx->io, meta_path, buf, header_len, 0);

    if (err <0) {
        tile_stat.size = -1;
        tile_stat.mtime = 0;
        tile_stat.atime = 0;
        tile_stat.ctime = 0;
        free(m);
        fprintf(stderr, "cannot read pool %s: %s\n", ctx->pool, strerror(-err));
        return tile_stat;
    }

    memcpy(&tile_stat,buf, sizeof(struct stat_info));
    memcpy(m, buf + sizeof(struct stat_info), header_len);
    tile_stat.size = m->index[offset].size;

    free(m);
    free(buf);
    return tile_stat;
}


static char * rados_tile_storage_id(struct storage_backend * store, const char *xmlconfig, int x, int y, int z, char * string) {
    char meta_path[PATH_MAX];

    rados_xyz_to_storagekey(xmlconfig, x, y, z, meta_path);
    snprintf(string,PATH_MAX - 1, "rados:///%s", meta_path);
    return string;
}

static int rados_metatile_write(struct storage_backend * store, const char *xmlconfig, int x, int y, int z, const char *buf, int sz) {
    char meta_path[PATH_MAX];
    char * tmp;
    struct stat_info tile_stat;
    int sz2 = sz + sizeof(struct stat_info);
    char * buf2 = malloc(sz2);
    int err;

    tile_stat.expired = 0;
    tile_stat.mtime = time(NULL);
    tile_stat.atime = tile_stat.mtime;
    tile_stat.ctime = tile_stat.mtime;

    memcpy(buf2, &tile_stat, sizeof(tile_stat));
    memcpy(buf2 + sizeof(tile_stat), buf, sz);

    fprintf(stderr, "Trying to create and write a tile to memcahced\n");
 
    snprintf(meta_path,PATH_MAX - 1, "%s/%d/%d/%d.meta", xmlconfig, x, y, z);

    err = rados_write_full(((struct rados_ctx *)store->storage_ctx)->io, meta_path, buf2, sz2);
    if (err < 0) {
        fprintf(stderr, "cannot write pool %s: %s\n", "data", strerror(-err));
        rados_ioctx_destroy(store->storage_ctx);
        free(buf2);
        return -1;
    }
    free(buf2);

    return sz;
}


static int rados_metatile_delete(struct storage_backend * store, const char *xmlconfig, int x, int y, int z) {
    struct rados_ctx * ctx = (struct rados_ctx *)store->storage_ctx;
    char meta_path[PATH_MAX];
    int err;

    rados_xyz_to_storagekey(xmlconfig, x, y, z, meta_path);

    err =  rados_remove(ctx->io, meta_path);

    if (err < 0) {
        fprintf(stderr, "failed to delete %s from pool %s: %s\n", meta_path, ctx->pool, strerror(-err));
        return -1;
    }

    return 0;
}

static int rados_metatile_expire(struct storage_backend * store, const char *xmlconfig, int x, int y, int z) {

    struct stat_info tile_stat;
    struct rados_ctx * ctx = (struct rados_ctx *)store->storage_ctx;
    char meta_path[PATH_MAX];
    char * buf;
    size_t len;
    int err;

    rados_xyz_to_storagekey(xmlconfig, x, y, z, meta_path);
    err = rados_read(ctx->io, meta_path, (char *)&tile_stat, sizeof(struct stat_info), 0);

    if (err < 0) {
        return -1;
    }

    tile_stat.expired = 1;

    err = rados_write(ctx->io, meta_path, (char *)&tile_stat, sizeof(struct stat_info), 0);

    if (err < 0) {
        free(buf);
        return -1;
    }

    free(buf);
    return 0;
}


static int rados_close_storage(struct storage_backend * store) {
    rados_ioctx_destroy(((struct rados_ctx *) store->storage_ctx)->io);
    rados_shutdown(((struct rados_ctx *) store->storage_ctx)->cluster);
    return 0;
}


#endif //Have rados



struct storage_backend * init_storage_rados(const char * connection_string) {
    
#ifndef HAVE_LIBRADOS
    return NULL;
#else
    struct rados_ctx * ctx = malloc(sizeof(struct rados_ctx));
    struct storage_backend * store = malloc(sizeof(struct storage_backend));
    int err;


    char * connection_str = "--server=localhost";

    err = rados_create(&(ctx->cluster), NULL);
    if (err < 0) {
            fprintf(stderr, "cannot create a cluster handle: %s\n", strerror(-err));
            exit(1);
    }

    err = rados_conf_read_file(ctx->cluster, NULL);
    if (err < 0) {
        fprintf(stderr, "cannot read rados config: %s\n", strerror(-err));
        exit(1);
    }

    err = rados_connect(ctx->cluster);
    if (err < 0) {
        fprintf(stderr, "cannot connect to cluster: %s\n", strerror(-err));
        exit(1);
    }

    err = rados_ioctx_create(ctx->cluster, "data", &(ctx->io));
    if (err < 0) {
        fprintf(stderr, "cannot open rados pool %s: %s\n", ctx->pool, strerror(-err));
        rados_shutdown(ctx->cluster);
        exit(1);
    }

    err = rados_write_full(ctx->io, "greeting2", "hello", 5);
    if (err < 0) {
            fprintf(stderr, "%s: cannot write pool %s: %s\n", ctx->pool, strerror(-err));
            exit(1);
    }


    store->storage_ctx = ctx;

    store->tile_read = &rados_tile_read;
    store->tile_stat = &rados_tile_stat;
    store->metatile_write = &rados_metatile_write;
    store->metatile_delete = &rados_metatile_delete;
    store->metatile_expire = &rados_metatile_expire;
    store->tile_storage_id = &rados_tile_storage_id;
    store->close_storage = &rados_close_storage;

    return store;
#endif
}
