/* SPDX-License-Identifier: GPL-2.0-only */
/* Test-only: split an actual hash collision across leaf and index boundaries. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ext2fs/ext2fs.h>
static unsigned get16(char *p) { unsigned short v;memcpy(&v,p,2);return ext2fs_le16_to_cpu(v); }
static unsigned get32(char *p) { unsigned v;memcpy(&v,p,4);return ext2fs_le32_to_cpu(v); }
static void put16(char *p,unsigned n) { unsigned short v=ext2fs_cpu_to_le16(n);memcpy(p,&v,2); }
static void put32(char *p,unsigned n) { unsigned v=ext2fs_cpu_to_le32(n);memcpy(p,&v,4); }
int main(int argc,char **argv)
{
    if (argc!=6) return 2;
    ext2_filsys fs=NULL;errcode_t err=ext2fs_open(argv[1],EXT2_FLAG_RW|EXT2_FLAG_64BITS,0,0,unix_io_manager,&fs);
    if (!err) err=ext2fs_read_bitmaps(fs);
    ext2_ino_t ino=strtoul(argv[2],NULL,10);unsigned split=atoi(argv[5]);
    struct ext2_inode inode;char root[4096];blk64_t physical=0;
    if (!err) err=ext2fs_read_inode(fs,ino,&inode);
    if (!err) err=ext2fs_bmap2(fs,ino,&inode,NULL,0,0,NULL,&physical);
    if (!err) err=ext2fs_read_dir_block4(fs,physical,root,0,ino);
    if (err) goto out;
    unsigned files[2]={0,0},hash[2];
    for (unsigned j=0;j<2;j++) {
        err=ext2fs_dirhash(0,argv[3+j],strlen(argv[3+j]),fs->super->s_hash_seed,&hash[j],NULL);
        if (err) goto out;
        for (unsigned off=0;off<fs->blocksize;) {
            unsigned length=get16(root+off+4);if (!length || length>fs->blocksize-off) return 2;
            if ((unsigned char)root[off+6]==strlen(argv[3+j]) && !memcmp(root+off+8,argv[3+j],strlen(argv[3+j]))) files[j]=get32(root+off);
            off+=length;
        }
    }
    if (!files[0] || !files[1] || hash[0]!=hash[1]) return 2;
    for (unsigned i=0;i<(split ? 4 : 2);i++) if ((err=ext2fs_expand_dir(fs,ino))) goto out;
    err=ext2fs_read_inode(fs,ino,&inode);if (err) goto out;
    inode.i_flags|=EXT2_INDEX_FL;err=ext2fs_write_inode(fs,ino,&inode);if (err) goto out;
    unsigned tail=ext2fs_has_feature_metadata_csum(fs->super) ? 8 : 0;
    memset(root+24,0,fs->blocksize-24);put16(root+16,fs->blocksize-12);
    root[28]=0;root[29]=8;root[30]=split ? 1 : 0;
    put16(root+32,(fs->blocksize-32-tail)/8);put16(root+34,2);
    put32(root+36,split ? 3 : 1);put32(root+40,hash[0]|1);put32(root+44,split ? 4 : 2);
    err=ext2fs_write_dir_block4(fs,physical,root,0,ino);if (err) goto out;
    for (unsigned i=0;i<2;i++) {
        char leaf[4096]={0};blk64_t block=0;
        put32(leaf,files[i]);put16(leaf+4,fs->blocksize-(tail ? 12 : 0));leaf[6]=strlen(argv[3+i]);leaf[7]=EXT2_FT_REG_FILE;
        memcpy(leaf+8,argv[3+i],strlen(argv[3+i]));
        if (tail) { put16(leaf+fs->blocksize-8,12);leaf[fs->blocksize-5]=(char)0xde; }
        err=ext2fs_bmap2(fs,ino,&inode,NULL,0,i+1,NULL,&block);if (err) goto out;
        err=ext2fs_write_dir_block4(fs,block,leaf,0,ino);if (err) goto out;
        if (split) {
            char node[4096]={0};put16(node+4,fs->blocksize);put16(node+8,(fs->blocksize-8-tail)/8);put16(node+10,1);put32(node+12,i+1);
            err=ext2fs_bmap2(fs,ino,&inode,NULL,0,i+3,NULL,&block);if (err) goto out;
            err=ext2fs_write_dir_block4(fs,block,node,0,ino);if (err) goto out;
        }
    }
out:
    if (fs) { errcode_t closed=ext2fs_close(fs);if (!err) err=closed; }
    if (err) fprintf(stderr,"collision fixture error: %ld\n",(long)err);
    return err ? 1 : 0;
}
