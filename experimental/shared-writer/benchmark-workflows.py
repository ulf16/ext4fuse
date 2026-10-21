#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Reproducible installed-mount timings on disposable images, with independent checks.

No device argument is accepted. Results describe this host and cache conditions;
there are no universal throughput pass thresholds. Failures retain all state.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--work',type=Path,required=True)
p.add_argument('--prefix',type=Path,required=True)
p.add_argument('--rounds',type=int,default=3)
p.add_argument('--file-mib',type=int,default=32)
p.add_argument('--small-files',type=int,default=128)
a=p.parse_args()
if not 1<=a.rounds<=10 or not 1<=a.file_mib<=64 or not 8<=a.small_files<=2048:p.error('rounds 1..10, file MiB 1..64, small files 8..2048')
if a.rounds*(a.file_mib+a.small_files*4096/1024**2)>384:p.error('combined retained payload must fit within 384 MiB')
a.work.mkdir(parents=True,exist_ok=True)
base=Path(tempfile.mkdtemp(prefix='bench-',dir=a.work)).resolve()
cli=a.prefix/'bin/ext4fuse-writer'
registry=base/'profiles';volume=[cli,'volume','--profiles-dir',registry]
block=hashlib.sha256(b'ext4fuse representative sequential payload').digest()*32768
expected=hashlib.sha256(block*a.file_mib).hexdigest()
checks=0

def check(condition,detail):
    global checks
    if not condition:raise AssertionError(detail)
    checks+=1


def run(argv,timeout=600):
    result=subprocess.run(list(map(str,argv)),capture_output=True,timeout=timeout)
    check(result.returncode==0,repr((argv,result.returncode,result.stdout[-2048:],result.stderr[-2048:])))
    return result


def timed(call):
    start=time.perf_counter();value=call();return time.perf_counter()-start,value


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def observation(state):
    return json.loads(run([cli,'status',state,'--json']).stdout)


def workload(point,number):
    dest=point/('round-'+str(number));dest.mkdir()
    large=dest/'large.bin'
    def write_large():
        with large.open('xb',buffering=0) as f:
            for _ in range(a.file_mib):
                view=memoryview(block)
                while view:
                    written=f.write(view)
                    if not written:raise OSError('short benchmark write')
                    view=view[written:]
            os.fsync(f.fileno())
    write_s,_=timed(write_large)
    read_s,actual=timed(lambda:digest(large));check(actual==expected,'sequential read digest')
    payload=b'small-file-data!'*256
    def small():
        for i in range(a.small_files):
            with (dest/f'small-{i:05}').open('xb',buffering=0) as f:
                check(f.write(payload)==len(payload),'small write size');os.fsync(f.fileno())
    small_s,_=timed(small)
    def browse():
        for _ in range(3):
            names=os.listdir(dest);check(len(names)==a.small_files+1,'directory entries')
            for name in names:check((dest/name).stat().st_size==(a.file_mib*1024**2 if name=='large.bin' else len(payload)),'entry metadata')
    browse_s,_=timed(browse)
    mutations=min(32,a.small_files)
    def rename_delete():
        for i in range(mutations):
            old=dest/f'small-{i:05}';new=dest/f'renamed-{i:05}'
            old.rename(new);check(new.read_bytes()==payload,'renamed data');new.unlink()
    namespace_s,_=timed(rename_delete)
    return dict(sequential_write_fsync_seconds=write_s,sequential_write_mib_s=a.file_mib/write_s,
                sequential_read_seconds=read_s,sequential_read_mib_s=a.file_mib/read_s,
                small_create_fsync_seconds=small_s,small_create_fsync_files_s=a.small_files/small_s,
                list_stat_three_passes_seconds=browse_s,rename_read_unlink_seconds=namespace_s,
                namespace_files=mutations,large_digest=actual)


rows=[]
try:
    # Same application calls on the local host filesystem; not a USB speed model.
    baseline=base/'host-files';baseline.mkdir()
    for i in range(a.rounds):rows.append(dict(profile='host-filesystem',round=i,metrics=workload(baseline,i)))
    for name,block_size,features in [('classic-1k','1024','^extent,^64bit,^metadata_csum,^orphan_file'),
                                      ('extent-4k','4096','extent,64bit,metadata_csum,^orphan_file')]:
        print('Benchmarking '+name+'; disposable state: '+str(base),file=sys.stderr,flush=True)
        source=base/(name+'.img')
        with source.open('xb') as f:f.truncate(512*1024**2)
        run(['mke2fs','-q','-F','-t','ext4','-b',block_size,'-O',features,source])
        for field,value in [('uid',os.getuid()),('gid',os.getgid())]:run(['debugfs','-w','-R',f'set_inode_field / {field} {value}',source])
        source_digest=digest(source);state=base/(name+'-state');point=base/(name+'-mount')
        init_s,_=timed(lambda:run([cli,'init','--image',source,state]));init_progress=observation(state)['progress']
        run(volume+['add',name,'--state',state,'--mountpoint',point])
        index=state/'chain'/'integrity-index'
        if index.exists():index.unlink()
        check(not index.exists(),'no-index admission starts without acceleration')
        #  # Only the optional acceleration in this new disposable state.
        cold_s,_=timed(lambda:run(volume+['mount',name]));cold_progress=observation(state)['progress']
        check('integrity-read' in cold_progress['completed_stage_seconds'],'no-index mount scanned')
        cold_close_s,_=timed(lambda:run(volume+['unmount',name]));cold_close=observation(state)
        check(not cold_close['busy'] and not cold_close['mounted'] and cold_close['phase']=='ready','cold close readiness')
        for i in range(a.rounds):
            print(f'{name}: round {i+1}/{a.rounds}',file=sys.stderr,flush=True)
            mount_s,_=timed(lambda:run(volume+['mount',name]));mounted=observation(state)
            check('integrity-index' in mounted['progress']['completed_stage_seconds'],'warm mount used index')
            check(mounted['busy'] and mounted['mounted'] and mounted['status']=='mounted','mounted observation')
            metrics=workload(point,i)
            close_s,_=timed(lambda:run(volume+['unmount',name]));closed=observation(state)
            check(not closed['busy'] and not closed['mounted'] and closed['phase']=='ready','warm close readiness')
            rows.append(dict(profile=name,round=i,metrics=dict(metrics,warm_mount_seconds=mount_s,checked_unmount_seconds=close_s),
                             mount_progress=mounted['progress'],close_progress=closed['progress'],
                             initialization_seconds=init_s,initialization_progress=init_progress,
                             no_index_mount_seconds=cold_s,no_index_mount_progress=cold_progress,no_index_unmount_seconds=cold_close_s))
        image=state/'chain'/'image.img'
        run(['e2fsck','-fn',image])
        for i in range(a.rounds):
            out=base/f'{name}-round-{i}-independent.bin'
            run(['debugfs','-R',f'dump /round-{i}/large.bin {out}',image])
            check(digest(out)==expected,'independent debugfs digest');out.unlink()
            # Check a surviving small file independently after clean publication.
            if a.small_files>32:
                result=run(['debugfs','-R',f'cat /round-{i}/small-{a.small_files-1:05}',image])
                check(result.stdout==b'small-file-data!'*256,'independent small file')
        check(digest(source)==source_digest,'source image changed')
    medians={};ranges={}
    for name in ('host-filesystem','classic-1k','extent-4k'):
        group=[r['metrics'] for r in rows if r['profile']==name]
        medians[name]={key:statistics.median(row[key] for row in group) for key in group[0] if isinstance(group[0][key],(int,float))}
        ranges[name]={key:dict(min=min(row[key] for row in group),max=max(row[key] for row in group)) for key in medians[name]}
    report=dict(result='passed',checks=checks,platform=platform.platform(),python=sys.version.split()[0],
        version=run([cli,'--version']).stdout.decode().strip(),prefix=str(a.prefix),diagnostics=str(base),
        configuration=dict(rounds=a.rounds,file_mib=a.file_mib,small_files=a.small_files,small_bytes=4096,image_mib=512),
        conditions='Host-cache-warm, timed sequentially; no cache eviction. Fresh image state with index removed measures no-index admission, not cold hardware. Same fsync calls on local host files are a comparison, not USB throughput. No physical devices or power-loss claims.',
        medians=medians,ranges=ranges,samples=rows)
    output=a.work/'workflow-benchmarks.json';output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps(dict(result='passed',checks=checks,report=str(output),medians=medians),sort_keys=True),flush=True)
except BaseException:
    print('Benchmark stopped; retain state and inspect mounts under '+str(base),file=sys.stderr,flush=True)
    # Never force detach, recover or delete state on an unverified failed run.
    raise
