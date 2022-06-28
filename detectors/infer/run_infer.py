import subprocess, os

def read_txt(fname):
    with open(fname, 'r') as fileReader:
        data = fileReader.read().splitlines()
    return data

base_path = '/media/nimashiri/DATA/vsprojects/ICSE23/ml_repos_cloned/numpy/numpy/'

compilation_options = '-DNPY_INTERNAL_BUILD=1 -DHAVE_NPY_CONFIG_H=1 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE=1 -D_LARGEFILE64_SOURCE=1 -DNO_ATLAS_INFO=1 -DHAVE_CBLAS -I/usr/local/include -Inumpy/core/src/multiarray -Inumpy/core/src/common -Inumpy/core/src/umath -Inumpy/core/include -Inumpy/core/include/numpy -Ibuild/src.linux-x86_64-3.8/numpy/distutils/include -Inumpy/core/src/common -Inumpy/core/src -Inumpy/core -Inumpy/core/src/npymath -Inumpy/core/src/multiarray -Inumpy/core/src/umath -Inumpy/core/src/npysort -Inumpy/core/src/_simd -I/usr/include/python3.8 -Inumpy/core/src/common -Inumpy/core/src/npymath -c '

# test_file_path1 = 'numpy/core/src/common/cblasfuncs.c'

data = read_txt('detectors/infer/files.txt')
for f in data:
    target = os.path.join(base_path, f)

    command_capture = 'infer capture -- gcc '+compilation_options+target
    command_analyze = 'infer analyze -- gcc '+compilation_options+target

# scan_build_command = 'clang-tidy gcc '+compilation_options+target
# subprocess.call(scan_build_command, shell=True)

    subprocess.call(command_capture, shell=True)
    subprocess.call(command_analyze, shell=True)
    subprocess.call('rm -rf infer-out', shell=True)
