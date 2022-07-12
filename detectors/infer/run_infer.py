import sys, os, re, subprocess, json
from pydriller import GitRepository as PyDrillerGitRepo

user_names = ['pytorch', 'numpy', 'pandas-dev', 'pytorch' ,'scipy', 'tensorflow']

_extensions = ['cc', 'cpp', 'hpp', 'h', 'c', 'cu']

this_project = os.getcwd()

REG_CHANGED = re.compile(".*@@ -(\d+),(\d+) \+(\d+),(\d+) @@.*")
REG_LOC_FLAWFINDER = re.compile('\:(\d+)')
REG_RATS = re.compile('<vulnerability>')
REG_CPP_CHECK_LOC = re.compile('line=\"(\d+)\"')
REG_CPP_CHECK = re.compile('error id=')

FIND_CWE_IDENTIFIER = re.compile('CWE-(\d+)')
FIND_RATS_VUL_TYPE = re.compile('<type.*>((.|\n)*?)<\/type>')
sys.path.insert(1, 'detectors/flawfinder')

import detectors.flawfinder.song_method as sm


def main():
    vic_path = '/media/nimashiri/DATA/vsprojects/ICSE23/data/vic_vfs_json'

    for i, dir in enumerate(os.listdir(vic_path)):
        if user_names[i] == 'tensorflow' or user_names[i] == 'pytorch':
            repository_path = this_project+'/ml_repos_cloned/'+user_names[i]
        else:
            repository_path = this_project+'/ml_repos_cloned/'+user_names[i]+'/'+dir.split('_')[1].split('.')[0]

        v = "https://github.com/{0}/{1}{2}".format(user_names[i], dir.split('_')[1].split('.')[0],'.git')

        commit_base_link = "https://github.com/{0}/{1}/{2}/".format(user_names[i], dir.split('_')[1].split('.')[0], 'commit')

        if not os.path.exists(repository_path):
            subprocess.call('git clone '+v+' '+repository_path, shell=True)
                
        vic_lib_path = os.path.join(vic_path, dir)

                # load vulnerable inducing commits
        with open(vic_lib_path, 'r', encoding='utf-8') as f:
            data = json.loads(f.read(),strict=False)

        try:
            for counter, item in enumerate(data):
                x = list(item.keys())
                current_commit = PyDrillerGitRepo(repository_path).get_commit(x[0])
                for mod in current_commit.modifications:
                    if 'test' not in mod.new_path and 'test' not in mod.filename and mod.filename.split('.')[-1] in _extensions:
                        cl = sm.get_fix_file_names(mod)

        except Exception as e:
            print(e)


if __name__ == '__main__':
    main()