
from numpy import diff
from py import code
from pydriller import ModificationType, GitRepository as PyDrillerGitRepo
import os, json, re

user_names = ['mlpack', 'numpy', 'pandas-dev', 'pytorch' ,'scipy', 'tensorflow']
REG_CHANGED = re.compile(".*@@ -(\d+),(\d+) \+(\d+),(\d+) @@.*")
this_project = os.getcwd()

def get_diff_header(diff):
    code_lines = diff.split('\n')
    if code_lines[0]:
        for line in code_lines:
            window = [int(REG_CHANGED.search(line).group(3)), int(REG_CHANGED.search(line).group(3))+int(REG_CHANGED.search(line).group(4))]
            break
        return window
    else:
        return 'None'


def get_fix_file_names(commits):
    f_names = {}
    if len(commits) == 1:
        for commit in commits:
            if 'test' not in commit.filename:
                diff_split = get_diff_header(commit.diff)
                if bool(commit.new_path):
                    f_names[commit.new_path] = diff_split
                else:
                    f_names[commit.old_path] = diff_split
    else:
        for commit in commits:
            if 'test' not in commit.filename:
                diff_split = get_diff_header(commit.diff)
                if bool(commit.new_path):
                    f_names[commit.new_path] = diff_split
                else:
                    f_names[commit.old_path] = diff_split
    return f_names

def get_prev_file_names(repository_path, items):
    f_names = {}
    for k, value in items.items():
        for item in value:
            for prev_commit in item['previous_commits']:
                x = PyDrillerGitRepo(repository_path).get_commit(prev_commit[0])
                for modification in x.modifications:
                    if 'test' not in modification.filename:
                        diff_split = get_diff_header(modification.diff)
                        if bool(modification.new_path):
                            f_names[modification.new_path] = diff_split
                        else:
                            f_names[modification.old_path] = diff_split
    return f_names

def main():
    vic_path = '/media/nimashiri/DATA/vsprojects/ICSE23/data/vic_vfs_json'

    for i, dir in enumerate(os.listdir(vic_path)):
        repository_path = this_project+'/ml_repos_cloned/'+user_names[i]+'/'+dir.split('_')[1].split('.')[0]
        vic_lib_path = os.path.join(vic_path, dir)
        with open(vic_lib_path, 'r', encoding='utf-8') as f:
            data = json.loads(f.read(),strict=False)
        for counter, item in enumerate(data):
            x = list(item.keys())
            if bool(item[x[0]]):
                # x = PyDrillerGitRepo(repository_path).get_commit('d881abd25e5439b01f7c71f114952c8425884cc0')
                x = PyDrillerGitRepo(repository_path).get_commit(x[0])
                fix_files = get_fix_file_names(x.modifications)
                prev_files = get_prev_file_names(repository_path, item)
                common_files = fix_files.keys() & prev_files.keys()
                if common_files:
                    for k, commits in item.items():
                        for commit_counter, commit in enumerate(commits):
                            if 'test' not in commit['file_path']:
                                if commit['file_path'] in common_files:
                                    approx_lines = fix_files[commit['file_path']]
                                if approx_lines:
                                    previous_commits = commit['previous_commits']
                                    for pc in previous_commits:
                                        x = PyDrillerGitRepo(repository_path).get_commit(commits)
                    
           
    #  if common_files:
    #     for f in list(common_files):
    #         fix_files[f]

if __name__ == '__main__':
    main()




