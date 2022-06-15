
from fnmatch import fnmatch
from numpy import diff
from py import code
from pydriller import ModificationType, GitRepository as PyDrillerGitRepo
import os, json, re, subprocess, codecs

user_names = ['mlpack', 'numpy', 'pandas-dev', 'pytorch' ,'scipy', 'tensorflow']
this_project = os.getcwd()

REG_CHANGED = re.compile(".*@@ -(\d+),(\d+) \+(\d+),(\d+) @@.*")
REG_LOC = re.compile('\:(\d+)')

def get_diff_header(diff):
    code_lines = diff.split('\n')
    if code_lines[0]:
        for line in code_lines:
            try:
                window = [int(REG_CHANGED.search(line).group(3)), int(REG_CHANGED.search(line).group(3))+int(REG_CHANGED.search(line).group(4))]
                break
            except Exception as e:
                # print('There is no diff content for this file.')
                return
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

def parse_output(output):
    if re.findall(r'(No hits found)', output):
        return 'not detected'
    if re.findall(r'(Hits =)', output):
        # if re.findall(r'(\(CWE-[0-9]+\))', output):
        #     match_ = re.findall(r'(\(CWE-[0-9]+\))', output)
        #     if match_[0] == actual_cwe_id:
        #         return 'true detected'
        #     else:
        #         return 'detected'
        return 'detected'


def run(test_file):
    command_ = 'flawfinder --context '
    output = subprocess.getoutput(command_+test_file)
    return [parse_output(output), output]

def diff_based_matching(changed_lines, current_commit, file):

    for f in current_commit.modifications:
        if f.filename == os.path.basename(file['file_path']):
            vul_file_object = f
            break
    
    save_source_code(vul_file_object.source_code, 'vul', vul_file_object.filename)

    if os.path.isfile(os.path.join(this_project, 'vul_'+vul_file_object.filename)):
        [res, output] = run(os.path.join(this_project, 'vul_'+vul_file_object.filename))
        if res == 'detected':
            g = REG_LOC.search(output).group(1)
            if changed_lines[0] <= int(g) <= changed_lines[1]:
                print('Full Match')
            if int(g) <= changed_lines[0] or int(g) >= changed_lines[1]:
                print('Partial Match')
            else:
                print('Mismatch')
        else:
            print(res)

    subprocess.call('rm -rf '+this_project+'/vul_'+vul_file_object.filename, shell=True)

def save_source_code(source_code, flag, filename):
    split_source_code = source_code.split('\n')
    with codecs.open(flag+'_'+filename, 'w') as f_method:
        for line in split_source_code:
            f_method.write("%s\n" % line)
        f_method.close()

def fixed_warning_base_matching(fix_commit, vul_commit, common_file):

    for f in fix_commit.modifications:
        if f.filename == os.path.basename(list(common_file)[0]):
            fixed_file_object = f
            break

    save_source_code(fixed_file_object.source_code, 'fix', fixed_file_object.filename)
    save_source_code(vul_commit.modifications[0].source_code, 'vul', vul_commit.modifications[0].filename)     

    if os.path.isfile(this_project+'/fix_'+fixed_file_object.filename):
        [res1, output1] = run(this_project+'/fix_'+fixed_file_object.filename)

    if os.path.isfile(this_project+'/fix_'+vul_commit.modifications[0].filename):
        [res2, output2] = run(this_project+'/fix_'+vul_commit.modifications[0].filename)
    
    if res1 == 'not detected' and res2 == 'detected':
        print('Fixed Warning Method Detected a Bug Candidate')
    
    subprocess.call('rm -rf '+this_project+'/fix_'+fixed_file_object.filename, shell=True)
    subprocess.call('rm -rf '+this_project+'/vul_'+vul_commit.modifications[0].filename, shell=True)


def main():
    vic_path = '/media/nimashiri/DATA/vsprojects/ICSE23/data/vic_vfs_json'

    for i, dir in enumerate(os.listdir(vic_path)):
        repository_path = this_project+'/ml_repos_cloned/'+user_names[i]+'/'+dir.split('_')[1].split('.')[0]
        
        v = "https://github.com/{0}/{1}{2}".format(user_names[i], dir.split('_')[1].split('.')[0],'.git')

        if not os.path.exists(repository_path):
            subprocess.call('git clone '+v+' '+repository_path, shell=True)
        
        vic_lib_path = os.path.join(vic_path, dir)
        with open(vic_lib_path, 'r', encoding='utf-8') as f:
            data = json.loads(f.read(),strict=False)
        for counter, item in enumerate(data):
            x = list(item.keys())
            if bool(item[x[0]]):
                for file in item[x[0]]:
                    if 'test' not in file['file_path']:
                        previous_commits = file['previous_commits']
                        for pc in previous_commits:
                            # here we must get the main file
                            current_commit = PyDrillerGitRepo(repository_path).get_commit(pc[0])
                            fix_commit = PyDrillerGitRepo(repository_path).get_commit(x[0])

                            single_prev_file_names = get_fix_file_names(current_commit.modifications)
                            fix_file_names = get_fix_file_names(fix_commit.modifications)

                            try:
                                if fix_file_names[file['file_path']] and single_prev_file_names[file['file_path']]:
                                    print('Running Flawfinder on {} Library, {}/{}'.format(dir.split('_')[1].split('.')[0], counter, len(data)))
                                    diff_based_matching(fix_file_names[file['file_path']], current_commit, file)
                                    # fixed_warning_base_matching(PyDrillerGitRepo(repository_path).get_commit(x[0]), current_commit, common_files)
                            except Exception as e:
                                # print('The vulnerable file is not found in fix files.')
                                pass

                                

if __name__ == '__main__':
    main()




