import json, os
from csv import writer
from git import Repo
import subprocess

# user_names = ['mlpack', 'numpy', 'pandas-dev', 'scipy', 'pytorch']

user_names = ['pandas-dev']

this_project = os.getcwd()

def write_list_to_txt(data, filename):
    with open(filename, "a", encoding='utf-8') as file:
        file.write(data+'\n')

def write_list_to_txt2(data, filename):
    with open(filename, "w") as file:
        for row in data:
            file.write(row+'\n')

def read_txt(fname):
    with open(fname, 'r') as fileReader:
        data = fileReader.read().splitlines()
    return data


def get_file_names(commits):
    f_names = []
    for commit in commits:
        f_names.append(commit['file_path'])
    return f_names

def main():

    # with open('statistics/number_of_vfc.txt', 'w') as fp:
    #     pass

    # with open('statistics/number_of_vfc_files.txt', 'w') as fp:
    #     pass

    # with open('statistics/number_of_vic.txt', 'w') as fp:
    #     pass

    # with open('statistics/number_of_vic_files.txt', 'w') as fp:
    #     pass

    
    vic_path = '/media/nimashiri/SSD/V-SZZ/ICSE2022ReplicationPackage/icse2021-szz-replication-package/tools/pyszz/out/test'
    for i, dir in enumerate(os.listdir(vic_path)):
        vic_lib_path = os.path.join(vic_path, dir)
        with open(vic_lib_path, 'r', encoding='utf-8') as f:
            data = json.loads(f.read(),strict=False)
        vic_counter = 0
        for counter, item in enumerate(data):
            print("#########################################################################")
            print('Total number of files analyzed: {}/{}'.format(counter, len(data)))
            print("#########################################################################")
            x = list(item.keys())
            if bool(item[x[0]]):
                for k, commits in item.items():
                    write_list_to_txt(k, 'statistics/number_of_vfc.txt')
                    f_names = list(set(get_file_names(commits)))
                    for commit_counter, commit in enumerate(commits):
                        if 'test' not in commit['file_path']:
                            try:
                                print("#########################################################################")
                                print('Total number of commits analyzed: {}/{}'.format(commit_counter, len(commits)))
                                print("#########################################################################")
                                v = "https://github.com/{0}/{1}{2}".format(user_names[i], dir.split('_')[1].split('.')[0],'.git')
                                if not os.path.exists(this_project+'/ml_repos_cloned/'+user_names[i]+'/'+dir.split('_')[1].split('.')[0]):
                                    subprocess.call('git clone '+v+' '+this_project+'/ml_repos_cloned/'+user_names[i]+'/'+dir.split('_')[1].split('.')[0], shell=True)

                                r = Repo(this_project+'/ml_repos_cloned/'+user_names[i]+'/'+dir.split('_')[1].split('.')[0])
                                subprocess.call("./checkout.sh %s %s" % (this_project+'/ml_repos_cloned/'+user_names[i]+'/'+dir.split('_')[1].split('.')[0], k), shell=True)

                                hcommit = r.head.commit
                                diffs = hcommit.diff('{}~1'.format(hcommit.hexsha), create_patch=True)
                                diffs = [d for d in diffs if str(d.b_path).endswith(".c") or str(d.b_path).endswith(".cc") or str(d.b_path).endswith(".cpp") or str(d.b_path).endswith(".h") or str(d.b_path).endswith(".hpp")]
                                # for d in diffs:
                                #     fname = d.b_path.split('/')[-1]
                                #     if d.b_path in f_names:
                                #         write_list_to_txt(d.b_path, 'statistics/number_of_vfc_files.txt')
                                #         subprocess.check_call("./get_raw_src.sh %s %s %s" % (this_project+'/ml_repos_cloned/'+user_names[i]\
                                #             +'/'+dir.split('_')[1].split('.')[0], d.b_blob.hexsha,\
                                #                 this_project+'/known_vul_files/'+dir.split('_')[1].split('.')[0]+'/0_'+k+'_'+fname), shell=True)

                                previous_commits = commit['previous_commits']
                                for pc in previous_commits:
                                    write_list_to_txt(dir.split('_')[1].split('.')[0]+'_'+pc[0], 'statistics/number_of_vic.txt')
                                    subprocess.check_call("./checkout.sh %s %s" % (this_project+'/ml_repos_cloned/'+user_names[i]+'/'+dir.split('_')[1].split('.')[0], pc[0]), shell=True)
                                    
                                    hcommit = r.head.commit
                                    diffs = hcommit.diff('{}~1'.format(hcommit.hexsha), create_patch=True)
                                    diffs = [d for d in diffs if str(d.a_path).endswith(".c") or str(d.a_path).endswith(".cc") or str(d.a_path).endswith(".cpp") or str(d.a_path).endswith(".h") or str(d.a_path).endswith(".hpp")]
                                    for d in diffs:
                                        fname = d.a_path.split('/')[-1]
                                        if d.a_path in f_names:
                                            write_list_to_txt(d.a_path, 'statistics/number_of_vic_files.txt')
                                            subprocess.check_call("./get_raw_src.sh %s %s %s" % (this_project+'/ml_repos_cloned/'+user_names[i]\
                                                +'/'+dir.split('_')[1].split('.')[0], d.a_blob.hexsha,\
                                                this_project+'/known_vul_files/'+dir.split('_')[1].split('.')[0]+'/1_'+k+'_'+fname), shell=True)
                            except Exception as e:
                                print(e)    
    x = read_txt('statistics/number_of_vic.txt')
    x = set(x)       
    write_list_to_txt2(x, 'statistics/number_of_vic_unique.txt')


if __name__ == '__main__':
    main()