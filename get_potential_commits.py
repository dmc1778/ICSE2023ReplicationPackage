
import this
from numpy import diff
from filter import read_txt, write_list_to_txt4
import os
from git import Repo
import subprocess
import re
import pandas as pd

repo_list = [
    'https://github.com/mlpack/mlpack',
    'https://github.com/Artelnics/opennn',
    'https://github.com/scipy/scipy',
    'https://github.com/Reference-LAPACK/lapack'
]

branches = ['master', 'master', 'master', 'main']

f = ['opennn', 'mlpack', 'numpy','pytorch', 'lapack', 'scipy', 'tensorflow']

this_project = os.getcwd()

# def main():
#     for root, dir, libs in os.walk(this_project+'/commits'):
#         for i, lib in enumerate(libs):
#             current_file = root + '/' + lib
#             data = read_txt(current_file)
#             for counter, llink in enumerate(data):
#                 l = llink.split('/')
#                 v = "https://github.com/{0}/{1}{2}".format(l[3],l[4],'.git')
#                 r = Repo(this_project+'/ml_repos_cloned/'+l[3]+'/'+l[4])
#                 commitList = list(r.iter_commits(branches[i], max_count=30000))
#                 for commit in commitList:
#                     subprocess.check_call("./checkout.sh %s %s" % (this_project+'/ml_repos_cloned/'+l[3]+'/'+l[4], l[-1]), shell=True)
                    
#                     hcommit = r.head.commit

#                     diffs = hcommit.diff('{}~1'.format(hcommit.hexsha), create_patch=True)
#                     diffs = [d for d in diffs if str(d.a_path).endswith(".c") or str(d.a_path).endswith(".cc") or str(d.a_path).endswith(".cpp")]
#                     for d in diffs:
#                         filename = d.a_path.split('/')[-1]
_rule = r"(denial of service|DOS|XXE|remote code execution|bopen redirect|OSVDB|bvuln|CVE|XSS|ReDoS|NVD|malicious|x−frame−options|attack|cross-site|exploit|directory traversal|RCE|XSRF|clickjack|session-fixation|hijack|advisory|insecure|security|cross-origin|unauthori[z|s]ed|infinite.loop|brute force|bypass|constant time|crack|credential|expos(e|ing|ure)|hack|harden|injection|lockout|overflow|password|PoC|proof of concept|priveale|(in)?secur(e|ity)|Heap buffer overflow|Integer division by zero|Undefined behavior|Heap OOB write|Division by zero|Crashes the Python interpreter|Heap overflow|Uninitialized memory accesses|Heap OOB access|Heap underflow|Heap OOB|Heap OOB read|Segmentation faults|Segmentation fault|seg fault|Buffer overflow|Null pointer dereference|FPE runtime|segfaults|segfault|attack|authenticate|authentication|checkclickjack|compromise|constant-time|corrupt|crack|craft|credential|cross Site Request Forgery|cross-Site Request Forgery|CVE-|Dan Rosenberg|deadlock|deep recursion|denial-of-service|directory traversal|disclosure|divide by 0|divide by zero|divide-by-zero|division by zero|division by 0|division-by-zero|division-by-0|double free|endless loop|exhaust|dos|fail|fixes CVE-|forgery|fuzz|general protection fault|GPF|grsecurity|guard|leak|initialize|insecure|invalid|KASAN|info leak|limit|lockout|long loop|loop|man in the middle|man-in-the-middle|mishandle|MITM|negative|null deref|null-deref|NULL dereference|null function pointer|null pointer dereference|null-ptr|null-ptr-deref|off-by-one|OOB|oops|open redirect|oss-security|out of array|out of bound|out-of-bound|overflow|overread|override|overrun|panic|password|poison|prevent|privesc|privilege|protect|race|race condition|RCE|remote code execution|replay|sanity check|sanity-check|security|security fix|security issue|security problem|session fixation|snprintf|spoof|syzkaller|trinity|unauthorized|undefined behavior|underflow|unexpected|uninitialize|unrealize|use after free|use-after-free|valid|verification|verifies|verify|violate|violation|vsecurity|vuln|vulnerab|XML External Entity)"
memory_related_rules = r"(denial of service|DOS|remote code execution|CVE|ReDoS|NVD|malicious|attack|exploit|RCE|advisory|insecure|security|infinite.loop|bypass|injection|overflow|(in)?secur(e|ity)|Heap buffer overflow|Integer division by zero|Undefined behavior|Heap OOB write|Division by zero|Crashes the Python interpreter|Heap overflow|Uninitialized memory accesses|Heap OOB access|Heap underflow|Heap OOB|Heap OOB read|Segmentation faults|Segmentation fault|seg fault|Buffer overflow|Null pointer dereference|FPE runtime|segfaults|segfault|attack|corrupt|crack|craft|CVE-|deadlock|deep recursion|denial-of-service|divide by 0|divide by zero|divide-by-zero|division by zero|division by 0|division-by-zero|division-by-0|double free|endless loop|leak|initialize|insecure|invalid|info leak|null deref|null-deref|NULL dereference|null function pointer|null pointer dereference|null-ptr|null-ptr-deref|OOB|out of bound|out-of-bound|overflow|protect|race|race condition|RCE|remote code execution|sanity check|sanity-check|security|security fix|security issue|security problem|snprintf|undefined behavior|underflow|uninitialize|use after free|use-after-free|violate|violation|vsecurity|vuln|vulnerab)"

def get_files_from_potential_commits():
    df = pd.read_csv('data/vul_data.csv', sep=',')
    for index, row in df.iterrows():
        commit_link = df.iloc[index, 2]
        split_link = commit_link.split('/')
        v = "https://github.com/{0}/{1}{2}".format(split_link[3],split_link[4],'.git')
        if not os.path.exists(this_project+'/ml_repos_cloned/'+split_link[3]+'/'+split_link[4]):
            subprocess.call('git clone '+v+' '+this_project+'/ml_repos_cloned/'+split_link[3]+'/'+split_link[4], shell=True)
        
        r = Repo(this_project+'/ml_repos_cloned/'+split_link[3]+'/'+split_link[4])

        subprocess.check_call("./checkout.sh %s %s" % (this_project+'/ml_repos_cloned/'+split_link[3]+'/'+split_link[4], split_link[-1]), shell=True)
        
        try:
            hcommit = r.head.commit
            diffs = hcommit.diff('{}~1'.format(hcommit.hexsha), create_patch=True)
            diffs = [d for d in diffs if str(d.a_path).endswith(".c") or str(d.a_path).endswith(".cc") or str(d.a_path).endswith(".cpp") or str(d.a_path).endswith(".h") or str(d.a_path).endswith(".hpp")]

            for d in diffs:
                
                # ext = d.a_path.split('/')[-1].split('.')[-1]
                    if 'test' not in d.a_blob.abspath:
                        if not os.path.exists(this_project+'/vul_files/'+df.iloc[index, 0]+'/'):
                            os.makedirs(this_project+'/vul_files/'+df.iloc[index, 0]+'/')
                        subprocess.check_call("./get_raw_src.sh %s %s %s" % (this_project+'/ml_repos_cloned/'+split_link[3]+'/'+split_link[4], d.a_blob.hexsha, this_project+'/vul_files/'+df.iloc[index, 0]+'/'+hcommit.hexsha+'_'+df.iloc[index, 1]+'_'+d.a_blob.name), shell=True)
                        print('d')
        except Exception as e:
            print(e)

def get_potential_commits():
    base = 'https://github.com/'
    for root, dir, libs in os.walk(this_project+'/ml_repos_cloned'):
        for _dir in dir:
            current_lib = os.path.join(root, _dir)
            j = os.listdir(current_lib)[0]
            current_lib = os.path.join(root, _dir, j)
            r = Repo(current_lib)
            commitList = list(r.iter_commits(r.heads[0].name, max_count=30000))
            temp = []
            for commit in commitList:
                # subprocess.check_call("./checkout.sh %s %s" % (this_project+'/ml_repos_cloned/'+l[3]+'/'+l[4], l[-1]), shell=True)
                        
                # hcommit = r.head.commit
      
                _match = re.findall(memory_related_rules, commit.message)
                if _match:
                    diffs = commit.diff('{}~1'.format(commit.hexsha), create_patch=True)

                    diffs = [d for d in diffs if str(d.a_path).endswith(".c") or str(d.a_path).endswith(".cc") or str(d.a_path).endswith(".cpp")]

                    if diffs:
                        project_git_url = os.path.join(base,_dir, j)
                        project_git_url = project_git_url + '/commit/' + commit.hexsha
                        temp.append(project_git_url)

            with open('./commits_local/'+j, 'a') as f:
                for item in temp:
                    f.write("%s\n" % item)


if __name__ == '__main__':
    get_files_from_potential_commits()
    # get_potential_commits()