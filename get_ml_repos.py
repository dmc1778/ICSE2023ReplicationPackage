import os, subprocess

repo_list = [
    'https://github.com/tensorflow/tensorflow',
    'https://github.com/pytorch/pytorch',
    'https://github.com/numpy/numpy',
    'https://github.com/mlpack/mlpack',
    'https://github.com/Artelnics/opennn',
    'https://github.com/scipy/scipy',
    'https://github.com/Reference-LAPACK/lapack'
]

this_project = os.getcwd()

for r in repo_list:
    l = r.split('/')
    v = "https://github.com/{0}/{1}{2}".format(l[3],l[4],'.git')
    if not os.path.exists(this_project+'/ml_repos_cloned/'+l[3]+'/'+l[4]):
        subprocess.call('git clone '+v+' '+this_project+'/ml_repos_cloned/'+l[3]+'/'+l[4], shell=True)