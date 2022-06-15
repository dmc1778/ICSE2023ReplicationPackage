from asyncore import read
import json
from lib2to3.pgen2 import token
import os
import re
from urllib import request
import requests as r
import requests
import argparse
import sys
import random
import datetime
import time
from filter import read_txt
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# (0, nimashiri2012@gmail.com, 1, cse19922021@gmail.com, 2, nshiri@yorku.ca, 3, nshiri@cse.yorku.ca)
tokens = {0: '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', 1: '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',
          2: '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', 3: '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'}

tokens_status = {'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': True, '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': True,
                 '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': True, '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': True}


def requests_retry_session(
    retries=3,
    backoff_factor=0.3,
    status_forcelist=(500, 502, 504),
    session=None,
):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


retries = 10
#potential_commits = []
now = datetime.datetime.now()


def get_commits(githubUser, currentRepo, qm, page, amp, sh_string, last_com, page_number, branch_sha, potential_commits, current_token):

    #token = os.getenv('GITHUB_TOKEN', token)
    page_number += 1

    if page_number == 1:
        first_100_commits = "https://api.github.com/repos/" + githubUser + "/" + \
            currentRepo+"/commits" + qm + page + amp + sh_string + branch_sha
    else:
        first_100_commits = "https://api.github.com/repos/" + githubUser + \
            "/"+currentRepo+"/commits" + qm + page + amp + sh_string + last_com

    # response = r.get(first_100_commits, headers={'Authorization': 'token {}'.format(token)})

    t0 = time.time()

    response = requests_retry_session().get(first_100_commits, headers={
        'Authorization': 'token {}'.format(current_token)})
    if response.status_code != 200:
        tokens_status[current_token] = False
        current_token = select_access_token(current_token)
        response = requests_retry_session().get(first_100_commits, headers={
            'Authorization': 'token {}'.format(current_token)})

    if response.status_code != 200:
        tokens_status[current_token] = False
        current_token = select_access_token(current_token)
        response = requests_retry_session().get(first_100_commits, headers={
            'Authorization': 'token {}'.format(current_token)})

    if response.status_code != 200:
        tokens_status[current_token] = False
        current_token = select_access_token(current_token)
        response = requests_retry_session().get(first_100_commits, headers={
            'Authorization': 'token {}'.format(current_token)})

    if response.status_code != 200:
        tokens_status[current_token] = False
        current_token = select_access_token(current_token)
        response = requests_retry_session().get(first_100_commits, headers={
            'Authorization': 'token {}'.format(current_token)})

    first_100_commits = json.loads(response.text)

    if len(first_100_commits) == 1:
        return None
    for i, commit in enumerate(first_100_commits):
        #print('Total number of fetched commits: {}, page:{}, branch: {}'.format(i, page_number, branch_sha))

        memory_related_rules = r"(denial of service|DOS|remote code execution|CVE|ReDoS|NVD|malicious|attack|exploit|RCE|advisory|insecure|security|infinite.loop|bypass|injection|overflow|(in)?secur(e|ity)|Heap buffer overflow|Integer division by zero|Undefined behavior|Heap OOB write|Division by zero|Crashes the Python interpreter|Heap overflow|Uninitialized memory accesses|Heap OOB access|Heap underflow|Heap OOB|Heap OOB read|Segmentation faults|Segmentation fault|seg fault|Buffer overflow|Null pointer dereference|FPE runtime|segfaults|segfault|attack|corrupt|crack|craft|CVE-|deadlock|deep recursion|denial-of-service|divide by 0|divide by zero|divide-by-zero|division by zero|division by 0|division-by-zero|division-by-0|double free|endless loop|leak|initialize|insecure|invalid|info leak|null deref|null-deref|NULL dereference|null function pointer|null pointer dereference|null-ptr|null-ptr-deref|OOB|out of bound|out-of-bound|overflow|protect|race|race condition|RCE|remote code execution|sanity check|sanity-check|security|security fix|security issue|security problem|snprintf|undefined behavior|underflow|uninitialize|use after free|use-after-free|violate|violation|vsecurity|vuln|vulnerab)"
        _rule = r"(denial of service|DOS|XXE|remote code execution|bopen redirect|OSVDB|bvuln|CVE|XSS|ReDoS|NVD|malicious|x−frame−options|attack|cross-site|exploit|directory traversal|RCE|XSRF|clickjack|session-fixation|hijack|advisory|insecure|security|cross-origin|unauthori[z|s]ed|infinite.loop|brute force|bypass|constant time|crack|credential|expos(e|ing|ure)|hack|harden|injection|lockout|overflow|password|PoC|proof of concept|priveale|(in)?secur(e|ity)|Heap buffer overflow|Integer division by zero|Undefined behavior|Heap OOB write|Division by zero|Crashes the Python interpreter|Heap overflow|Uninitialized memory accesses|Heap OOB access|Heap underflow|Heap OOB|Heap OOB read|Segmentation faults|Segmentation fault|seg fault|Buffer overflow|Null pointer dereference|FPE runtime|segfaults|segfault|attack|authenticate|authentication|checkclickjack|compromise|constant-time|corrupt|crack|craft|credential|cross Site Request Forgery|cross-Site Request Forgery|CVE-|Dan Rosenberg|deadlock|deep recursion|denial-of-service|directory traversal|disclosure|divide by 0|divide by zero|divide-by-zero|division by zero|division by 0|division-by-zero|division-by-0|double free|endless loop|exhaust|dos|fail|fixes CVE-|forgery|fuzz|general protection fault|GPF|grsecurity|guard|leak|initialize|insecure|invalid|KASAN|info leak|limit|lockout|long loop|loop|man in the middle|man-in-the-middle|mishandle|MITM|negative|null deref|null-deref|NULL dereference|null function pointer|null pointer dereference|null-ptr|null-ptr-deref|off-by-one|OOB|oops|open redirect|oss-security|out of array|out of bound|out-of-bound|overflow|overread|override|overrun|panic|password|poison|prevent|privesc|privilege|protect|race|race condition|RCE|remote code execution|replay|sanity check|sanity-check|security|security fix|security issue|security problem|session fixation|snprintf|spoof|syzkaller|trinity|unauthorized|undefined behavior|underflow|unexpected|uninitialize|unrealize|use after free|use-after-free|valid|verification|verifies|verify|violate|violation|vsecurity|vuln|vulnerab|XML External Entity)"
        _match = re.findall(_rule, commit['commit']['message'])
        _date = commit['commit']['committer']['date']
        sdate = _date.split('-')
        if _match:
            print('got one!')
            _date = commit['commit']['committer']['date']
            sdate = _date.split('-')
            # if any(commit['html_url'] in s for s in commit_data) == False:
            potential_commits.append(commit['html_url'])
            # else:
            # print('Already Extracted')
    #   print('I found a relevant commit from:  {}'.format(int(sdate[0])))
    #   if ending_date is None:
    #     if int(sdate[0]) >= start_date and int(sdate[0]) <= now.year:
    #         print(len(potential_commits))

    #   else:
    #     if int(sdate[0]) >= start_date and int(sdate[0]) <= ending_date:
    #         print(len(potential_commits))
    #         potential_commits.append(commit['html_url'])

        if i == len(first_100_commits)-1:
            last_com = commit['sha']
            get_commits(githubUser, currentRepo, qm, page, amp, sh_string,
                        last_com, page_number, branch_sha, potential_commits, current_token)


def search_comit_data(c, commit_data):
    t = []

    for item in commit_data:
        temp = item.split('/')
        t.append('/' + temp[3] + '/' + temp[4] + '/')

    r_prime = c.split('/')
    x = '/' + r_prime[3] + '/' + r_prime[4] + '/'
    if any(x in s for s in t):
        return True
    else:
        return False


def select_access_token(current_token):
    x = ''
    if all(value == False for value in tokens_status.values()):
        for k, v in tokens_status.items():
            tokens_status[k] = True

    for k, v in tokens.items():
        if tokens_status[v] != False:
            x = v
            break
    current_token = x
    return current_token



def main():

    repo_list = [
        'https://github.com/tensorflow/tensorflow'
        # 'https://github.com/mlpack/mlpack',
        # 'https://github.com/Artelnics/opennn',
        # 'https://github.com/scipy/scipy',
        # 'https://github.com/Reference-LAPACK/lapack'
    ]


    if not os.path.exists('./commits'):
        os.makedirs('./commits')

    current_token = tokens[0]
    for lib in repo_list:
                x = []
                # if search_comit_data(c, commit_data) == False:
                potential_commits = []
                #print('Repo {0}/{1}/{2} The token is '.format(j, len(data), current_token))
                r_prime = lib.split('/')

                qm = '?'
                page = 'per_page='+str(100)
                amp = '&'
                sh_string = "sha="

                branchLink = "https://api.github.com/repos/{0}/{1}/branches".format(
                    r_prime[3], r_prime[4])

                t0 = time.time()
                response = requests_retry_session().get(
                    branchLink, headers={'Authorization': 'token {}'.format(current_token)})
                if response.status_code != 200:
                    tokens_status[current_token] = False
                    current_token = select_access_token(current_token)
                    response = requests_retry_session().get(
                        branchLink, headers={'Authorization': 'token {}'.format(current_token)})

                if response.status_code != 200:
                    tokens_status[current_token] = False
                    current_token = select_access_token(current_token)
                    response = requests_retry_session().get(
                        branchLink, headers={'Authorization': 'token {}'.format(current_token)})

                if response.status_code != 200:
                    tokens_status[current_token] = False
                    current_token = select_access_token(current_token)
                    response = requests_retry_session().get(
                        branchLink, headers={'Authorization': 'token {}'.format(current_token)})

                if response.status_code != 200:
                    tokens_status[current_token] = False
                    current_token = select_access_token(current_token)
                    response = requests_retry_session().get(
                        branchLink, headers={'Authorization': 'token {}'.format(current_token)})

                branches = json.loads(response.text)

                # if branches != []:
                try:
                    selected_branch = random.choice(branches)
                    branch_sha = selected_branch['commit']['sha']

                    page_number = 0

                    first_100_commits = "https://api.github.com/repos/" + \
                        r_prime[3] + "/"+r_prime[4]+"/commits" + \
                        qm + page + amp + sh_string + branch_sha

                    t0 = time.time()

                    response = requests_retry_session().get(first_100_commits, headers={
                        'Authorization': 'token {}'.format(current_token)})
                    if response.status_code != 200:
                        tokens_status[current_token] = False
                        current_token = select_access_token(current_token)
                        response = requests_retry_session().get(first_100_commits, headers={
                            'Authorization': 'token {}'.format(current_token)})

                    if response.status_code != 200:
                        tokens_status[current_token] = False
                        current_token = select_access_token(current_token)
                        response = requests_retry_session().get(first_100_commits, headers={
                            'Authorization': 'token {}'.format(current_token)})

                    if response.status_code != 200:
                        tokens_status[current_token] = False
                        current_token = select_access_token(current_token)
                        response = requests_retry_session().get(first_100_commits, headers={
                            'Authorization': 'token {}'.format(current_token)})

                    if response.status_code != 200:
                        tokens_status[current_token] = False
                        current_token = select_access_token(current_token)
                        response = requests_retry_session().get(first_100_commits, headers={
                            'Authorization': 'token {}'.format(current_token)})

                    first_100_commits = json.loads(response.text)

                    if len(first_100_commits) >= 100:
                        last_com = first_100_commits[-1]['sha']
                        get_commits(r_prime[3], r_prime[4], qm, page, amp, sh_string, last_com,
                                    page_number, branch_sha, potential_commits, current_token)
                        

                        with open('./commits/'+r_prime[4], 'a') as f:
                        #with open('./'+r_prime[4]+file, 'a') as f:
                            for item in potential_commits:
                                f.write("%s\n" % item)
                    else:
                        memory_related_rules = r"(denial of service|DOS|remote code execution|CVE|ReDoS|NVD|malicious|attack|exploit|RCE|advisory|insecure|security|infinite.loop|bypass|injection|overflow|(in)?secur(e|ity)|Heap buffer overflow|Integer division by zero|Undefined behavior|Heap OOB write|Division by zero|Crashes the Python interpreter|Heap overflow|Uninitialized memory accesses|Heap OOB access|Heap underflow|Heap OOB|Heap OOB read|Segmentation faults|Segmentation fault|seg fault|Buffer overflow|Null pointer dereference|FPE runtime|segfaults|segfault|attack|corrupt|crack|craft|CVE-|deadlock|deep recursion|denial-of-service|divide by 0|divide by zero|divide-by-zero|division by zero|division by 0|division-by-zero|division-by-0|double free|endless loop|leak|initialize|insecure|invalid|info leak|null deref|null-deref|NULL dereference|null function pointer|null pointer dereference|null-ptr|null-ptr-deref|OOB|out of bound|out-of-bound|overflow|protect|race|race condition|RCE|remote code execution|sanity check|sanity-check|security|security fix|security issue|security problem|snprintf|undefined behavior|underflow|uninitialize|use after free|use-after-free|violate|violation|vsecurity|vuln|vulnerab)"
                        _rule = r"(denial of service|DOS|XXE|remote code execution|bopen redirect|OSVDB|bvuln|CVE|XSS|ReDoS|NVD|malicious|x−frame−options|attack|cross-site|exploit|directory traversal|RCE|XSRF|clickjack|session-fixation|hijack|advisory|insecure|security|cross-origin|unauthori[z|s]ed|infinite.loop|brute force|bypass|constant time|crack|credential|expos(e|ing|ure)|hack|harden|injection|lockout|overflow|password|PoC|proof of concept|priveale|(in)?secur(e|ity)|Heap buffer overflow|Integer division by zero|Undefined behavior|Heap OOB write|Division by zero|Crashes the Python interpreter|Heap overflow|Uninitialized memory accesses|Heap OOB access|Heap underflow|Heap OOB|Heap OOB read|Segmentation faults|Segmentation fault|seg fault|Buffer overflow|Null pointer dereference|FPE runtime|segfaults|segfault|attack|authenticate|authentication|checkclickjack|compromise|constant-time|corrupt|crack|craft|credential|cross Site Request Forgery|cross-Site Request Forgery|CVE-|Dan Rosenberg|deadlock|deep recursion|denial-of-service|directory traversal|disclosure|divide by 0|divide by zero|divide-by-zero|division by zero|division by 0|division-by-zero|division-by-0|double free|endless loop|exhaust|dos|fail|fixes CVE-|forgery|fuzz|general protection fault|GPF|grsecurity|guard|leak|initialize|insecure|invalid|KASAN|info leak|limit|lockout|long loop|loop|man in the middle|man-in-the-middle|mishandle|MITM|negative|null deref|null-deref|NULL dereference|null function pointer|null pointer dereference|null-ptr|null-ptr-deref|off-by-one|OOB|oops|open redirect|oss-security|out of array|out of bound|out-of-bound|overflow|overread|override|overrun|panic|password|poison|prevent|privesc|privilege|protect|race|race condition|RCE|remote code execution|replay|sanity check|sanity-check|security|security fix|security issue|security problem|session fixation|snprintf|spoof|syzkaller|trinity|unauthorized|undefined behavior|underflow|unexpected|uninitialize|unrealize|use after free|use-after-free|valid|verification|verifies|verify|violate|violation|vsecurity|vuln|vulnerab|XML External Entity)"
                        try:
                            temp = []
                            for i, com in enumerate(first_100_commits):
                                #print('Total number of fetched commits: {}, page:{}, branch: {}'.format(i, page_number, branch_sha))
                                _match = re.findall(_rule, com['commit']['message'])
                                if _match:
                                    x = requests_retry_session().get(com['url'])
                                    x = json.loads(x.text)
                                    print('got one!')
                                    # if any(com['html_url'] in s for s in commit_data) == False:
                                    temp.append(com['html_url'])
                                    # else:
                                    #print('Already Extracted')
                        except Exception as e:
                            print(e)

                        with open('./commits/'+r_prime[4], 'a') as f:
                            for item in temp:
                                f.write("%s\n" % item)

                except Exception as e:
                    print(e)
# 13915
if __name__ == "__main__":
    main()