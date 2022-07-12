from importlib.resources import path
import pandas as pd
import os, subprocess
from csv import writer

this_project = os.getcwd()

user_names = {'mlpack': os.path.join(this_project, 'ml_repos_cloned', 'mlpack', 'mlpack')
, 'numpy': os.path.join(this_project, 'ml_repos_cloned', 'numpy')\
     , 'pandas': os.path.join(this_project, 'ml_repos_cloned', 'pandas-dev')\
         , 'pytorch': os.path.join(this_project, 'ml_repos_cloned', 'pytorch') \
             , 'scipy': os.path.join(this_project, 'ml_repos_cloned', 'scipy')\
                  , 'tensorflow': os.path.join(this_project, 'ml_repos_cloned', 'tensorflow')}

def main():

    data = pd.read_csv(os.path.join(this_project, 'detection_results', 'workflow1', 'reem.csv'), sep=',', encoding='utf-8')
    for i in range(len(data)):
        print('The total number of files analyzed {}/{}'.format(i, len(data)-1))
        current_path = user_names[data.iloc[i, 1]]
        if os.path.isfile(os.path.join(current_path, data.iloc[i, 2])):
            output = subprocess.getoutput('cppcheck --enable=all --suppress=missingIncludeSystem --xml '+os.path.join(current_path, data.iloc[i, 2]))
            my_data = [data.iloc[i, 2], output]
            with open('cppcheck_res.csv', 'a', newline='\n') as fd:
                writer_object = writer(fd)
                writer_object.writerow(my_data)
    #         cmd_out_col.append(output)

    # cmd_out_col = pd.DataFrame(cmd_out_col, columns=['cppcheck_results'])
    # new_data = pd.concat((data, cmd_out_col), axis=1)
    # new_data.to_csv('cppcheck_res.csv', index=False, sep=',')

    

if __name__ == '__main__':
    main()