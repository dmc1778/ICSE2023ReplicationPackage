import os
import pandas as pd

this_project = os.getcwd()

def main():
    for dir in os.listdir('./detection_results/project_level'):
        data = pd.read_csv('./detection_results/project_level/'+dir)
        flawfinder_data = len(data[data.iloc[:, 1] == 'flawfinder'])
        cppcheck_data = len(data[data.iloc[:, 1] == 'cppcheck'])
        rats_data = len(data[data.iloc[:, 1] == 'rats'])


        if len(data[data.iloc[:, 1] == 'flawfinder']) >= 20:
            df_flaw = data[data.iloc[:, 1] == 'flawfinder'].sample(20)

        if len(data[data.iloc[:, 1] == 'cppcheck']) >= 20:
            df_cpp = data[data.iloc[:, 1] == 'cppcheck'].sample(20)
        else:
            df_cpp = data[data.iloc[:, 1] == 'cppcheck'].sample(len(data[data.iloc[:, 1] == 'cppcheck']))

        if len(data[data.iloc[:, 1] == 'rats']) >= 20:
            df_rats = data[data.iloc[:, 1] == 'rats'].sample(20)
        
        df_flaw.to_csv('./detection_results/randomly_selected/flawfinder_'+dir, sep=',')
        df_cpp.to_csv('./detection_results/randomly_selected/cppcheck_'+dir, sep=',')
        df_rats.to_csv('./detection_results/randomly_selected/rats_'+dir, sep=',')



if __name__ == '__main__':
    main()