# This file add other columns, and uses codebert_laabeled_1.csv as input

import csv

# For output file
fieldnames = []


data_ground = []
with open('copilot_codebert_input_new.csv', 'r') as f:
    reader = csv.DictReader(f)
    print(reader.fieldnames)
    for row in reader:
      data_ground.append(row)
      
# Read main file
data_main = []
with open('codebert_labeled_1.csv', 'r') as f:
    reader = csv.DictReader(f)  
    fieldnames = reader.fieldnames
    for row in reader:
      data_main.append(row)
    
fieldnames.insert(0, 'Vulnerable') 
fieldnames.insert(0, 'Folder')
fieldnames.insert(0, 'CWE')


print(fieldnames[0])
      
with open('codebert_labeled_2.csv', 'w') as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    
    for x in range(len(data_main)):
        _, id = data_ground[x]['CWE'].split('-')
        
        data_main[x]['CWE'] = id
        data_main[x]['Folder'] = data_ground[x]['Folder']
        data_main[x]['Vulnerable'] = ''
        
        writer.writerow(data_main[x])
        
    
    #for dic in data_main:
     #   dic['Index'] = 
     #   dic['CWE'] =
      #  dic['Vulnerable'] = 
       # writer.writerow(dic)