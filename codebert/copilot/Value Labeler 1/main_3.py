import csv

fieldnames = []
data = []
file_name = 'codebert_labeled_2.csv'
with open(file_name, 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        data.append(row)
    

    fieldnames = reader.fieldnames
    
        
data_ground = []
with open('../../../dow_results.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
      data_ground.append(row)
      
with open('codebert_labeled_3.csv', 'w') as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    
    # Add vulnerable key to each dic in data
    for dic in data:
        
        id = dic['CWE']
        
        for dic_ground in data_ground:
            
            _, id_ground = dic_ground['cwe'].split('-')
            _, _, folder_ground = dic_ground['scenario_location'].split('/')
            
            if id == id_ground and dic['Folder'] == folder_ground:
                dic['Vulnerable'] = dic_ground['top_choice_vulnerable']
                break
            
        writer.writerow(dic)
    
    