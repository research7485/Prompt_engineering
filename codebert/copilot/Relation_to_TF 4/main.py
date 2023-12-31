import sys
import csv 

data_not_ground = []
with open('input/codebert_copilot_relation_98_T10.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
      data_not_ground.append(row)
      
    
    

with open('output/relation_copilot_with_98_T10.csv', 'w') as f:
    writer = csv.DictWriter(f, fieldnames=['CWE', 'Folder', 'Vulnerable', 'relation-with-Top-3', '#relevant-top-3', 'relations', 'TP', 'TN', 'FP', 'FN', 'Extra FN', 'similar-id-1', 'similar-id-2', 'similar-id-3', 'similar-id-4', 'similar-id-5', 'similar-id-6', 'similar-id-7', 'similar-id-8', 'similar-id-9', 'similar-id-10'])
    writer.writeheader()
    for x in data_not_ground:
        record = {'Folder': x['Folder'],
                  'CWE': x['CWE'],
                  'Vulnerable': x['Vulnerable'],
                'relation-with-Top-3': x['relation-with-Top-3'],
                '#relevant-top-3': x['#relevant-top-3'],
                'relations': x['relations'],
                'similar-id-1': x['similar-id-1'],
                'similar-id-2': x['similar-id-2'],
                'similar-id-3': x['similar-id-3'],
                'similar-id-4': x['similar-id-4'],
                'similar-id-5': x['similar-id-5'],
                'similar-id-6': x['similar-id-6'],
                'similar-id-7': x['similar-id-7'],
                'similar-id-8': x['similar-id-8'],
                'similar-id-9': x['similar-id-9'],
                'similar-id-10': x['similar-id-10'],
                'TP': '',
                'TN': '',
                'FP': '',
                'FN': '',
                'Extra FN': ''}
            
        
        #print(x['#relevant-top-3'], y['top_choice_vulnerable'])
                    
        if int(x['#relevant-top-3']) > 0 and x['Vulnerable'] == 'True': #Something return by sbert (at least cwe must be related to original cwe) and actually vulnerable
            record['TP'] = 'Yes'
            
        elif x['similar-id-1'] != '' and x['Vulnerable'] == 'False':  #Something return by sbert and actually not vulnerable
            record['FP'] = 'Yes'
            
        elif (x['similar-id-1'] == '' and  x['Vulnerable'] == 'True'): # Nothing return by sbert and actually vulnerable
            record['FN'] = 'Yes'
            
        elif x['similar-id-1'] == '' and x['Vulnerable'] == 'False':    #Nothing return by sbert and actually not vulnerable
            record['TN'] = 'Yes'
        
        elif (x['similar-id-1'] != '' and int(x['#relevant-top-3']) == 0 and x['Vulnerable'] == 'True'):
            record['Extra FN'] = 'Yes'
                    
        writer.writerow(record) 