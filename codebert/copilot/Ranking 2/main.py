import csv

data = []
with open('codebert_labeled_3.csv', 'r') as f:
    writer = csv.DictReader(f)
    for row in writer:
        data.append(row)

skipped = 0
sum = 0
count = 0
all_values = []
with open('codebert_copilot_ranked_98_T10.csv', 'w') as f:
    fieldnames = ['CWE', 'Folder', 'Vulnerable',
                  'Ground_Ranking', 'Ground_Score', 'Id_of_description_1', 'Score_1', 'Id_of_description_2', 'Score_2', 'Id_of_description_3', 'Score_3', 'Id_of_description_4', 'Score_4', 'Id_of_description_5', 'Score_5', 'Id_of_description_6', 'Score_6', 'Id_of_description_7', 'Score_7', 'Id_of_description_8', 'Score_8', 'Id_of_description_9', 'Score_9', 'Id_of_description_10', 'Score_10']
    
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
   
    for dic in data:
        
        record = {
            'Folder': dic['Folder'], 'CWE': dic['CWE'],
            'Vulnerable': dic['Vulnerable']
        }
        dic_of_scores = []
        # get the dictionary where value is float (only)
        for key, value in dic.items():
            if key.isnumeric():
                temp_dic = {}
                temp_dic['id'] = key
                temp_dic['score'] = round(float(value), 4)
                
                #! Next two lines are for threshold sum
                all_values.append(temp_dic['score'])
                count += 1
                
                dic_of_scores.append(temp_dic)
              
        sorted_dic_of_scores = sorted(dic_of_scores, key=lambda d: d['score'], reverse=True)  
        
        # Get top 3 closest
        for i, _ in enumerate(sorted_dic_of_scores[:10]):
          if sorted_dic_of_scores[i]['score'] >= 0.7113:
            record['Id_of_description_' + str(i+1)] = sorted_dic_of_scores[i]['id']
            record['Score_' + str(i+1)] = sorted_dic_of_scores[i]['score']
            #count += 1
            #sum += sorted_dic_of_scores[i]['score']
          else:
              break
          
          #! Next two lines are for threshold sum
          #sum += record['Score_' + str(i+1)]
          
          #count += 1
    
        # Getting ground ranking only for vulnerable methods
        if dic['Vulnerable'] == 'True':
            ranked = False
            # Add the ground truth prosition and score
            for i, zdic in enumerate(sorted_dic_of_scores): # For each dictionary
                if zdic['id'] == dic['CWE']:
                    record['Ground_Ranking'] = i + 1
                    record['Ground_Score'] = zdic['score']
                    ranked = True
            if ranked:      
                writer.writerow(record)
            else:
                skipped += 1       # Skipped if CWE is vunerbale func is not found in database
            
        else:
            writer.writerow(record)
    
print("Skipped:", skipped)
#print("Count: {}".format(count))
#print("Sum: {}".format(sum))
#print("Average: {}".format(sum/count))

print("Count: {}".format(count))
sorted_values = sorted(all_values)
print(len(sorted_values))
# Calculate the index for the top 10%
index = int(0.98 * len(sorted_values))

# Calculate the threshold
threshold = sorted_values[index]
print(f'Threshold: {threshold}')
    
    


