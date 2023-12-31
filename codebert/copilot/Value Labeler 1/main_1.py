import csv

data_ground = []
with open('copilot_codebert_input_new.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
      data_ground.append(row)


data_website_description = []
with open('descriptions.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
      data_website_description.append(row)


data_main = []    # List of lists
# Reading the main score file  
with open('similarity_copilot.csv', 'r') as csvfile:
    reader = csv.reader(csvfile, delimiter=',')
    for row in reader:
        data_main.append(row)

fieldnames = []
for x in data_website_description:
    fieldnames.append(x['id'])


with open('codebert_labeled_1.csv', 'w') as f:
    writer = csv.writer(f, delimiter=',')   
    writer.writerow(fieldnames)
    
    for x in data_main:
        writer.writerow(x)
    