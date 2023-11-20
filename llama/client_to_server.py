# python client_to_server.py hello.txt
# input file contains prompt for llama 2 model to answer
# RUNNING THIS FILE REQUIRES LM STUDIO WITH A LOCAL SERVER ON PORT 8555
# the specific model I used is TheBloke\Llama-2-7B-Chat-GGML
import openai
import sys

openai.api_base='http://localhost:8555/v1'
openai.api_key='something' # leave empty

# 'Llama2 Chat' prompt format:
prefix = "[INST]"
suffix = "[/INST]"


def get_completion(prompt, model="local model", temperature=0.75):
    formatted_prompt = f"{prefix}{prompt}{suffix}"
    messages = [{"role": "user", "content": formatted_prompt}]
    #print(f'{prompt}\n')
    response = openai.ChatCompletion.create(
        model=model,
        messages=messages,
        temperature=temperature
    )
    return response.choices[0].message["content"]


# prompt = """alright so here is a description about a cwe vulnerability "cwe-200 is The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information. There are many different kinds of mistakes that introduce information exposures. The severity of the error can range widely, depending on the context in which the product operates, the type of sensitive information that is revealed, and the benefits it may provide to an attacker. Some kinds of sensitive information include: private, personal information, such as personal messages, financial data, health records, geographic location, or contact details system status and environment, such as the operating system and installed packages business secrets and intellectual property network status and configuration the product's own code or internal state metadata, e.g. logging of connections or message headers indirect information, such as a discrepancy between two internal operations that can be observed by an outsider Information might be sensitive to different parties, each of which may have their own expectations for whether the information should be protected. These parties include: the product's own users people or organizations whose information is created or used by the product, even if they are not direct product users the product's administrators, including the admins of the system(s) and/or networks on which the product operates the developer Information exposures can occur in different ways: the code explicitly inserts sensitive information into resources or messages that are intentionally made accessible to unauthorized actors, but should not contain the information - i.e., the information should have been "scrubbed" or "sanitized" a different weakness or mistake indirectly inserts the sensitive information into resources, such as a web script error revealing the full system path of the program. the code manages resources that intentionally contain sensitive information, but the resources are unintentionally made accessible to unauthorized actors. In this case, the information exposure is resultant - i.e., a different weakness enabled the access to the information in the first place. It is common practice to describe any loss of confidentiality as an "information exposure," but this can lead to overuse of CWE-200 in CWE mapping. From the CWE perspective, loss of confidentiality is a technical impact that can arise from dozens of different weaknesses, such as insecure file permissions or out-of-bounds read. CWE-200 and its lower-level descendants are intended to cover the mistakes that occur in behaviors that explicitly manage, store, transfer, or cleanse sensitive information." With knowledge of this cwe is the code below vulnerable to the specific cwe vulnerability. Please start response with Yes or No depending on the answer.

#         def login():
#         username = request.form['username']
#         password = request.form['password']
#         db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="db")
#         cursor = db.cursor()
#         sql = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
#         try:
#             cursor.execute(sql)
#             results = cursor.fetchall()
#             for row in results:
#                 id = row[0]
#             # log the user in
#             session['id'] = id
#             session['Role'] = row[1]
#             return redirect('/dashboard')
#         except:
#             return redirect('/login')


#         @app.route('/dashboard', methods = ['GET'])"""


prompt = ''
with open(sys.argv[1], 'r') as f:
    prompt = f.read()

response = get_completion(prompt)
print(f"{response}")
