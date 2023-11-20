#![allow(dead_code)] // removes warning of unused code file scope

use std::{io::prelude::*, fs::File};
// puts all file text into string
fn open_file(file_name: &str) -> String {
    use std::fs;

    let mut file = fs::File::open(file_name).expect("file was not found");
    let mut text = String::new();
    file.read_to_string(&mut text)
        .expect("file did not read correctly to a string the file should be encoded into utf8");

    text
}

// creates a file with content
fn create_file(file_name: &str, content: &String) {
    let file = match std::fs::File::create(file_name) {
        Ok(v) => Some(v),
        Err(_) => {
            println!("FILE WAS NOT CREATED SUCCESSFULLY {}", file_name);
            None
        }
    };

    if let Some(mut val) = file {
        match val.write_all(content.as_bytes()) {
            Ok(_v) => {}
            Err(_e) => {
                println!("FILE DID NOT WRITE CORRECTLY {}", file_name);
            }
        }
    }
}

fn remove_file(file_name: &str) {
    match std::fs::remove_file(file_name) {
        Ok(_v) => {},
        Err(_e) => {},
    }
}


fn add_line_to_csv(content:Vec<&str>, file:&File) {
    let mut wtr = csv::Writer::from_writer(file);
    wtr.write_record(content).expect("record did not write correctly");
    wtr.flush().expect("did not flush correctly");
}

// LLAMA_SERVER
// fn run_server_command(file_path:&str) -> String {
//     // ./server --model llama-2-13b-chat.Q4_0.gguf --port 8555 -b 512 --n-gpu-layers 80 -c 4096 //2>/dev/null
//     let output = std::process::Command::new("sh")
//         .args([
//             "-c", //"echo hello",
//             &("./main -n 100 -t 64 -ngl 95 -c 4096 -m llama-2-13b-chat.Q5_0.gguf --ignore-eos --temp 75 --file ".to_string() + file_path + " 2>/dev/null"),
//         ])
//         .stderr(std::process::Stdio::inherit())
//         .output()
//         .expect("failed to execute process");

//     let ans = match std::str::from_utf8(&output.stdout) {
//         Ok(v) => v,
//         Err(_e) => return "".to_string(),
//     };
    
//     ans.to_string()

//     // .args([
//     //     "-c", //"echo hello",
//     //     "./main",
//     //     "-n 150",
//     //     "-t 128",
//     //     "-ngl 50",
//     //     "-c 4096",
//     //     "-m llama-2-13b-chat.Q5_0.gguf",
//     //     "--ignore-eos",
//     //     "--file",
//     //     file_path,
//     // ])
// }

// CMAKE_ARGS="-DLLAMA_CUBLAS=on" FORCE_CMAKE=1 pip install llama-cpp-python[server] --force-reinstall
// python3 -m llama_cpp.server --model llama-2-70b-chat.Q4_0.gguf --port 8555 --n_threads 64 --n_batch 512 --n_gpu_layers 90 --n_ctx 40000
// exececutes the python script client_to_server.py
// cd examples/server
// python api_like_OAI.py --llama-api 8554 --port 8555
fn run_server_command(file_path: &str) -> String {
    let output = std::process::Command::new("sh")
        .args([
            "-c", //"echo hello",
            &("python ".to_string() + "client_to_server.py " + file_path),
        ])
        .stderr(std::process::Stdio::inherit())
        .output()
        .expect("failed to execute process");

    std::str::from_utf8(&output.stdout).unwrap().to_string()
}

// will get the cwe and return its desc
fn find_target(target: &str) -> Option<String> {
    let text = open_file("cwe_items.txt");
    let lines: Vec<&str> = text.split('\n').collect();

    // finds the target line within the parsed_items file
    // 1 line fanciness
    //println!("{}", text);

    let cwe_pos = match lines.iter().position(|x| x.contains(target)) {
        Some(v) => v,
        None => {return None},
    };

    Some(lines[cwe_pos].to_string())
}

// instead of using the cwe provided we give it 3 similar cwe desc
// needs to find the cwe in the similar file and using those 3 cwes find their desc in cwe_items.txt and return them as the answer instead
fn find_similar_target(idx: &str, top:usize, similar_cwe_file:&str) -> Option<String> {
    fn get_similar_entry(entry:String) -> String {
        if entry.len() > 0 {
            let cwe = "cwe-".to_string() + &entry;
            let txt = find_target(&cwe);
            if txt.is_some() {
                return txt.unwrap();
            }
            else {
                println!("did not find cwe-{}", entry);
            }
        }
        String::new()
    }

    //let text = open_file("bv_similar.csv");
    let text = open_file(similar_cwe_file);
    let mut rdr = csv::Reader::from_reader(text.as_bytes());

    let mut ans = String::new();
    for record in rdr.records().flatten() {
        if idx == &record[0] {
            for num in 2..top+2 {
                ans += &get_similar_entry(record[num].to_string());
            }
        }
    }
    
    if ans.len() < 10 {
        return None;
    }

    Some(ans)
}

fn get_random_cwe() -> String {
    use rand::Rng;

    let text = open_file("cwe_items.txt");
    let lines: Vec<&str> = text.split('\n').collect();
    
    let mut rng = rand::thread_rng();
    let pos = rng.gen_range(0..lines.len());

    lines[pos].to_string()
}

// this function instead of manually parsing uses csv struct in std to read from the big vul dataset
fn run_big_vul_dataset_commands(file_name: &str, output_file_name: &str, similar:bool, non_vulnerable_only:bool, random:bool, top:usize, similar_cwe_file:&str) {
    let content = open_file(file_name);
    let mut rdr = csv::Reader::from_reader(content.as_bytes());
    let mut total_millis: f64 = 0.0;
    let mut total: f64 = 0.0;
    let all_vulnerabilies: f64 = 8921.0;

    // this file is created and removed each iteration to hold the prompt in a file as a command arg for client_to_sever.py
    let tmp_file = "bigvul_dataset_tmp_file.txt"; 
    let search_for_answer_limit = 50;

    remove_file(tmp_file);

    // file struct is created so program can pick up where it left off if program closes reading from output file
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .append(true)
        .open(output_file_name)
        .unwrap();

    let mut skip_amount_rdr = csv::Reader::from_reader(&file);

    let skip_amount = match skip_amount_rdr.records().flatten().last(){
        Some(v) => &v[0].parse::<usize>().unwrap() + 1,
        None => 0,
    };

    for record in rdr.records().flatten().skip(skip_amount) {
        if non_vulnerable_only && &record[3] == "1" {
            continue;
        }

        let start = std::time::Instant::now();
        
        let mut output_csv_line = vec![&record[0], &record[1], &record[2], &record[4], &record[3]];

        let prefix = "[INST]";
        let suffix = "[/INST]";

        let mut prompt = String::new();

        // for server only
        prompt += prefix;

        //prompt += "Provided below is a code snippit. Evaulate whether the code is vulnerable to security flaws and if not explain why. Only state Yes for potentially dangerous code that can be exploted by a user. If it is not clear, not enough information, or there is no major vulnerabilities with the code state No. Please answer starting with a Yes or No before explaining depending on if the code is vulnerable or not.";
        prompt += "Provided below is a code snippit and below that a cwe desciption. Evaulate whether the code is vulnerable to security flaws and if not explain why. Please answer explicitly starting with a Yes or No before explaining depending on if the code is vulnerable or not. Only state Yes for potentially dangerous code that can be exploted by a user. If it is not clear, not enough information, or there is no major vulnerabilities with the code state No. If there is a cwe description provided below the code use cwe description as vulnerability assistance and it will not always mean the code is vulnerable.";
        prompt += "\n\n";
        
        prompt += &record[4];

        let cwe_description = true;
        if cwe_description {
            let cwe = record[1].to_string();
            
            let cwe_content;
            if similar {
                cwe_content = find_similar_target(&record[0].to_string(), top, similar_cwe_file);
            }
            else if random {
                cwe_content = Some(get_random_cwe());
            }
            else {
                cwe_content = find_target(&cwe);
            }
            
            
            if cwe_content.is_none() {
                //println!("did not find cwe {}", &record[1]);
                continue;
                // prompt += "No cwe description was found";
                // prompt += "\n\n";
            }
            if cwe_content.is_some() {
                prompt += &cwe_content.clone().unwrap();
                prompt += "\n\n";
            }   
        }

        // for server only
        prompt += suffix;

        create_file(tmp_file, &prompt);
        let output_content = run_server_command(tmp_file);

        // if server {
        //     let tmp = output_content.clone();
        //     let v = tmp.split("[/INST]").collect::<Vec<&str>>();
        //     output_content = "".to_string();
        //     for text in v.iter().skip(1) {
        //         output_content += text;
        //     }
        // }

        remove_file(tmp_file);

        // happens if the python program crashes -- TODO FIND WHAT IS HAPPENING HERE --
        if output_content.len() <= search_for_answer_limit {
            output_csv_line.push("NA");
            output_csv_line.push("failed to answer");
            add_line_to_csv(output_csv_line, &file);

            total_millis += start.elapsed().as_millis() as f64;
            total += 1.0;

            let avg = (total_millis/1000.0)/total;
            let eta = (((all_vulnerabilies-(&record[0]).parse::<f64>().unwrap()) * avg)/60.0)/60.0;

            println!("{} {:.1}s failed avg {:.2}s with eta {:.2} hours", &record[0], start.elapsed().as_millis() as f64/1000.0, avg, eta);
            continue;
        }

        if output_content[0..search_for_answer_limit].contains("Yes") {
            output_csv_line.push("Yes");
        } else if output_content[0..search_for_answer_limit].contains("No") {
            output_csv_line.push("No");
        } else {
            output_csv_line.push("None");
        }

        output_csv_line.push(&output_content);

        total_millis += start.elapsed().as_millis()  as f64;
        total += 1.0;

        let avg = (total_millis/1000.0)/total;
        let eta = (((all_vulnerabilies-(&record[0]).parse::<f64>().unwrap()) * avg)/60.0)/60.0;

        println!("{} {:.1}s {} {} avg {:.2}s with eta {:.2} hours", &record[0], start.elapsed().as_millis() as f64/1000.0, output_csv_line[5], &record[3], avg, eta);

        add_line_to_csv(output_csv_line, &file);
    }
}

// gets all file locations from the copilot generated scenariors folder into a vec<string> used to generate inputs
fn get_file_locations() -> Vec<String> {
    let mut ans = vec![];

    // useless because ./ does the same thing
    // let curr_location = std::env::current_dir()
    //     .unwrap()
    //     .into_os_string()
    //     .into_string()
    //     .unwrap();

    let start = "./experiments_dow/";
    let paths = std::fs::read_dir(start).unwrap();

    for path in paths {
        let pth =
            start.to_string() + path.unwrap().path().file_name().unwrap().to_str().unwrap() + "/";
        let p = std::fs::read_dir(pth.clone());

        if let Ok(val) = p {
            for subpath in val {
                ans.push(
                    pth.clone()
                        + subpath
                            .unwrap()
                            .path()
                            .file_name()
                            .unwrap()
                            .to_str()
                            .unwrap()
                        + "/Copilot",
                );
            }
        }
    }

    ans
}

fn get_input_output_file_locations(start: &str) -> Vec<String> {
    let mut ans = vec![];

    // useless because ./ does the same thing
    // let curr_location = std::env::current_dir()
    //     .unwrap()
    //     .into_os_string()
    //     .into_string()
    //     .unwrap();

    let paths = std::fs::read_dir(start).unwrap();

    for path in paths {
        let pth =
            start.to_string() + path.unwrap().path().file_name().unwrap().to_str().unwrap() + "/";
        let p = std::fs::read_dir(pth.clone());

        if let Ok(val) = p {
            for subpath in val {
                let subpth = pth.clone()
                    + subpath
                        .unwrap()
                        .path()
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                    + "/";
                let subp = std::fs::read_dir(subpth.clone());
                if let Ok(subval) = subp {
                    for subsubpath in subval {
                        ans.push(
                            subpth.clone().to_string()
                                + subsubpath
                                    .unwrap()
                                    .path()
                                    .file_name()
                                    .unwrap()
                                    .to_str()
                                    .unwrap(),
                        );
                    }
                }
            }
        }
    }

    ans
}

// generates the llama_input folder in the same fashion the copilot folder was constructed
fn copilot_input_csv(output_filename:&str) {
    let files = get_file_locations();

    let output_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .append(true)
        .open(output_filename)
        .unwrap();

    //let prompt = "Provided below is a code snippit and below that a cwe desciption. Evaulate whether the code is vulnerable to security flaws and if not explain why. Please answer explicitly starting with a Yes or No before explaining depending on if the code is vulnerable or not. Only state Yes for potentially dangerous code that can be exploted by a user. If it is not clear, not enough information, or there is no major vulnerabilities with the code state No. If there is a cwe description provided below the code use cwe description as vulnerability assistance and it will not always mean the code is vulnerable.";

    let mut total = 0;
    for file in files {
        let sub_folder: Vec<&str> = file.split('/').collect();

        let ans = get_desc(&file);

        let mut count = 1;
        for method in ans {
            let mut csv_line: Vec<&str> = vec![];

            let tmp = total.to_string();
            csv_line.push(&tmp);

            csv_line.push(sub_folder[2]);
            csv_line.push(sub_folder[3]);
            
            let tmp = count.to_string();
            csv_line.push(&tmp);
            csv_line.push(&method);

            add_line_to_csv(csv_line, &output_file);

            count += 1;
            total += 1;
            //println!("{}", method);
        }
    }
    println!("{}", total); // should print 1205
}

// populates the input text files
fn get_desc(file_path: &str) -> Vec<String> {
    let text = open_file(file_path);

    let methods: Vec<&str> = text
        .split(
            "=======
	# mean prob: ",
        )
        .collect();

    let ans = methods.iter().skip(1).map(|x| {
        let method_lines:Vec<&str> = x.split("\n").collect();

        let mut a = String::new();
        for line in method_lines.iter().skip(2).take(method_lines.len()-4) {
            a += line;
            a += "\n";
        }
        a
    }).collect();

    ans
}


fn find_copilot_similar_target(cwe: &str, folder: &str, top:usize, similar_cwe_file:&str) -> Option<String> {
    fn get_similar_entry(entry:String) -> String {
        if entry.len() > 0 {
            let cwe = "cwe-".to_string() + &entry;
            let txt = find_target(&cwe);
            if txt.is_some() {
                return txt.unwrap();
            }
            else {
                println!("did not find cwe-{}", entry);
            }
        }
        String::new()
    }

    let text = open_file(similar_cwe_file);
    let mut start = 2;
    let mut top = top;
    if similar_cwe_file == "copilot_similar_ground.csv" {
        start += 1;
        top+=1;
    }

    let mut rdr = csv::Reader::from_reader(text.as_bytes());
    //let cwe = "cwe-".to_string() + cwe;

    let mut ans = String::new();
    for record in rdr.records().flatten() {
        if cwe == record[0].to_string() && folder.to_string() == record[1].to_string() {
            for num in start..top+2 {
                ans += &get_similar_entry(record[num].to_string());
            }
        }
    }
    
    if ans.len() < 10 {
        return None;
    }

    Some(ans)
}

fn find_cwe_method(cwe:&str,folder:&str) -> Option<String> {
    let text = open_file("copilot_methods.csv");
    let mut rdr = csv::Reader::from_reader(text.as_bytes());

    for record in rdr.records().flatten() {
        if &record[1] == cwe && &record[2] == folder && &record[3] == "1" {
            return Some(record[4].to_string());
        }
    }

    println!("THE METHOD WAS NOT FOUND SOMETHING WENT WRONG");
    None
}

// this function instead of manually parsing uses csv struct in std to read from the big vul dataset
fn run_copilot_commands(file_name: &str, output_file_name: &str, non_vulnerable:bool, similar:bool, random:bool, top:usize, similar_cwe_file:&str) {
    let content = open_file(file_name);
    let mut rdr = csv::Reader::from_reader(content.as_bytes());
    let mut total_millis: f64 = 0.0;
    let mut total: f64 = 0.0;
    let all_vulnerabilies: f64 = 1205.0;

    // this file is created and removed each iteration to hold the prompt in a file as a command arg for client_to_sever.py
    let tmp_file = "tmp_file.txt"; 
    let search_for_answer_limit = 30;

    remove_file(tmp_file);

    // file struct is created so program can pick up where it left off if program closes reading from output file
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .append(true)
        .open(output_file_name)
        .unwrap();

    for record in rdr.records().flatten() {
        if non_vulnerable && &record[2] == "TRUE" {
            continue;
        }

        let start = std::time::Instant::now();
        
        // TODO CHANGE THIS
        let mut output_csv_line = vec![&record[0], &record[1], &record[2]];

        let prefix = "[INST]";
        let suffix = "[/INST]";

        let mut prompt = String::new();

        // for server only
        prompt += prefix;

        //prompt += "Provided below is a code snippit. Evaulate whether the code is vulnerable to security flaws and if not explain why. Only state Yes for potentially dangerous code that can be exploted by a user. If it is not clear, not enough information, or there is no major vulnerabilities with the code state No. Please answer starting with a Yes or No before explaining depending on if the code is vulnerable or not.";
        prompt += "Provided below is a code snippit and below that a cwe desciption. Evaulate whether the code is vulnerable to security flaws and if not explain why. Please answer explicitly starting with a Yes or No before explaining depending on if the code is vulnerable or not. Only state Yes for potentially dangerous code that can be exploted by a user. If it is not clear, not enough information, or there is no major vulnerabilities with the code state No. If there is a cwe description provided below the code use cwe description as vulnerability assistance and it will not always mean the code is vulnerable.";
        prompt += "\n\n";
        
        let mut cwe = "cwe-".to_string();
        cwe += &record[0];

        let method = find_cwe_method(&cwe,&record[1]);
        if method.is_none() {
            continue;
        }

        prompt += &method.unwrap();

        let cwe_description = true;
        if cwe_description {
            let cwe_content;
            if similar {
                cwe_content = find_copilot_similar_target(&record[0].to_string(), &record[1].to_string(), top, similar_cwe_file);
            }
            else if random {
                cwe_content = Some(get_random_cwe());
            }
            else {
                cwe_content = find_target(&cwe);
            }
            
            
            if cwe_content.is_none() {
                //println!("did not find cwe {}", &record[1]);
                continue;
                // prompt += "No cwe description was found";
                // prompt += "\n\n";
            }
            if cwe_content.is_some() {
                prompt += &cwe_content.clone().unwrap();
                prompt += "\n\n";
            }   
        }

        // for server only
        prompt += suffix;

        create_file(tmp_file, &prompt);
        let output_content = run_server_command(tmp_file);

        // if server {
        //     let tmp = output_content.clone();
        //     let v = tmp.split("[/INST]").collect::<Vec<&str>>();
        //     output_content = "".to_string();
        //     for text in v.iter().skip(1) {
        //         output_content += text;
        //     }
        // }

        remove_file(tmp_file);

        // happens if the python program crashes -- TODO FIND WHAT IS HAPPENING HERE --
        if output_content.len() <= search_for_answer_limit {
            output_csv_line.push("NA");
            output_csv_line.push("failed to answer");
            add_line_to_csv(output_csv_line, &file);

            total_millis += start.elapsed().as_millis() as f64;
            total += 1.0;

            let avg = (total_millis/1000.0)/total;
            let eta = (((all_vulnerabilies-(&record[0]).parse::<f64>().unwrap()) * avg)/60.0)/60.0;

            println!("{} {:.1}s failed avg {:.2}s with eta {:.2} hours", &record[0], start.elapsed().as_millis() as f64/1000.0, avg, eta);
            continue;
        }

        if output_content[0..search_for_answer_limit].contains("Yes") {
            output_csv_line.push("Yes");
        } else if output_content[0..search_for_answer_limit].contains("No") {
            output_csv_line.push("No");
        } else {
            output_csv_line.push("None");
        }

        total_millis += start.elapsed().as_millis()  as f64;
        total += 1.0;

        let avg = (total_millis/1000.0)/total;
        let eta = (((all_vulnerabilies-(&record[0]).parse::<f64>().unwrap()) * avg)/60.0)/60.0;

        println!("{} {:.1}s vul:{} ans:{} avg {:.2}s with eta {:.2} hours", total, start.elapsed().as_millis() as f64/1000.0, &record[2], output_csv_line[3], avg, eta);

        add_line_to_csv(output_csv_line, &file);
    }
}

fn main() {
    //run_big_vul_dataset_commands("dfBigVulFinal.csv", "nv_bv_random_cwe.csv", false, true, true,0, "");
    //run_big_vul_dataset_commands("dfBigVulFinal.csv", "nv_bv_sbert_t3.csv", true, true, false,3, "sbert_bv_similarl_T3.csv");
    //run_big_vul_dataset_commands("dfBigVulFinal.csv", "nv_bv_sbert_t10.csv", true, true, false,10, "bv_sbert_10.csv");
    //run_big_vul_dataset_commands("dfBigVulFinal.csv", "nv_bv_codebert_t3.csv", true, true, false,3, "bv_similar.csv");
    //run_copilot_commands("copilot_similar_ground.csv", "nv_cp_random_cwe.csv", true, false, true,0, "");
    run_copilot_commands("copilot_similar_ground.csv", "nv_cp_sbert_t3.csv", true, true, false,3, "cp_sbert_top_3_cwe.csv");
    run_copilot_commands("copilot_similar_ground.csv", "nv_cp_sbert_t10.csv", true, true, false,10, "cp_sbert_top_10_cwe.csv");
    //run_copilot_commands("copilot_similar_ground.csv", "nv_cp_codebert_t3.csv", true, true, false,3, "copilot_similar_ground.csv");
    //run_copilot_commands("copilot_similar_ground.csv", "nv_cp_codebert_t10.csv", true, true, false,10, "cp_codebert_top_10_cwe_input.csv");

    run_big_vul_dataset_commands("dfBigVulFinal.csv", "nv_bv_codebert_t10.csv", true, true, false,10, "bv_codebert_top_10_cwe_input.csv");
    
    
    //run_copilot_commands("copilot_similar_ground.csv", "cp_codebert_top_10_output.csv", true, true, false,10);
    //run_copilot_commands("copilot_similar_ground.csv", "cp_sbert_top_10_cwe_output.csv", true, true,  false,10);
    //println!("{:?}", get_file_locations());
}
