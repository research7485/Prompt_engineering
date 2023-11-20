use std::io::prelude::*;
// puts all file text into string
fn open_file(file_name: &str) -> String {
    use std::fs;

    let mut file = fs::File::open(file_name).expect("file was not found");
    let mut text = String::new();
    file.read_to_string(&mut text)
        .expect("file did not read correctly to a string the file should be encoded into utf8");

    text
}

pub fn cut(file_name:&str, first:&str, second:&str) {
    let content = open_file(file_name);
    let mut rdr = csv::Reader::from_reader(content.as_bytes());

    let mut first_wtr = csv::Writer::from_path(first).unwrap();
    let mut second_wtr = csv::Writer::from_path(second).unwrap();

    let mut flag:bool = true; 
    for record in rdr.records().flatten() {
        if &record[4] == "1" {
            flag = false;
        }
        if flag {
            first_wtr.write_record(&record).unwrap();
        }
        else {
            second_wtr.write_record(&record).unwrap();
        }
    }
}

pub fn count_bv(file_name:&str) {
    let content = open_file(file_name);
    let mut rdr = csv::Reader::from_reader(content.as_bytes());
    let mut total = 0;

    let mut vul = 0; // 8921
    let mut not_vul = 0; // 8740
    let mut yes = 0;
    let mut no = 0;

    let mut true_pos = 0;
    let mut true_neg = 0;
    let mut false_pos = 0;
    let mut false_neg = 0;

    let vulnerable = 4;
    let answer = 5;

    for record in rdr.records().flatten() {
        // this happens if the ai did not answer correctly
        if !(&record[answer] == "Yes" || &record[answer] == "No") {
            continue;
        }

        if &record[vulnerable] == "1" {
            vul += 1;
        }
        else {
            not_vul += 1;
        }
        

        if &record[answer] == "Yes" {
            yes += 1;
        }
        else {
            no += 1;
        }

        // said yes to a vulnerable correct answer
        if &record[vulnerable] == "1" && &record[answer] == "Yes" {
            true_pos += 1;
        }
        else if &record[vulnerable] == "1" && &record[answer] == "No" {
            false_neg += 1;
        }

        // said no to a not vulnerable correct answer
        else if &record[vulnerable] == "0" && &record[answer] == "No" {
            false_pos += 1;
        }
        else if &record[vulnerable] == "0" && &record[answer] == "Yes" {
            true_neg += 1;
        }

        total += 1;
    }

    println!("{}", file_name);
    println!("{} total answers", total);
    println!("vulnerable: {} not vulnerable: {}", vul, not_vul);
    println!("yes: {} no: {}", yes, no);
    println!("TP: {} FN: {} FP: {} TN: {}\n", true_pos, false_neg, false_pos, true_neg);

    println!("TP/(TP+FP) TP precision calculation {:.2}%", (true_pos as f64/ (true_pos+false_pos) as f64) * 100.0);
    println!("TP/(TP+FN) TP recall calculation {:.2}%\n", (true_pos as f64/ (true_pos+false_neg) as f64) * 100.0);

    println!("FP/(TP+FP) FP precision calculation {:.2}%", (false_pos as f64/ (true_pos+false_pos) as f64) * 100.0);
    println!("FP/(FP+TN) FP recall calculation {:.2}%\n\n", (false_pos as f64/ (false_pos+true_neg) as f64) * 100.0);
}

pub fn count_copilot(file_name:&str) {
    let content = open_file(file_name);
    let mut rdr = csv::Reader::from_reader(content.as_bytes());
    let mut total = 0;

    let mut vul = 0;
    let mut not_vul = 0;
    let mut yes = 0;
    let mut no = 0;

    let mut true_pos = 0;
    let mut true_neg = 0;
    let mut false_pos = 0;
    let mut false_neg = 0;

    let vulnerable = 2;
    let answer = 3;

    for record in rdr.records().flatten() {
        // this happens if the ai did not answer correctly
        if !(&record[answer] == "Yes" || &record[answer] == "No") {
            continue;
        }

        if &record[vulnerable] == "FALSE" {
            not_vul += 1;
        }
        else if &record[vulnerable] == "TRUE" {
            vul += 1;
        }

        if &record[answer] == "Yes" {
            yes += 1;
        }
        else if &record[answer] == "No" {
            no += 1;
        }

        if &record[vulnerable] == "TRUE" && &record[answer] == "Yes" {
            true_pos += 1;
        }
        else if &record[vulnerable] == "TRUE" && &record[answer] == "No" {
            false_neg += 1;
        }
        else if &record[vulnerable] == "FALSE" && &record[answer] == "No" {
            false_pos += 1;
        }
        else if &record[vulnerable] == "FALSE" && &record[answer] == "Yes" {
            true_neg += 1;
        }

        total += 1;
    }

    println!("{}", file_name);
    println!("{} total answers", total);
    println!("vulnerable: {} not vulnerable: {}", vul, not_vul);
    println!("yes: {} no: {}", yes, no);
    println!("TP: {} FN: {} FP: {} TN: {}\n", true_pos, false_neg, false_pos, true_neg);

    println!("TP/(TP+FP) TP precision calculation {:.2}%", (true_pos as f64/ (true_pos+false_pos) as f64) * 100.0);
    println!("TP/(TP+FN) TP recall calculation {:.2}%\n", (true_pos as f64/ (true_pos+false_neg) as f64) * 100.0);

    println!("FP/(TP+FP) FP precision calculation {:.2}%", (false_pos as f64/ (true_pos+false_pos) as f64) * 100.0);
    println!("FP/(FP+TN) FP recall calculation {:.2}%\n\n", (false_pos as f64/ (false_pos+true_neg) as f64) * 100.0);
}

fn main() {
    // println!("BIGVUL");
    // count_bv("nv_bv_random_cwe.csv");
    // count_bv("nv_bv_codebert_t3.csv");
    count_bv("nv_bv_codebert_t10.csv");
    // count_bv("nv_bv_sbert_t3.csv");
    // count_bv("nv_bv_sbert_t10.csv");
    // println!("\n\nCOPILOT\n\n");
    // count_copilot("nv_cp_random_cwe.csv");
    // count_copilot("nv_cp_codebert_t3.csv");
    // count_copilot("nv_cp_codebert_t10.csv");
    // count_copilot("nv_cp_sbert_t3.csv");
    // count_copilot("nv_cp_sbert_t10.csv");
    //cut("bigvul_dataset_with_cwe.csv","bv_with_cwe_not_vulnerable.csv","bv_with_cwe_vulnerable.csv");
}
