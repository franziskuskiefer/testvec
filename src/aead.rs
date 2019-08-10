use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::io::BufReader;

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct Test {
    pub tcId: usize,
    pub comment: String,
    pub key: String,
    pub iv: String,
    pub aad: String,
    pub msg: String,
    pub ct: String,
    pub tag: String,
    pub result: String,
    pub flags: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct TestGroup {
    pub ivSize: usize,
    pub keySize: usize,
    pub tagSize: usize,
    pub r#type: String,
    pub tests: Vec<Test>,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct AEADTestVector {
    pub algorithm: String,
    pub generatorVersion: String,
    pub numberOfTests: usize,
    pub notes: Option<Value>, // text notes (might not be present), keys correspond to flags
    pub header: Vec<Value>,   // not used
    pub testGroups: Vec<TestGroup>,
}

impl AEADTestVector {
    pub fn new(file: String) -> Result<Self, String> {
        let file = match File::open(file) {
            Ok(f) => f,
            Err(_) => return Err("Couldn't open file.".to_string()),
        };
        let reader = BufReader::new(file);
        match serde_json::from_reader(reader) {
            Ok(r) => Ok(r),
            Err(_) => Err("Error reading file.".to_string()),
        }
    }
    pub fn get_notes(&self) -> Vec<(String, String)> {
        let notes = match &self.notes {
            Some(notes) => notes,
            None => return vec![],
        };
        let mut flags: Vec<String> = Vec::new();
        for tg in self.testGroups.iter() {
            for t in tg.tests.iter() {
                flags.extend(t.flags.clone());
            }
        }
        flags.sort_unstable();
        flags.dedup();
        let mut result: Vec<(String, String)> = Vec::new();
        // If there are flags, there have to be notes.
        // Otherwise we don't care about notes.
        for flag in flags.iter() {
            // Skip anything that's not a string. (Really shouldn't happen)
            if notes[flag].is_string() {
                result.push((flag.to_string(), notes[flag].as_str().unwrap().to_string()));
            }
        }
        return result;
    }
}
