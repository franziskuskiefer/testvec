use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;

#[test]
fn test_simple() {
    #[derive(Serialize, Deserialize, Debug)]
    struct Person {
        age: u8,
        name: String,
        phones: Vec<String>,
    }
    let path = "tests/person.json";
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);

    // Parse the string of data into serde_json::Value.
    let p: Person = serde_json::from_reader(reader).unwrap();
    println!("{:?}", p);
}
