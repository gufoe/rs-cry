mod cry;
use std::fs::File;
use std::io::{Read, Write};

pub fn enc_file (src: String, key: &cry::KeyIv) -> Vec<u8> {
  let mut file = File::open(src).unwrap();
  let mut s: Vec<u8> = Vec::with_capacity(file.metadata().unwrap().len() as usize);
  file.read_to_end(&mut s).unwrap();
  cry::encrypt(&s, key).unwrap()
}

fn prepend_crypter () {

}

fn main() {
  let key = cry::rnd_key_iv();
  let src = std::env::args().nth(1).unwrap();
  let dst = std::env::args().nth(2).unwrap();
  println!("file: {} -> {}", src, dst);
  let payload = enc_file (src, key);


}
