use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

pub struct KeyIv ([u8; 32], [u8; 16]);

impl KeyIv {
  pub fn blank () -> KeyIv{
    KeyIv ([0; 32], [0; 16])
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut bytes = self.0.to_vec();
    bytes.extend_from_slice(&self.1);
    bytes
  }
  pub fn from_bytes(data: &[u8]) -> KeyIv {
    let mut key: [u8; 32] = [0; 32];
    let mut iv: [u8; 16] = [0; 16];
    key.copy_from_slice(&data[0..32]);
    iv.copy_from_slice(&data[32..]);
    KeyIv (key, iv)
  }
}

pub fn encrypt(data: &[u8], key: &KeyIv) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
  let mut encryptor = aes::cbc_encryptor( aes::KeySize::KeySize256, &key.0, &key.1, blockmodes::PkcsPadding);

  let mut final_result = Vec::<u8>::new();
  let mut read_buffer = buffer::RefReadBuffer::new(data);
  let mut buffer = [0; 2];
  let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

  loop {
    let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;
    final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

    match result {
      BufferResult::BufferUnderflow => break,
      BufferResult::BufferOverflow => { }
    }
  }

  Ok(final_result)
}

pub fn decrypt(encrypted_data: &[u8], key: &KeyIv) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
  let mut decryptor = aes::cbc_decryptor( aes::KeySize::KeySize256, &key.0, &key.1, blockmodes::PkcsPadding);

  let mut final_result = Vec::<u8>::new();
  let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
  let mut buffer = [0; 2];
  let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

  loop {
    let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
    final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
    match result {
      BufferResult::BufferUnderflow => break,
      BufferResult::BufferOverflow => { }
    }
  }

  Ok(final_result)
}

pub fn rnd_key_iv () -> KeyIv {
  use rand::RngCore;
  let mut key: [u8; 32] = [0; 32];
  let mut iv: [u8; 16] = [0; 16];

  let mut rng = rand::thread_rng();
  rng.fill_bytes(&mut key);
  rng.fill_bytes(&mut iv);

  KeyIv (key, iv)
}


pub fn b64e(s: &[u8]) -> String {
  use rustc_serialize::base64::{ToBase64, STANDARD};
  s.to_base64(STANDARD)
}

pub fn b64d(s: &str) -> Vec<u8> {
  use rustc_serialize::base64::{FromBase64};
  s.from_base64().unwrap()
}


pub fn sha1 (s: &str) -> String {
  use crypto::digest::Digest;
  use crypto::sha1::Sha1;
  let mut hasher = Sha1::new();
  hasher.input_str(s);
  hasher.result_str()
}



#[allow(dead_code)]
pub fn encode_prv (key: &rsa::RSAPrivateKey) -> String {
  // use num_bigint_dig::BigUint;
  use rsa::PublicKey;
  // let mut txt = "".to_string();
  let mut txt = vec![
    key.n(),
    key.e(),
    key.d(),
  ];
  txt.extend(key.primes());

  let mut vec = vec![];
  vec.extend(txt.iter().map(|n| n.to_str_radix(36)));
  vec.join("-")
}


pub fn decode_prv (s: &str) -> Option<rsa::RSAPrivateKey> {
  use num_bigint_dig::BigUint;
  let mut pieces = vec![];
  for n in s.split("-") {
    let n = BigUint::parse_bytes(n.as_bytes(), 36);
    if n.is_none() { return None }
    pieces.push(n.unwrap());
  }
  if pieces.len() < 4 { return None }

  let result = std::panic::catch_unwind(|| {
    rsa::RSAPrivateKey::from_components(
      pieces.remove(0),
      pieces.remove(0),
      pieces.remove(0),
      pieces,
    )
  });
  if result.is_err() { return None }
  let key = result.unwrap();
  if !rsa_verify_key(&key) { return None }
  Some(key)
}


#[allow(dead_code)]
pub fn encode_pub (key: &rsa::RSAPublicKey) -> String {
  // use num_bigint_dig::BigUint;
  use rsa::PublicKey;
  // let mut txt = "".to_string();
  let txt = vec![
    key.n(),
    key.e(),
  ];

  let mut vec = vec![];
  vec.extend(txt.iter().map(|n| n.to_str_radix(36)));
  vec.join("-")
}


pub fn decode_pub (s: &str) -> Option<rsa::RSAPublicKey> {
  use num_bigint_dig::BigUint;
  let mut pieces = vec![];
  for n in s.split("-") {
    let n = BigUint::parse_bytes(n.as_bytes(), 36);
    if n.is_none() { return None }
    pieces.push(n.unwrap());
  }
  if pieces.len() != 2 { return None }
  let ret = rsa::RSAPublicKey::new(
    pieces.remove(0),
    pieces.remove(0),
  );
  if ret.is_err() { return None }
  Some(ret.unwrap())
}


pub fn rsa_encrypt(key: &rsa::RSAPublicKey, data: &[u8]) -> Vec<u8> {
  use rsa::PublicKey;
  use rand::rngs::OsRng;
  let mut rng = OsRng::new().expect("no secure randomness available");
  key.encrypt(&mut rng, rsa::PaddingScheme::PKCS1v15, data).unwrap()
}

pub fn rsa_decrypt(key: &rsa::RSAPrivateKey, data: &[u8]) -> Result<Vec<u8>, rsa::errors::Error> {
  key.decrypt(rsa::PaddingScheme::PKCS1v15, data)
}


fn rsa_verify_key(key: &rsa::RSAPrivateKey) -> bool {
  let str = "98eyrxn9w8q0n98fasud98ua";
  let res = rsa_decrypt(key, &rsa_encrypt(&key.to_public_key(), str.as_bytes()));
  !res.is_err() && res.unwrap() == str.as_bytes()
}
