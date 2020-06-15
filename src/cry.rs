use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

pub type KeyIv = ([u8; 32], [u8; 16]);

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

  (key, iv)
}
