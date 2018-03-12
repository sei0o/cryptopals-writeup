# Recover the key from CBC with IV=Key
require 'openssl'

class Oracle
  def initialize
    @key = random_bytes
    @iv = @key
  end

  def encrypt
    encrypt_cbc padding_pkcs7("comment1=cooking%20MCs;userdata=SECRETsecretSECRET;comment2=%20like%20a%20pound%20of%20bacon", 16)
  end

  def decrypt encrypted
    # I don't know how to validate whether a string complies ASCII...
    decrypt_cbc(encrypted)
  end

  def random_bytes length = 16
    length.times.map { (0x00..0xFF).to_a.sample.chr }.join
  end

  def padding_pkcs7 str, len # From Challenge 9
    add = len - str.size % len
    add == len ? str : str + add.chr * add
  end

  def encrypt_cbc plain
    cipher = OpenSSL::Cipher::Cipher.new 'AES-128-CBC'
    cipher.encrypt
    cipher.padding = 0
    cipher.key = @key
    cipher.iv = @iv
    cipher.update(plain) + cipher.final
  end

  def decrypt_cbc encrypted, key = nil
    cipher = OpenSSL::Cipher::Cipher.new 'AES-128-CBC'
    cipher.decrypt
    cipher.key = key || @key
    cipher.iv = key || @iv
    cipher.update(encrypted) + cipher.final
  end
end

class Attacker
  def initialize oracle
    @oracle = oracle
  end

  def attack
    original_enc = @oracle.encrypt
    
    modified_enc_blocks = original_enc.bytes.each_slice(16).to_a
    modified_enc_blocks[0] = [0] * 16
    modified_enc_blocks[1] = [0] * 16

    modified_dec = @oracle.decrypt modified_enc_blocks.flatten.pack("C*") # Let's say it has returned an error with a decrypted text
    dec_blocks = modified_dec.bytes.each_slice(16).to_a

    # Assume c1, c2 ... is ciphertext blocks, m1, m2 ... is plaintext blocks and K is the key (and the IV)
    # [1] Dec(c1) XOR K = m1
    # [2] c1 XOR Dec(c2) = m2
    # if c1 and c2 are 0 (null), [3] Dec(c1) = Dec(c2), [2'] Dec(c2) = m2
    # From above, [4] K = Dec(c1) XOR m1 = m2 XOR m1
    m1 = dec_blocks[0]
    m2 = dec_blocks[1]
    key = m1.zip(m2).map { |a, b| a ^ b }.pack("C*")
    
    @oracle.decrypt_cbc original_enc, key
  end
end

attacker = Attacker.new Oracle.new
puts attacker.attack