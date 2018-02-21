# CBC bitflipping attacks
require 'openssl'

class Oracle
  def initialize
    @key = random_bytes
    @iv = random_bytes
  end

  def encrypt input
    escaped = input.gsub(/;|=/, '')
    encrypt_cbc padding_pkcs7("comment1=cooking%20MCs;userdata=#{escaped};comment2=%20like%20a%20pound%20of%20bacon", 16)
  end

  def decrypt_and_validate encrypted
    decrypt_cbc(encrypted).include? ';admin=true;'
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

  def decrypt_cbc encrypted
    cipher = OpenSSL::Cipher::Cipher.new 'AES-128-CBC'
    cipher.decrypt
    cipher.key = @key
    cipher.iv = @iv
    cipher.update(encrypted) + cipher.final
  end
end

class Attacker
  def initialize oracle
    @oracle = oracle
  end

  def attack
    original_enc_bytes = @oracle.encrypt('aaa_admin_true').bytes
    
    # I didn't come up with the idea ... so I opened a write-up: https://medium.com/@__cpg/cryptopals-2-16-cbc-bit-flipping-attack-774c5f7d8d7
    puts "Before (encrypted previous block, decrypted block including '_admin_true'):"
    puts original_enc_bytes.each_slice(16).to_a[1].map { |x| x.to_s(2).rjust 8, '0' }.join ' '
    puts @oracle.decrypt_cbc(original_enc_bytes.pack("C*")).bytes.each_slice(16).to_a.map { |x| x.map { |y| y.to_s(2).rjust 8, '0' }.join " " }[2] 
    
    modified_enc_bytes = original_enc_bytes
    modified_enc_bytes[19] ^= '_'.ord ^ ';'.ord
    modified_enc_bytes[25] ^= '_'.ord ^ '='.ord

    puts "After:"
    puts modified_enc_bytes.each_slice(16).to_a[1].map { |x| x.to_s(2).rjust 8, '0'}.join ' '    
    puts @oracle.decrypt_cbc(modified_enc_bytes.pack("C*")).bytes.each_slice(16).to_a.map { |x| x.map { |y| y.to_s(2).rjust 8, '0' }.join " " }[2]
    
    puts @oracle.decrypt_cbc(modified_enc_bytes.pack("C*"))

    @oracle.decrypt_and_validate modified_enc_bytes.pack("C*")
  end
end

attacker = Attacker.new Oracle.new
puts attacker.attack