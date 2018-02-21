# ECB cut-and-paste
require 'openssl'

def padding_pkcs7 str, len # From Challenge 9
  add = len - str.size % len
  add == len ? str : str + add.chr * add
end

class Oracle
  def initialize
    @key = random_bytes
  end

  def profile_for email
    modified = padding_pkcs7 encode(email), 16
    encrypt_block @key, modified
  end

  def decrypt_profile encrypted
    prof = decrypt_block @key, encrypted
    decode prof
  end

  def encode email
    {
      email: email.gsub(/&|=/, ''),
      uid: 10,
      role: 'user'
    }.map { |k, v| "#{k}=#{v}" }.join "&"
  end

  def decode str
    str.split("&").map { |s| s.split("=") }.to_h
  end
  
  def random_bytes length = 16
    length.times.map { (0x00..0xFF).to_a.sample.chr }.join
  end

  def encrypt_block key, plain
    cipher = OpenSSL::Cipher::Cipher.new 'AES-128-ECB'
    cipher.encrypt
    cipher.padding = 0
    cipher.key = key
    cipher.update(plain) + cipher.final
  end

  def decrypt_block key, plain
    cipher = OpenSSL::Cipher::Cipher.new 'AES-128-ECB'
    cipher.decrypt
    # cipher.padding = 0
    cipher.key = key
    cipher.update(plain) + cipher.final
  end
end

class Attacker
  def initialize oracle
    @oracle = oracle
  end

  def attack
    enc1 = @oracle.profile_for('A' * 10 + padding_pkcs7('admin', 16))
    enc1_block_admin = enc1[16...32]

    enc2 = @oracle.profile_for('A' * 13)[0...32]
    @oracle.decrypt_profile enc2 + enc1_block_admin
  end
end

attacker = Attacker.new Oracle.new
puts attacker.attack