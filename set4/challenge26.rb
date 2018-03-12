# CTR bitflipping
require 'openssl'

class Oracle
  def initialize
    @key = random_bytes
    @nonce = random_bytes 8
  end

  def encrypt input
    escaped = input.gsub(/;|=/, '')
    encrypt_ctr "comment1=cooking%20MCs;userdata=#{escaped};comment2=%20like%20a%20pound%20of%20bacon"
  end

  def decrypt_and_validate encrypted
    decrypt_ctr(encrypted).include? ';admin=true;'
  end

  def random_bytes length = 16
    length.times.map { (0x00..0xFF).to_a.sample.chr }.join
  end

  def encrypt_block plain
    cipher = OpenSSL::Cipher::Cipher.new 'AES-128-ECB'
    cipher.encrypt
    cipher.padding = 0
    cipher.key = @key
    cipher.update(plain) + cipher.final
  end

  def keystream count
    encrypt_block @nonce + [count].pack("Q*")
  end
  
  def encrypt_ctr input, offset = 0
    input.bytes.each_slice(16).map.with_index(offset) do |block, i|
      keystream(i).bytes.zip(block).map do |ks, b|
        next unless b
        ks ^ b
      end
    end.flatten.compact.pack("C*")
  end
  alias :decrypt_ctr :encrypt_ctr
end

class Attacker
  def initialize oracle
    @oracle = oracle
  end

  def attack
    original_enc_bytes = @oracle.encrypt('aaa_admin_true').bytes
    
    # puts "Before (encrypted block, decrypted block including '_admin_true'):"
    # puts original_enc_bytes.each_slice(16).to_a[2].map { |x| x.to_s(2).rjust 8, '0' }.join ' '
    # puts @oracle.decrypt_ctr(original_enc_bytes.pack("C*")).bytes.each_slice(16).to_a.map { |x| x.map { |y| y.to_s(2).rjust 8, '0' }.join " " }[2] 
    
    modified_enc_bytes = original_enc_bytes
    modified_enc_bytes[35] ^= '_'.ord ^ ';'.ord # CTR mode uses keystream so it doesn't depend on the previous block
    modified_enc_bytes[41] ^= '_'.ord ^ '='.ord

    # puts "After:"
    # puts modified_enc_bytes.each_slice(16).to_a[2].map { |x| x.to_s(2).rjust 8, '0'}.join ' '    
    # puts @oracle.decrypt_ctr(modified_enc_bytes.pack("C*")).bytes.each_slice(16).to_a.map { |x| x.map { |y| y.to_s(2).rjust 8, '0' }.join " " }[2]
    
    puts @oracle.decrypt_ctr(modified_enc_bytes.pack("C*"))

    @oracle.decrypt_and_validate modified_enc_bytes.pack("C*")
  end
end

attacker = Attacker.new Oracle.new
puts attacker.attack