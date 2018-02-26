# Break "random access read/write" AES CTR
require 'openssl'
require 'base64'

class Oracle
  def initialize
    @key = random_bytes
    @nonce = (0..0xffff).to_a.sample
  end

  def get_ciphertext
    plain = decrypt_block "YELLOW SUBMARINE", Base64.decode64(File.read("challenge25.txt"))
    encrypt_ctr plain
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
  
  def decrypt_block key, encrypted
    cipher = OpenSSL::Cipher::Cipher.new 'AES-128-ECB'
    cipher.decrypt
    cipher.key = key
    cipher.update(encrypted) + cipher.final
  end
  
  def keystream count
    encrypt_block [@nonce,count].pack("Q*")
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
  
  def edit encrypted, offset, newtext
    enc_newtext = encrypt_ctr newtext, offset
    (encrypted.bytes[0...offset] || []).pack("C*") + enc_newtext + (encrypted.bytes[offset+enc_newtext.bytesize..-1] || []).pack("C*")
  end
end

oracle = Oracle.new
encrypted = oracle.get_ciphertext

recovered_keystream = oracle.edit(encrypted, 0, "\x00" * encrypted.bytesize)
p recovered_keystream.bytes[0...8], oracle.keystream(0).bytes[0...8]
puts encrypted.bytes.zip(recovered_keystream.bytes).map { |e, k| e ^ k }.pack("C*")