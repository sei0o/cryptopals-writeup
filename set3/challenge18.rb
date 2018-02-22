# Implement CTR, the stream cipher mode
require 'openssl'
require 'base64'

def encrypt_block key, plain
  cipher = OpenSSL::Cipher::Cipher.new 'AES-128-ECB'
  cipher.encrypt
  cipher.padding = 0
  cipher.key = key
  cipher.update(plain) + cipher.final
end

def keystream key, nonce, count
  encrypt_block key, [nonce,count].pack("Q*")
end

def encrypt_ctr key, nonce, input
  input.bytes.each_slice(16).map.with_index do |block, i|
    keystream(key, nonce, i).bytes.zip(block).map do |ks, b|
      next unless b
      ks ^ b
    end
  end.flatten.compact.pack("C*")
end
alias :decrypt_ctr :encrypt_ctr

puts decrypt_ctr("YELLOW SUBMARINE", 0, Base64.decode64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="))
puts decrypt_ctr("Adrenaline Power", 10, encrypt_ctr("Adrenaline Power", 10, "Let the bass kick"))