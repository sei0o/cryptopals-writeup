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

def keystream key, count
  encrypt_block key, "\x00" * 8 + count.chr + "\x00" * 7
end

def encrypt_ctr key, input
  input.bytes.each_slice(16).map.with_index do |block, i|
    keystream(key, i).bytes.zip(block).map do |ks, b|
      next unless b
      ks ^ b
    end
  end.flatten.compact.pack("C*")
end
alias :decrypt_ctr :encrypt_ctr

puts decrypt_ctr("YELLOW SUBMARINE", Base64.decode64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="))
puts decrypt_ctr("Adrenaline Power", encrypt_ctr("Adrenaline Power", "Let the bass kick"))