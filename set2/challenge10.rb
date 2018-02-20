# Implement CBC mode
require 'openssl'
require 'base64'

def decrypt_block key, encrypted
  cipher = OpenSSL::Cipher::Cipher.new 'AES-128-ECB'
  cipher.decrypt
  cipher.padding = 0 # an error occurs without this
  cipher.key = key
  
  cipher.update(encrypted) + cipher.final
end

def xor_str a, b
  a.chars.zip(b.chars).map { |cha, chb| (cha.ord ^ chb.ord).chr }.join
end

def decrypt key, encrypted, iv
  blocks = encrypted.bytes.each_slice(16).map {|arr| arr.pack("C*") }

  plain = []
  blocks.unshift(iv).each_cons(2) do |a, b|
    plain << xor_str(decrypt_block(key, b), a)
  end

  plain.join
end

iv = "\x00" * (128 / 8)
key = 'YELLOW SUBMARINE'
encrypted = Base64.decode64 File.read('challenge10.txt')

puts decrypt(key, encrypted, iv)