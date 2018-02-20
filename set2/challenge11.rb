# An ECB/CBC detection oracle
require 'openssl'

def random_bytes length = 16
  length.times.map { (0x00..0xFF).to_a.sample.chr }.join
end

def xor_str a, b
  a.bytes.zip(b.bytes).map { |cha, chb| (cha.ord ^ chb.ord).chr }.join
end

def padding_pkcs7 str, len # From Challenge 9
  add = len - str.size % len
  add == len ? str : str + add.chr * add
end

def encrypt_block key, plain
  cipher = OpenSSL::Cipher::Cipher.new 'AES-128-ECB'
  cipher.encrypt
  cipher.padding = 0
  cipher.key = key
  cipher.update(plain) + cipher.final
end

def encrypt_cbc key, plain, iv
  blocks = plain.bytes.each_slice(16).map {|arr| arr.pack("C*") }

  encrypted = [iv]
  blocks.each do |b|
    encrypted << encrypt_block(key, xor_str(encrypted[-1], b))
  end

  encrypted[1..-1].join
end

def random_oracle plain
  modified = random_bytes((5..10).to_a.sample) + plain + random_bytes((5..10).to_a.sample)
  modified = padding_pkcs7 modified, 16

  if [true, false].sample 
    puts 'ecb'
    encrypt_block random_bytes, modified
  else
    puts 'cbc'
    encrypt_cbc random_bytes, modified, random_bytes
  end
end

input = 'a' * 16 * 3
encrypted = random_oracle input

# if random_oracle choose ECB, there should be some identical parts in the result
result = 'CBC'
encrypted.bytes.each_cons(16) do |part|
  if encrypted.bytes.each_cons(16).count(part) >= 2
    result = 'ECB'
    break
  end
end

puts result