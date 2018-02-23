# Break fixed-nonce CTR mode using substitutions
require 'openssl'
require 'base64'

def encrypt_block key, plain
  cipher = OpenSSL::Cipher::Cipher.new 'AES-128-ECB'
  cipher.encrypt
  cipher.padding = 0
  cipher.key = key
  cipher.update(plain) + cipher.final
end

def random_bytes length = 16
  length.times.map { (0x00..0xFF).to_a.sample.chr }.join
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

key = random_bytes
encrypted = File.read("challenge19.txt").split("\n").map do |x|
  encrypt_ctr key, 0, Base64.decode64(x)
end

# encrypted bytes in the same position use the same keystream's byte
mxsize = encrypted.max_by { |x| x.size }.size
bytes = encrypted.map(&:bytes)
bytes_same_pos = ([nil] * mxsize).zip(*bytes) # safe transpose

# bruteforce
decrypted = []
recovered_keystream = []
bytes_same_pos.each do |bs|
  0xFF.times do |ks_byte| # bruteforce
    xored = bs.compact.map { |x| x ^ ks_byte }
    if xored.pack("C*")[/[a-zA-Z0-9\s;,.?!]+/] == xored.pack("C*") # if xored
      recovered_keystream << ks_byte
      decrypted << xored
      break
    end
  end
end

puts ([nil] * encrypted.size).zip(*decrypted).map(&:compact).map { |x| x.pack("C*") }
p recovered_keystream

# see also: https://fattybeagle.com/2017/01/03/cryptopals-challenge-19/