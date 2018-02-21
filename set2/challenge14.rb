# Byte-at-a-time ECB decryption (Harder)
require 'openssl'
require 'base64'

class Oracle
  UNKNOWN = Base64.decode64 "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
  
  def initialize
    @key = random_bytes
    @random_prefix = random_bytes (3..50).to_a.sample
  end

  def get_oracle plain
    modified = @random_prefix + plain + UNKNOWN
    modified = padding_pkcs7 modified, 16
  
    encrypt_block @key, modified
  end
  
  def random_bytes length = 16
    length.times.map { (0x00..0xFF).to_a.sample.chr }.join
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
end

class Attacker
  def initialize oracle
    @oracle = oracle
  end

  def attack
    known = ''
    rand_prefix_len = guess_prefix_length
    rand_prefix_pad = rand_prefix_len % 16 ? 'A' * (16 - rand_prefix_len % 16) : ''
    head_blocks = rand_prefix_len / 16 * 16
    
    loop do
      prefix_block = (known.bytesize / 16).floor + 1 # calculate the blocks we have to use
      prefix = rand_prefix_pad + 'A' * ([prefix_block, 1].max * 16 - 1 - known.bytesize)

      dict = (0x00..0xFF).map do |b| # map the oracle to the last char
        [@oracle.get_oracle(prefix + known + b.chr).bytes[head_blocks...(head_blocks + prefix.size + known.size + 1)].pack("C*"), b.chr]
      end.to_h

      result = @oracle.get_oracle(prefix).bytes[head_blocks...(head_blocks + prefix.size + known.size + 1)].pack("C*")
      break unless dict[result] # if the oracle didn't match any of dict, there is no more unknown character

      known += dict[result]
    end

    return known
  end

  def guess_prefix_length
    blocks = @oracle.get_oracle('A' * 16 * 3).bytes.each_slice(16).map { |k| k.pack("C*") } # inside blocks, there should be 2 same blocks encrypted 'A' * 16
    a_fill_block = nil
    prefix_blocks = 0

    blocks.each_cons(2).with_index do |(a, b), i|
      if a == b
        a_fill_block = a
        prefix_blocks = i
        break
      end
    end

    (16 * 2).times do |len|
      bs = @oracle.get_oracle('A' * (16 * 2 - len)).bytes.each_slice(16).map { |k| k.pack("C*") }
      return ((prefix_blocks - 1) * 16) + (len - 1) if bs.count(a_fill_block) == 0 # We have to use prefix_blocks - 1
    end

    return nil
  end
end

attacker = Attacker.new Oracle.new
puts attacker.attack