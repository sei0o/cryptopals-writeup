# Byte-at-a-time ECB decryption (Simple)
require 'openssl'
require 'base64'

class Oracle
  UNKNOWN = Base64.decode64 "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
  
  def initialize
    @key = random_bytes
  end

  def get_oracle plain
    modified = plain + UNKNOWN
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
    block_size = guess_block_size
    mode = judge_mode block_size

    if mode == :ecb
      known = ''

      loop do
        prefix_block = (known.bytesize / block_size).floor + 1 # calculate the blocks we have to use
        prefix = 'A' * ([prefix_block, 1].max * block_size - 1 - known.bytesize)

        dict = (0x00..0xFF).map do |b| # map the oracle to the last char
          [@oracle.get_oracle(prefix + known + b.chr).bytes[0...(prefix.size + known.size + 1)].pack("C*"), b.chr]
        end.to_h

        result = @oracle.get_oracle(prefix).bytes[0...(prefix.size + known.size + 1)].pack("C*")
        break unless dict[result] # if the oracle didn't match any of dict, there is no more unknown character

        known += dict[result]
      end

      return known
    else
      return false
    end
  end

  def guess_block_size
    # The length of encrypted string continue to increase by a block's size
    before = @oracle.get_oracle ''
    size = 0
    1.upto(99999) do |i|
      after = @oracle.get_oracle 'A' * i
      if before.size < after.size
        size = after.size - before.size
        break
      end
    end

    size
  end

  def judge_mode block_size # From challenge 11
    plain = 'A' * block_size * 3
    encrypted = @oracle.get_oracle plain

    result = :cbc
    parts = encrypted.bytes.each_cons(block_size).to_a
    parts.each do |part|
      if parts.count(part) >= 2
        result = :ecb
        break
      end
    end

    result
  end
end

attacker = Attacker.new Oracle.new
puts attacker.attack