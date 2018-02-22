# The CBC padding oracle
require 'openssl'

class Oracle
  UNKNOWN = [
    'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
    'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
    'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
    'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
    'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
    'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
    'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
    'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
    'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
    'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

  def initialize
    @key = random_bytes
    @iv = random_bytes
  end

  def encrypt
    [encrypt_cbc(padding_pkcs7(UNKNOWN.sample, 16)), @iv]
  end

  def decrypt_and_validate encrypted, iv
    @iv = iv
    begin
      validate_pkcs7 decrypt_cbc(encrypted)
    rescue
      false
    end
  end

  def random_bytes length = 16
    length.times.map { (0x00..0xFF).to_a.sample.chr }.join
  end

  def padding_pkcs7 str, len
    add = len - str.size % len
    str + add.chr * add # padding is added in any case
  end
  
  def validate_pkcs7 str
    len = 0
    str.bytes.last(16).reverse.each_with_index do |b, i|
      if b == str.bytes[-1]
        len += 1
      else
        break
      end
    end
    
    len == str.bytes.last 
  end

  def encrypt_cbc plain
    cipher = OpenSSL::Cipher::Cipher.new 'AES-128-CBC'
    cipher.encrypt
    cipher.padding = 0
    cipher.key = @key
    cipher.iv = @iv
    cipher.update(plain) + cipher.final
  end

  def decrypt_cbc encrypted
    cipher = OpenSSL::Cipher::Cipher.new 'AES-128-CBC'
    cipher.decrypt
    cipher.padding = 0
    cipher.key = @key
    cipher.iv = @iv
    cipher.update(encrypted) + cipher.final
  end 
end

class Attacker
  def initialize oracle
    @oracle = oracle
  end

  def attack
    # explanation (in Japanese): https://www.goto.info.waseda.ac.jp/~kiire/crypto/pad-oracle.php
    encrypted, iv = @oracle.encrypt # using IV we can decrypt the first block
    enc_blocks = encrypted.bytes.each_slice(16).to_a
    enc_blocks.unshift iv.bytes

    plain_blocks = []
    (enc_blocks.size - 1).downto(1) do |block_pos| # loop backwards from the last block
      xored_block = []

      15.downto(0) do |byte_pos| # loop backwards from the last byte
        plain_pad = 16 - byte_pos

        256.times do |inject_val|
          bks = Marshal.load(Marshal.dump(enc_blocks)) # deep copy
          
          bks[block_pos-1][byte_pos] = inject_val
          (byte_pos+1).upto(15) do |xpos|
            bks[block_pos-1][xpos] = plain_pad ^ xored_block[xpos]
          end

          if @oracle.decrypt_and_validate bks[1..block_pos].flatten.pack("C*"), bks[0].pack("C*") # succeed, go to next byte
            xored_block[byte_pos] = plain_pad ^ inject_val
            break
          end
        end

        raise 'Could not find padding' unless xored_block[byte_pos] # decryption block not found
      end

      plain_blocks[block_pos] = xored_block.zip(enc_blocks[block_pos-1]).map { |a, b| a ^ b }
      p plain_blocks.flatten.compact.pack("C*")
    end

    plain_blocks.flatten.compact.pack("C*")
  end
end

attacker = Attacker.new Oracle.new
attacker.attack