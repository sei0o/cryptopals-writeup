# Break fixed-nonce CTR statistically
require 'openssl'
require 'base64'

def random_bytes length = 16
  length.times.map { (0x00..0xFF).to_a.sample.chr }.join
end

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

def calculate_monogram_score str
  return -1 if !str.ascii_only? || str.match(/[\^\(\)\n\r\/~><\|$``]/) #str[/[0-9a-zA-Z\s,.!?]+/] == str

  str.count('e') * 12.10 +
  str.count('t') *  8.94 +
  str.count('a') *  8.55 +
  str.count('o') *  7.47 +
  str.count('i') *  7.33 +
  str.count('n') *  7.17 +

  str.count('E') *  6.05 +
  str.count('T') *  4.49 +
  str.count('A') *  4.27 +
  str.count('O') *  3.73 +
  str.count('I') *  3.73 +
  str.count('N') *  3.08
end

def calculate_bigram_score strs # strs = ['th', 'ay', 'nG', ...]
  return 0 if strs.any? { |s| !s.ascii_only? }
  
  s = strs # s = strs.map(&:downcase)
  s.count('th') * 2.71 +
  s.count('he') * 2.33 +
  s.count('in') * 2.03 +
  s.count('er') * 1.78 +
  s.count('an') * 1.61 +
  s.count('re') * 1.41
end

def decrypt encrypted
  # min_size = encrypted.min_by(&:bytesize).bytesize
  # truncated = encrypted.map { |e| e.bytes[0...min_size] }
  transposed = ([nil] * 60).zip(*encrypted.map(&:bytes)).compact.map(&:compact)
  decrypted = []
  
  # Monogram
  monogram_scores = [[0] * 256]
  transposed.each_with_index do |col, i|
    monogram_scores << [0] * 256
    (0x00..0xFF).each do |key|
      dec = col.map { |t| t ^ key }.pack("C*")
      monogram_scores[i][key] = calculate_monogram_score dec
    end
  end

  # Bigram
  bigram_scores = [[0] * 256] 
  transposed.each_cons(2).with_index do |cols, i|
    bigram_scores << [0] * 256
    (0x00..0xFF).to_a.permutation(2).each do |ks|
      decs = cols.zip(ks).map do |(col, key)|
        col.map { |t| t ^ key }
      end
      score = calculate_bigram_score ([nil] * 60).zip(*decs).compact.map { |x| x.compact.pack("C*") }
      bigram_scores[i][ks[0]] += score
      bigram_scores[i+1][ks[1]] += score
    end
    p i
  end

  scores = bigram_scores.zip(monogram_scores).map do |(col_bi, col_mono)|
    col_bi.zip(col_mono).map { |(bi, mo)| 5 * bi + mo }
  end
  p scores
  scores.each_with_index do |col, i|
    sorted = col.map.with_index.sort.reverse # https://stackoverflow.com/a/14446365
    best_key = sorted[0][1]
    decrypted << transposed[i].map { |t| t ^ best_key }
  end

  # p keystream 
  ([nil] * 60).zip(*decrypted).compact.map {|x| x.compact.pack("C*")}
end

key = random_bytes
encrypted = File.read('challenge20.txt').split("\n").map do |x|
  encrypt_ctr key, 0, Base64.decode64(x)
end

puts decrypt encrypted
