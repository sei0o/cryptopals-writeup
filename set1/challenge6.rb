# Break repeating-key XOR
MAP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
PADDING = '='

def decode_base64 encoded
  result = ''

  encoded.chars.each do |ch|
    if MAP.index(ch)
      result += MAP.index(ch).to_s(2).rjust(6, '0')
    end
  end

  [result].pack("B*").strip
end

def hamming_distance a, b
  a_bits = a.unpack("B*")[0].chars
  b_bits = b.unpack("B*")[0].chars

  a_bits.zip(b_bits).count { |cha, chb| cha != chb }
end

# From Challenge 4
def solve_xor bytes
  max_score = 0
  result_key = 0
  result = ''
  (0x01..0xFF).each do |key|
    decrypted = bytes.map { |byte| (byte ^ key).chr }.join
    next unless decrypted.ascii_only?

    score = decrypted.bytes.count { |byte| byte.chr =~ /[0-9a-zA-Z]/ }
    'eatiosnr'.chars.each_with_index do |ch, i| # most frequent alphabets
      score += decrypted.count(ch) * (8-i/2) + decrypted.count(ch.upcase) * (8-i/2)
    end
    if score > max_score
      max_score = score
      result_key = key
      result = decrypted
    end
  end

  [result_key, result]
end

encrypted = decode_base64 File.read("challenge6.txt")

distances = []
(2..40).each do |size| # sample two pairs of blocks and calculate the distance
  blocks = encrypted.chars.each_slice(size).take(4)
  sum = blocks.each_slice(2).inject(0) { |memo, (a, b)| hamming_distance a.join, b.join }
  distances << [size, sum / (size.to_f * 2)]
end
distances.sort_by! { |a| a[1] }

distances[0..4].each do |(size, _)| # try 5 key sizes which have small distance
  blocks = encrypted.bytes.each_slice(size).to_a
  blocks.pop if blocks[-1].size < size
  result = blocks.transpose.map do |block|
    solve_xor(block)[0]
  end

  puts result.pack("U*")
end