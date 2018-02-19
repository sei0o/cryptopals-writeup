# Single-byte XOR cipher
def decrypt hexstr
  bytes = [hexstr].pack("H*").bytes

  max_score = 0
  result_key = 0
  result = ''
  (0x01..0xFF).each do |key|
    decrypted = bytes.map { |byte| (byte ^ key).chr }.join
    next unless decrypted.ascii_only?

    score = decrypted.bytes.count { |byte| byte.chr =~ /[0-9a-zA-Z]/ }
    'eatiosnr'.chars.each do |ch| # most frequent alphabets
      score += decrypted.count(ch) + decrypted.count(ch.upcase)
    end
    if score > max_score
      max_score = score
      result_key = key
      result = decrypted
    end
  end

  [result_key, result]
end

encrypted = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
puts "The key is %d: %s" % decrypt(encrypted)