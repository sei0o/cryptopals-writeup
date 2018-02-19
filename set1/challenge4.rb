# Detect single-character XOR
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

File.read('challenge4.txt').split("\n").each do |line|
  result = decrypt(line)
  puts "The key is %d: %s" % result if result[0] > 0
end