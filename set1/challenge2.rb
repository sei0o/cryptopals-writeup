# Fixed XOR
def xor_hex hex1, hex2
  val1 = [hex1].pack("H*").bytes
  val2 = [hex2].pack("H*").bytes

  val1.zip(val2).map { |x, y| (x ^ y).to_s 16 }.join
end

puts xor_hex('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965')