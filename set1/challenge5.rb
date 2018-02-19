# Implement repeating-key XOR
def encrypt plain, key
  bytes = plain.unpack 'C*'
  bytes.map.with_index { |b, i| (b ^ key[i % key.size].ord).to_s(16).rjust(2, '0') }.join
end

plain = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"
key = 'ICE'

puts encrypt(plain, key)