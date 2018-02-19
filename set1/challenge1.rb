# Convert hex to base64
MAP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
PADDING = '='

def hex2base64 hexstr
  bits = [hexstr].pack("H*").unpack("B*")[0].chars
  
  result = ''
  bits.each_slice(6) do |b|
    result += MAP[b.join.to_i(2)]
    result += PADDING * (6 - b.size)
  end

  result
end

hex = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
puts hex2base64(hex)