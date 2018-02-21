# PKCS#7 padding validation
def strip_pkcs7 str
  len = 0
  str.bytes.last(16).reverse.each_with_index do |b, i|
    if b == str.bytes[-1]
      len += 1
    else
      break
    end
  end
  
  raise "Not valid string" if len != str.bytes.last 
  str[0..-len-1]
end

puts strip_pkcs7("ICE ICE BABY\x04\x04\x04\x04")
# puts strip_pkcs7("ICE ICE BABY\x04\x02\x04\x03")
# puts strip_pkcs7("ICE ICE BABY\x04\x04\x04\x04\x04")