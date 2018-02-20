# Implement PKCS#7 padding
def padding_pkcs7 str, len
  add = len - str.size % len
  str + add.chr * add
end

p padding_pkcs7("YELLOW SUBMARINE", 20)