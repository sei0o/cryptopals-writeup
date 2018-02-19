require 'openssl'

def decrypt str
  cipher = OpenSSL::Cipher.new "AES-128-ECB"
  cipher.decrypt
  cipher.key = 'YELLOW SUBMARINE'
  
  begin
    cipher.update(str) + cipher.final
  rescue
    return nil
  end
end

File.read('challenge8.txt').split("\n").each do |line|
  p decrypt [line].pack("H*")
end