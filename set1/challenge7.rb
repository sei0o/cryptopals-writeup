# AES in ECB mode
require 'openssl'
require 'base64'

key = 'YELLOW SUBMARINE'
encrypted = Base64.decode64 File.read('challenge7.txt')

cipher = OpenSSL::Cipher::Cipher.new 'AES-128-ECB'
cipher.decrypt
cipher.key = key

puts cipher.update(encrypted) + cipher.final