# Break fixed-nonce CTR mode using substitutions
require 'openssl'
require 'base64'

def encrypt_block key, plain
  cipher = OpenSSL::Cipher::Cipher.new 'AES-128-ECB'
  cipher.encrypt
  cipher.padding = 0
  cipher.key = key
  cipher.update(plain) + cipher.final
end

def random_bytes length = 16
  length.times.map { (0x00..0xFF).to_a.sample.chr }.join
end

def keystream key, nonce, count
  encrypt_block key, [nonce,count].pack("Q*")
end

def encrypt_ctr key, nonce, input
  input.bytes.each_slice(16).map.with_index do |block, i|
    keystream(key, nonce, i).bytes.zip(block).map do |ks, b|
      next unless b
      ks ^ b
    end
  end.flatten.compact.pack("C*")
end
alias :decrypt_ctr :encrypt_ctr

key = random_bytes
encrypted = [
  'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
  'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
  'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
  'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
  'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
  'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
  'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
  'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
  'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
  'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
  'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
  'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
  'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
  'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
  'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
  'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
  'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
  'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
  'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
  'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
  'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
  'U2hlIHJvZGUgdG8gaGFycmllcnM/',
  'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
  'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
  'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
  'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
  'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
  'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
  'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
  'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
  'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
  'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
  'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
  'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
  'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
  'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
  'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
  'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
  'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
  'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4='
].map do |x|
  encrypt_ctr key, 0, Base64.decode64(x)
end

# bytes in the same position use the same keystream's byte
mxsize = encrypted.max_by { |x| x.size }.size
bytes = encrypted.map(&:bytes)
bytes_same_pos = ([nil] * mxsize).zip(*bytes) # safe transpose

require 'pp'
pp bytes_same_pos

bytes_same_pos.each do |i|
end

# well...oh no I don't know what to do