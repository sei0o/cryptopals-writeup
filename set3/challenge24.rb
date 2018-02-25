# Create the MT19937 stream cipher and break it
class MT19937
  W = 32
  N = 624
  M = 397
  R = 31
  A = 0x9908b0df
  U = 11
  D = 0xffffffff
  S = 7
  B = 0x9d2c5680
  T = 15
  C = 0xefc60000
  L = 18
  F = 1812433253

  MASK = ("1" * W).to_i 2
  UPPER_MASK = ("1" * (W - R) + "0" * R).to_i 2
  LOWER_MASK = ("0" * (W - R) + "1" * R).to_i 2

  def initialize seed
    @i = 0
    @x = [seed & MASK]
    1.upto(N-1) do |i|
      @x[i] = (F * (@x[i-1] ^ (@x[i-1] >> (W-2))) + i) & MASK
    end
  end

  def next
    v = @x[@i] & UPPER_MASK | @x[(@i + 1) % N] & LOWER_MASK
    @x[@i] = @x[(@i + M) % N] ^ (v >> 1) ^ (v & 1 == 0 ? 0 : A)

    y = @x[@i] ^ ((@x[@i] >> U) & D)
    y = y ^ ((y << S) & B)
    y = y ^ ((y << T) & C)
    z = y ^ (y >> L)

    @i = (@i + 1) % N
    z
  end
end

class MTStreamCipher
  def initialize seed
    @seed = seed
  end
  
  def next_keystream_byte
    @mt.next & 0xff
  end

  def encrypt plain
    @mt = MT19937.new @seed
    plain.bytes.map do |b|
      b ^ next_keystream_byte
    end.pack("C*")
  end
  alias :decrypt :encrypt
end

# Create the MT19937 Cipher
cipher = MTStreamCipher.new 0x4b53
p cipher.decrypt cipher.encrypt("foobar") # => "foobar"

# Recover the key(seed)
cipher = MTStreamCipher.new (0x0000..0xFFFF).to_a.sample
prefix = (0x00..0xff).to_a.sample((2..20).to_a.sample).pack("C*")
known = 'A' * 14
encrypted = cipher.encrypt prefix + known

0xffff.times do |seed|
  ci = MTStreamCipher.new seed
  dec = ci.decrypt encrypted
  if dec.include? known
    p [dec, seed]
    break
  end
end

# Write a function to check password token
token = MTStreamCipher.new(Time.now.to_i).encrypt "This is a reset token"

sleep (3..10).to_a.sample

(Time.now.to_i).downto(Time.now.to_i - 300) do |t| # check whether the token was created within 300 secs
  result = MTStreamCipher.new(t).decrypt token
  if result.include? "This is a reset token"
    puts "Valid token created #{Time.now.to_i - t} seconds ago"
  end
end