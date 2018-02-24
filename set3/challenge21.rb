# Implement the MT19937 Mersenne Twister RNG
# see here: https://narusejun.com/archives/5/
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

t = MT19937.new 19650218
20.times do |i|
  p t.next
end