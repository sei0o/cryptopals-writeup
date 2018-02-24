# Clone an MT19937 RNG from its output
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

class MT19937
  MASK = ("1" * W).to_i 2
  UPPER_MASK = ("1" * (W - R) + "0" * R).to_i 2
  LOWER_MASK = ("0" * (W - R) + "1" * R).to_i 2
  attr_accessor :x

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

def temper x
  y = x ^ ((x >> U) & D)
  y = y ^ ((y << S) & B)
  y = y ^ ((y << T) & C)
  z = y ^ (y >> L)
end

def untemper z
  # z = y ^ (y >> 18)
  y3 = z & ("1" * 18 + "0" * 14).to_i(2) | z & ("1" * 14).to_i(2) ^ (z >> 18)
  
  # y = y ^ ((y << 15) & 0xefc60000)
  y2  = y3 & ("1" * 17).to_i(2) 
  y2 |= ((y2 << 15) & 0xefc60000) ^ (y3 & ("1" * 15 + "0" * 17).to_i(2))
  
  # y = y ^ ((y << 7) & 0x9d2c5680)
  y1  = y2 & ("1" * 7).to_i(2)
  y1 |= (((y1 << 7) & 0x9d2c5680) ^ y2) & ("1" * 7 + "0" * 7).to_i(2)
  y1 |= (((y1 << 7) & 0x9d2c5680) ^ y2) & ("1" * 7 + "0" * 14).to_i(2)
  y1 |= (((y1 << 7) & 0x9d2c5680) ^ y2) & ("1" * 7 + "0" * 21).to_i(2)
  y1 |= (((y1 << 7) & 0x9d2c5680) ^ y2) & ("1" * 4 + "0" * 28).to_i(2)

  # y = x ^ ((x >> U) & 0xffffffff) = x ^ (x >> 11)
  x  = y1 & ("1" * 11 + "0" * 21).to_i(2)
  x |= ((x >> 11) ^ y1) & ("1" * 11 + "0" * 10).to_i(2)
  x |= ((x >> 11) ^ y1) & ("1" * 10).to_i(2)
  
  x
end

mt = MT19937.new 20180225
rnds = (0...N).map { mt.next }
untempered = rnds.map { |rnd| untemper rnd }

clone_mt = MT19937.new 5478749 # different seed
# clone_mt.x = Marshal.load(Marshal.dump(mt.x)) # copy Xs and predict further numbers
clone_mt.x = Marshal.load(Marshal.dump(untempered)) # "Untemper" and predict further numbers

predicted_rnds = (0...N).map { clone_mt.next }
new_rnds = (0...N).map { mt.next }

p predicted_rnds[0..3], new_rnds[0..3]
p predicted_rnds == new_rnds