  --==[[          Shaman         ]]==--
  --==[[ Encryption for Minetest ]]==--
  --==[[    MIT (c) 2024 monk    ]]==--
  ------------------------------------------------------------------------------
  -- Forked from pure_lua_SHA/sha2.lua by Egor Skriptunoff
  ------------------------------------------------------------------------------
  -- VERSION: 12 (2022-02-23)
  -- AUTHOR:  Egor Skriptunoff
  -- LICENSE: MIT (the same license as Lua itself)
  -- URL:     https://github.com/Egor-Skriptunoff/pure_lua_SHA
  -- DESCRIPTION:
  --    This module contains functions to calculate SHA digest:
  --       MD5, SHA-1,
  --       SHA-224, SHA-256, SHA-512/224, SHA-512/256, SHA-384, SHA-512,
  --       SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256,
  --       HMAC,
  --       BLAKE2b, BLAKE2s, BLAKE2bp, BLAKE2sp, BLAKE2Xb, BLAKE2Xs,
  --       BLAKE3, BLAKE3_KDF
  -- USAGE:
  --    Input data should be provided as a binary string: either as a whole string or as a sequence of substrings (chunk-by-chunk loading, total length < 9*10^15 bytes).
  --    Result (SHA digest) is returned in hexadecimal representation as a string of lowercase hex digits.
  --    Simplest usage example:
  --       local sha = require("sha2")
  --       local your_hash = sha.sha256("your string")
  --    See file "sha2_test.lua" for more examples.
  -------------------------------------------------------------------------------
local unpack = table.unpack or unpack
local concat = table.concat
local byte = string.byte
local char = string.char
local string_rep = string.rep
local sub = string.sub
local gsub = string.gsub
local gmatch = string.gmatch
local string_format = string.format
local floor = math.floor
local ceil = math.ceil
local math_min = math.min
local math_max = math.max
local tonumber = tonumber
local type = type
local math_huge = math.huge

    -- local path = minetest.get_modpath(minetest.get_current_modname()).."/"
    -- local sha = dofile(path.."sha_lib.lua")

  --------------------------------------------------------------------------------
  -- BASIC 32-BIT BITWISE FUNCTIONS
  --------------------------------------------------------------------------------
  -- Emulating 32-bit bitwise operations using 53-bit floating point arithmetic
  local AND, OR, XOR, SHL, SHR, ROL, ROR, NOT, NORM, HEX, XOR_BYTE
  local function SHL(x, n)
    return (x * 2^n) % 2^32
  end

  local function SHR(x, n)
    x = x % 2^32 / 2^n
    return x - x % 1
  end

  local function ROL(x, n)
    x = x % 2^32 * 2^n
    local r = x % 2^32
    return r + (x - r) / 2^32
  end

  local function ROR(x, n)
    x = x % 2^32 / 2^n
    local r = x % 1
    return r * 2^32 + (x - r)
  end

  local AND_of_two_bytes = {[0] = 0}  -- look-up table (256*256 entries)
  local idx = 0
  for y = 0, 127 * 256, 256 do
    for x = y, y + 127 do
        x = AND_of_two_bytes[x] * 2
        AND_of_two_bytes[idx] = x
        AND_of_two_bytes[idx + 1] = x
        AND_of_two_bytes[idx + 256] = x
        AND_of_two_bytes[idx + 257] = x + 1
        idx = idx + 2
    end
    idx = idx + 256
  end

  local function and_or_xor(x, y, operation)
    -- operation: nil = AND, 1 = OR, 2 = XOR
    local x0 = x % 2^32
    local y0 = y % 2^32
    local rx = x0 % 256
    local ry = y0 % 256
    local res = AND_of_two_bytes[rx + ry * 256]
    x = x0 - rx
    y = (y0 - ry) / 256
    rx = x % 65536
    ry = y % 256
    res = res + AND_of_two_bytes[rx + ry] * 256
    x = (x - rx) / 256
    y = (y - ry) / 256
    rx = x % 65536 + y % 256
    res = res + AND_of_two_bytes[rx] * 65536
    res = res + AND_of_two_bytes[(x + y - rx) / 256] * 16777216
    if operation then
        res = x0 + y0 - operation * res
    end
    return res
  end

  local function AND(x, y)
    return and_or_xor(x, y)
  end

  local function OR(x, y)
    return and_or_xor(x, y, 1)
  end

  local function XOR(x, y, z, t, u)          -- 2..5 arguments
    if z then
        if t then
          if u then
              t = and_or_xor(t, u, 2)
          end
          z = and_or_xor(z, t, 2)
        end
        y = and_or_xor(y, z, 2)
    end
    return and_or_xor(x, y, 2)
  end

  local function XOR_BYTE(x, y)
    return x + y - 2 * AND_of_two_bytes[x + y * 256]
  end


  HEX = HEX or pcall(string_format, "%x", 2^31) and function(x) -- returns string of 8 lowercase hexadecimal digits
      return string_format("%08x", x % 4294967296)
    end or function(x)  -- for OpenWrt's dialect of Lua
      return string_format("%08x", (x + 2^31) % 2^32 - 2^31)
  end

  local function XORA5(x, y)
    return XOR(x, y or 0xA5A5A5A5) % 4294967296
  end

  local function create_array_of_lanes()
    return {
      0, 0, 0, 0, 0,
      0, 0, 0, 0, 0,
      0, 0, 0, 0, 0,
      0, 0, 0, 0, 0,
      0, 0, 0, 0, 0
    }
  end

  --------------------------------------------------------------------------------
  -- CREATING OPTIMIZED INNER LOOP
  --------------------------------------------------------------------------------

  -- Inner loop functions
  local sha256_feed_64, sha512_feed_128, md5_feed_64, sha1_feed_64, keccak_feed, blake2s_feed_64, blake2b_feed_128, blake3_feed_64

  -- Arrays of SHA-2 "magic numbers" (in "INT64" and "FFI" branches "*_lo" arrays contain 64-bit values)
  local sha2_K_lo, sha2_K_hi, sha2_H_lo, sha2_H_hi, sha3_RC_lo, sha3_RC_hi = {}, {}, {}, {}, {}, {}
  local sha2_H_ext256 = {[224] = {}, [256] = sha2_H_hi}
  local sha2_H_ext512_lo, sha2_H_ext512_hi = {[384] = {}, [512] = sha2_H_lo}, {[384] = {}, [512] = sha2_H_hi}
  local md5_K, md5_sha1_H = {}, {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}
  local md5_next_shift = {0, 0, 0, 0, 0, 0, 0, 0, 28, 25, 26, 27, 0, 0, 10, 9, 11, 12, 0, 15, 16, 17, 18, 0, 20, 22, 23, 21}
  local HEX64, lanes_index_base  -- defined only for branches that internally use 64-bit integers: "INT64" and "FFI"
  local common_W = {}    -- temporary table shared between all calculations (to avoid creating new temporary table every time)
  local common_W_blake2b, common_W_blake2s, v_for_blake2s_feed_64 = common_W, common_W, {}
  local K_lo_modulo, hi_factor, hi_factor_keccak = 4294967296, 0, 0
  local sigma = {
    {  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16 },
    { 15, 11,  5,  9, 10, 16, 14,  7,  2, 13,  1,  3, 12,  8,  6,  4 },
    { 12,  9, 13,  1,  6,  3, 16, 14, 11, 15,  4,  7,  8,  2, 10,  5 },
    {  8, 10,  4,  2, 14, 13, 12, 15,  3,  7,  6, 11,  5,  1, 16,  9 },
    { 10,  1,  6,  8,  3,  5, 11, 16, 15,  2, 12, 13,  7,  9,  4, 14 },
    {  3, 13,  7, 11,  1, 12,  9,  4,  5, 14,  8,  6, 16, 15,  2, 10 },
    { 13,  6,  2, 16, 15, 14,  5, 11,  1,  8,  7,  4, 10,  3,  9, 12 },
    { 14, 12,  8, 15, 13,  2,  4, 10,  6,  1, 16,  5,  9,  7,  3, 11 },
    {  7, 16, 15, 10, 12,  4,  1,  9, 13,  3, 14,  8,  2,  5, 11,  6 },
    { 11,  3,  9,  5,  8,  7,  2,  6, 16, 12, 10, 15,  4, 13, 14,  1 },
  };  sigma[11], sigma[12] = sigma[1], sigma[2]
  local perm_blake3 = {
    1, 3, 4, 11, 13, 10, 12, 6,
    1, 3, 4, 11, 13, 10,
    2, 7, 5, 8, 14, 15, 16, 9,
    2, 7, 5, 8, 14, 15,
  }

  XOR = XOR or XORA5

    -- implementation for Lua 5.1/5.2 (with or without bitwise library available)
  local function sha256_feed_64(H, str, offs, size)
    -- offs >= 0, size >= 0, size is multiple of 64
    local W, K = common_W, sha2_K_hi
    local h1, h2, h3, h4, h5, h6, h7, h8 = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
    for pos = offs, offs + size - 1, 64 do
        for j = 1, 16 do
          pos = pos + 4
          local a, b, c, d = byte(str, pos - 3, pos)
          W[j] = ((a * 256 + b) * 256 + c) * 256 + d
        end
        for j = 17, 64 do
          local a, b = W[j-15], W[j-2]
          local a7, a18, b17, b19 = a / 2^7, a / 2^18, b / 2^17, b / 2^19
          W[j] = (XOR(a7 % 1 * (2^32 - 1) + a7, a18 % 1 * (2^32 - 1) + a18, (a - a % 2^3) / 2^3) + W[j-16] + W[j-7]
              + XOR(b17 % 1 * (2^32 - 1) + b17, b19 % 1 * (2^32 - 1) + b19, (b - b % 2^10) / 2^10)) % 2^32
        end
        local a, b, c, d, e, f, g, h = h1, h2, h3, h4, h5, h6, h7, h8
        for j = 1, 64 do
          e = e % 2^32
          local e6, e11, e7 = e / 2^6, e / 2^11, e * 2^7
          local e7_lo = e7 % 2^32
          local z = AND(e, f) + AND(-1-e, g) + h + K[j] + W[j]
              + XOR(e6 % 1 * (2^32 - 1) + e6, e11 % 1 * (2^32 - 1) + e11, e7_lo + (e7 - e7_lo) / 2^32)
          h = g
          g = f
          f = e
          e = z + d
          d = c
          c = b
          b = a % 2^32
          local b2, b13, b10 = b / 2^2, b / 2^13, b * 2^10
          local b10_lo = b10 % 2^32
          a = z + AND(d, c) + AND(b, XOR(d, c)) +
              XOR(b2 % 1 * (2^32 - 1) + b2, b13 % 1 * (2^32 - 1) + b13, b10_lo + (b10 - b10_lo) / 2^32)
        end
        h1, h2, h3, h4 = (a + h1) % 2^32, (b + h2) % 2^32, (c + h3) % 2^32, (d + h4) % 2^32
        h5, h6, h7, h8 = (e + h5) % 2^32, (f + h6) % 2^32, (g + h7) % 2^32, (h + h8) % 2^32
    end
    H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8] = h1, h2, h3, h4, h5, h6, h7, h8
  end

  local function sha512_feed_128(H_lo, H_hi, str, offs, size)
    -- offs >= 0, size >= 0, size is multiple of 128
    -- W1_hi, W1_lo, W2_hi, W2_lo, ...   Wk_hi = W[2*k-1], Wk_lo = W[2*k]
    local W, K_lo, K_hi = common_W, sha2_K_lo, sha2_K_hi
    local h1_lo, h2_lo, h3_lo, h4_lo, h5_lo, h6_lo, h7_lo, h8_lo = H_lo[1], H_lo[2], H_lo[3], H_lo[4], H_lo[5], H_lo[6], H_lo[7], H_lo[8]
    local h1_hi, h2_hi, h3_hi, h4_hi, h5_hi, h6_hi, h7_hi, h8_hi = H_hi[1], H_hi[2], H_hi[3], H_hi[4], H_hi[5], H_hi[6], H_hi[7], H_hi[8]
    for pos = offs, offs + size - 1, 128 do
        for j = 1, 16*2 do
          pos = pos + 4
          local a, b, c, d = byte(str, pos - 3, pos)
          W[j] = ((a * 256 + b) * 256 + c) * 256 + d
        end
        for jj = 17*2, 80*2, 2 do
          local a_hi, a_lo, b_hi, b_lo = W[jj-31], W[jj-30], W[jj-5], W[jj-4]
          local b_hi_6, b_hi_19, b_hi_29, b_lo_19, b_lo_29, a_hi_1, a_hi_7, a_hi_8, a_lo_1, a_lo_8 =
              b_hi % 2^6, b_hi % 2^19, b_hi % 2^29, b_lo % 2^19, b_lo % 2^29, a_hi % 2^1, a_hi % 2^7, a_hi % 2^8, a_lo % 2^1, a_lo % 2^8
          local tmp1 = XOR((a_lo - a_lo_1) / 2^1 + a_hi_1 * 2^31, (a_lo - a_lo_8) / 2^8 + a_hi_8 * 2^24, (a_lo - a_lo % 2^7) / 2^7 + a_hi_7 * 2^25) % 2^32
              + XOR((b_lo - b_lo_19) / 2^19 + b_hi_19 * 2^13, b_lo_29 * 2^3 + (b_hi - b_hi_29) / 2^29, (b_lo - b_lo % 2^6) / 2^6 + b_hi_6 * 2^26) % 2^32
              + W[jj-14] + W[jj-32]
          local tmp2 = tmp1 % 2^32
          W[jj-1] = (XOR((a_hi - a_hi_1) / 2^1 + a_lo_1 * 2^31, (a_hi - a_hi_8) / 2^8 + a_lo_8 * 2^24, (a_hi - a_hi_7) / 2^7)
              + XOR((b_hi - b_hi_19) / 2^19 + b_lo_19 * 2^13, b_hi_29 * 2^3 + (b_lo - b_lo_29) / 2^29, (b_hi - b_hi_6) / 2^6)
              + W[jj-15] + W[jj-33] + (tmp1 - tmp2) / 2^32) % 2^32
          W[jj] = tmp2
        end
        local a_lo, b_lo, c_lo, d_lo, e_lo, f_lo, g_lo, h_lo = h1_lo, h2_lo, h3_lo, h4_lo, h5_lo, h6_lo, h7_lo, h8_lo
        local a_hi, b_hi, c_hi, d_hi, e_hi, f_hi, g_hi, h_hi = h1_hi, h2_hi, h3_hi, h4_hi, h5_hi, h6_hi, h7_hi, h8_hi
        for j = 1, 80 do
          local jj = 2*j
          local e_lo_9, e_lo_14, e_lo_18, e_hi_9, e_hi_14, e_hi_18 = e_lo % 2^9, e_lo % 2^14, e_lo % 2^18, e_hi % 2^9, e_hi % 2^14, e_hi % 2^18
          local tmp1 = (AND(e_lo, f_lo) + AND(-1-e_lo, g_lo)) % 2^32 + h_lo + K_lo[j] + W[jj]
              + XOR((e_lo - e_lo_14) / 2^14 + e_hi_14 * 2^18, (e_lo - e_lo_18) / 2^18 + e_hi_18 * 2^14, e_lo_9 * 2^23 + (e_hi - e_hi_9) / 2^9) % 2^32
          local z_lo = tmp1 % 2^32
          local z_hi = AND(e_hi, f_hi) + AND(-1-e_hi, g_hi) + h_hi + K_hi[j] + W[jj-1] + (tmp1 - z_lo) / 2^32
              + XOR((e_hi - e_hi_14) / 2^14 + e_lo_14 * 2^18, (e_hi - e_hi_18) / 2^18 + e_lo_18 * 2^14, e_hi_9 * 2^23 + (e_lo - e_lo_9) / 2^9)
          h_lo = g_lo;  h_hi = g_hi
          g_lo = f_lo;  g_hi = f_hi
          f_lo = e_lo;  f_hi = e_hi
          tmp1 = z_lo + d_lo
          e_lo = tmp1 % 2^32
          e_hi = (z_hi + d_hi + (tmp1 - e_lo) / 2^32) % 2^32
          d_lo = c_lo;  d_hi = c_hi
          c_lo = b_lo;  c_hi = b_hi
          b_lo = a_lo;  b_hi = a_hi
          local b_lo_2, b_lo_7, b_lo_28, b_hi_2, b_hi_7, b_hi_28 = b_lo % 2^2, b_lo % 2^7, b_lo % 2^28, b_hi % 2^2, b_hi % 2^7, b_hi % 2^28
          tmp1 = z_lo + (AND(d_lo, c_lo) + AND(b_lo, XOR(d_lo, c_lo))) % 2^32
              + XOR((b_lo - b_lo_28) / 2^28 + b_hi_28 * 2^4, b_lo_2 * 2^30 + (b_hi - b_hi_2) / 2^2, b_lo_7 * 2^25 + (b_hi - b_hi_7) / 2^7) % 2^32
          a_lo = tmp1 % 2^32
          a_hi = (z_hi + AND(d_hi, c_hi) + AND(b_hi, XOR(d_hi, c_hi)) + (tmp1 - a_lo) / 2^32
              + XOR((b_hi - b_hi_28) / 2^28 + b_lo_28 * 2^4, b_hi_2 * 2^30 + (b_lo - b_lo_2) / 2^2, b_hi_7 * 2^25 + (b_lo - b_lo_7) / 2^7)) % 2^32
        end
        a_lo = h1_lo + a_lo
        h1_lo = a_lo % 2^32
        h1_hi = (h1_hi + a_hi + (a_lo - h1_lo) / 2^32) % 2^32
        a_lo = h2_lo + b_lo
        h2_lo = a_lo % 2^32
        h2_hi = (h2_hi + b_hi + (a_lo - h2_lo) / 2^32) % 2^32
        a_lo = h3_lo + c_lo
        h3_lo = a_lo % 2^32
        h3_hi = (h3_hi + c_hi + (a_lo - h3_lo) / 2^32) % 2^32
        a_lo = h4_lo + d_lo
        h4_lo = a_lo % 2^32
        h4_hi = (h4_hi + d_hi + (a_lo - h4_lo) / 2^32) % 2^32
        a_lo = h5_lo + e_lo
        h5_lo = a_lo % 2^32
        h5_hi = (h5_hi + e_hi + (a_lo - h5_lo) / 2^32) % 2^32
        a_lo = h6_lo + f_lo
        h6_lo = a_lo % 2^32
        h6_hi = (h6_hi + f_hi + (a_lo - h6_lo) / 2^32) % 2^32
        a_lo = h7_lo + g_lo
        h7_lo = a_lo % 2^32
        h7_hi = (h7_hi + g_hi + (a_lo - h7_lo) / 2^32) % 2^32
        a_lo = h8_lo + h_lo
        h8_lo = a_lo % 2^32
        h8_hi = (h8_hi + h_hi + (a_lo - h8_lo) / 2^32) % 2^32
    end
    H_lo[1], H_lo[2], H_lo[3], H_lo[4], H_lo[5], H_lo[6], H_lo[7], H_lo[8] = h1_lo, h2_lo, h3_lo, h4_lo, h5_lo, h6_lo, h7_lo, h8_lo
    H_hi[1], H_hi[2], H_hi[3], H_hi[4], H_hi[5], H_hi[6], H_hi[7], H_hi[8] = h1_hi, h2_hi, h3_hi, h4_hi, h5_hi, h6_hi, h7_hi, h8_hi
  end

  local function md5_feed_64(H, str, offs, size)
      -- offs >= 0, size >= 0, size is multiple of 64
      local W, K, md5_next_shift = common_W, md5_K, md5_next_shift
      local h1, h2, h3, h4 = H[1], H[2], H[3], H[4]
      for pos = offs, offs + size - 1, 64 do
        for j = 1, 16 do
            pos = pos + 4
            local a, b, c, d = byte(str, pos - 3, pos)
            W[j] = ((d * 256 + c) * 256 + b) * 256 + a
        end
        local a, b, c, d = h1, h2, h3, h4
        local s = 25
        for j = 1, 16 do
            local z = (AND(b, c) + AND(-1-b, d) + a + K[j] + W[j]) % 2^32 / 2^s
            local y = z % 1
            s = md5_next_shift[s]
            a = d
            d = c
            c = b
            b = y * 2^32 + (z - y) + b
        end
        s = 27
        for j = 17, 32 do
            local z = (AND(d, b) + AND(-1-d, c) + a + K[j] + W[(5*j-4) % 16 + 1]) % 2^32 / 2^s
            local y = z % 1
            s = md5_next_shift[s]
            a = d
            d = c
            c = b
            b = y * 2^32 + (z - y) + b
        end
        s = 28
        for j = 33, 48 do
            local z = (XOR(XOR(b, c), d) + a + K[j] + W[(3*j+2) % 16 + 1]) % 2^32 / 2^s
            local y = z % 1
            s = md5_next_shift[s]
            a = d
            d = c
            c = b
            b = y * 2^32 + (z - y) + b
        end
        s = 26
        for j = 49, 64 do
            local z = (XOR(c, OR(b, -1-d)) + a + K[j] + W[(j*7-7) % 16 + 1]) % 2^32 / 2^s
            local y = z % 1
            s = md5_next_shift[s]
            a = d
            d = c
            c = b
            b = y * 2^32 + (z - y) + b
        end
        h1 = (a + h1) % 2^32
        h2 = (b + h2) % 2^32
        h3 = (c + h3) % 2^32
        h4 = (d + h4) % 2^32
      end
      H[1], H[2], H[3], H[4] = h1, h2, h3, h4
  end

  local function sha1_feed_64(H, str, offs, size)
    -- offs >= 0, size >= 0, size is multiple of 64
    local W = common_W
    local h1, h2, h3, h4, h5 = H[1], H[2], H[3], H[4], H[5]
    for pos = offs, offs + size - 1, 64 do
        for j = 1, 16 do
          pos = pos + 4
          local a, b, c, d = byte(str, pos - 3, pos)
          W[j] = ((a * 256 + b) * 256 + c) * 256 + d
        end
        for j = 17, 80 do
          local a = XOR(W[j-3], W[j-8], W[j-14], W[j-16]) % 2^32 * 2
          local b = a % 2^32
          W[j] = b + (a - b) / 2^32
        end
        local a, b, c, d, e = h1, h2, h3, h4, h5
        for j = 1, 20 do
          local a5 = a * 2^5
          local z = a5 % 2^32
          z = z + (a5 - z) / 2^32 + AND(b, c) + AND(-1-b, d) + 0x5A827999 + W[j] + e        -- constant = floor(2^30 * sqrt(2))
          e = d
          d = c
          c = b / 2^2
          c = c % 1 * (2^32 - 1) + c
          b = a
          a = z % 2^32
        end
        for j = 21, 40 do
          local a5 = a * 2^5
          local z = a5 % 2^32
          z = z + (a5 - z) / 2^32 + XOR(b, c, d) + 0x6ED9EBA1 + W[j] + e                    -- 2^30 * sqrt(3)
          e = d
          d = c
          c = b / 2^2
          c = c % 1 * (2^32 - 1) + c
          b = a
          a = z % 2^32
        end
        for j = 41, 60 do
          local a5 = a * 2^5
          local z = a5 % 2^32
          z = z + (a5 - z) / 2^32 + AND(d, c) + AND(b, XOR(d, c)) + 0x8F1BBCDC + W[j] + e   -- 2^30 * sqrt(5)
          e = d
          d = c
          c = b / 2^2
          c = c % 1 * (2^32 - 1) + c
          b = a
          a = z % 2^32
        end
        for j = 61, 80 do
          local a5 = a * 2^5
          local z = a5 % 2^32
          z = z + (a5 - z) / 2^32 + XOR(b, c, d) + 0xCA62C1D6 + W[j] + e                    -- 2^30 * sqrt(10)
          e = d
          d = c
          c = b / 2^2
          c = c % 1 * (2^32 - 1) + c
          b = a
          a = z % 2^32
        end
        h1 = (a + h1) % 2^32
        h2 = (b + h2) % 2^32
        h3 = (c + h3) % 2^32
        h4 = (d + h4) % 2^32
        h5 = (e + h5) % 2^32
    end
    H[1], H[2], H[3], H[4], H[5] = h1, h2, h3, h4, h5
  end

  local function keccak_feed(lanes_lo, lanes_hi, str, offs, size, block_size_in_bytes)
    -- This is an example of a Lua function having 79 local variables :-)
    -- offs >= 0, size >= 0, size is multiple of block_size_in_bytes, block_size_in_bytes is positive multiple of 8
    local RC_lo, RC_hi = sha3_RC_lo, sha3_RC_hi
    local qwords_qty = block_size_in_bytes / 8
    for pos = offs, offs + size - 1, block_size_in_bytes do
        for j = 1, qwords_qty do
          local a, b, c, d = byte(str, pos + 1, pos + 4)
          lanes_lo[j] = XOR(lanes_lo[j], ((d * 256 + c) * 256 + b) * 256 + a)
          pos = pos + 8
          a, b, c, d = byte(str, pos - 3, pos)
          lanes_hi[j] = XOR(lanes_hi[j], ((d * 256 + c) * 256 + b) * 256 + a)
        end
        local L01_lo, L01_hi, L02_lo, L02_hi, L03_lo, L03_hi, L04_lo, L04_hi, L05_lo, L05_hi, L06_lo, L06_hi, L07_lo, L07_hi, L08_lo, L08_hi,
          L09_lo, L09_hi, L10_lo, L10_hi, L11_lo, L11_hi, L12_lo, L12_hi, L13_lo, L13_hi, L14_lo, L14_hi, L15_lo, L15_hi, L16_lo, L16_hi,
          L17_lo, L17_hi, L18_lo, L18_hi, L19_lo, L19_hi, L20_lo, L20_hi, L21_lo, L21_hi, L22_lo, L22_hi, L23_lo, L23_hi, L24_lo, L24_hi, L25_lo, L25_hi =
          lanes_lo[1], lanes_hi[1], lanes_lo[2], lanes_hi[2], lanes_lo[3], lanes_hi[3], lanes_lo[4], lanes_hi[4], lanes_lo[5], lanes_hi[5],
          lanes_lo[6], lanes_hi[6], lanes_lo[7], lanes_hi[7], lanes_lo[8], lanes_hi[8], lanes_lo[9], lanes_hi[9], lanes_lo[10], lanes_hi[10],
          lanes_lo[11], lanes_hi[11], lanes_lo[12], lanes_hi[12], lanes_lo[13], lanes_hi[13], lanes_lo[14], lanes_hi[14], lanes_lo[15], lanes_hi[15],
          lanes_lo[16], lanes_hi[16], lanes_lo[17], lanes_hi[17], lanes_lo[18], lanes_hi[18], lanes_lo[19], lanes_hi[19], lanes_lo[20], lanes_hi[20],
          lanes_lo[21], lanes_hi[21], lanes_lo[22], lanes_hi[22], lanes_lo[23], lanes_hi[23], lanes_lo[24], lanes_hi[24], lanes_lo[25], lanes_hi[25]
        for round_idx = 1, 24 do
          local C1_lo = XOR(L01_lo, L06_lo, L11_lo, L16_lo, L21_lo)
          local C1_hi = XOR(L01_hi, L06_hi, L11_hi, L16_hi, L21_hi)
          local C2_lo = XOR(L02_lo, L07_lo, L12_lo, L17_lo, L22_lo)
          local C2_hi = XOR(L02_hi, L07_hi, L12_hi, L17_hi, L22_hi)
          local C3_lo = XOR(L03_lo, L08_lo, L13_lo, L18_lo, L23_lo)
          local C3_hi = XOR(L03_hi, L08_hi, L13_hi, L18_hi, L23_hi)
          local C4_lo = XOR(L04_lo, L09_lo, L14_lo, L19_lo, L24_lo)
          local C4_hi = XOR(L04_hi, L09_hi, L14_hi, L19_hi, L24_hi)
          local C5_lo = XOR(L05_lo, L10_lo, L15_lo, L20_lo, L25_lo)
          local C5_hi = XOR(L05_hi, L10_hi, L15_hi, L20_hi, L25_hi)
          local D_lo = XOR(C1_lo, C3_lo * 2 + (C3_hi % 2^32 - C3_hi % 2^31) / 2^31)
          local D_hi = XOR(C1_hi, C3_hi * 2 + (C3_lo % 2^32 - C3_lo % 2^31) / 2^31)
          local T0_lo = XOR(D_lo, L02_lo)
          local T0_hi = XOR(D_hi, L02_hi)
          local T1_lo = XOR(D_lo, L07_lo)
          local T1_hi = XOR(D_hi, L07_hi)
          local T2_lo = XOR(D_lo, L12_lo)
          local T2_hi = XOR(D_hi, L12_hi)
          local T3_lo = XOR(D_lo, L17_lo)
          local T3_hi = XOR(D_hi, L17_hi)
          local T4_lo = XOR(D_lo, L22_lo)
          local T4_hi = XOR(D_hi, L22_hi)
          L02_lo = (T1_lo % 2^32 - T1_lo % 2^20) / 2^20 + T1_hi * 2^12
          L02_hi = (T1_hi % 2^32 - T1_hi % 2^20) / 2^20 + T1_lo * 2^12
          L07_lo = (T3_lo % 2^32 - T3_lo % 2^19) / 2^19 + T3_hi * 2^13
          L07_hi = (T3_hi % 2^32 - T3_hi % 2^19) / 2^19 + T3_lo * 2^13
          L12_lo = T0_lo * 2 + (T0_hi % 2^32 - T0_hi % 2^31) / 2^31
          L12_hi = T0_hi * 2 + (T0_lo % 2^32 - T0_lo % 2^31) / 2^31
          L17_lo = T2_lo * 2^10 + (T2_hi % 2^32 - T2_hi % 2^22) / 2^22
          L17_hi = T2_hi * 2^10 + (T2_lo % 2^32 - T2_lo % 2^22) / 2^22
          L22_lo = T4_lo * 2^2 + (T4_hi % 2^32 - T4_hi % 2^30) / 2^30
          L22_hi = T4_hi * 2^2 + (T4_lo % 2^32 - T4_lo % 2^30) / 2^30
          D_lo = XOR(C2_lo, C4_lo * 2 + (C4_hi % 2^32 - C4_hi % 2^31) / 2^31)
          D_hi = XOR(C2_hi, C4_hi * 2 + (C4_lo % 2^32 - C4_lo % 2^31) / 2^31)
          T0_lo = XOR(D_lo, L03_lo)
          T0_hi = XOR(D_hi, L03_hi)
          T1_lo = XOR(D_lo, L08_lo)
          T1_hi = XOR(D_hi, L08_hi)
          T2_lo = XOR(D_lo, L13_lo)
          T2_hi = XOR(D_hi, L13_hi)
          T3_lo = XOR(D_lo, L18_lo)
          T3_hi = XOR(D_hi, L18_hi)
          T4_lo = XOR(D_lo, L23_lo)
          T4_hi = XOR(D_hi, L23_hi)
          L03_lo = (T2_lo % 2^32 - T2_lo % 2^21) / 2^21 + T2_hi * 2^11
          L03_hi = (T2_hi % 2^32 - T2_hi % 2^21) / 2^21 + T2_lo * 2^11
          L08_lo = (T4_lo % 2^32 - T4_lo % 2^3) / 2^3 + T4_hi * 2^29 % 2^32
          L08_hi = (T4_hi % 2^32 - T4_hi % 2^3) / 2^3 + T4_lo * 2^29 % 2^32
          L13_lo = T1_lo * 2^6 + (T1_hi % 2^32 - T1_hi % 2^26) / 2^26
          L13_hi = T1_hi * 2^6 + (T1_lo % 2^32 - T1_lo % 2^26) / 2^26
          L18_lo = T3_lo * 2^15 + (T3_hi % 2^32 - T3_hi % 2^17) / 2^17
          L18_hi = T3_hi * 2^15 + (T3_lo % 2^32 - T3_lo % 2^17) / 2^17
          L23_lo = (T0_lo % 2^32 - T0_lo % 2^2) / 2^2 + T0_hi * 2^30 % 2^32
          L23_hi = (T0_hi % 2^32 - T0_hi % 2^2) / 2^2 + T0_lo * 2^30 % 2^32
          D_lo = XOR(C3_lo, C5_lo * 2 + (C5_hi % 2^32 - C5_hi % 2^31) / 2^31)
          D_hi = XOR(C3_hi, C5_hi * 2 + (C5_lo % 2^32 - C5_lo % 2^31) / 2^31)
          T0_lo = XOR(D_lo, L04_lo)
          T0_hi = XOR(D_hi, L04_hi)
          T1_lo = XOR(D_lo, L09_lo)
          T1_hi = XOR(D_hi, L09_hi)
          T2_lo = XOR(D_lo, L14_lo)
          T2_hi = XOR(D_hi, L14_hi)
          T3_lo = XOR(D_lo, L19_lo)
          T3_hi = XOR(D_hi, L19_hi)
          T4_lo = XOR(D_lo, L24_lo)
          T4_hi = XOR(D_hi, L24_hi)
          L04_lo = T3_lo * 2^21 % 2^32 + (T3_hi % 2^32 - T3_hi % 2^11) / 2^11
          L04_hi = T3_hi * 2^21 % 2^32 + (T3_lo % 2^32 - T3_lo % 2^11) / 2^11
          L09_lo = T0_lo * 2^28 % 2^32 + (T0_hi % 2^32 - T0_hi % 2^4) / 2^4
          L09_hi = T0_hi * 2^28 % 2^32 + (T0_lo % 2^32 - T0_lo % 2^4) / 2^4
          L14_lo = T2_lo * 2^25 % 2^32 + (T2_hi % 2^32 - T2_hi % 2^7) / 2^7
          L14_hi = T2_hi * 2^25 % 2^32 + (T2_lo % 2^32 - T2_lo % 2^7) / 2^7
          L19_lo = (T4_lo % 2^32 - T4_lo % 2^8) / 2^8 + T4_hi * 2^24 % 2^32
          L19_hi = (T4_hi % 2^32 - T4_hi % 2^8) / 2^8 + T4_lo * 2^24 % 2^32
          L24_lo = (T1_lo % 2^32 - T1_lo % 2^9) / 2^9 + T1_hi * 2^23 % 2^32
          L24_hi = (T1_hi % 2^32 - T1_hi % 2^9) / 2^9 + T1_lo * 2^23 % 2^32
          D_lo = XOR(C4_lo, C1_lo * 2 + (C1_hi % 2^32 - C1_hi % 2^31) / 2^31)
          D_hi = XOR(C4_hi, C1_hi * 2 + (C1_lo % 2^32 - C1_lo % 2^31) / 2^31)
          T0_lo = XOR(D_lo, L05_lo)
          T0_hi = XOR(D_hi, L05_hi)
          T1_lo = XOR(D_lo, L10_lo)
          T1_hi = XOR(D_hi, L10_hi)
          T2_lo = XOR(D_lo, L15_lo)
          T2_hi = XOR(D_hi, L15_hi)
          T3_lo = XOR(D_lo, L20_lo)
          T3_hi = XOR(D_hi, L20_hi)
          T4_lo = XOR(D_lo, L25_lo)
          T4_hi = XOR(D_hi, L25_hi)
          L05_lo = T4_lo * 2^14 + (T4_hi % 2^32 - T4_hi % 2^18) / 2^18
          L05_hi = T4_hi * 2^14 + (T4_lo % 2^32 - T4_lo % 2^18) / 2^18
          L10_lo = T1_lo * 2^20 % 2^32 + (T1_hi % 2^32 - T1_hi % 2^12) / 2^12
          L10_hi = T1_hi * 2^20 % 2^32 + (T1_lo % 2^32 - T1_lo % 2^12) / 2^12
          L15_lo = T3_lo * 2^8 + (T3_hi % 2^32 - T3_hi % 2^24) / 2^24
          L15_hi = T3_hi * 2^8 + (T3_lo % 2^32 - T3_lo % 2^24) / 2^24
          L20_lo = T0_lo * 2^27 % 2^32 + (T0_hi % 2^32 - T0_hi % 2^5) / 2^5
          L20_hi = T0_hi * 2^27 % 2^32 + (T0_lo % 2^32 - T0_lo % 2^5) / 2^5
          L25_lo = (T2_lo % 2^32 - T2_lo % 2^25) / 2^25 + T2_hi * 2^7
          L25_hi = (T2_hi % 2^32 - T2_hi % 2^25) / 2^25 + T2_lo * 2^7
          D_lo = XOR(C5_lo, C2_lo * 2 + (C2_hi % 2^32 - C2_hi % 2^31) / 2^31)
          D_hi = XOR(C5_hi, C2_hi * 2 + (C2_lo % 2^32 - C2_lo % 2^31) / 2^31)
          T1_lo = XOR(D_lo, L06_lo)
          T1_hi = XOR(D_hi, L06_hi)
          T2_lo = XOR(D_lo, L11_lo)
          T2_hi = XOR(D_hi, L11_hi)
          T3_lo = XOR(D_lo, L16_lo)
          T3_hi = XOR(D_hi, L16_hi)
          T4_lo = XOR(D_lo, L21_lo)
          T4_hi = XOR(D_hi, L21_hi)
          L06_lo = T2_lo * 2^3 + (T2_hi % 2^32 - T2_hi % 2^29) / 2^29
          L06_hi = T2_hi * 2^3 + (T2_lo % 2^32 - T2_lo % 2^29) / 2^29
          L11_lo = T4_lo * 2^18 + (T4_hi % 2^32 - T4_hi % 2^14) / 2^14
          L11_hi = T4_hi * 2^18 + (T4_lo % 2^32 - T4_lo % 2^14) / 2^14
          L16_lo = (T1_lo % 2^32 - T1_lo % 2^28) / 2^28 + T1_hi * 2^4
          L16_hi = (T1_hi % 2^32 - T1_hi % 2^28) / 2^28 + T1_lo * 2^4
          L21_lo = (T3_lo % 2^32 - T3_lo % 2^23) / 2^23 + T3_hi * 2^9
          L21_hi = (T3_hi % 2^32 - T3_hi % 2^23) / 2^23 + T3_lo * 2^9
          L01_lo = XOR(D_lo, L01_lo)
          L01_hi = XOR(D_hi, L01_hi)
          L01_lo, L02_lo, L03_lo, L04_lo, L05_lo = XOR(L01_lo, AND(-1-L02_lo, L03_lo)), XOR(L02_lo, AND(-1-L03_lo, L04_lo)), XOR(L03_lo, AND(-1-L04_lo, L05_lo)), XOR(L04_lo, AND(-1-L05_lo, L01_lo)), XOR(L05_lo, AND(-1-L01_lo, L02_lo))
          L01_hi, L02_hi, L03_hi, L04_hi, L05_hi = XOR(L01_hi, AND(-1-L02_hi, L03_hi)), XOR(L02_hi, AND(-1-L03_hi, L04_hi)), XOR(L03_hi, AND(-1-L04_hi, L05_hi)), XOR(L04_hi, AND(-1-L05_hi, L01_hi)), XOR(L05_hi, AND(-1-L01_hi, L02_hi))
          L06_lo, L07_lo, L08_lo, L09_lo, L10_lo = XOR(L09_lo, AND(-1-L10_lo, L06_lo)), XOR(L10_lo, AND(-1-L06_lo, L07_lo)), XOR(L06_lo, AND(-1-L07_lo, L08_lo)), XOR(L07_lo, AND(-1-L08_lo, L09_lo)), XOR(L08_lo, AND(-1-L09_lo, L10_lo))
          L06_hi, L07_hi, L08_hi, L09_hi, L10_hi = XOR(L09_hi, AND(-1-L10_hi, L06_hi)), XOR(L10_hi, AND(-1-L06_hi, L07_hi)), XOR(L06_hi, AND(-1-L07_hi, L08_hi)), XOR(L07_hi, AND(-1-L08_hi, L09_hi)), XOR(L08_hi, AND(-1-L09_hi, L10_hi))
          L11_lo, L12_lo, L13_lo, L14_lo, L15_lo = XOR(L12_lo, AND(-1-L13_lo, L14_lo)), XOR(L13_lo, AND(-1-L14_lo, L15_lo)), XOR(L14_lo, AND(-1-L15_lo, L11_lo)), XOR(L15_lo, AND(-1-L11_lo, L12_lo)), XOR(L11_lo, AND(-1-L12_lo, L13_lo))
          L11_hi, L12_hi, L13_hi, L14_hi, L15_hi = XOR(L12_hi, AND(-1-L13_hi, L14_hi)), XOR(L13_hi, AND(-1-L14_hi, L15_hi)), XOR(L14_hi, AND(-1-L15_hi, L11_hi)), XOR(L15_hi, AND(-1-L11_hi, L12_hi)), XOR(L11_hi, AND(-1-L12_hi, L13_hi))
          L16_lo, L17_lo, L18_lo, L19_lo, L20_lo = XOR(L20_lo, AND(-1-L16_lo, L17_lo)), XOR(L16_lo, AND(-1-L17_lo, L18_lo)), XOR(L17_lo, AND(-1-L18_lo, L19_lo)), XOR(L18_lo, AND(-1-L19_lo, L20_lo)), XOR(L19_lo, AND(-1-L20_lo, L16_lo))
          L16_hi, L17_hi, L18_hi, L19_hi, L20_hi = XOR(L20_hi, AND(-1-L16_hi, L17_hi)), XOR(L16_hi, AND(-1-L17_hi, L18_hi)), XOR(L17_hi, AND(-1-L18_hi, L19_hi)), XOR(L18_hi, AND(-1-L19_hi, L20_hi)), XOR(L19_hi, AND(-1-L20_hi, L16_hi))
          L21_lo, L22_lo, L23_lo, L24_lo, L25_lo = XOR(L23_lo, AND(-1-L24_lo, L25_lo)), XOR(L24_lo, AND(-1-L25_lo, L21_lo)), XOR(L25_lo, AND(-1-L21_lo, L22_lo)), XOR(L21_lo, AND(-1-L22_lo, L23_lo)), XOR(L22_lo, AND(-1-L23_lo, L24_lo))
          L21_hi, L22_hi, L23_hi, L24_hi, L25_hi = XOR(L23_hi, AND(-1-L24_hi, L25_hi)), XOR(L24_hi, AND(-1-L25_hi, L21_hi)), XOR(L25_hi, AND(-1-L21_hi, L22_hi)), XOR(L21_hi, AND(-1-L22_hi, L23_hi)), XOR(L22_hi, AND(-1-L23_hi, L24_hi))
          L01_lo = XOR(L01_lo, RC_lo[round_idx])
          L01_hi = L01_hi + RC_hi[round_idx]      -- RC_hi[] is either 0 or 0x80000000, so we could use fast addition instead of slow XOR
        end
        lanes_lo[1]  = L01_lo;  lanes_hi[1]  = L01_hi
        lanes_lo[2]  = L02_lo;  lanes_hi[2]  = L02_hi
        lanes_lo[3]  = L03_lo;  lanes_hi[3]  = L03_hi
        lanes_lo[4]  = L04_lo;  lanes_hi[4]  = L04_hi
        lanes_lo[5]  = L05_lo;  lanes_hi[5]  = L05_hi
        lanes_lo[6]  = L06_lo;  lanes_hi[6]  = L06_hi
        lanes_lo[7]  = L07_lo;  lanes_hi[7]  = L07_hi
        lanes_lo[8]  = L08_lo;  lanes_hi[8]  = L08_hi
        lanes_lo[9]  = L09_lo;  lanes_hi[9]  = L09_hi
        lanes_lo[10] = L10_lo;  lanes_hi[10] = L10_hi
        lanes_lo[11] = L11_lo;  lanes_hi[11] = L11_hi
        lanes_lo[12] = L12_lo;  lanes_hi[12] = L12_hi
        lanes_lo[13] = L13_lo;  lanes_hi[13] = L13_hi
        lanes_lo[14] = L14_lo;  lanes_hi[14] = L14_hi
        lanes_lo[15] = L15_lo;  lanes_hi[15] = L15_hi
        lanes_lo[16] = L16_lo;  lanes_hi[16] = L16_hi
        lanes_lo[17] = L17_lo;  lanes_hi[17] = L17_hi
        lanes_lo[18] = L18_lo;  lanes_hi[18] = L18_hi
        lanes_lo[19] = L19_lo;  lanes_hi[19] = L19_hi
        lanes_lo[20] = L20_lo;  lanes_hi[20] = L20_hi
        lanes_lo[21] = L21_lo;  lanes_hi[21] = L21_hi
        lanes_lo[22] = L22_lo;  lanes_hi[22] = L22_hi
        lanes_lo[23] = L23_lo;  lanes_hi[23] = L23_hi
        lanes_lo[24] = L24_lo;  lanes_hi[24] = L24_hi
        lanes_lo[25] = L25_lo;  lanes_hi[25] = L25_hi
    end
  end

  local function blake2s_feed_64(H, str, offs, size, bytes_compressed, last_block_size, is_last_node)
    -- offs >= 0, size >= 0, size is multiple of 64
    local W = common_W
    local h1, h2, h3, h4, h5, h6, h7, h8 = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
    for pos = offs, offs + size - 1, 64 do
        if str then
          for j = 1, 16 do
              pos = pos + 4
              local a, b, c, d = byte(str, pos - 3, pos)
              W[j] = ((d * 256 + c) * 256 + b) * 256 + a
          end
        end
        local v0, v1, v2, v3, v4, v5, v6, v7 = h1, h2, h3, h4, h5, h6, h7, h8
        local v8, v9, vA, vB, vC, vD, vE, vF = sha2_H_hi[1], sha2_H_hi[2], sha2_H_hi[3], sha2_H_hi[4], sha2_H_hi[5], sha2_H_hi[6], sha2_H_hi[7], sha2_H_hi[8]
        bytes_compressed = bytes_compressed + (last_block_size or 64)
        local t0 = bytes_compressed % 2^32
        local t1 = (bytes_compressed - t0) / 2^32
        vC = XOR(vC, t0)  -- t0 = low_4_bytes(bytes_compressed)
        vD = XOR(vD, t1)  -- t1 = high_4_bytes(bytes_compressed)
        if last_block_size then  -- flag f0
          vE = -1 - vE
        end
        if is_last_node then  -- flag f1
          vF = -1 - vF
        end
        for j = 1, 10 do
          local row = sigma[j]
          v0 = v0 + v4 + W[row[1]]
          vC = XOR(vC, v0) % 2^32 / 2^16
          vC = vC % 1 * (2^32 - 1) + vC
          v8 = v8 + vC
          v4 = XOR(v4, v8) % 2^32 / 2^12
          v4 = v4 % 1 * (2^32 - 1) + v4
          v0 = v0 + v4 + W[row[2]]
          vC = XOR(vC, v0) % 2^32 / 2^8
          vC = vC % 1 * (2^32 - 1) + vC
          v8 = v8 + vC
          v4 = XOR(v4, v8) % 2^32 / 2^7
          v4 = v4 % 1 * (2^32 - 1) + v4
          v1 = v1 + v5 + W[row[3]]
          vD = XOR(vD, v1) % 2^32 / 2^16
          vD = vD % 1 * (2^32 - 1) + vD
          v9 = v9 + vD
          v5 = XOR(v5, v9) % 2^32 / 2^12
          v5 = v5 % 1 * (2^32 - 1) + v5
          v1 = v1 + v5 + W[row[4]]
          vD = XOR(vD, v1) % 2^32 / 2^8
          vD = vD % 1 * (2^32 - 1) + vD
          v9 = v9 + vD
          v5 = XOR(v5, v9) % 2^32 / 2^7
          v5 = v5 % 1 * (2^32 - 1) + v5
          v2 = v2 + v6 + W[row[5]]
          vE = XOR(vE, v2) % 2^32 / 2^16
          vE = vE % 1 * (2^32 - 1) + vE
          vA = vA + vE
          v6 = XOR(v6, vA) % 2^32 / 2^12
          v6 = v6 % 1 * (2^32 - 1) + v6
          v2 = v2 + v6 + W[row[6]]
          vE = XOR(vE, v2) % 2^32 / 2^8
          vE = vE % 1 * (2^32 - 1) + vE
          vA = vA + vE
          v6 = XOR(v6, vA) % 2^32 / 2^7
          v6 = v6 % 1 * (2^32 - 1) + v6
          v3 = v3 + v7 + W[row[7]]
          vF = XOR(vF, v3) % 2^32 / 2^16
          vF = vF % 1 * (2^32 - 1) + vF
          vB = vB + vF
          v7 = XOR(v7, vB) % 2^32 / 2^12
          v7 = v7 % 1 * (2^32 - 1) + v7
          v3 = v3 + v7 + W[row[8]]
          vF = XOR(vF, v3) % 2^32 / 2^8
          vF = vF % 1 * (2^32 - 1) + vF
          vB = vB + vF
          v7 = XOR(v7, vB) % 2^32 / 2^7
          v7 = v7 % 1 * (2^32 - 1) + v7
          v0 = v0 + v5 + W[row[9]]
          vF = XOR(vF, v0) % 2^32 / 2^16
          vF = vF % 1 * (2^32 - 1) + vF
          vA = vA + vF
          v5 = XOR(v5, vA) % 2^32 / 2^12
          v5 = v5 % 1 * (2^32 - 1) + v5
          v0 = v0 + v5 + W[row[10]]
          vF = XOR(vF, v0) % 2^32 / 2^8
          vF = vF % 1 * (2^32 - 1) + vF
          vA = vA + vF
          v5 = XOR(v5, vA) % 2^32 / 2^7
          v5 = v5 % 1 * (2^32 - 1) + v5
          v1 = v1 + v6 + W[row[11]]
          vC = XOR(vC, v1) % 2^32 / 2^16
          vC = vC % 1 * (2^32 - 1) + vC
          vB = vB + vC
          v6 = XOR(v6, vB) % 2^32 / 2^12
          v6 = v6 % 1 * (2^32 - 1) + v6
          v1 = v1 + v6 + W[row[12]]
          vC = XOR(vC, v1) % 2^32 / 2^8
          vC = vC % 1 * (2^32 - 1) + vC
          vB = vB + vC
          v6 = XOR(v6, vB) % 2^32 / 2^7
          v6 = v6 % 1 * (2^32 - 1) + v6
          v2 = v2 + v7 + W[row[13]]
          vD = XOR(vD, v2) % 2^32 / 2^16
          vD = vD % 1 * (2^32 - 1) + vD
          v8 = v8 + vD
          v7 = XOR(v7, v8) % 2^32 / 2^12
          v7 = v7 % 1 * (2^32 - 1) + v7
          v2 = v2 + v7 + W[row[14]]
          vD = XOR(vD, v2) % 2^32 / 2^8
          vD = vD % 1 * (2^32 - 1) + vD
          v8 = v8 + vD
          v7 = XOR(v7, v8) % 2^32 / 2^7
          v7 = v7 % 1 * (2^32 - 1) + v7
          v3 = v3 + v4 + W[row[15]]
          vE = XOR(vE, v3) % 2^32 / 2^16
          vE = vE % 1 * (2^32 - 1) + vE
          v9 = v9 + vE
          v4 = XOR(v4, v9) % 2^32 / 2^12
          v4 = v4 % 1 * (2^32 - 1) + v4
          v3 = v3 + v4 + W[row[16]]
          vE = XOR(vE, v3) % 2^32 / 2^8
          vE = vE % 1 * (2^32 - 1) + vE
          v9 = v9 + vE
          v4 = XOR(v4, v9) % 2^32 / 2^7
          v4 = v4 % 1 * (2^32 - 1) + v4
        end
        h1 = XOR(h1, v0, v8)
        h2 = XOR(h2, v1, v9)
        h3 = XOR(h3, v2, vA)
        h4 = XOR(h4, v3, vB)
        h5 = XOR(h5, v4, vC)
        h6 = XOR(h6, v5, vD)
        h7 = XOR(h7, v6, vE)
        h8 = XOR(h8, v7, vF)
    end
    H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8] = h1, h2, h3, h4, h5, h6, h7, h8
    return bytes_compressed
  end

  local function blake2b_feed_128(H_lo, H_hi, str, offs, size, bytes_compressed, last_block_size, is_last_node)
    -- offs >= 0, size >= 0, size is multiple of 128
    local W = common_W
    local h1_lo, h2_lo, h3_lo, h4_lo, h5_lo, h6_lo, h7_lo, h8_lo = H_lo[1], H_lo[2], H_lo[3], H_lo[4], H_lo[5], H_lo[6], H_lo[7], H_lo[8]
    local h1_hi, h2_hi, h3_hi, h4_hi, h5_hi, h6_hi, h7_hi, h8_hi = H_hi[1], H_hi[2], H_hi[3], H_hi[4], H_hi[5], H_hi[6], H_hi[7], H_hi[8]
    for pos = offs, offs + size - 1, 128 do
        if str then
          for j = 1, 32 do
              pos = pos + 4
              local a, b, c, d = byte(str, pos - 3, pos)
              W[j] = ((d * 256 + c) * 256 + b) * 256 + a
          end
        end
        local v0_lo, v1_lo, v2_lo, v3_lo, v4_lo, v5_lo, v6_lo, v7_lo = h1_lo, h2_lo, h3_lo, h4_lo, h5_lo, h6_lo, h7_lo, h8_lo
        local v0_hi, v1_hi, v2_hi, v3_hi, v4_hi, v5_hi, v6_hi, v7_hi = h1_hi, h2_hi, h3_hi, h4_hi, h5_hi, h6_hi, h7_hi, h8_hi
        local v8_lo, v9_lo, vA_lo, vB_lo, vC_lo, vD_lo, vE_lo, vF_lo = sha2_H_lo[1], sha2_H_lo[2], sha2_H_lo[3], sha2_H_lo[4], sha2_H_lo[5], sha2_H_lo[6], sha2_H_lo[7], sha2_H_lo[8]
        local v8_hi, v9_hi, vA_hi, vB_hi, vC_hi, vD_hi, vE_hi, vF_hi = sha2_H_hi[1], sha2_H_hi[2], sha2_H_hi[3], sha2_H_hi[4], sha2_H_hi[5], sha2_H_hi[6], sha2_H_hi[7], sha2_H_hi[8]
        bytes_compressed = bytes_compressed + (last_block_size or 128)
        local t0_lo = bytes_compressed % 2^32
        local t0_hi = (bytes_compressed - t0_lo) / 2^32
        vC_lo = XOR(vC_lo, t0_lo)  -- t0 = low_8_bytes(bytes_compressed)
        vC_hi = XOR(vC_hi, t0_hi)
        -- t1 = high_8_bytes(bytes_compressed) = 0,  message length is always below 2^53 bytes
        if last_block_size then  -- flag f0
          vE_lo = -1 - vE_lo
          vE_hi = -1 - vE_hi
        end
        if is_last_node then  -- flag f1
          vF_lo = -1 - vF_lo
          vF_hi = -1 - vF_hi
        end
        for j = 1, 12 do
          local row = sigma[j]
          local k = row[1] * 2
          local z = v0_lo % 2^32 + v4_lo % 2^32 + W[k-1]
          v0_lo = z % 2^32
          v0_hi = v0_hi + v4_hi + (z - v0_lo) / 2^32 + W[k]
          vC_lo, vC_hi = XOR(vC_hi, v0_hi), XOR(vC_lo, v0_lo)
          z = v8_lo % 2^32 + vC_lo % 2^32
          v8_lo = z % 2^32
          v8_hi = v8_hi + vC_hi + (z - v8_lo) / 2^32
          v4_lo, v4_hi = XOR(v4_lo, v8_lo), XOR(v4_hi, v8_hi)
          local z_lo, z_hi = v4_lo % 2^24, v4_hi % 2^24
          v4_lo, v4_hi = (v4_lo - z_lo) / 2^24 % 2^8 + z_hi * 2^8, (v4_hi - z_hi) / 2^24 % 2^8 + z_lo * 2^8
          k = row[2] * 2
          z = v0_lo % 2^32 + v4_lo % 2^32 + W[k-1]
          v0_lo = z % 2^32
          v0_hi = v0_hi + v4_hi + (z - v0_lo) / 2^32 + W[k]
          vC_lo, vC_hi = XOR(vC_lo, v0_lo), XOR(vC_hi, v0_hi)
          z_lo, z_hi = vC_lo % 2^16, vC_hi % 2^16
          vC_lo, vC_hi = (vC_lo - z_lo) / 2^16 % 2^16 + z_hi * 2^16, (vC_hi - z_hi) / 2^16 % 2^16 + z_lo * 2^16
          z = v8_lo % 2^32 + vC_lo % 2^32
          v8_lo = z % 2^32
          v8_hi = v8_hi + vC_hi + (z - v8_lo) / 2^32
          v4_lo, v4_hi = XOR(v4_lo, v8_lo), XOR(v4_hi, v8_hi)
          z_lo, z_hi = v4_lo % 2^31, v4_hi % 2^31
          v4_lo, v4_hi = z_lo * 2^1 + (v4_hi - z_hi) / 2^31 % 2^1, z_hi * 2^1 + (v4_lo - z_lo) / 2^31 % 2^1
          k = row[3] * 2
          z = v1_lo % 2^32 + v5_lo % 2^32 + W[k-1]
          v1_lo = z % 2^32
          v1_hi = v1_hi + v5_hi + (z - v1_lo) / 2^32 + W[k]
          vD_lo, vD_hi = XOR(vD_hi, v1_hi), XOR(vD_lo, v1_lo)
          z = v9_lo % 2^32 + vD_lo % 2^32
          v9_lo = z % 2^32
          v9_hi = v9_hi + vD_hi + (z - v9_lo) / 2^32
          v5_lo, v5_hi = XOR(v5_lo, v9_lo), XOR(v5_hi, v9_hi)
          z_lo, z_hi = v5_lo % 2^24, v5_hi % 2^24
          v5_lo, v5_hi = (v5_lo - z_lo) / 2^24 % 2^8 + z_hi * 2^8, (v5_hi - z_hi) / 2^24 % 2^8 + z_lo * 2^8
          k = row[4] * 2
          z = v1_lo % 2^32 + v5_lo % 2^32 + W[k-1]
          v1_lo = z % 2^32
          v1_hi = v1_hi + v5_hi + (z - v1_lo) / 2^32 + W[k]
          vD_lo, vD_hi = XOR(vD_lo, v1_lo), XOR(vD_hi, v1_hi)
          z_lo, z_hi = vD_lo % 2^16, vD_hi % 2^16
          vD_lo, vD_hi = (vD_lo - z_lo) / 2^16 % 2^16 + z_hi * 2^16, (vD_hi - z_hi) / 2^16 % 2^16 + z_lo * 2^16
          z = v9_lo % 2^32 + vD_lo % 2^32
          v9_lo = z % 2^32
          v9_hi = v9_hi + vD_hi + (z - v9_lo) / 2^32
          v5_lo, v5_hi = XOR(v5_lo, v9_lo), XOR(v5_hi, v9_hi)
          z_lo, z_hi = v5_lo % 2^31, v5_hi % 2^31
          v5_lo, v5_hi = z_lo * 2^1 + (v5_hi - z_hi) / 2^31 % 2^1, z_hi * 2^1 + (v5_lo - z_lo) / 2^31 % 2^1
          k = row[5] * 2
          z = v2_lo % 2^32 + v6_lo % 2^32 + W[k-1]
          v2_lo = z % 2^32
          v2_hi = v2_hi + v6_hi + (z - v2_lo) / 2^32 + W[k]
          vE_lo, vE_hi = XOR(vE_hi, v2_hi), XOR(vE_lo, v2_lo)
          z = vA_lo % 2^32 + vE_lo % 2^32
          vA_lo = z % 2^32
          vA_hi = vA_hi + vE_hi + (z - vA_lo) / 2^32
          v6_lo, v6_hi = XOR(v6_lo, vA_lo), XOR(v6_hi, vA_hi)
          z_lo, z_hi = v6_lo % 2^24, v6_hi % 2^24
          v6_lo, v6_hi = (v6_lo - z_lo) / 2^24 % 2^8 + z_hi * 2^8, (v6_hi - z_hi) / 2^24 % 2^8 + z_lo * 2^8
          k = row[6] * 2
          z = v2_lo % 2^32 + v6_lo % 2^32 + W[k-1]
          v2_lo = z % 2^32
          v2_hi = v2_hi + v6_hi + (z - v2_lo) / 2^32 + W[k]
          vE_lo, vE_hi = XOR(vE_lo, v2_lo), XOR(vE_hi, v2_hi)
          z_lo, z_hi = vE_lo % 2^16, vE_hi % 2^16
          vE_lo, vE_hi = (vE_lo - z_lo) / 2^16 % 2^16 + z_hi * 2^16, (vE_hi - z_hi) / 2^16 % 2^16 + z_lo * 2^16
          z = vA_lo % 2^32 + vE_lo % 2^32
          vA_lo = z % 2^32
          vA_hi = vA_hi + vE_hi + (z - vA_lo) / 2^32
          v6_lo, v6_hi = XOR(v6_lo, vA_lo), XOR(v6_hi, vA_hi)
          z_lo, z_hi = v6_lo % 2^31, v6_hi % 2^31
          v6_lo, v6_hi = z_lo * 2^1 + (v6_hi - z_hi) / 2^31 % 2^1, z_hi * 2^1 + (v6_lo - z_lo) / 2^31 % 2^1
          k = row[7] * 2
          z = v3_lo % 2^32 + v7_lo % 2^32 + W[k-1]
          v3_lo = z % 2^32
          v3_hi = v3_hi + v7_hi + (z - v3_lo) / 2^32 + W[k]
          vF_lo, vF_hi = XOR(vF_hi, v3_hi), XOR(vF_lo, v3_lo)
          z = vB_lo % 2^32 + vF_lo % 2^32
          vB_lo = z % 2^32
          vB_hi = vB_hi + vF_hi + (z - vB_lo) / 2^32
          v7_lo, v7_hi = XOR(v7_lo, vB_lo), XOR(v7_hi, vB_hi)
          z_lo, z_hi = v7_lo % 2^24, v7_hi % 2^24
          v7_lo, v7_hi = (v7_lo - z_lo) / 2^24 % 2^8 + z_hi * 2^8, (v7_hi - z_hi) / 2^24 % 2^8 + z_lo * 2^8
          k = row[8] * 2
          z = v3_lo % 2^32 + v7_lo % 2^32 + W[k-1]
          v3_lo = z % 2^32
          v3_hi = v3_hi + v7_hi + (z - v3_lo) / 2^32 + W[k]
          vF_lo, vF_hi = XOR(vF_lo, v3_lo), XOR(vF_hi, v3_hi)
          z_lo, z_hi = vF_lo % 2^16, vF_hi % 2^16
          vF_lo, vF_hi = (vF_lo - z_lo) / 2^16 % 2^16 + z_hi * 2^16, (vF_hi - z_hi) / 2^16 % 2^16 + z_lo * 2^16
          z = vB_lo % 2^32 + vF_lo % 2^32
          vB_lo = z % 2^32
          vB_hi = vB_hi + vF_hi + (z - vB_lo) / 2^32
          v7_lo, v7_hi = XOR(v7_lo, vB_lo), XOR(v7_hi, vB_hi)
          z_lo, z_hi = v7_lo % 2^31, v7_hi % 2^31
          v7_lo, v7_hi = z_lo * 2^1 + (v7_hi - z_hi) / 2^31 % 2^1, z_hi * 2^1 + (v7_lo - z_lo) / 2^31 % 2^1
          k = row[9] * 2
          z = v0_lo % 2^32 + v5_lo % 2^32 + W[k-1]
          v0_lo = z % 2^32
          v0_hi = v0_hi + v5_hi + (z - v0_lo) / 2^32 + W[k]
          vF_lo, vF_hi = XOR(vF_hi, v0_hi), XOR(vF_lo, v0_lo)
          z = vA_lo % 2^32 + vF_lo % 2^32
          vA_lo = z % 2^32
          vA_hi = vA_hi + vF_hi + (z - vA_lo) / 2^32
          v5_lo, v5_hi = XOR(v5_lo, vA_lo), XOR(v5_hi, vA_hi)
          z_lo, z_hi = v5_lo % 2^24, v5_hi % 2^24
          v5_lo, v5_hi = (v5_lo - z_lo) / 2^24 % 2^8 + z_hi * 2^8, (v5_hi - z_hi) / 2^24 % 2^8 + z_lo * 2^8
          k = row[10] * 2
          z = v0_lo % 2^32 + v5_lo % 2^32 + W[k-1]
          v0_lo = z % 2^32
          v0_hi = v0_hi + v5_hi + (z - v0_lo) / 2^32 + W[k]
          vF_lo, vF_hi = XOR(vF_lo, v0_lo), XOR(vF_hi, v0_hi)
          z_lo, z_hi = vF_lo % 2^16, vF_hi % 2^16
          vF_lo, vF_hi = (vF_lo - z_lo) / 2^16 % 2^16 + z_hi * 2^16, (vF_hi - z_hi) / 2^16 % 2^16 + z_lo * 2^16
          z = vA_lo % 2^32 + vF_lo % 2^32
          vA_lo = z % 2^32
          vA_hi = vA_hi + vF_hi + (z - vA_lo) / 2^32
          v5_lo, v5_hi = XOR(v5_lo, vA_lo), XOR(v5_hi, vA_hi)
          z_lo, z_hi = v5_lo % 2^31, v5_hi % 2^31
          v5_lo, v5_hi = z_lo * 2^1 + (v5_hi - z_hi) / 2^31 % 2^1, z_hi * 2^1 + (v5_lo - z_lo) / 2^31 % 2^1
          k = row[11] * 2
          z = v1_lo % 2^32 + v6_lo % 2^32 + W[k-1]
          v1_lo = z % 2^32
          v1_hi = v1_hi + v6_hi + (z - v1_lo) / 2^32 + W[k]
          vC_lo, vC_hi = XOR(vC_hi, v1_hi), XOR(vC_lo, v1_lo)
          z = vB_lo % 2^32 + vC_lo % 2^32
          vB_lo = z % 2^32
          vB_hi = vB_hi + vC_hi + (z - vB_lo) / 2^32
          v6_lo, v6_hi = XOR(v6_lo, vB_lo), XOR(v6_hi, vB_hi)
          z_lo, z_hi = v6_lo % 2^24, v6_hi % 2^24
          v6_lo, v6_hi = (v6_lo - z_lo) / 2^24 % 2^8 + z_hi * 2^8, (v6_hi - z_hi) / 2^24 % 2^8 + z_lo * 2^8
          k = row[12] * 2
          z = v1_lo % 2^32 + v6_lo % 2^32 + W[k-1]
          v1_lo = z % 2^32
          v1_hi = v1_hi + v6_hi + (z - v1_lo) / 2^32 + W[k]
          vC_lo, vC_hi = XOR(vC_lo, v1_lo), XOR(vC_hi, v1_hi)
          z_lo, z_hi = vC_lo % 2^16, vC_hi % 2^16
          vC_lo, vC_hi = (vC_lo - z_lo) / 2^16 % 2^16 + z_hi * 2^16, (vC_hi - z_hi) / 2^16 % 2^16 + z_lo * 2^16
          z = vB_lo % 2^32 + vC_lo % 2^32
          vB_lo = z % 2^32
          vB_hi = vB_hi + vC_hi + (z - vB_lo) / 2^32
          v6_lo, v6_hi = XOR(v6_lo, vB_lo), XOR(v6_hi, vB_hi)
          z_lo, z_hi = v6_lo % 2^31, v6_hi % 2^31
          v6_lo, v6_hi = z_lo * 2^1 + (v6_hi - z_hi) / 2^31 % 2^1, z_hi * 2^1 + (v6_lo - z_lo) / 2^31 % 2^1
          k = row[13] * 2
          z = v2_lo % 2^32 + v7_lo % 2^32 + W[k-1]
          v2_lo = z % 2^32
          v2_hi = v2_hi + v7_hi + (z - v2_lo) / 2^32 + W[k]
          vD_lo, vD_hi = XOR(vD_hi, v2_hi), XOR(vD_lo, v2_lo)
          z = v8_lo % 2^32 + vD_lo % 2^32
          v8_lo = z % 2^32
          v8_hi = v8_hi + vD_hi + (z - v8_lo) / 2^32
          v7_lo, v7_hi = XOR(v7_lo, v8_lo), XOR(v7_hi, v8_hi)
          z_lo, z_hi = v7_lo % 2^24, v7_hi % 2^24
          v7_lo, v7_hi = (v7_lo - z_lo) / 2^24 % 2^8 + z_hi * 2^8, (v7_hi - z_hi) / 2^24 % 2^8 + z_lo * 2^8
          k = row[14] * 2
          z = v2_lo % 2^32 + v7_lo % 2^32 + W[k-1]
          v2_lo = z % 2^32
          v2_hi = v2_hi + v7_hi + (z - v2_lo) / 2^32 + W[k]
          vD_lo, vD_hi = XOR(vD_lo, v2_lo), XOR(vD_hi, v2_hi)
          z_lo, z_hi = vD_lo % 2^16, vD_hi % 2^16
          vD_lo, vD_hi = (vD_lo - z_lo) / 2^16 % 2^16 + z_hi * 2^16, (vD_hi - z_hi) / 2^16 % 2^16 + z_lo * 2^16
          z = v8_lo % 2^32 + vD_lo % 2^32
          v8_lo = z % 2^32
          v8_hi = v8_hi + vD_hi + (z - v8_lo) / 2^32
          v7_lo, v7_hi = XOR(v7_lo, v8_lo), XOR(v7_hi, v8_hi)
          z_lo, z_hi = v7_lo % 2^31, v7_hi % 2^31
          v7_lo, v7_hi = z_lo * 2^1 + (v7_hi - z_hi) / 2^31 % 2^1, z_hi * 2^1 + (v7_lo - z_lo) / 2^31 % 2^1
          k = row[15] * 2
          z = v3_lo % 2^32 + v4_lo % 2^32 + W[k-1]
          v3_lo = z % 2^32
          v3_hi = v3_hi + v4_hi + (z - v3_lo) / 2^32 + W[k]
          vE_lo, vE_hi = XOR(vE_hi, v3_hi), XOR(vE_lo, v3_lo)
          z = v9_lo % 2^32 + vE_lo % 2^32
          v9_lo = z % 2^32
          v9_hi = v9_hi + vE_hi + (z - v9_lo) / 2^32
          v4_lo, v4_hi = XOR(v4_lo, v9_lo), XOR(v4_hi, v9_hi)
          z_lo, z_hi = v4_lo % 2^24, v4_hi % 2^24
          v4_lo, v4_hi = (v4_lo - z_lo) / 2^24 % 2^8 + z_hi * 2^8, (v4_hi - z_hi) / 2^24 % 2^8 + z_lo * 2^8
          k = row[16] * 2
          z = v3_lo % 2^32 + v4_lo % 2^32 + W[k-1]
          v3_lo = z % 2^32
          v3_hi = v3_hi + v4_hi + (z - v3_lo) / 2^32 + W[k]
          vE_lo, vE_hi = XOR(vE_lo, v3_lo), XOR(vE_hi, v3_hi)
          z_lo, z_hi = vE_lo % 2^16, vE_hi % 2^16
          vE_lo, vE_hi = (vE_lo - z_lo) / 2^16 % 2^16 + z_hi * 2^16, (vE_hi - z_hi) / 2^16 % 2^16 + z_lo * 2^16
          z = v9_lo % 2^32 + vE_lo % 2^32
          v9_lo = z % 2^32
          v9_hi = v9_hi + vE_hi + (z - v9_lo) / 2^32
          v4_lo, v4_hi = XOR(v4_lo, v9_lo), XOR(v4_hi, v9_hi)
          z_lo, z_hi = v4_lo % 2^31, v4_hi % 2^31
          v4_lo, v4_hi = z_lo * 2^1 + (v4_hi - z_hi) / 2^31 % 2^1, z_hi * 2^1 + (v4_lo - z_lo) / 2^31 % 2^1
        end
        h1_lo = XOR(h1_lo, v0_lo, v8_lo) % 2^32
        h2_lo = XOR(h2_lo, v1_lo, v9_lo) % 2^32
        h3_lo = XOR(h3_lo, v2_lo, vA_lo) % 2^32
        h4_lo = XOR(h4_lo, v3_lo, vB_lo) % 2^32
        h5_lo = XOR(h5_lo, v4_lo, vC_lo) % 2^32
        h6_lo = XOR(h6_lo, v5_lo, vD_lo) % 2^32
        h7_lo = XOR(h7_lo, v6_lo, vE_lo) % 2^32
        h8_lo = XOR(h8_lo, v7_lo, vF_lo) % 2^32
        h1_hi = XOR(h1_hi, v0_hi, v8_hi) % 2^32
        h2_hi = XOR(h2_hi, v1_hi, v9_hi) % 2^32
        h3_hi = XOR(h3_hi, v2_hi, vA_hi) % 2^32
        h4_hi = XOR(h4_hi, v3_hi, vB_hi) % 2^32
        h5_hi = XOR(h5_hi, v4_hi, vC_hi) % 2^32
        h6_hi = XOR(h6_hi, v5_hi, vD_hi) % 2^32
        h7_hi = XOR(h7_hi, v6_hi, vE_hi) % 2^32
        h8_hi = XOR(h8_hi, v7_hi, vF_hi) % 2^32
    end
    H_lo[1], H_lo[2], H_lo[3], H_lo[4], H_lo[5], H_lo[6], H_lo[7], H_lo[8] = h1_lo, h2_lo, h3_lo, h4_lo, h5_lo, h6_lo, h7_lo, h8_lo
    H_hi[1], H_hi[2], H_hi[3], H_hi[4], H_hi[5], H_hi[6], H_hi[7], H_hi[8] = h1_hi, h2_hi, h3_hi, h4_hi, h5_hi, h6_hi, h7_hi, h8_hi
    return bytes_compressed
  end

  local function blake3_feed_64(str, offs, size, flags, chunk_index, H_in, H_out, wide_output, block_length)
    -- offs >= 0, size >= 0, size is multiple of 64
    block_length = block_length or 64
    local W = common_W
    local h1, h2, h3, h4, h5, h6, h7, h8 = H_in[1], H_in[2], H_in[3], H_in[4], H_in[5], H_in[6], H_in[7], H_in[8]
    H_out = H_out or H_in
    for pos = offs, offs + size - 1, 64 do
        if str then
          for j = 1, 16 do
              pos = pos + 4
              local a, b, c, d = byte(str, pos - 3, pos)
              W[j] = ((d * 256 + c) * 256 + b) * 256 + a
          end
        end
        local v0, v1, v2, v3, v4, v5, v6, v7 = h1, h2, h3, h4, h5, h6, h7, h8
        local v8, v9, vA, vB = sha2_H_hi[1], sha2_H_hi[2], sha2_H_hi[3], sha2_H_hi[4]
        local vC = chunk_index % 2^32         -- t0 = low_4_bytes(chunk_index)
        local vD = (chunk_index - vC) / 2^32  -- t1 = high_4_bytes(chunk_index)
        local vE, vF = block_length, flags
        for j = 1, 7 do
          v0 = v0 + v4 + W[perm_blake3[j]]
          vC = XOR(vC, v0) % 2^32 / 2^16
          vC = vC % 1 * (2^32 - 1) + vC
          v8 = v8 + vC
          v4 = XOR(v4, v8) % 2^32 / 2^12
          v4 = v4 % 1 * (2^32 - 1) + v4
          v0 = v0 + v4 + W[perm_blake3[j + 14]]
          vC = XOR(vC, v0) % 2^32 / 2^8
          vC = vC % 1 * (2^32 - 1) + vC
          v8 = v8 + vC
          v4 = XOR(v4, v8) % 2^32 / 2^7
          v4 = v4 % 1 * (2^32 - 1) + v4
          v1 = v1 + v5 + W[perm_blake3[j + 1]]
          vD = XOR(vD, v1) % 2^32 / 2^16
          vD = vD % 1 * (2^32 - 1) + vD
          v9 = v9 + vD
          v5 = XOR(v5, v9) % 2^32 / 2^12
          v5 = v5 % 1 * (2^32 - 1) + v5
          v1 = v1 + v5 + W[perm_blake3[j + 2]]
          vD = XOR(vD, v1) % 2^32 / 2^8
          vD = vD % 1 * (2^32 - 1) + vD
          v9 = v9 + vD
          v5 = XOR(v5, v9) % 2^32 / 2^7
          v5 = v5 % 1 * (2^32 - 1) + v5
          v2 = v2 + v6 + W[perm_blake3[j + 16]]
          vE = XOR(vE, v2) % 2^32 / 2^16
          vE = vE % 1 * (2^32 - 1) + vE
          vA = vA + vE
          v6 = XOR(v6, vA) % 2^32 / 2^12
          v6 = v6 % 1 * (2^32 - 1) + v6
          v2 = v2 + v6 + W[perm_blake3[j + 7]]
          vE = XOR(vE, v2) % 2^32 / 2^8
          vE = vE % 1 * (2^32 - 1) + vE
          vA = vA + vE
          v6 = XOR(v6, vA) % 2^32 / 2^7
          v6 = v6 % 1 * (2^32 - 1) + v6
          v3 = v3 + v7 + W[perm_blake3[j + 15]]
          vF = XOR(vF, v3) % 2^32 / 2^16
          vF = vF % 1 * (2^32 - 1) + vF
          vB = vB + vF
          v7 = XOR(v7, vB) % 2^32 / 2^12
          v7 = v7 % 1 * (2^32 - 1) + v7
          v3 = v3 + v7 + W[perm_blake3[j + 17]]
          vF = XOR(vF, v3) % 2^32 / 2^8
          vF = vF % 1 * (2^32 - 1) + vF
          vB = vB + vF
          v7 = XOR(v7, vB) % 2^32 / 2^7
          v7 = v7 % 1 * (2^32 - 1) + v7
          v0 = v0 + v5 + W[perm_blake3[j + 21]]
          vF = XOR(vF, v0) % 2^32 / 2^16
          vF = vF % 1 * (2^32 - 1) + vF
          vA = vA + vF
          v5 = XOR(v5, vA) % 2^32 / 2^12
          v5 = v5 % 1 * (2^32 - 1) + v5
          v0 = v0 + v5 + W[perm_blake3[j + 5]]
          vF = XOR(vF, v0) % 2^32 / 2^8
          vF = vF % 1 * (2^32 - 1) + vF
          vA = vA + vF
          v5 = XOR(v5, vA) % 2^32 / 2^7
          v5 = v5 % 1 * (2^32 - 1) + v5
          v1 = v1 + v6 + W[perm_blake3[j + 3]]
          vC = XOR(vC, v1) % 2^32 / 2^16
          vC = vC % 1 * (2^32 - 1) + vC
          vB = vB + vC
          v6 = XOR(v6, vB) % 2^32 / 2^12
          v6 = v6 % 1 * (2^32 - 1) + v6
          v1 = v1 + v6 + W[perm_blake3[j + 6]]
          vC = XOR(vC, v1) % 2^32 / 2^8
          vC = vC % 1 * (2^32 - 1) + vC
          vB = vB + vC
          v6 = XOR(v6, vB) % 2^32 / 2^7
          v6 = v6 % 1 * (2^32 - 1) + v6
          v2 = v2 + v7 + W[perm_blake3[j + 4]]
          vD = XOR(vD, v2) % 2^32 / 2^16
          vD = vD % 1 * (2^32 - 1) + vD
          v8 = v8 + vD
          v7 = XOR(v7, v8) % 2^32 / 2^12
          v7 = v7 % 1 * (2^32 - 1) + v7
          v2 = v2 + v7 + W[perm_blake3[j + 18]]
          vD = XOR(vD, v2) % 2^32 / 2^8
          vD = vD % 1 * (2^32 - 1) + vD
          v8 = v8 + vD
          v7 = XOR(v7, v8) % 2^32 / 2^7
          v7 = v7 % 1 * (2^32 - 1) + v7
          v3 = v3 + v4 + W[perm_blake3[j + 19]]
          vE = XOR(vE, v3) % 2^32 / 2^16
          vE = vE % 1 * (2^32 - 1) + vE
          v9 = v9 + vE
          v4 = XOR(v4, v9) % 2^32 / 2^12
          v4 = v4 % 1 * (2^32 - 1) + v4
          v3 = v3 + v4 + W[perm_blake3[j + 20]]
          vE = XOR(vE, v3) % 2^32 / 2^8
          vE = vE % 1 * (2^32 - 1) + vE
          v9 = v9 + vE
          v4 = XOR(v4, v9) % 2^32 / 2^7
          v4 = v4 % 1 * (2^32 - 1) + v4
        end
        if wide_output then
          H_out[ 9] = XOR(h1, v8)
          H_out[10] = XOR(h2, v9)
          H_out[11] = XOR(h3, vA)
          H_out[12] = XOR(h4, vB)
          H_out[13] = XOR(h5, vC)
          H_out[14] = XOR(h6, vD)
          H_out[15] = XOR(h7, vE)
          H_out[16] = XOR(h8, vF)
        end
        h1 = XOR(v0, v8)
        h2 = XOR(v1, v9)
        h3 = XOR(v2, vA)
        h4 = XOR(v3, vB)
        h5 = XOR(v4, vC)
        h6 = XOR(v5, vD)
        h7 = XOR(v6, vE)
        h8 = XOR(v7, vF)
    end
    H_out[1], H_out[2], H_out[3], H_out[4], H_out[5], H_out[6], H_out[7], H_out[8] = h1, h2, h3, h4, h5, h6, h7, h8
  end

  --------------------------------------------------------------------------------
  -- MAGIC NUMBERS CALCULATOR
  --------------------------------------------------------------------------------
  do
    local function mul(src1, src2, factor, result_length)
        -- src1, src2 - long integers (arrays of digits in base 2^24)
        -- factor - small integer
        -- returns long integer result (src1 * src2 * factor) and its floating point approximation
        local result, carry, value, weight = {}, 0.0, 0.0, 1.0
        for j = 1, result_length do
          for k = math_max(1, j + 1 - #src2), math_min(j, #src1) do
              carry = carry + factor * src1[k] * src2[j + 1 - k]  -- "int32" is not enough for multiplication result, that's why "factor" must be of type "double"
          end
          local digit = carry % 2^24
          result[j] = floor(digit)
          carry = (carry - digit) / 2^24
          value = value + digit * weight
          weight = weight * 2^24
        end
        return result, value
    end

    local idx, step, p, one, sqrt_hi, sqrt_lo = 0, {4, 1, 2, -2, 2}, 4, {1}, sha2_H_hi, sha2_H_lo
    repeat
        p = p + step[p % 6]
        local d = 1
        repeat
          d = d + step[d % 6]
          if d*d > p then -- next prime number is found
              local root = p^(1/3)
              local R = root * 2^40
              R = mul({R - R % 1}, one, 1.0, 2)
              local _, delta = mul(R, mul(R, R, 1.0, 4), -1.0, 4)
              local hi = R[2] % 65536 * 65536 + floor(R[1] / 256)
              local lo = R[1] % 256 * 16777216 + floor(delta * (2^-56 / 3) * root / p)
              if idx < 16 then
                root = p^(1/2)
                R = root * 2^40
                R = mul({R - R % 1}, one, 1.0, 2)
                _, delta = mul(R, R, -1.0, 2)
                local hi = R[2] % 65536 * 65536 + floor(R[1] / 256)
                local lo = R[1] % 256 * 16777216 + floor(delta * 2^-17 / root)
                local idx = idx % 8 + 1
                sha2_H_ext256[224][idx] = lo
                sqrt_hi[idx], sqrt_lo[idx] = hi, lo + hi * hi_factor
                if idx > 7 then
                    sqrt_hi, sqrt_lo = sha2_H_ext512_hi[384], sha2_H_ext512_lo[384]
                end
              end
              idx = idx + 1
              sha2_K_hi[idx], sha2_K_lo[idx] = hi, lo % K_lo_modulo + hi * hi_factor
              break
          end
        until p % d == 0
    until idx > 79
  end

  -- Calculating IVs for SHA512/224 and SHA512/256
  for width = 224, 256, 32 do
    local H_lo, H_hi = {}
    if HEX64 then
        for j = 1, 8 do
          H_lo[j] = XORA5(sha2_H_lo[j])
        end
    else
        H_hi = {}
        for j = 1, 8 do
          H_lo[j] = XORA5(sha2_H_lo[j])
          H_hi[j] = XORA5(sha2_H_hi[j])
        end
    end
    sha512_feed_128(H_lo, H_hi, "SHA-512/"..tostring(width).."\128"..string_rep("\0", 115).."\88", 0, 128)
    sha2_H_ext512_lo[width] = H_lo
    sha2_H_ext512_hi[width] = H_hi
  end

  -- Constants for MD5
  do
    local sin, abs, modf = math.sin, math.abs, math.modf
    for idx = 1, 64 do
        -- we can't use formula floor(abs(sin(idx))*2^32) because its result may be beyond integer range on Lua built with 32-bit integers
        local hi, lo = modf(abs(sin(idx)) * 2^16)
        md5_K[idx] = hi * 65536 + floor(lo * 2^16)
    end
  end

  -- Constants for SHA-3
  do
    local sh_reg = 29

    local function next_bit()
        local r = sh_reg % 2
        sh_reg = XOR_BYTE((sh_reg - r) / 2, 142 * r)
        return r
    end

    for idx = 1, 24 do
        local lo, m = 0
        for _ = 1, 6 do
          m = m and m * m * 2 or 1
          lo = lo + next_bit() * m
        end
        local hi = next_bit() * m
        sha3_RC_hi[idx], sha3_RC_lo[idx] = hi, lo + hi * hi_factor_keccak
    end
  end

  --------------------------------------------------------------------------------
  -- MAIN FUNCTIONS
  --------------------------------------------------------------------------------
  local function sha256ext(width, message)
    -- Create an instance (private objects for current calculation)
    local H, length, tail = {unpack(sha2_H_ext256[width])}, 0.0, ""

    local function partial(message_part)
        if message_part then
          if tail then
              length = length + #message_part
              local offs = 0
              if tail ~= "" and #tail + #message_part >= 64 then
                offs = 64 - #tail
                sha256_feed_64(H, tail..sub(message_part, 1, offs), 0, 64)
                tail = ""
              end
              local size = #message_part - offs
              local size_tail = size % 64
              sha256_feed_64(H, message_part, offs, size - size_tail)
              tail = tail..sub(message_part, #message_part + 1 - size_tail)
              return partial
          else
              error("Adding more chunks is not allowed after receiving the result", 2)
          end
        else
          if tail then
              local final_blocks = {tail, "\128", string_rep("\0", (-9 - length) % 64 + 1)}
              tail = nil
              -- Assuming user data length is shorter than (2^53)-9 bytes
              -- Anyway, it looks very unrealistic that someone would spend more than a year of calculations to process 2^53 bytes of data by using this Lua script :-)
              -- 2^53 bytes = 2^56 bits, so "bit-counter" fits in 7 bytes
              length = length * (8 / 256^7)  -- convert "byte-counter" to "bit-counter" and move decimal point to the left
              for j = 4, 10 do
                length = length % 1 * 256
                final_blocks[j] = char(floor(length))
              end
              final_blocks = concat(final_blocks)
              sha256_feed_64(H, final_blocks, 0, #final_blocks)
              local max_reg = width / 32
              for j = 1, max_reg do
                H[j] = HEX(H[j])
              end
              H = concat(H, "", 1, max_reg)
          end
          return H
        end
    end

    if message then
        -- Actually perform calculations and return the SHA256 digest of a message
        return partial(message)()
    else
        -- Return function for chunk-by-chunk loading
        -- User should feed every chunk of input data as single argument to this function and finally get SHA256 digest by invoking this function without an argument
        return partial
    end
  end

  local function sha512ext(width, message)
    -- Create an instance (private objects for current calculation)
    local length, tail, H_lo, H_hi = 0.0, "", {unpack(sha2_H_ext512_lo[width])}, not HEX64 and {unpack(sha2_H_ext512_hi[width])}

    local function partial(message_part)
        if message_part then
          if tail then
              length = length + #message_part
              local offs = 0
              if tail ~= "" and #tail + #message_part >= 128 then
                offs = 128 - #tail
                sha512_feed_128(H_lo, H_hi, tail..sub(message_part, 1, offs), 0, 128)
                tail = ""
              end
              local size = #message_part - offs
              local size_tail = size % 128
              sha512_feed_128(H_lo, H_hi, message_part, offs, size - size_tail)
              tail = tail..sub(message_part, #message_part + 1 - size_tail)
              return partial
          else
              error("Adding more chunks is not allowed after receiving the result", 2)
          end
        else
          if tail then
              local final_blocks = {tail, "\128", string_rep("\0", (-17-length) % 128 + 9)}
              tail = nil
              -- Assuming user data length is shorter than (2^53)-17 bytes
              -- 2^53 bytes = 2^56 bits, so "bit-counter" fits in 7 bytes
              length = length * (8 / 256^7)  -- convert "byte-counter" to "bit-counter" and move floating point to the left
              for j = 4, 10 do
                length = length % 1 * 256
                final_blocks[j] = char(floor(length))
              end
              final_blocks = concat(final_blocks)
              sha512_feed_128(H_lo, H_hi, final_blocks, 0, #final_blocks)
              local max_reg = ceil(width / 64)
              if HEX64 then
                for j = 1, max_reg do
                    H_lo[j] = HEX64(H_lo[j])
                end
              else
                for j = 1, max_reg do
                    H_lo[j] = HEX(H_hi[j])..HEX(H_lo[j])
                end
                H_hi = nil
              end
              H_lo = sub(concat(H_lo, "", 1, max_reg), 1, width / 4)
          end
          return H_lo
        end
    end

    if message then
        -- Actually perform calculations and return the SHA512 digest of a message
        return partial(message)()
    else
        -- Return function for chunk-by-chunk loading
        -- User should feed every chunk of input data as single argument to this function and finally get SHA512 digest by invoking this function without an argument
        return partial
    end
  end

  local function md5(message)
    -- Create an instance (private objects for current calculation)
    local H, length, tail = {unpack(md5_sha1_H, 1, 4)}, 0.0, ""

    local function partial(message_part)
        if message_part then
          if tail then
              length = length + #message_part
              local offs = 0
              if tail ~= "" and #tail + #message_part >= 64 then
                offs = 64 - #tail
                md5_feed_64(H, tail..sub(message_part, 1, offs), 0, 64)
                tail = ""
              end
              local size = #message_part - offs
              local size_tail = size % 64
              md5_feed_64(H, message_part, offs, size - size_tail)
              tail = tail..sub(message_part, #message_part + 1 - size_tail)
              return partial
          else
              error("Adding more chunks is not allowed after receiving the result", 2)
          end
        else
          if tail then
              local final_blocks = {tail, "\128", string_rep("\0", (-9 - length) % 64)}
              tail = nil
              length = length * 8  -- convert "byte-counter" to "bit-counter"
              for j = 4, 11 do
                local low_byte = length % 256
                final_blocks[j] = char(low_byte)
                length = (length - low_byte) / 256
              end
              final_blocks = concat(final_blocks)
              md5_feed_64(H, final_blocks, 0, #final_blocks)
              for j = 1, 4 do
                H[j] = HEX(H[j])
              end
              H = gsub(concat(H), "(..)(..)(..)(..)", "%4%3%2%1")
          end
          return H
        end
    end

    if message then
        -- Actually perform calculations and return the MD5 digest of a message
        return partial(message)()
    else
        -- Return function for chunk-by-chunk loading
        -- User should feed every chunk of input data as single argument to this function and finally get MD5 digest by invoking this function without an argument
        return partial
    end
  end

  local function sha1(message)
    -- Create an instance (private objects for current calculation)
    local H, length, tail = {unpack(md5_sha1_H)}, 0.0, ""

    local function partial(message_part)
        if message_part then
          if tail then
              length = length + #message_part
              local offs = 0
              if tail ~= "" and #tail + #message_part >= 64 then
                offs = 64 - #tail
                sha1_feed_64(H, tail..sub(message_part, 1, offs), 0, 64)
                tail = ""
              end
              local size = #message_part - offs
              local size_tail = size % 64
              sha1_feed_64(H, message_part, offs, size - size_tail)
              tail = tail..sub(message_part, #message_part + 1 - size_tail)
              return partial
          else
              error("Adding more chunks is not allowed after receiving the result", 2)
          end
        else
          if tail then
              local final_blocks = {tail, "\128", string_rep("\0", (-9 - length) % 64 + 1)}
              tail = nil
              -- Assuming user data length is shorter than (2^53)-9 bytes
              -- 2^53 bytes = 2^56 bits, so "bit-counter" fits in 7 bytes
              length = length * (8 / 256^7)  -- convert "byte-counter" to "bit-counter" and move decimal point to the left
              for j = 4, 10 do
                length = length % 1 * 256
                final_blocks[j] = char(floor(length))
              end
              final_blocks = concat(final_blocks)
              sha1_feed_64(H, final_blocks, 0, #final_blocks)
              for j = 1, 5 do
                H[j] = HEX(H[j])
              end
              H = concat(H)
          end
          return H
        end
    end

    if message then
        -- Actually perform calculations and return the SHA-1 digest of a message
        return partial(message)()
    else
        -- Return function for chunk-by-chunk loading
        -- User should feed every chunk of input data as single argument to this function and finally get SHA-1 digest by invoking this function without an argument
        return partial
    end
  end

  local function keccak(block_size_in_bytes, digest_size_in_bytes, is_SHAKE, message)
    if type(digest_size_in_bytes) ~= "number" then
      error("Argument 'digest_size_in_bytes' must be a number", 2)
    end

    local tail, lanes_lo, lanes_hi = "", create_array_of_lanes(), hi_factor_keccak == 0 and create_array_of_lanes()
    local result

    local function partial(message_part)
      if message_part then
          if tail then
            local offs = 0
            if tail ~= "" and #tail + #message_part >= block_size_in_bytes then
                offs = block_size_in_bytes - #tail
                keccak_feed(lanes_lo, lanes_hi, tail..sub(message_part, 1, offs), 0, block_size_in_bytes, block_size_in_bytes)
                tail = ""
            end
            local size = #message_part - offs
            local size_tail = size % block_size_in_bytes
            keccak_feed(lanes_lo, lanes_hi, message_part, offs, size - size_tail, block_size_in_bytes)
            tail = tail..sub(message_part, #message_part + 1 - size_tail)
            return partial
          else
            error("Adding more chunks is not allowed after receiving the result", 2)
          end
      else
          if tail then
            -- append the following bits to the message: for usual SHA-3: 011(0*)1, for SHAKE: 11111(0*)1
            local gap_start = is_SHAKE and 31 or 6
            tail = tail..(#tail + 1 == block_size_in_bytes and char(gap_start + 128) or char(gap_start)..string_rep("\0", (-2 - #tail) % block_size_in_bytes).."\128")
            keccak_feed(lanes_lo, lanes_hi, tail, 0, #tail, block_size_in_bytes)
            tail = nil
            local lanes_used = 0
            local total_lanes = floor(block_size_in_bytes / 8)
            local qwords = {}

            local function get_next_qwords_of_digest(qwords_qty)
                -- returns not more than 'qwords_qty' qwords ('qwords_qty' might be non-integer)
                -- doesn't go across keccak-buffer boundary
                -- block_size_in_bytes is a multiple of 8, so, keccak-buffer contains integer number of qwords
                if lanes_used >= total_lanes then
                  keccak_feed(lanes_lo, lanes_hi, "\0\0\0\0\0\0\0\0", 0, 8, 8)
                  lanes_used = 0
                end
                qwords_qty = floor(math_min(qwords_qty, total_lanes - lanes_used))
                if hi_factor_keccak ~= 0 then
                  for j = 1, qwords_qty do
                      qwords[j] = HEX64(lanes_lo[lanes_used + j - 1 + lanes_index_base])
                  end
                else
                  for j = 1, qwords_qty do
                      qwords[j] = HEX(lanes_hi[lanes_used + j])..HEX(lanes_lo[lanes_used + j])
                  end
                end
                lanes_used = lanes_used + qwords_qty
                return
                  gsub(concat(qwords, "", 1, qwords_qty), "(..)(..)(..)(..)(..)(..)(..)(..)", "%8%7%6%5%4%3%2%1"),
                  qwords_qty * 8
            end

            local parts = {}      -- digest parts
            local last_part, last_part_size = "", 0

            local function get_next_part_of_digest(bytes_needed)
                -- returns 'bytes_needed' bytes, for arbitrary integer 'bytes_needed'
                bytes_needed = bytes_needed or 1
                if bytes_needed <= last_part_size then
                  last_part_size = last_part_size - bytes_needed
                  local part_size_in_nibbles = bytes_needed * 2
                  local result = sub(last_part, 1, part_size_in_nibbles)
                  last_part = sub(last_part, part_size_in_nibbles + 1)
                  return result
                end
                local parts_qty = 0
                if last_part_size > 0 then
                  parts_qty = 1
                  parts[parts_qty] = last_part
                  bytes_needed = bytes_needed - last_part_size
                end
                -- repeats until the length is enough
                while bytes_needed >= 8 do
                  local next_part, next_part_size = get_next_qwords_of_digest(bytes_needed / 8)
                  parts_qty = parts_qty + 1
                  parts[parts_qty] = next_part
                  bytes_needed = bytes_needed - next_part_size
                end
                if bytes_needed > 0 then
                  last_part, last_part_size = get_next_qwords_of_digest(1)
                  parts_qty = parts_qty + 1
                  parts[parts_qty] = get_next_part_of_digest(bytes_needed)
                else
                  last_part, last_part_size = "", 0
                end
                return concat(parts, "", 1, parts_qty)
            end

            if digest_size_in_bytes < 0 then
                result = get_next_part_of_digest
            else
                result = get_next_part_of_digest(digest_size_in_bytes)
            end
          end
          return result
      end
    end

    if message then
      -- Actually perform calculations and return the SHA-3 digest of a message
      return partial(message)()
    else
      -- Return function for chunk-by-chunk loading
      -- User should feed every chunk of input data as single argument to this function and finally get SHA-3 digest by invoking this function without an argument
      return partial
    end
  end

  local function hex_to_bin(hex_string)
    return (
      gsub(hex_string, "%x%x",
        function (hh)
            return char(tonumber(hh, 16))
        end)
    )
  end

  local function bin_to_hex(binary_string)
    return (
      gsub(binary_string, ".",
        function (c)
          return string_format("%02x", byte(c))
        end)
    )
  end

  local base64_symbols = {
    ['+'] = 62, ['-'] = 62,  [62] = '+',
    ['/'] = 63, ['_'] = 63,  [63] = '/',
    ['='] = -1, ['.'] = -1,  [-1] = '='
  }
  local symbol_index = 0
  for j, pair in ipairs{'AZ', 'az', '09'} do
    for ascii = byte(pair), byte(pair, 2) do
      local ch = char(ascii)
      base64_symbols[ch] = symbol_index
      base64_symbols[symbol_index] = ch
      symbol_index = symbol_index + 1
    end
  end

  local function bin_to_base64(binary_string)
    local result = {}
    for pos = 1, #binary_string, 3 do
      local c1, c2, c3, c4 = byte(sub(binary_string, pos, pos + 2)..'\0', 1, -1)
      result[#result + 1] =
        base64_symbols[floor(c1 / 4)]
        ..base64_symbols[c1 % 4 * 16 + floor(c2 / 16)]
        ..base64_symbols[c3 and c2 % 16 * 4 + floor(c3 / 64) or -1]
        ..base64_symbols[c4 and c3 % 64 or -1]
    end
    return concat(result)
  end

  local function base64_to_bin(base64_string)
    local result, chars_qty = {}, 3
    for pos, ch in gmatch(gsub(base64_string, '%s+', ''), '()(.)') do
      local code = base64_symbols[ch]
      if code < 0 then
        chars_qty = chars_qty - 1
        code = 0
      end
      local idx = pos % 4
      if idx > 0 then
        result[-idx] = code
      else
        local c1 = result[-1] * 4 + floor(result[-2] / 16)
        local c2 = (result[-2] % 16) * 16 + floor(result[-3] / 4)
        local c3 = (result[-3] % 4) * 64 + code
        result[#result + 1] = sub(char(c1, c2, c3), 1, chars_qty)
      end
    end
    return concat(result)
  end

  local block_size_for_HMAC  -- this table will be initialized at the end of the module

  local function pad_and_xor(str, result_length, byte_for_xor)
    return gsub(str, ".",
        function(c)
          return char(XOR_BYTE(byte(c), byte_for_xor))
        end
    )..string_rep(char(byte_for_xor), result_length - #str)
  end

  local function hmac(hash_func, key, message)
    -- Create an instance (private objects for current calculation)
    local block_size = block_size_for_HMAC[hash_func]
    if not block_size then
        error("Unknown hash function", 2)
    end
    if #key > block_size then
        key = hex_to_bin(hash_func(key))
    end
    local append = hash_func()(pad_and_xor(key, block_size, 0x36))
    local result

    local function partial(message_part)
        if not message_part then
          result = result or hash_func(pad_and_xor(key, block_size, 0x5C)..hex_to_bin(append()))
          return result
        elseif result then
          error("Adding more chunks is not allowed after receiving the result", 2)
        else
          append(message_part)
          return partial
        end
    end

    if message then
        -- Actually perform calculations and return the HMAC of a message
        return partial(message)()
    else
        -- Return function for chunk-by-chunk loading of a message
        -- User should feed every chunk of the message as single argument to this function and finally get HMAC by invoking this function without an argument
        return partial
    end
  end

  local function xor_blake2_salt(salt, letter, H_lo, H_hi)
    -- salt: concatenation of "Salt"+"Personalization" fields
    local max_size = letter == "s" and 16 or 32
    local salt_size = #salt
    if salt_size > max_size then
        error(string_format("For BLAKE2%s/BLAKE2%sp/BLAKE2X%s the 'salt' parameter length must not exceed %d bytes", letter, letter, letter, max_size), 2)
    end
    if H_lo then
        local offset, blake2_word_size, xor = 0, letter == "s" and 4 or 8, letter == "s" and XOR or XORA5
        for j = 5, 4 + ceil(salt_size / blake2_word_size) do
          local prev, last
          for _ = 1, blake2_word_size, 4 do
              offset = offset + 4
              local a, b, c, d = byte(salt, offset - 3, offset)
              local four_bytes = (((d or 0) * 256 + (c or 0)) * 256 + (b or 0)) * 256 + (a or 0)
              prev, last = last, four_bytes
          end
          H_lo[j] = xor(H_lo[j], prev and last * hi_factor + prev or last)
          if H_hi then
              H_hi[j] = xor(H_hi[j], last)
          end
        end
    end
  end

  local function blake2s(message, key, salt, digest_size_in_bytes, XOF_length, B2_offset)
    -- message:  binary string to be hashed (or nil for "chunk-by-chunk" input mode)
    -- key:      (optional) binary string up to 32 bytes, by default empty string
    -- salt:     (optional) binary string up to 16 bytes, by default empty string
    -- digest_size_in_bytes: (optional) integer from 1 to 32, by default 32
    -- The last two parameters "XOF_length" and "B2_offset" are for internal use only, user must omit them (or pass nil)
    digest_size_in_bytes = digest_size_in_bytes or 32
    if digest_size_in_bytes < 1 or digest_size_in_bytes > 32 then
        error("BLAKE2s digest length must be from 1 to 32 bytes", 2)
    end
    key = key or ""
    local key_length = #key
    if key_length > 32 then
        error("BLAKE2s key length must not exceed 32 bytes", 2)
    end
    salt = salt or ""
    local bytes_compressed, tail, H = 0.0, "", {unpack(sha2_H_hi)}
    if B2_offset then
        H[1] = XOR(H[1], digest_size_in_bytes)
        H[2] = XOR(H[2], 0x20)
        H[3] = XOR(H[3], B2_offset)
        H[4] = XOR(H[4], 0x20000000 + XOF_length)
    else
        H[1] = XOR(H[1], 0x01010000 + key_length * 256 + digest_size_in_bytes)
        if XOF_length then
          H[4] = XOR(H[4], XOF_length)
        end
    end
    if salt ~= "" then
        xor_blake2_salt(salt, "s", H)
    end

    local function partial(message_part)
        if message_part then
          if tail then
              local offs = 0
              if tail ~= "" and #tail + #message_part > 64 then
                offs = 64 - #tail
                bytes_compressed = blake2s_feed_64(H, tail..sub(message_part, 1, offs), 0, 64, bytes_compressed)
                tail = ""
              end
              local size = #message_part - offs
              local size_tail = size > 0 and (size - 1) % 64 + 1 or 0
              bytes_compressed = blake2s_feed_64(H, message_part, offs, size - size_tail, bytes_compressed)
              tail = tail..sub(message_part, #message_part + 1 - size_tail)
              return partial
          else
              error("Adding more chunks is not allowed after receiving the result", 2)
          end
        else
          if tail then
              if B2_offset then
                blake2s_feed_64(H, nil, 0, 64, 0, 32)
              else
                blake2s_feed_64(H, tail..string_rep("\0", 64 - #tail), 0, 64, bytes_compressed, #tail)
              end
              tail = nil
              if not XOF_length or B2_offset then
                local max_reg = ceil(digest_size_in_bytes / 4)
                for j = 1, max_reg do
                    H[j] = HEX(H[j])
                end
                H = sub(gsub(concat(H, "", 1, max_reg), "(..)(..)(..)(..)", "%4%3%2%1"), 1, digest_size_in_bytes * 2)
              end
          end
          return H
        end
    end

    if key_length > 0 then
        partial(key..string_rep("\0", 64 - key_length))
    end
    if B2_offset then
        return partial()
    elseif message then
        -- Actually perform calculations and return the BLAKE2s digest of a message
        return partial(message)()
    else
        -- Return function for chunk-by-chunk loading
        -- User should feed every chunk of input data as single argument to this function and finally get BLAKE2s digest by invoking this function without an argument
        return partial
    end
  end

  local function blake2b(message, key, salt, digest_size_in_bytes, XOF_length, B2_offset)
    -- message:  binary string to be hashed (or nil for "chunk-by-chunk" input mode)
    -- key:      (optional) binary string up to 64 bytes, by default empty string
    -- salt:     (optional) binary string up to 32 bytes, by default empty string
    -- digest_size_in_bytes: (optional) integer from 1 to 64, by default 64
    -- The last two parameters "XOF_length" and "B2_offset" are for internal use only, user must omit them (or pass nil)
    digest_size_in_bytes = floor(digest_size_in_bytes or 64)
    if digest_size_in_bytes < 1 or digest_size_in_bytes > 64 then
        error("BLAKE2b digest length must be from 1 to 64 bytes", 2)
    end
    key = key or ""
    local key_length = #key
    if key_length > 64 then
        error("BLAKE2b key length must not exceed 64 bytes", 2)
    end
    salt = salt or ""
    local bytes_compressed, tail, H_lo, H_hi = 0.0, "", {unpack(sha2_H_lo)}, not HEX64 and {unpack(sha2_H_hi)}
    if B2_offset then
        if H_hi then
          H_lo[1] = XORA5(H_lo[1], digest_size_in_bytes)
          H_hi[1] = XORA5(H_hi[1], 0x40)
          H_lo[2] = XORA5(H_lo[2], B2_offset)
          H_hi[2] = XORA5(H_hi[2], XOF_length)
        else
          H_lo[1] = XORA5(H_lo[1], 0x40 * hi_factor + digest_size_in_bytes)
          H_lo[2] = XORA5(H_lo[2], XOF_length * hi_factor + B2_offset)
        end
        H_lo[3] = XORA5(H_lo[3], 0x4000)
    else
        H_lo[1] = XORA5(H_lo[1], 0x01010000 + key_length * 256 + digest_size_in_bytes)
        if XOF_length then
          if H_hi then
              H_hi[2] = XORA5(H_hi[2], XOF_length)
          else
              H_lo[2] = XORA5(H_lo[2], XOF_length * hi_factor)
          end
        end
    end
    if salt ~= "" then
        xor_blake2_salt(salt, "b", H_lo, H_hi)
    end

    local function partial(message_part)
        if message_part then
          if tail then
              local offs = 0
              if tail ~= "" and #tail + #message_part > 128 then
                offs = 128 - #tail
                bytes_compressed = blake2b_feed_128(H_lo, H_hi, tail..sub(message_part, 1, offs), 0, 128, bytes_compressed)
                tail = ""
              end
              local size = #message_part - offs
              local size_tail = size > 0 and (size - 1) % 128 + 1 or 0
              bytes_compressed = blake2b_feed_128(H_lo, H_hi, message_part, offs, size - size_tail, bytes_compressed)
              tail = tail..sub(message_part, #message_part + 1 - size_tail)
              return partial
          else
              error("Adding more chunks is not allowed after receiving the result", 2)
          end
        else
          if tail then
              if B2_offset then
                blake2b_feed_128(H_lo, H_hi, nil, 0, 128, 0, 64)
              else
                blake2b_feed_128(H_lo, H_hi, tail..string_rep("\0", 128 - #tail), 0, 128, bytes_compressed, #tail)
              end
              tail = nil
              if XOF_length and not B2_offset then
                if H_hi then
                    for j = 8, 1, -1 do
                      H_lo[j*2] = H_hi[j]
                      H_lo[j*2-1] = H_lo[j]
                    end
                    return H_lo, 16
                end
              else
                local max_reg = ceil(digest_size_in_bytes / 8)
                if H_hi then
                    for j = 1, max_reg do
                      H_lo[j] = HEX(H_hi[j])..HEX(H_lo[j])
                    end
                else
                    for j = 1, max_reg do
                      H_lo[j] = HEX64(H_lo[j])
                    end
                end
                H_lo = sub(gsub(concat(H_lo, "", 1, max_reg), "(..)(..)(..)(..)(..)(..)(..)(..)", "%8%7%6%5%4%3%2%1"), 1, digest_size_in_bytes * 2)
              end
              H_hi = nil
          end
          return H_lo
        end
    end

    if key_length > 0 then
        partial(key..string_rep("\0", 128 - key_length))
    end
    if B2_offset then
        return partial()
    elseif message then
        -- Actually perform calculations and return the BLAKE2b digest of a message
        return partial(message)()
    else
        -- Return function for chunk-by-chunk loading
        -- User should feed every chunk of input data as single argument to this function and finally get BLAKE2b digest by invoking this function without an argument
        return partial
    end
  end

  local function blake2sp(message, key, salt, digest_size_in_bytes)
    -- message:  binary string to be hashed (or nil for "chunk-by-chunk" input mode)
    -- key:      (optional) binary string up to 32 bytes, by default empty string
    -- salt:     (optional) binary string up to 16 bytes, by default empty string
    -- digest_size_in_bytes: (optional) integer from 1 to 32, by default 32
    digest_size_in_bytes = digest_size_in_bytes or 32
    if digest_size_in_bytes < 1 or digest_size_in_bytes > 32 then
        error("BLAKE2sp digest length must be from 1 to 32 bytes", 2)
    end
    key = key or ""
    local key_length = #key
    if key_length > 32 then
        error("BLAKE2sp key length must not exceed 32 bytes", 2)
    end
    salt = salt or ""
    local instances, length, first_dword_of_parameter_block, result = {}, 0.0, 0x02080000 + key_length * 256 + digest_size_in_bytes
    for j = 1, 8 do
        local bytes_compressed, tail, H = 0.0, "", {unpack(sha2_H_hi)}
        instances[j] = {bytes_compressed, tail, H}
        H[1] = XOR(H[1], first_dword_of_parameter_block)
        H[3] = XOR(H[3], j-1)
        H[4] = XOR(H[4], 0x20000000)
        if salt ~= "" then
          xor_blake2_salt(salt, "s", H)
        end
    end

    local function partial(message_part)
        if message_part then
          if instances then
              local from = 0
              while true do
                local to = math_min(from + 64 - length % 64, #message_part)
                if to > from then
                    local inst = instances[floor(length / 64) % 8 + 1]
                    local part = sub(message_part, from + 1, to)
                    length, from = length + to - from, to
                    local bytes_compressed, tail = inst[1], inst[2]
                    if #tail < 64 then
                      tail = tail..part
                    else
                      local H = inst[3]
                      bytes_compressed = blake2s_feed_64(H, tail, 0, 64, bytes_compressed)
                      tail = part
                    end
                    inst[1], inst[2] = bytes_compressed, tail
                else
                    break
                end
              end
              return partial
          else
              error("Adding more chunks is not allowed after receiving the result", 2)
          end
        else
          if instances then
              local root_H = {unpack(sha2_H_hi)}
              root_H[1] = XOR(root_H[1], first_dword_of_parameter_block)
              root_H[4] = XOR(root_H[4], 0x20010000)
              if salt ~= "" then
                xor_blake2_salt(salt, "s", root_H)
              end
              for j = 1, 8 do
                local inst = instances[j]
                local bytes_compressed, tail, H = inst[1], inst[2], inst[3]
                blake2s_feed_64(H, tail..string_rep("\0", 64 - #tail), 0, 64, bytes_compressed, #tail, j == 8)
                if j % 2 == 0 then
                    local index = 0
                    for k = j - 1, j do
                      local inst = instances[k]
                      local H = inst[3]
                      for i = 1, 8 do
                          index = index + 1
                          common_W_blake2s[index] = H[i]
                      end
                    end
                    blake2s_feed_64(root_H, nil, 0, 64, 64 * (j/2 - 1), j == 8 and 64, j == 8)
                end
              end
              instances = nil
              local max_reg = ceil(digest_size_in_bytes / 4)
              for j = 1, max_reg do
                root_H[j] = HEX(root_H[j])
              end
              result = sub(gsub(concat(root_H, "", 1, max_reg), "(..)(..)(..)(..)", "%4%3%2%1"), 1, digest_size_in_bytes * 2)
          end
          return result
        end
    end

    if key_length > 0 then
        key = key..string_rep("\0", 64 - key_length)
        for j = 1, 8 do
          partial(key)
        end
    end
    if message then
        -- Actually perform calculations and return the BLAKE2sp digest of a message
        return partial(message)()
    else
        -- Return function for chunk-by-chunk loading
        -- User should feed every chunk of input data as single argument to this function and finally get BLAKE2sp digest by invoking this function without an argument
        return partial
    end

  end

  local function blake2bp(message, key, salt, digest_size_in_bytes)
    -- message:  binary string to be hashed (or nil for "chunk-by-chunk" input mode)
    -- key:      (optional) binary string up to 64 bytes, by default empty string
    -- salt:     (optional) binary string up to 32 bytes, by default empty string
    -- digest_size_in_bytes: (optional) integer from 1 to 64, by default 64
    digest_size_in_bytes = digest_size_in_bytes or 64
    if digest_size_in_bytes < 1 or digest_size_in_bytes > 64 then
        error("BLAKE2bp digest length must be from 1 to 64 bytes", 2)
    end
    key = key or ""
    local key_length = #key
    if key_length > 64 then
        error("BLAKE2bp key length must not exceed 64 bytes", 2)
    end
    salt = salt or ""
    local instances, length, first_dword_of_parameter_block, result = {}, 0.0, 0x02040000 + key_length * 256 + digest_size_in_bytes
    for j = 1, 4 do
        local bytes_compressed, tail, H_lo, H_hi = 0.0, "", {unpack(sha2_H_lo)}, not HEX64 and {unpack(sha2_H_hi)}
        instances[j] = {bytes_compressed, tail, H_lo, H_hi}
        H_lo[1] = XORA5(H_lo[1], first_dword_of_parameter_block)
        H_lo[2] = XORA5(H_lo[2], j-1)
        H_lo[3] = XORA5(H_lo[3], 0x4000)
        if salt ~= "" then
          xor_blake2_salt(salt, "b", H_lo, H_hi)
        end
    end

    local function partial(message_part)
        if message_part then
          if instances then
              local from = 0
              while true do
                local to = math_min(from + 128 - length % 128, #message_part)
                if to > from then
                    local inst = instances[floor(length / 128) % 4 + 1]
                    local part = sub(message_part, from + 1, to)
                    length, from = length + to - from, to
                    local bytes_compressed, tail = inst[1], inst[2]
                    if #tail < 128 then
                      tail = tail..part
                    else
                      local H_lo, H_hi = inst[3], inst[4]
                      bytes_compressed = blake2b_feed_128(H_lo, H_hi, tail, 0, 128, bytes_compressed)
                      tail = part
                    end
                    inst[1], inst[2] = bytes_compressed, tail
                else
                    break
                end
              end
              return partial
          else
              error("Adding more chunks is not allowed after receiving the result", 2)
          end
        else
          if instances then
              local root_H_lo, root_H_hi = {unpack(sha2_H_lo)}, not HEX64 and {unpack(sha2_H_hi)}
              root_H_lo[1] = XORA5(root_H_lo[1], first_dword_of_parameter_block)
              root_H_lo[3] = XORA5(root_H_lo[3], 0x4001)
              if salt ~= "" then
                xor_blake2_salt(salt, "b", root_H_lo, root_H_hi)
              end
              for j = 1, 4 do
                local inst = instances[j]
                local bytes_compressed, tail, H_lo, H_hi = inst[1], inst[2], inst[3], inst[4]
                blake2b_feed_128(H_lo, H_hi, tail..string_rep("\0", 128 - #tail), 0, 128, bytes_compressed, #tail, j == 4)
                if j % 2 == 0 then
                    local index = 0
                    for k = j - 1, j do
                      local inst = instances[k]
                      local H_lo, H_hi = inst[3], inst[4]
                      for i = 1, 8 do
                          index = index + 1
                          common_W_blake2b[index] = H_lo[i]
                          if H_hi then
                            index = index + 1
                            common_W_blake2b[index] = H_hi[i]
                          end
                      end
                    end
                    blake2b_feed_128(root_H_lo, root_H_hi, nil, 0, 128, 128 * (j/2 - 1), j == 4 and 128, j == 4)
                end
              end
              instances = nil
              local max_reg = ceil(digest_size_in_bytes / 8)
              if HEX64 then
                for j = 1, max_reg do
                    root_H_lo[j] = HEX64(root_H_lo[j])
                end
              else
                for j = 1, max_reg do
                    root_H_lo[j] = HEX(root_H_hi[j])..HEX(root_H_lo[j])
                end
              end
              result = sub(gsub(concat(root_H_lo, "", 1, max_reg), "(..)(..)(..)(..)(..)(..)(..)(..)", "%8%7%6%5%4%3%2%1"), 1, digest_size_in_bytes * 2)
          end
          return result
        end
    end

    if key_length > 0 then
        key = key..string_rep("\0", 128 - key_length)
        for j = 1, 4 do
          partial(key)
        end
    end
    if message then
        -- Actually perform calculations and return the BLAKE2bp digest of a message
        return partial(message)()
    else
        -- Return function for chunk-by-chunk loading
        -- User should feed every chunk of input data as single argument to this function and finally get BLAKE2bp digest by invoking this function without an argument
        return partial
    end

  end

  local function blake2x(inner_func, inner_func_letter, common_W_blake2, block_size, digest_size_in_bytes, message, key, salt)
    local XOF_digest_length_limit, XOF_digest_length, chunk_by_chunk_output = 2^(block_size / 2) - 1
    if digest_size_in_bytes == -1 then  -- infinite digest
        digest_size_in_bytes = math_huge
        XOF_digest_length = floor(XOF_digest_length_limit)
        chunk_by_chunk_output = true
    else
        if digest_size_in_bytes < 0 then
          digest_size_in_bytes = -1.0 * digest_size_in_bytes
          chunk_by_chunk_output = true
        end
        XOF_digest_length = floor(digest_size_in_bytes)
        if XOF_digest_length >= XOF_digest_length_limit then
          error("Requested digest is too long.  BLAKE2X"..inner_func_letter.." finite digest is limited by (2^"..floor(block_size / 2)..")-2 bytes.  Hint: you can generate infinite digest.", 2)
        end
    end
    salt = salt or ""
    if salt ~= "" then
        xor_blake2_salt(salt, inner_func_letter)  -- don't xor, only check the size of salt
    end
    local inner_partial = inner_func(nil, key, salt, nil, XOF_digest_length)
    local result

    local function partial(message_part)
        if message_part then
          if inner_partial then
              inner_partial(message_part)
              return partial
          else
              error("Adding more chunks is not allowed after receiving the result", 2)
          end
        else
          if inner_partial then
              local half_W, half_W_size = inner_partial()
              half_W_size, inner_partial = half_W_size or 8

              local function get_hash_block(block_no)
                -- block_no = 0...(2^32-1)
                local size = math_min(block_size, digest_size_in_bytes - block_no * block_size)
                if size <= 0 then
                    return ""
                end
                for j = 1, half_W_size do
                    common_W_blake2[j] = half_W[j]
                end
                for j = half_W_size + 1, 2 * half_W_size do
                    common_W_blake2[j] = 0
                end
                return inner_func(nil, nil, salt, size, XOF_digest_length, floor(block_no))
              end

              local hash = {}
              if chunk_by_chunk_output then
                local pos, period, cached_block_no, cached_block = 0, block_size * 2^32

                local function get_next_part_of_digest(arg1, arg2)
                    if arg1 == "seek" then
                      -- Usage #1:  get_next_part_of_digest("seek", new_pos)
                      pos = arg2 % period
                    else
                      -- Usage #2:  hex_string = get_next_part_of_digest(size)
                      local size, index = arg1 or 1, 0
                      while size > 0 do
                          local block_offset = pos % block_size
                          local block_no = (pos - block_offset) / block_size
                          local part_size = math_min(size, block_size - block_offset)
                          if cached_block_no ~= block_no then
                            cached_block_no = block_no
                            cached_block = get_hash_block(block_no)
                          end
                          index = index + 1
                          hash[index] = sub(cached_block, block_offset * 2 + 1, (block_offset + part_size) * 2)
                          size = size - part_size
                          pos = (pos + part_size) % period
                      end
                      return concat(hash, "", 1, index)
                    end
                end

                result = get_next_part_of_digest
              else
                for j = 1.0, ceil(digest_size_in_bytes / block_size) do
                    hash[j] = get_hash_block(j - 1.0)
                end
                result = concat(hash)
              end
          end
          return result
        end
    end

    if message then
        -- Actually perform calculations and return the BLAKE2X digest of a message
        return partial(message)()
    else
        -- Return function for chunk-by-chunk loading
        -- User should feed every chunk of input data as single argument to this function and finally get BLAKE2X digest by invoking this function without an argument
        return partial
    end
  end

  local function blake2xs(digest_size_in_bytes, message, key, salt)
    -- digest_size_in_bytes:
    --    0..65534       = get finite digest as single Lua string
    --    (-1)           = get infinite digest in "chunk-by-chunk" output mode
    --    (-2)..(-65534) = get finite digest in "chunk-by-chunk" output mode
    -- message:  binary string to be hashed (or nil for "chunk-by-chunk" input mode)
    -- key:      (optional) binary string up to 32 bytes, by default empty string
    -- salt:     (optional) binary string up to 16 bytes, by default empty string
    return blake2x(blake2s, "s", common_W_blake2s, 32, digest_size_in_bytes, message, key, salt)
  end

  local function blake2xb(digest_size_in_bytes, message, key, salt)
    -- digest_size_in_bytes:
    --    0..4294967294       = get finite digest as single Lua string
    --    (-1)                = get infinite digest in "chunk-by-chunk" output mode
    --    (-2)..(-4294967294) = get finite digest in "chunk-by-chunk" output mode
    -- message:  binary string to be hashed (or nil for "chunk-by-chunk" input mode)
    -- key:      (optional) binary string up to 64 bytes, by default empty string
    -- salt:     (optional) binary string up to 32 bytes, by default empty string
    return blake2x(blake2b, "b", common_W_blake2b, 64, digest_size_in_bytes, message, key, salt)
  end

  local function blake3(message, key, digest_size_in_bytes, message_flags, K, return_array)
    -- message:  binary string to be hashed (or nil for "chunk-by-chunk" input mode)
    -- key:      (optional) binary string up to 32 bytes, by default empty string
    -- digest_size_in_bytes: (optional) by default 32
    --    0,1,2,3,4,...  = get finite digest as single Lua string
    --    (-1)           = get infinite digest in "chunk-by-chunk" output mode
    --    -2,-3,-4,...   = get finite digest in "chunk-by-chunk" output mode
    -- The last three parameters "message_flags", "K" and "return_array" are for internal use only, user must omit them (or pass nil)
    key = key or ""
    digest_size_in_bytes = digest_size_in_bytes or 32
    message_flags = message_flags or 0
    if key == "" then
        K = K or sha2_H_hi
    else
        local key_length = #key
        if key_length > 32 then
          error("BLAKE3 key length must not exceed 32 bytes", 2)
        end
        key = key..string_rep("\0", 32 - key_length)
        K = {}
        for j = 1, 8 do
          local a, b, c, d = byte(key, 4*j-3, 4*j)
          K[j] = ((d * 256 + c) * 256 + b) * 256 + a
        end
        message_flags = message_flags + 16  -- flag:KEYED_HASH
    end
    local tail, H, chunk_index, blocks_in_chunk, stack_size, stack = "", {}, 0, 0, 0, {}
    local final_H_in, final_block_length, chunk_by_chunk_output, result, wide_output = K
    local final_compression_flags = 3      -- flags:CHUNK_START,CHUNK_END

    local function feed_blocks(str, offs, size)
        -- size >= 0, size is multiple of 64
        while size > 0 do
          local part_size_in_blocks, block_flags, H_in = 1, 0, H
          if blocks_in_chunk == 0 then
              block_flags = 1               -- flag:CHUNK_START
              H_in, final_H_in = K, H
              final_compression_flags = 2   -- flag:CHUNK_END
          elseif blocks_in_chunk == 15 then
              block_flags = 2               -- flag:CHUNK_END
              final_compression_flags = 3   -- flags:CHUNK_START,CHUNK_END
              final_H_in = K
          else
              part_size_in_blocks = math_min(size / 64, 15 - blocks_in_chunk)
          end
          local part_size = part_size_in_blocks * 64
          blake3_feed_64(str, offs, part_size, message_flags + block_flags, chunk_index, H_in, H)
          offs, size = offs + part_size, size - part_size
          blocks_in_chunk = (blocks_in_chunk + part_size_in_blocks) % 16
          if blocks_in_chunk == 0 then
              -- completing the currect chunk
              chunk_index = chunk_index + 1.0
              local divider = 2.0
              while chunk_index % divider == 0 do
                divider = divider * 2.0
                stack_size = stack_size - 8
                for j = 1, 8 do
                    common_W_blake2s[j] = stack[stack_size + j]
                end
                for j = 1, 8 do
                    common_W_blake2s[j + 8] = H[j]
                end
                blake3_feed_64(nil, 0, 64, message_flags + 4, 0, K, H)  -- flag:PARENT
              end
              for j = 1, 8 do
                stack[stack_size + j] = H[j]
              end
              stack_size = stack_size + 8
          end
        end
    end

    local function get_hash_block(block_no)
        local size = math_min(64, digest_size_in_bytes - block_no * 64)
        if block_no < 0 or size <= 0 then
          return ""
        end
        if chunk_by_chunk_output then
          for j = 1, 16 do
              common_W_blake2s[j] = stack[j + 16]
          end
        end
        blake3_feed_64(nil, 0, 64, final_compression_flags, block_no, final_H_in, stack, wide_output, final_block_length)
        if return_array then
          return stack
        end
        local max_reg = ceil(size / 4)
        for j = 1, max_reg do
          stack[j] = HEX(stack[j])
        end
        return sub(gsub(concat(stack, "", 1, max_reg), "(..)(..)(..)(..)", "%4%3%2%1"), 1, size * 2)
    end

    local function partial(message_part)
        if message_part then
          if tail then
              local offs = 0
              if tail ~= "" and #tail + #message_part > 64 then
                offs = 64 - #tail
                feed_blocks(tail..sub(message_part, 1, offs), 0, 64)
                tail = ""
              end
              local size = #message_part - offs
              local size_tail = size > 0 and (size - 1) % 64 + 1 or 0
              feed_blocks(message_part, offs, size - size_tail)
              tail = tail..sub(message_part, #message_part + 1 - size_tail)
              return partial
          else
              error("Adding more chunks is not allowed after receiving the result", 2)
          end
        else
          if tail then
              final_block_length = #tail
              tail = tail..string_rep("\0", 64 - #tail)
              if common_W_blake2s[0] then
                for j = 1, 16 do
                    local a, b, c, d = byte(tail, 4*j-3, 4*j)
                    common_W_blake2s[j] = OR(SHL(d, 24), SHL(c, 16), SHL(b, 8), a)
                end
              else
                for j = 1, 16 do
                    local a, b, c, d = byte(tail, 4*j-3, 4*j)
                    common_W_blake2s[j] = ((d * 256 + c) * 256 + b) * 256 + a
                end
              end
              tail = nil
              for stack_size = stack_size - 8, 0, -8 do
                blake3_feed_64(nil, 0, 64, message_flags + final_compression_flags, chunk_index, final_H_in, H, nil, final_block_length)
                chunk_index, final_block_length, final_H_in, final_compression_flags = 0, 64, K, 4  -- flag:PARENT
                for j = 1, 8 do
                    common_W_blake2s[j] = stack[stack_size + j]
                end
                for j = 1, 8 do
                    common_W_blake2s[j + 8] = H[j]
                end
              end
              final_compression_flags = message_flags + final_compression_flags + 8  -- flag:ROOT
              if digest_size_in_bytes < 0 then
                if digest_size_in_bytes == -1 then  -- infinite digest
                    digest_size_in_bytes = math_huge
                else
                    digest_size_in_bytes = -1.0 * digest_size_in_bytes
                end
                chunk_by_chunk_output = true
                for j = 1, 16 do
                    stack[j + 16] = common_W_blake2s[j]
                end
              end
              digest_size_in_bytes = math_min(2^53, digest_size_in_bytes)
              wide_output = digest_size_in_bytes > 32
              if chunk_by_chunk_output then
                local pos, cached_block_no, cached_block = 0.0

                local function get_next_part_of_digest(arg1, arg2)
                    if arg1 == "seek" then
                      -- Usage #1:  get_next_part_of_digest("seek", new_pos)
                      pos = arg2 * 1.0
                    else
                      -- Usage #2:  hex_string = get_next_part_of_digest(size)
                      local size, index = arg1 or 1, 32
                      while size > 0 do
                          local block_offset = pos % 64
                          local block_no = (pos - block_offset) / 64
                          local part_size = math_min(size, 64 - block_offset)
                          if cached_block_no ~= block_no then
                            cached_block_no = block_no
                            cached_block = get_hash_block(block_no)
                          end
                          index = index + 1
                          stack[index] = sub(cached_block, block_offset * 2 + 1, (block_offset + part_size) * 2)
                          size = size - part_size
                          pos = pos + part_size
                      end
                      return concat(stack, "", 33, index)
                    end
                end

                result = get_next_part_of_digest
              elseif digest_size_in_bytes <= 64 then
                result = get_hash_block(0)
              else
                local last_block_no = ceil(digest_size_in_bytes / 64) - 1
                for block_no = 0.0, last_block_no do
                    stack[33 + block_no] = get_hash_block(block_no)
                end
                result = concat(stack, "", 33, 33 + last_block_no)
              end
          end
          return result
        end
    end

    if message then
        -- Actually perform calculations and return the BLAKE3 digest of a message
        return partial(message)()
    else
        -- Return function for chunk-by-chunk loading
        -- User should feed every chunk of input data as single argument to this function and finally get BLAKE3 digest by invoking this function without an argument
        return partial
    end
  end

  local function blake3_derive_key(key_material, context_string, derived_key_size_in_bytes)
    -- key_material: (string) your source of entropy to derive a key from (for example, it can be a master password)
    --               set to nil for feeding the key material in "chunk-by-chunk" input mode
    -- context_string: (string) unique description of the derived key
    -- digest_size_in_bytes: (optional) by default 32
    --    0,1,2,3,4,...  = get finite derived key as single Lua string
    --    (-1)           = get infinite derived key in "chunk-by-chunk" output mode
    --    -2,-3,-4,...   = get finite derived key in "chunk-by-chunk" output mode
    if type(context_string) ~= "string" then
        error("'context_string' parameter must be a Lua string", 2)
    end
    local K = blake3(context_string, nil, nil, 32, nil, true)           -- flag:DERIVE_KEY_CONTEXT
    return blake3(key_material, nil, derived_key_size_in_bytes, 64, K)  -- flag:DERIVE_KEY_MATERIAL
  end

  local sha = {
    md5        = function(message) return md5(message) end,
    sha1       = function(message) return sha1(message) end,
    -- SHA-2 hash functions:
    sha224     = function(message) return sha256ext(224, message) end,
    sha256     = function(message) return sha256ext(256, message) end,
    sha512     = function(message) return sha512ext(512, message) end,
    sha512_224 = function(message) return sha512ext(224, message) end,
    sha512_256 = function(message) return sha512ext(256, message) end,
    sha384     = function(message) return sha512ext(384, message) end,
    -- SHA-3 hash functions:
    sha3_224   = function(message) return keccak((1600 - 2 * 224) / 8, 224 / 8, false, message) end,
    sha3_256   = function(message) return keccak((1600 - 2 * 256) / 8, 256 / 8, false, message) end,
    sha3_384   = function(message) return keccak((1600 - 2 * 384) / 8, 384 / 8, false, message) end,
    sha3_512   = function(message) return keccak((1600 - 2 * 512) / 8, 512 / 8, false, message) end,
    shake128   = function(message, digest_size_in_bytes) return keccak((1600 - 2 * 128) / 8, (digest_size_in_bytes or 32), true, message) end,
    shake256   = function(message, digest_size_in_bytes) return keccak((1600 - 2 * 256) / 8, (digest_size_in_bytes or 64), true, message) end,
    hmac       = function(hash_func, message, key) return hmac(hash_func, key, message) end,
    -- misc utilities:
    hex2bin  = function(hex_string) return hex_to_bin(hex_string) end,
    bin2hex  = function(bin_string) return bin_to_hex(bin_string) end,
    bin2base = function(binary_string) return bin_to_base64(binary_string) end,
    base2bin = function(base64_string) return base64_to_bin(base64_string) end,
    -- BLAKE2 hash functions:
    blake2s    = function(message, key, salt) return blake2s(message, key, salt, 32) end,
    blake2b    = function(message, key, salt) return blake2b(message, key, salt, 64) end,
    blake2sp   = function(message, key, salt) return blake2sp(message, key, salt, 32) end,
    blake2bp   = function(message, key, salt) return blake2bp(message, key, salt, 64) end,
    blake2xb   = function(message, key, salt) return blake2xb(512, message, key, salt) end,
    blake2xs   = function(message, key, salt) return blake2xs(512, message, key, salt) end,
    -- BLAKE3 hash function
    blake3 = function(message, key) return blake3(message, key, 512) end,
  }


  block_size_for_HMAC = {
    [sha.md5]        =  64,
    [sha.sha1]       =  64,
    [sha.sha224]     =  64,
    [sha.sha256]     =  64,
    [sha.sha512_224] = 128,
    [sha.sha512_256] = 128,
    [sha.sha384]     = 128,
    [sha.sha512]     = 128,
    [sha.sha3_224]   = 144,  -- (1600 - 2 * 224) / 8
    [sha.sha3_256]   = 136,  -- (1600 - 2 * 256) / 8
    [sha.sha3_384]   = 104,  -- (1600 - 2 * 384) / 8
    [sha.sha3_512]   =  72,  -- (1600 - 2 * 512) / 8
  }

--------------------------------------------------------------------------------
-- BENCHMARK
--------------------------------------------------------------------------------

local part = ("\165"):rep(2^7 * 3^2 * 13 * 17)   -- 254592 = least common multiple of all SHA functions' block lengths
-- local number_of_measures = 1   -- number of measures for each SHA function (set to 1 if you're in a hurry)
local measure_duration = 3.0   -- one measure would take about 3 sec (don't reduce this value)

local function to3digit(x)
   local n = math.floor(math.log(2*x)/math.log(10))
   x = x / 10^n
   -- Now: x in the range (0.5)...(5.0)
   local four_digits = math.floor(x * 1000 + 0.5)
   return math.floor(four_digits / 1000).."."..tostring(four_digits):sub(-3).."*10^"..n
end

local function benchmark(hash_func, number_of_measures)
   local N = 0.5
   local function measure()
      local tm = os.clock()
      local x = hash_func()
      for j = 1, N do
         x(part)
      end
      local result = x()
      return os.clock() - tm, result
   end
   local seconds_passed
   repeat
      N = N * 2
      seconds_passed = measure()
   until seconds_passed > measure_duration / 10
   local N_calc = math.max(1, math.floor(N * measure_duration / seconds_passed + 0.5))
   if N_calc ~= N then
      N, seconds_passed = N_calc
   end
   local bytes_hashed = 1.0 * #part * N
   for j = 1, number_of_measures do
      seconds_passed = seconds_passed or measure()
      local bytes_per_secods = bytes_hashed / seconds_passed
      -- print('CPU seconds to hash 1 GByte:   '..math.floor(0.5 + 2^30 / bytes_per_secods * 100) / 100)
      print('Hashing speed (Bytes per Second):   '..to3digit(bytes_per_secods))
      seconds_passed = nil
   end
end

local function run_benchpress(number_of_measures, algorithms)
  local number_of_measures = tonumber(number_of_measures) and number_of_measures or 5

  if number_of_measures <= 0 then
    number_of_measures = 1
  end
  print(number_of_measures)
  local algorithms = type(algorithms) == "table" and algorithms or {
      "blake2b", "blake2bp", "blake2s", "blake2sp", "blake2xb",
      "blake2xs", "blake3", "md5", "sha1", "sha224", "sha256",
      "sha3_224", "sha3_256", "sha3_384", "sha3_512", "sha384",
      "sha512_224", "sha512_256", "sha512", "shake128", "shake256"
    }

  if algorithm then
    for a = 1, #algorithms do
      print(algorithms[a])
      print()
      print(algo:gsub("_", "-"):upper())
      benchmark(sha[algorithms[a]], number_of_measures)
    end
  end
end


minetest.register_chatcommand("shaman", {
  description = "test shash",
  params = "<algorithm|dump|bench> [message]",
  privs = {server = true},
  func = function(name, params)
    local algorithm = params:gsub("^([%S]+)%s*(.*)$", function(algorithm, message)

      if sha[algorithm] then
        print("'"..(message).."' > "..algorithm..":"..sha[algorithm](message))
        
      elseif algorithm == "dump" then
        print("Dumping available hashes on string: '"..(message).."'")
        for algo in pairs(sha) do
          if algo then
            print(algo..":"..sha[algo](message))
          end
        end

      elseif string.match(algorithm, "bench") then
        run_benchpress(message) -- number or reps

      else
        minetest.chat_send_player(name, "Hash Algorithm: '"..algorithm.."' not found.")
      end
    end)
  end
})
