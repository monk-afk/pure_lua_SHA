local concat = table.concat
local byte = string.byte
local string_rep = string.rep
local sub = string.sub
local gsub = string.gsub
local string_format = string.format
local floor = math.floor
local ceil = math.ceil
local math_min = math.min
local math_max = math.max

local AND_of_two_bytes = {[0] = 0}
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

local function XOR(x, y, z, t, u)
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

HEX = HEX or pcall(string_format, "%x", 2^31) and function(x)
    return string_format("%08x", x % 4294967296)
  end

local function XORA5(x, y)
  return XOR(x, y or 0xA5A5A5A5) % 4294967296
end

local sha2_K_lo, sha2_K_hi, sha2_H_lo, sha2_H_hi, sha3_RC_lo, sha3_RC_hi = {}, {}, {}, {}, {}, {}
local sha2_H_ext256 = {[224] = {}, [256] = sha2_H_hi}
local sha2_H_ext512_lo, sha2_H_ext512_hi = {[384] = {}, [512] = sha2_H_lo}, {[384] = {}, [512] = sha2_H_hi}
local common_W = {}
local common_W_blake2s = common_W
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
    local result, carry, value, weight = {}, 0.0, 0.0, 1.0
    for j = 1, result_length do
    for k = math_max(1, j + 1 - #src2), math_min(j, #src1) do
      carry = carry + factor * src1[k] * src2[j + 1 - k]
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
    if d*d > p then
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


local function blake3(message, key, digest_size_in_bytes, message_flags, K, return_array)
  -- message:  binary string to be hashed (or nil for "chunk-by-chunk" input mode)
  -- key:    (optional) binary string up to 32 bytes, by default empty string
  -- digest_size_in_bytes: (optional) by default 32
  --  0,1,2,3,4,...  = get finite digest as single Lua string
  --  (-1)       = get infinite digest in "chunk-by-chunk" output mode
  --  -2,-3,-4,...   = get finite digest in "chunk-by-chunk" output mode
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
  local final_compression_flags = 3    -- flags:CHUNK_START,CHUNK_END

  local function feed_blocks(str, offs, size)
    -- size >= 0, size is multiple of 64
    while size > 0 do
    local part_size_in_blocks, block_flags, H_in = 1, 0, H
    if blocks_in_chunk == 0 then
      block_flags = 1         -- flag:CHUNK_START
      H_in, final_H_in = K, H
      final_compression_flags = 2   -- flag:CHUNK_END
    elseif blocks_in_chunk == 15 then
      block_flags = 2         -- flag:CHUNK_END
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


return blake3





------------------------------------------------------------------------------------
-- MIT License                                                                    --
--                                                                                --
-- Copyright (c) 2018-2022  Egor Skriptunoff                                      --
--                                                                                --
-- Permission is hereby granted, free of charge, to any person obtaining a copy   --
-- of this software and associated documentation files (the "Software"), to deal  --
-- in the Software without restriction, including without limitation the rights   --
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      --
-- copies of the Software, and to permit persons to whom the Software is          --
-- furnished to do so, subject to the following conditions:                       --
--                                                                                --
-- The above copyright notice and this permission notice shall be included in all --
-- copies or substantial portions of the Software.                                --
--                                                                                --
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     --
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       --
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE    --
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         --
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  --
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  --
-- SOFTWARE.                                                                      --
------------------------------------------------------------------------------------