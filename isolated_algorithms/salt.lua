-- generate salt for hashing
local gsub = string.gsub
local byte = string.byte
local sfmt = string.format
local char = string.char
local srep = string.rep

local rand = function()
  math.randomseed(os.time() * os.clock())
  return math.random(33,126)
end

function generate_salt(length)
  length = length or 16
  local salt = {}
  for i = 1, length do
    salt[i] = char(rand())
  end
  return table.concat(salt)
end

function pad_string(str)
  local original_len = #str
  local pad = 64-(original_len + 1 + 8) % 64

  local function len_to_8byte(len)
    local result = ""
    len = len * 8
    for i = 1, 8 do
      local rem = len % 256
      result = char(rem) .. result
      len = (len - rem) / 256
    end
    return result
  end

  str = str .."0".. srep("0", pad) .. len_to_8byte(original_len)
  assert(#str % 64 == 0)
  return str
end

return generate_salt, pad_string


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