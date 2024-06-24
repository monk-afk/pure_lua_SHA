-- test
dofile("salt.lua")
local message = arg[1] or "test message"
local key     = arg[2] or "test key"
local salt  = generate_salt(16)

local msg_salt = message..salt
local msg_pad = pad_string(msg_salt)

local blake2 = dofile("blake2.lua")
for k,_ in pairs(blake2) do
  print(k, blake2[k](message, key, salt), "\n")
end

local blake3 = dofile("blake3.lua")
for bits = 1, 64 do
  local bits = bits * 8
  print("blake3 "..bits, blake3(message..salt, key, bits), "\n")
end

local sha2 = dofile("sha256.lua")
for k,_ in pairs(sha2) do
  print(k, sha2[k](message..salt), "\n")
end

local sha5 = dofile("sha512.lua")
for k,_ in pairs(sha5) do
  print(k, sha5[k](message..salt), "\n")
end

print("Random Salt:", salt)
print("Salted Message:", msg_salt)
print("Padded Message:", msg_pad)


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