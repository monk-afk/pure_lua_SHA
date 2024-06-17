pur_lua_SHA
---

SHA-1, SHA-2, SHA-3, BLAKE2 and BLAKE3 functions written in pure Lua and optimized for speed.

Adapted for use in Minetest.

___

### Usage

To encrypt a string from chat command:

`/shaman algorithm message` ex: `/shaman sha256 test`  hashes the string with algorithm.

`/shaman dump test` will iterate and print all the hash from the sha table. 

`/shaman bench 3` will benchmark 3 reps the sha table (not completely tested)

All but two hash types have been tested, hmac and blake3_derive_key.

Tested on 5.9-dev Minetest, and 5.4 Minetest(multicraft)

___

### Description

**Minetest output hashes found at the [end of this document](#test-hash)!**

This module provides functions to calculate SHA digest.  
This is a pure-Lua module, compatible with **Lua 5.1**, **Lua 5.2**, **Lua 5.3**, **Lua 5.4**, **LuaJIT 2.0/2.1** and **Fengari**.

Main feature of this module: it was heavily optimized for speed.  
For every Lua version the module contains particular implementation branch to get benefits from version-specific features.

Supported hashes:
```lua
MD5            - sha.md5(message)
SHA-1          - sha.sha1(message)
-- SHA2
SHA-224        - sha.sha224(message)
SHA-256        - sha.sha256(message)
SHA-384        - sha.sha384(message)
SHA-512        - sha.sha512(message)
SHA-512/224    - sha.sha512_224(message)
SHA-512/256    - sha.sha512_256(message)
-- SHA3
SHA3-224       - sha.sha3_224(message)
SHA3-256       - sha.sha3_256(message)
SHA3-384       - sha.sha3_384(message)
SHA3-512       - sha.sha3_512(message)
SHAKE128       - sha.shake128(digest_size_in_bytes, message)
SHAKE256       - sha.shake256(digest_size_in_bytes, message)
-- HMAC (applicable to any hash function mentioned above except SHAKE)
HMAC           - sha.hmac(sha.any_hash_func, key, message)
-- BLAKE2
BLAKE2b        - sha.blake2b(message, key, salt, digest_size_in_bytes)
BLAKE2s        - sha.blake2s(message, key, salt, digest_size_in_bytes)
BLAKE2bp       - sha.blake2bp(message, key, salt, digest_size_in_bytes)
BLAKE2sp       - sha.blake2sp(message, key, salt, digest_size_in_bytes)  -- BLAKE2sp is used in WinRAR and 7-Zip
BLAKE2Xb       - sha.blake2xb(digest_size_in_bytes, message, key, salt)
BLAKE2Xs       - sha.blake2xs(digest_size_in_bytes, message, key, salt)
-- BLAKE2b synonyms for shortened digest:
BLAKE2b-160    - sha.blake2b_160(message, key, salt)  -- BLAKE2b with digest_size_in_bytes = 20
BLAKE2b-256    - sha.blake2b_256(message, key, salt)  -- BLAKE2b with digest_size_in_bytes = 32
BLAKE2b-384    - sha.blake2b_384(message, key, salt)  -- BLAKE2b with digest_size_in_bytes = 48
BLAKE2b-512    - sha.blake2b_512(message, key, salt)  -- BLAKE2b with digest_size_in_bytes = 64 (default size)
-- BLAKE2s synonyms for shortened digest:
BLAKE2s-128    - sha.blake2s_128(message, key, salt)  -- BLAKE2s with digest_size_in_bytes = 16
BLAKE2s-160    - sha.blake2s_160(message, key, salt)  -- BLAKE2s with digest_size_in_bytes = 20
BLAKE2s-224    - sha.blake2s_224(message, key, salt)  -- BLAKE2s with digest_size_in_bytes = 28
BLAKE2s-256    - sha.blake2s_256(message, key, salt)  -- BLAKE2s with digest_size_in_bytes = 32 (default size)
-- BLAKE3
BLAKE3         - sha.blake3(message, key, digest_size_in_bytes)
BLAKE3_KDF     - sha.blake3_derive_key(key_material, context_string, derived_key_size_in_bytes)
```
---
### Usage

Input data should be provided as a binary string: either as a whole string or as a sequence of substrings ("chunk-by-chunk" loading).  
Result (SHA digest) is returned in hexadecimal representation (as a string of lowercase hex digits).  

Simplest usage example:
```lua
local sha = require("sha2")
local your_hash = sha.sha256("your string")
-- assert(your_hash == "d14d691dac70eada14d9f23ef80091bca1c75cf77cf1cd5cf2d04180ca0d9911")
```
See file "sha2_test.lua" for more examples.

---
### FAQ
---
#### :large_blue_circle: Does this module calculate SHA really fast?
Probably, this is the fastest pure Lua implementation of SHA you can find.  
For example, on x64 Lua 5.3 this module calculates SHA256 twice as fast as the implementation published at [lua-users.org](http://lua-users.org/wiki/SecureHashAlgorithmBw)  
This module has best performance on every Lua version because it contains several version-specific implementation branches:  
   - branch for **Lua 5.1** (emulating bitwise operators using look-up table)
   - branch for **Lua 5.2** (using **bit32** library), suitable also for **Lua 5.1** with external **bit** library
   - branch for **Lua 5.3 / 5.4** (using native **64**-bit bitwise operators)
   - branch for **Lua 5.3 / 5.4** (using native **32**-bit bitwise operators) for Lua built with `LUA_INT_TYPE=LUA_INT_INT`
   - branch for **LuaJIT without FFI library** (if you're working in a sandboxed environment with FFI disabled)
   - branch for **LuaJIT x86 without FFI library** (LuaJIT x86 has oddity because of lack of x86 CPU registers)
   - branch for **LuaJIT 2.0 with FFI library** (`bit.*` functions work only with 32-bit values)
   - branch for **LuaJIT 2.1 with FFI library** (`bit.*` functions can work with `int64_t` cdata)
---
#### :large_blue_circle: How to get SHA digest as binary string instead of hexadecimal representation?
Use function `sha.hex_to_bin()` to convert hexadecimal to binary:
```lua
local sha = require("sha2")
local binary_hash = sha.hex_to_bin(sha.sha256("your string"))
-- assert(binary_hash == "\209Mi\29\172p\234\218\20\217\242>\248\0\145\188\161\199\\\247|\241\205\\\242\208A\128\202\r\153\17")
```
---
#### :large_blue_circle: How to get SHA digest as base64 string?
There are functions `sha.bin_to_base64()` and `sha.base64_to_bin()` for converting between binary and base64:
```lua
local sha = require("sha2")
local binary_hash = sha.hex_to_bin(sha.sha256("your string"))
local base64_hash = sha.bin_to_base64(binary_hash)
-- assert(base64_hash == "0U1pHaxw6toU2fI++ACRvKHHXPd88c1c8tBBgMoNmRE=")
```
---
#### :large_blue_circle: How to calculate SHA digest of long data stream?
It is not necessary to prepare the whole data stream as single Lua string.  
All hash functions implemented in this module switch to "chunk-by-chunk" input mode when `message` parameter is `nil`:
```lua
local sha = require("sha2")
local append = sha.sha256()  -- if the "message" argument is omitted then "append" function is returned
append("your")
append(" st")                -- you should pass all parts of your long message to the "append" function (chunk-by-chunk)
append("ring")
local your_hash = append()   -- and finally ask for the result (by invoking the "append" function without argument)
-- assert(your_hash == "d14d691dac70eada14d9f23ef80091bca1c75cf77cf1cd5cf2d04180ca0d9911")
```
---
#### :large_blue_circle: Is it possible to calculate multiple hash digests of the same file by reading the file only once?
Yes.  
Each calculation instance uses its own private variables, so you can run multiple calculations in parallel:
```lua
local sha = require("sha2")
local append1 = sha.sha256()  -- create calculation instance #1
local append2 = sha.sha512()  -- create calculation instance #2
local file = io.open("path/to/your/file", "rb")
for message_part in function() return file:read(4096) end do  -- "file:lines(4096)" is shorter but incompatible with Lua 5.1
   append1(message_part)
   append2(message_part)
end
file:close()
local file_sha256 = append1()
local file_sha512 = append2()
```
---
#### :large_blue_circle: How to calculate HMAC-SHA1, HMAC-SHA256, etc. ?
The `key` parameter of HMAC function is a binary string of any length.
```lua
-- Calculating HMAC-SHA1
local sha = require("sha2")
local your_hmac = sha.hmac(sha.sha1, "your key", "your message")
-- assert(your_hmac == "317d0dfd868a5c06c9444ac1328aa3e2bfd29fb2")
```
The same in "chunk-by-chunk" input mode (for long messages):
```lua
local sha = require("sha2")
local append = sha.hmac(sha.sha1, "your key")
append("your")
append(" message")
local your_hmac = append()
-- assert(your_hmac == "317d0dfd868a5c06c9444ac1328aa3e2bfd29fb2")
```
---
#### :large_blue_circle: How to calculate MAC based on BLAKE2?
BLAKE2 supports keying out-of-the-box, additional function like HMAC is not required for BLAKE2 functions.  
The `key` parameter in BLAKE2 functions is a binary string, its length is limited by:
- 64 bytes for BLAKE2b/BLAKE2bp/BLAKE2Xb
- 32 bytes for BLAKE2s/BLAKE2sp/BLAKE2Xs

If the `key` parameter set to empty string, BLAKE2 function is calculated key-less (as if `key` parameter was omitted).
```lua
local sha = require("sha2")
local your_mac = sha.blake2b("your message", "your key")
-- assert(your_mac == "feee3e3aac7d5a3a4653fb70667ad6fb5fafe5256c78867b421eb0ce4134fc62784002b261056c4ef4222e99a8944826dff6f4845ac0117df128de116b159d75")
```
The same in "chunk-by-chunk" input mode (for long messages):
```lua
local sha = require("sha2")
local append = sha.blake2b(nil, "your key")
append("your")
append(" message")
local your_mac = append()
-- assert(your_mac == "feee3e3aac7d5a3a4653fb70667ad6fb5fafe5256c78867b421eb0ce4134fc62784002b261056c4ef4222e99a8944826dff6f4845ac0117df128de116b159d75")
```
---
#### :large_blue_circle: Can SHAKE128 / SHAKE256 be used to generate digest of infinite length?
Yes!  
For example, you can convert your password into infinite stream of pseudo-random bytes.  
Set `digest_size_in_bytes` to magic value `-1` and obtain the function `get_next_part(part_size_in_bytes)`.  
Invoke this function repeatedly to get consecutive parts of the infinite digest.
```lua
local sha = require("sha2")
local get_next_part_of_digest = sha.shake128(-1, "The quick brown fox jumps over the lazy dog")
assert(get_next_part_of_digest(5) == "f4202e3c58") -- 5 bytes in hexadecimal representation
assert(get_next_part_of_digest()  == "52")         -- size=1 is assumed when omitted
assert(get_next_part_of_digest(0) == "")           -- size=0 is a valid size
assert(get_next_part_of_digest(4) == "f9182a04")   -- and so on to the infinity...
-- Note: you can use sha.hex_to_bin() to convert these hexadecimal parts to binary strings
-- By definition, the result of SHAKE with finite "digest_size_in_bytes" is just a finite prefix of "infinite digest":
assert(sha.shake128(4, "The quick brown fox jumps over the lazy dog")) == "f4202e3c")
```
It's possible to combine "chunk-by-chunk" input mode with "chunk-by-chunk" output mode:
```lua
local sha = require("sha2")
local append_input_message = sha.shake128(-1)
append_input_message("The quick brown fox")
append_input_message(" jumps over the lazy dog")
local get_next_part_of_digest = append_input_message()  -- input stream is terminated, now we can start receiving the output stream
assert(get_next_part_of_digest(5) == "f4202e3c58")
assert(get_next_part_of_digest(5) == "52f9182a04")      -- and so on...
```
Please note that you can NOT get the bytes at some arbitrary position of the SHAKE digest without calculating all previous bytes.

---
#### :large_blue_circle: Are BLAKE2bp / BLAKE2sp just a multithread-friendly implementations of BLAKE2b / BLAKE2s?
No.  They are different hash functions.  
For example, `sha.blake2s("message")` and `sha.blake2sp("message")` return different hashes.

---
#### :large_blue_circle: Why does each BLAKE2 function have `digest_size_in_bytes` parameter?
For SHA2 family of hash functions, if you want to get a shorter digest, you calculate the full-size digest and truncate it to the size you want.  
For BLAKE2 family of hash functions, the situation is different.  
By default the digest size is:  
   - 64 for BLAKE2b and BLAKE2bp (512 bits)
   - 32 for BLAKE2s and BLAKE2sp (256 bits)

If you need a shorter digest, specify the size in `digest_size_in_bytes` parameter.  
Please note that the shorter result will NOT match the prefix of the full-length digest for the same message.  
This happens because in BLAKE2 family of hash functions different `digest_size_in_bytes` values produce different hash functions.

If you need a longer digest, use BLAKE2Xb or BLAKE2Xs to produce digest of arbitrary size.

---
#### :large_blue_circle: How to use BLAKE2X functions?
X means XOF = "extensible output function".  
Internally BLAKE2Xb/BLAKE2Xs invokes its inner function (BLAKE2b for BLAKE2Xb, BLAKE2s for BLAKE2Xs) to get fixed size hash, and then extends the hash to arbitrary size.  
The full name of a BLAKE2X function includes the digest length in bytes, for example, BLAKE2Xs132 produces 1056-bit digests.  
Usage example:
```lua
local sha = require("sha2")
-- calculate BLAKE2Xb16MiB and get the result as huge Lua string
local your_hash = sha.blake2xb(16 * 2^20, "The quick brown fox jumps over the lazy dog")
-- assert(#your_hash == 32 * 2^20 and your_hash:match"^53e2dcdfe2.*b2b5312606$")
```
Sometimes you might want to avoid creating very long Lua strings.  
Negative values of `digest_size_in_bytes` mean you want to receive the result in "chunk-by-chunk" output mode:
```lua
local sha = require("sha2")
-- calculate BLAKE2Xb16MiB and get the result in "chunk-by-chunk" output mode
local get_next_part_of_digest = sha.blake2xb(-16 * 2^20, "The quick brown fox jumps over the lazy dog")
assert(get_next_part_of_digest(5) == "53e2dcdfe2") -- 5 bytes in hexadecimal representation
assert(get_next_part_of_digest()  == "1b")         -- size=1 is assumed when omitted
assert(get_next_part_of_digest(0) == "")           -- size=0 is a valid size
assert(get_next_part_of_digest(3) == "21af5b")     -- next 3 bytes
get_next_part_of_digest(16 * 2^20 - 14)            -- read all the remaining bytes of 16MiB hash except last 5
assert(get_next_part_of_digest(5) == "b2b5312606") -- last 5 bytes of 16MiB
assert(get_next_part_of_digest(1) == "")           -- after all parts of the digest are received, empty strings are returned
```
It's possible to combine "chunk-by-chunk" input mode with "chunk-by-chunk" output mode:
```lua
local sha = require("sha2")
-- calculate BLAKE2Xb16MiB: pass message in "chunk-by-chunk" input mode and get the result in "chunk-by-chunk" output mode
local append_input_message = sha.blake2xb(-16 * 2^20)
append_input_message("The quick brown fox")
append_input_message(" jumps over the lazy dog")
local get_next_part_of_digest = append_input_message()  -- input stream is terminated, now we can start receiving the output stream
assert(get_next_part_of_digest(4) == "53e2dcdf")
assert(get_next_part_of_digest(4) == "e21b21af")        -- and so on...
```
Sometimes you don't know the digest size in advance.  
You can set `digest_size_in_bytes` to magic value `-1` to generate infinite digest.  
Please note that BLAKE2X digest of finite size will NOT match the prefix of the infinite digest for the same message.
```lua
local sha = require("sha2")
-- calculate BLAKE2XbInf (infinite digest)
local get_next_part_of_digest = sha.blake2xb(-1, "The quick brown fox jumps over the lazy dog")
assert(get_next_part_of_digest(5) == "364e84ca4c")
assert(get_next_part_of_digest(5) == "103df29230")      -- and so on to the infinity...
```
When generating BLAKE2X digest (finite or infinite) in "chunk-by-chunk" output mode, you can immediately jump to arbitrary position of the digest:
```lua
local sha = require("sha2")
-- calculate BLAKE2XbInf (infinite digest)
local get_next_part_of_digest = sha.blake2xb(-1, "The quick brown fox jumps over the lazy dog")
assert(get_next_part_of_digest(5) == "364e84ca4c")
get_next_part_of_digest("seek", 10*2^30)  -- jump to position 10GiB of the digest without calculating all previous bytes
assert(get_next_part_of_digest(5) == "eeafce070f")
get_next_part_of_digest("seek", 0)        -- jump to the beginning of the digest
assert(get_next_part_of_digest(5) == "364e84ca4c")
get_next_part_of_digest("seek", 1)        -- jump to the second byte of the digest
assert(get_next_part_of_digest(5) == "4e84ca4c10")
```
Please note that BLAKE2Xb / BLAKE2Xs are not continuations of BLAKE2b / BLAKE2s.  
For example, `sha.blake2xb(64, "message")` is not the same as `sha.blake2b("message")`

---
#### :large_blue_circle: How to create digests of arbitrary size with BLAKE3?
By default the digest size of BLAKE3 is 32 bytes (256 bits).  
Unlike BLAKE2 family of separate functions for short (BLAKE2b) and long (BLAKE2Xb) digests, BLAKE3 is an "all-in-one" function.  
You can produce BLAKE3 digest of arbitrary size by passing the size as `digest_size_in_bytes` argument.  
Similar to BLAKE2, you can specify positive digest size, negative digest size or magic number `-1`.  
Similar to BLAKE2, you can jump to arbitrary position in the digest.  
Unlike BLAKE2, a shorter BLAKE3 digest is always a prefix of a longer digest for the same message.

---
#### :large_blue_circle: Is the SHAKE / BLAKE2X / BLAKE3 "infinite digest" obtained by `digest_size_in_bytes = -1` really infinite ?
For SHAKE functions, the "infinite digest" is really infinite.  
You can NOT fast forward to arbitrary position without calculating all previous bytes of the digest.

For BLAKE2X functions, the "infinite digest" is NOT infinite, it is periodic with a large period: 256GiB for BLAKE2Xb and 128GiB for BLAKE2Xs.  
You can fast forward to arbitrary position.  
Please note that `get_next_part_of_digest("seek", 256*2^30)` is equivalent to `get_next_part_of_digest("seek", 0)` due to periodicity.

For BLAKE3 function, the "infinite digest" is NOT infinite, it is periodic with a huge period: `2^70` bytes.  
This implementation is able to produce only the first `2^53` bytes of this period.  
You can fast forward to arbitrary position, but you will receive empty strings instead of hexadecimal digest for positions beyond `2^53`.

---
#### :large_blue_circle: What is the `salt` parameter in all BLAKE2 functions?
`salt` is a binary string, different `salt` values generate different hash functions.  
By default empty string is used as a `salt`.

`salt` is useful when you need to create multiple hash functions which don't collide with each other.  
Let's imagine you want to have 10 different hash functions similar to SHA-256.  
You can define them as salted BLAKE2:
```lua
for i = 1, 10 do
   local salt = "salt"..i
   H[i] = function (message, key)
      return sha.blake2b_256(message, key, salt)
   end
end
```
Collisions are practically impossible: if `i1 ~= i2` then `H[i1](message1) ~= H[i2](message2)`.  
In other words, you can safely store hash values of all 10 functions as keys inside a common table.

To implement salt for other hash functions (like SHA-256) you usually have to append salt string to a message, but BLAKE2 implements salt more efficiently.

According to the BLAKE2 documentation, "Salt" field length is limited by:
- 16 bytes for BLAKE2b/BLAKE2bp/BLAKE2Xb
- 8 bytes for BLAKE2s/BLAKE2sp/BLAKE2Xs

If `salt` parameter is shorter, it is right-padded with zero bytes and stored in "Salt" field of the BLAKE2 Parameter Block.  
If `salt` parameter is longer, this implementation does not raise an error, instead it sends extra bytes to "Personalization" field.  
"Personalization" is actually "just another salt" field in BLAKE2 Parameter Block, "Personalization" field has the same length as "Salt" field.  
In other words, BLAKE2 functions implemented in this module expect `salt` parameter to hold a concatenation of "Salt"+"Personalization" fields, so maximal length of `salt` parameter is limited by:
- 32 bytes for BLAKE2b/BLAKE2bp/BLAKE2Xb
- 16 bytes for BLAKE2s/BLAKE2sp/BLAKE2Xs

---
#### :large_blue_circle: There are two methods of BLAKE2 hash function customization: adding `key` and adding `salt`.  What is the difference?
Processing the `key` is significantly more expensive (in terms of CPU load) than processing the `salt`.  
Adding `key` is equivalent to prepending a whole block of data (128 bytes for BLAKE2b, 64 bytes for BLAKE2s) to the message, hashing this additional block is a lot of extra CPU work.  
Adding `salt` is equivalent to modifying initialization vectors with the salt string, this is just a few XOR operations.  
Usually `key` is used for secret strings and `salt` for non-secret strings.  
One might guess that `key` is somehow more securely protected than `salt`, but actually `salt` can also store secret strings (very similar hash function BLAKE3 processes its `key` exactly the same non-expensive way as `salt` is processed in BLAKE2).

---
#### :large_blue_circle: BLAKE3 does not have `salt` parameter.  How to use salted BLAKE3?
If you want to add salt to key-less BLAKE3, just pass your salt instead of `key`.  
If you want to add salt to keyed BLAKE3, see the next question.

---
#### :large_blue_circle: I can personalize keyed BLAKE2 function by providing both `salt` and `key` arguments simultaneously. How to personalize keyed BLAKE3?
Derive personalized key and pass it to BLAKE3.
```lua
-----------------------------------------------------------------
-- A personalized keyed hash function constructor using BLAKE2
-----------------------------------------------------------------
local function create_personalized_keyed_hash_function(key, personalization_string, digest_size_in_bytes)
   return function (message)
      -- pass the personalization string to BLAKE2
      return sha.blake2b(message, key, personalization_string, digest_size_in_bytes)
   end
end

-----------------------------------------------------------------
-- The same constructor using BLAKE3
-----------------------------------------------------------------
local function create_personalized_keyed_hash_function(key, personalization_string, digest_size_in_bytes)
   -- create personalized 256-bit key
   local derived_key = sha.hex_to_bin(sha.blake3_derive_key(key, personalization_string))
   return function (message)
      -- pass the personalized key to BLAKE3
      return sha.blake3(message, derived_key, digest_size_in_bytes)
   end
end

-----------------------------------------------------------------
-- Usage example for the constructor
-----------------------------------------------------------------
local password = "password"
-- create two different 160-bit hash functions depending on the same password
local H1 = create_personalized_keyed_hash_function(password, "personalization string 1", 20)
local H2 = create_personalized_keyed_hash_function(password, "personalization string 2", 20)
-- use them
local hash1 = H1("message")
local hash2 = H2("message")
```
---
#### :large_blue_circle: Why deriving keys?
There are two reasons:
- Derived keys have an important security benefit: if the "context string" (a.k.a "personalization string") is globally unique then leaking this derived key does not leak information about other keys derived from the same key material.  
- You might need to convert long and sparse entropy source (a.k.a "key material") into a fixed-size key.  Deriving a key is one of possible ways to make such conversion.

---
#### :large_blue_circle: How to use function `blake3_derive_key`?
The `key_material` parameter must be either a Lua string (of any length) or a sequence of substrings (switch to "chunk-by-chunk" input mode by passing `nil` as `key_material`).  
The `context_string` parameter must be a Lua string (of any length), it is recommended to use globally unique string literal (to make sure it does not depend on malicious user input).  
By default `derived_key_size_in_bytes` is 32, but you can derive key of arbitrary size: you can pass a positive value, a negative value or magic value `-1` as `derived_key_size_in_bytes`.  A note: "infinite derived key" is limited by `2^53` bytes.  
You probably would want to convert hexadecimal output of `blake3_derive_key` to binary Lua string, because all hash functions implemented in this module expect their `key` parameter to be a binary string of limited size.

---
#### :large_blue_circle: I need a secure hash function in my Lua script.  Which one is the fastest?
MD5 and SHA-1 are not secure (collisions are known), so six competitors remain: SHA-256, BLAKE2s, BLAKE3, SHA-512, BLAKE2b, SHA3-256.  
(The first three internally use 32-bit words, the last three - 64-bit words.)  
If these hash functions implemented in C, the fastest one will be BLAKE3 because it benefits from SIMD instructions in modern CPUs.  
But in Lua we can not tell the compiler to use SIMD instructions, so the winner is different.

| Lua version      | The fastest        | 2nd                 | 3rd                 | 4th                 |
| ---------------- | ------------------ | ------------------- | ------------------- | ------------------- |
| Lua 5.1          | BLAKE3  (0.5 MB/s) | BLAKE2s  (0.4 MB/s) | BLAKE2b  (0.3 MB/s) | SHA256  (0.2 MB/s)  |
| Lua 5.2          | BLAKE3  (3.1 MB/s) | BLAKE2s  (2.4 MB/s) | BLAKE2b  (1.6 MB/s) | SHA256  (1.5 MB/s)  |
| Lua 5.4          | BLAKE2b  (18 MB/s) | BLAKE3  (11 MB/s)   | BLAKE2s  (10 MB/s)  | SHA512  (8 MB/s)    |
| LuaJIT sandboxed | SHA256  (140 MB/s) | BLAKE3  (130 MB/s)  | BLAKE2s  (100 MB/s) | SHA3-256  (33 MB/s) |
| LuaJIT + FFI     | BLAKE3  (300 MB/s) | BLAKE2s  (260 MB/s) | SHA512  (220 MB/s)  | BLAKE2b  (220 MB/s) |

---
#### :large_blue_circle: I need a hash function for hashing user passwords.  Which one should I use?
Strictly speaking, you should NOT use a general-purpose hash functions for hashing passwords in a serious application, instead you should use Argon2 or the like.  
But probably your Lua script does not have a lot of RAM for a good password hashing algorithm.  
So, as a workaround, you can calculate salted BLAKE3 thousands of times:
```lua
local sha = require("sha2")
local function hash_user_password(user_id, user_name, user_password)
   local user_salt = (tostring(user_id).."\0"..user_name):sub(1, 32)
   local f = sha.blake3
   local hash = user_password
   for i = 1, 10000 do  -- tune the repeat count to get about 0.1 second of CPU work
      hash = f(hash, user_salt)
   end
   return hash  -- string of 64 hex digits
end
```
---
#### :large_blue_circle: Why does this module called "sha2.lua" despite of having implemented SHA1, SHA2, SHA3, BLAKE2 and BLAKE3?
The first release of this module contained only SHA2 functions, hence the name `sha2.lua`.  
But I can't rename the module due to backward-compatibility I've promised to keep forever (Was it a silly promise?)

---
### Backward-compatibility
This module will always keep backward-compatibility.  
If your program works successfully with some previous version of `sha2.lua`, it will also work with the latest version.

___

test hash
---

Hashes for string: `test`

========================= terminal

**base64_to_bin**:`��-`

**bin_to_base64**:`dGVzdA==`

**bin_to_hex**:`74657374`

**blake2b**:`a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572`

**blake2bp**:`ec93bfef647e0f82f040b4e81d4d7491002cb559ca3f2755881fc8d3bec1c3f182990f97ff2d3d9e5a0c5bcd77baf4d992e2f8c2e60cfd84ef5269a92b5b3f9c`

**blake2s**:`f308fc02ce9172ad02a7d75800ecfc027109bc67987ea32aba9b8dcc7b10150e`

**blake2sp**:`442287ccee7d089d2a82abdc6262557a30a472045f6b5debbfc2b48e3de7c4a9`

**blake2xb**:`facbddb22d24181a48dbad860a3f06a9f350e419b9357249c37c2b9b8004cbf3b92823bf00ad5a6181b9af8917816738a0dc63ec7217ddd6a52910e2bbd16e74339071d6875f9a1fe33ad1a2d22c91e70519ac1815644198ddaf3fa5a091838f492eba464eb739ea352438224085bb196de69939b73133b10cdb44c79bac6cfa8406e963502ff8881ce827e1b7ded2442f9fe40b0f1b44fd3c69212cc01c71dd9a768f059abc724c7fb09df3024c63c614212fb719295654fdbe57a846886147c5e9e5ad15eae2e7615262e4dc8ca1192e791b4bb10ac5f08f5cae40e4cecced817f74638182e806397e2968451ed372b95c35b31a38963844ace01a501244857692e78896d21f6b3210a95b7cd7f0584952dc683c06e829a4a52412031bbe877efd5fa8aa4237045ca4d8debc0044e40fecce1ab3c38d93c027f22b84672cdc079eafdadbcc1cdb607e555ae49d8bd0ee20f45b72c5a2ff4734c0090c77d8737c0000cc461ae667aacaf7e25cdb79980c7e0b7b7c992749b3d9355e492882167e266733e31856257a9f594581fc8f7221c8eabe879b7e367d98e56b555e44c9a9b8d9ea5b4600e04670e260ff75e2051825b1b80e1867a87006e0e667b385f08e549e742f4a934254c0db2ee6cc8bfc484565c600ef08baac67ccaa851f6af92eb8cd0a3b59f4230a752622587a2bf7373b329c65cb964a9f47ac0f813ed0c7`

**blake2xs**:`877fbc3227a32a4c370de06d29f023210b77c44be3954a252c9c3e2063a8a819522b8f8b3485e86b847bb23788075ccb9017de7b32cb256029882367ea3c94fb28814a7f866fc3faeace09469c950742c0e3ae9ec993b507c6bb957057f773866cf7d77fa2f1eb6d941d7814ae247102d1766a0eeb05a6efe777c686d7ebb16df2fa7d8d0992bf5311a62813b509b712469b0f481863e3e937d5e07fdbb93a97ca02a4bc80f7099c2eb9fda112fdebfd4b53000280a6eff4e9bccfb65a8f6d5a4eda42fc4e3be437009c5be789301756e2d6bac41c06a6d4cd3afccda4a92cd0dd45d195aa24fc72952a94cbca9036f6a13098db613b7a08d6d3d70c3294e4575c173786ed4b460ec062901247f4bf2c1f1ed75747290ffee1e0d49c1acf58b5e3d409cf23b6f73171de8927b7b4aa7d62c427f4eff61a6190f4eee245bd007969802a1dcfa7188f9e014325108367110b5ec0e813602d445a95f960b3ab8e89df346b903d4f02204271c1c99ac67bd3b74b7f05214efb644b28416046daec76abf6529bd3b14e40ff1040e1b3612f8dc7f151e760a90019477ce06112bc527f046617cbcf1069600d7e2f0e4443df010a84a8f88889148f22baa3d041578f7ca7bb0e03a81c2f38b76d343ca4b2cc43abf70e3ad8a87713c6999664466511890cb82c7a2ac369ce852de817809f276afbeac20ae6689322af44b2b9f5f15c0d`

**blake3**:`4878ca0425c739fa427f7eda20fe845f6b2e46ba5fe2a14df5b1e32f50603215`

**hex_to_bin**:`test`

**md5**:`098f6bcd4621d373cade4e832627b4f6`

**sha1**:`a94a8fe5ccb19ba61c4c0873d391e987982fbbd3`

**sha224**:`90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809`

**sha256**:`9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`

**sha3_224**:`3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b`

**sha3_256**:`36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80`

**sha3_384**:`e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd`

**sha3_512**:`9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14`

**sha384**:`768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9`

**sha512_224**:`06001bf08dfb17d2b54925116823be230e98b5c6c278303bc4909a8c`

**sha512_256**:`3d37fe58435e0d87323dee4a2c1b339ef954de63716ee79f5747f94d974f913f`

**sha512**:`ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff`

**shake128**:`d3b0aa9cd8b7255622cebc631e867d4093d6f6010191a53973c45fec9b07c774`

**shake256**:`b54ff7255705a71ee2925e4a3e30e41aed489a579d5595e0df13e32e1e4dd202a7c7f68b31d6418d9845eb4d757adda6ab189e1bb340db818e5b3bc725d992fa`


========================= minetest 5.9-dev

**base64_to_bin**:`��-`

**bin_to_base64**:`dGVzdA==`

**bin_to_hex**:`74657374`

**blake2b**:`a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572`

**blake2bp**:`ec93bfef647e0f82f040b4e81d4d7491002cb559ca3f2755881fc8d3bec1c3f182990f97ff2d3d9e5a0c5bcd77baf4d992e2f8c2e60cfd84ef5269a92b5b3f9c`

**blake2s**:`f308fc02ce9172ad02a7d75800ecfc027109bc67987ea32aba9b8dcc7b10150e`

**blake2sp**:`442287ccee7d089d2a82abdc6262557a30a472045f6b5debbfc2b48e3de7c4a9`

**blake2xb**:`facbddb22d24181a48dbad860a3f06a9f350e419b9357249c37c2b9b8004cbf3b92823bf00ad5a6181b9af8917816738a0dc63ec7217ddd6a52910e2bbd16e74339071d6875f9a1fe33ad1a2d22c91e70519ac1815644198ddaf3fa5a091838f492eba464eb739ea352438224085bb196de69939b73133b10cdb44c79bac6cfa8406e963502ff8881ce827e1b7ded2442f9fe40b0f1b44fd3c69212cc01c71dd9a768f059abc724c7fb09df3024c63c614212fb719295654fdbe57a846886147c5e9e5ad15eae2e7615262e4dc8ca1192e791b4bb10ac5f08f5cae40e4cecced817f74638182e806397e2968451ed372b95c35b31a38963844ace01a501244857692e78896d21f6b3210a95b7cd7f0584952dc683c06e829a4a52412031bbe877efd5fa8aa4237045ca4d8debc0044e40fecce1ab3c38d93c027f22b84672cdc079eafdadbcc1cdb607e555ae49d8bd0ee20f45b72c5a2ff4734c0090c77d8737c0000cc461ae667aacaf7e25cdb79980c7e0b7b7c992749b3d9355e492882167e266733e31856257a9f594581fc8f7221c8eabe879b7e367d98e56b555e44c9a9b8d9ea5b4600e04670e260ff75e2051825b1b80e1867a87006e0e667b385f08e549e742f4a934254c0db2ee6cc8bfc484565c600ef08baac67ccaa851f6af92eb8cd0a3b59f4230a752622587a2bf7373b329c65cb964a9f47ac0f813ed0c7`

**blake2xs**:`877fbc3227a32a4c370de06d29f023210b77c44be3954a252c9c3e2063a8a819522b8f8b3485e86b847bb23788075ccb9017de7b32cb256029882367ea3c94fb28814a7f866fc3faeace09469c950742c0e3ae9ec993b507c6bb957057f773866cf7d77fa2f1eb6d941d7814ae247102d1766a0eeb05a6efe777c686d7ebb16df2fa7d8d0992bf5311a62813b509b712469b0f481863e3e937d5e07fdbb93a97ca02a4bc80f7099c2eb9fda112fdebfd4b53000280a6eff4e9bccfb65a8f6d5a4eda42fc4e3be437009c5be789301756e2d6bac41c06a6d4cd3afccda4a92cd0dd45d195aa24fc72952a94cbca9036f6a13098db613b7a08d6d3d70c3294e4575c173786ed4b460ec062901247f4bf2c1f1ed75747290ffee1e0d49c1acf58b5e3d409cf23b6f73171de8927b7b4aa7d62c427f4eff61a6190f4eee245bd007969802a1dcfa7188f9e014325108367110b5ec0e813602d445a95f960b3ab8e89df346b903d4f02204271c1c99ac67bd3b74b7f05214efb644b28416046daec76abf6529bd3b14e40ff1040e1b3612f8dc7f151e760a90019477ce06112bc527f046617cbcf1069600d7e2f0e4443df010a84a8f88889148f22baa3d041578f7ca7bb0e03a81c2f38b76d343ca4b2cc43abf70e3ad8a87713c6999664466511890cb82c7a2ac369ce852de817809f276afbeac20ae6689322af44b2b9f5f15c0d`

**blake3**:`4878ca0425c739fa427f7eda20fe845f6b2e46ba5fe2a14df5b1e32f50603215`

**hex_to_bin**:`test`

**md5**:`098f6bcd4621d373cade4e832627b4f6`

**sha1**:`a94a8fe5ccb19ba61c4c0873d391e987982fbbd3`

**sha224**:`90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809`

**sha256**:`9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`

**sha3_224**:`3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b`

**sha3_256**:`36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80`

**sha3_384**:`e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd`

**sha3_512**:`9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14`

**sha384**:`768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9`

**sha512_224**:`06001bf08dfb17d2b54925116823be230e98b5c6c278303bc4909a8c`

**sha512_256**:`3d37fe58435e0d87323dee4a2c1b339ef954de63716ee79f5747f94d974f913f`

**sha512**:`ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff`

**shake128**:`d3b0aa9cd8b7255622cebc631e867d4093d6f6010191a53973c45fec9b07c774`

**shake256**:`b54ff7255705a71ee2925e4a3e30e41aed489a579d5595e0df13e32e1e4dd202a7c7f68b31d6418d9845eb4d757adda6ab189e1bb340db818e5b3bc725d992fa`


========================= multicraft(minetest 5.4)

**base64_to_bin**:`��-`

**bin_to_base64**:`dGVzdA==`

**bin_to_hex**:`74657374`

**blake2b**:`a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572`

**blake2bp**:`ec93bfef647e0f82f040b4e81d4d7491002cb559ca3f2755881fc8d3bec1c3f182990f97ff2d3d9e5a0c5bcd77baf4d992e2f8c2e60cfd84ef5269a92b5b3f9c`

**blake2s**:`f308fc02ce9172ad02a7d75800ecfc027109bc67987ea32aba9b8dcc7b10150e`

**blake2sp**:`442287ccee7d089d2a82abdc6262557a30a472045f6b5debbfc2b48e3de7c4a9`

**blake2xb**:`facbddb22d24181a48dbad860a3f06a9f350e419b9357249c37c2b9b8004cbf3b92823bf00ad5a6181b9af8917816738a0dc63ec7217ddd6a52910e2bbd16e74339071d6875f9a1fe33ad1a2d22c91e70519ac1815644198ddaf3fa5a091838f492eba464eb739ea352438224085bb196de69939b73133b10cdb44c79bac6cfa8406e963502ff8881ce827e1b7ded2442f9fe40b0f1b44fd3c69212cc01c71dd9a768f059abc724c7fb09df3024c63c614212fb719295654fdbe57a846886147c5e9e5ad15eae2e7615262e4dc8ca1192e791b4bb10ac5f08f5cae40e4cecced817f74638182e806397e2968451ed372b95c35b31a38963844ace01a501244857692e78896d21f6b3210a95b7cd7f0584952dc683c06e829a4a52412031bbe877efd5fa8aa4237045ca4d8debc0044e40fecce1ab3c38d93c027f22b84672cdc079eafdadbcc1cdb607e555ae49d8bd0ee20f45b72c5a2ff4734c0090c77d8737c0000cc461ae667aacaf7e25cdb79980c7e0b7b7c992749b3d9355e492882167e266733e31856257a9f594581fc8f7221c8eabe879b7e367d98e56b555e44c9a9b8d9ea5b4600e04670e260ff75e2051825b1b80e1867a87006e0e667b385f08e549e742f4a934254c0db2ee6cc8bfc484565c600ef08baac67ccaa851f6af92eb8cd0a3b59f4230a752622587a2bf7373b329c65cb964a9f47ac0f813ed0c7`

**blake2xs**:`877fbc3227a32a4c370de06d29f023210b77c44be3954a252c9c3e2063a8a819522b8f8b3485e86b847bb23788075ccb9017de7b32cb256029882367ea3c94fb28814a7f866fc3faeace09469c950742c0e3ae9ec993b507c6bb957057f773866cf7d77fa2f1eb6d941d7814ae247102d1766a0eeb05a6efe777c686d7ebb16df2fa7d8d0992bf5311a62813b509b712469b0f481863e3e937d5e07fdbb93a97ca02a4bc80f7099c2eb9fda112fdebfd4b53000280a6eff4e9bccfb65a8f6d5a4eda42fc4e3be437009c5be789301756e2d6bac41c06a6d4cd3afccda4a92cd0dd45d195aa24fc72952a94cbca9036f6a13098db613b7a08d6d3d70c3294e4575c173786ed4b460ec062901247f4bf2c1f1ed75747290ffee1e0d49c1acf58b5e3d409cf23b6f73171de8927b7b4aa7d62c427f4eff61a6190f4eee245bd007969802a1dcfa7188f9e014325108367110b5ec0e813602d445a95f960b3ab8e89df346b903d4f02204271c1c99ac67bd3b74b7f05214efb644b28416046daec76abf6529bd3b14e40ff1040e1b3612f8dc7f151e760a90019477ce06112bc527f046617cbcf1069600d7e2f0e4443df010a84a8f88889148f22baa3d041578f7ca7bb0e03a81c2f38b76d343ca4b2cc43abf70e3ad8a87713c6999664466511890cb82c7a2ac369ce852de817809f276afbeac20ae6689322af44b2b9f5f15c0d`

**blake3**:`4878ca0425c739fa427f7eda20fe845f6b2e46ba5fe2a14df5b1e32f50603215`

**hex_to_bin**:`test`

**md5**:`098f6bcd4621d373cade4e832627b4f6`

**sha1**:`a94a8fe5ccb19ba61c4c0873d391e987982fbbd3`

**sha224**:`90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809`

**sha256**:`9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`

**sha3_224**:`3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b`

**sha3_256**:`36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80`

**sha3_384**:`e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd`

**sha3_512**:`9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14`

**sha384**:`768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9`

**sha512_224**:`06001bf08dfb17d2b54925116823be230e98b5c6c278303bc4909a8c`

**sha512_256**:`3d37fe58435e0d87323dee4a2c1b339ef954de63716ee79f5747f94d974f913f`

**sha512**:`ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff`

**shake128**:`d3b0aa9cd8b7255622cebc631e867d4093d6f6010191a53973c45fec9b07c774`

**shake256**:`b54ff7255705a71ee2925e4a3e30e41aed489a579d5595e0df13e32e1e4dd202a7c7f68b31d6418d9845eb4d757adda6ab189e1bb340db818e5b3bc725d992fa`

