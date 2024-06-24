function hex_to_bin(hex_string)
  return (gsub(hex_string, "%x%x",
    function (hh)
      return char(tonumber(hh, 16))
    end
  ))
end

function bin_to_hex(binary_string)
  return (gsub(binary_string, ".",
    function (c)
      return string_format("%02x", byte(c))
    end
  ))
end

local base64_symbols = {
  ['+'] = 62, ['-'] = 62, [62] = '+',
  ['/'] = 63, ['_'] = 63, [63] = '/',
  ['='] = -1, ['.'] = -1, [-1] = '='
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

function bin_to_base64(binary_string)
  local result = {}
  for pos = 1, #binary_string, 3 do
    local c1, c2, c3, c4 = byte(sub(binary_string, pos, pos + 2)..'\0', 1, -1)
    result[#result + 1] =
      base64_symbols[floor(c1 / 4)]
      ..base64_symbols[c1 % 4 * 16 + floor(c2 / 16)]
      ..base64_symbols[c3 and c2 % 16 * 4 + floor(c3 / 64) or -1]
      ..base64_symbols[c4 and c3 % 64 or -1]
  end
  return table_concat(result)
end

function base64_to_bin(base64_string)
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
  return table_concat(result)
end