local sha = dofile("init.lua")

          for algo in pairs(sha) do
            if algo then
              print(algo..":"..sha[algo](arg[1]))
            end
          end
