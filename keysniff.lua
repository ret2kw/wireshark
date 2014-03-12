--[[
Tshark USB KeySniffer -- This has only been tested with tshark on Ubuntu
 
Short howto for using this script:
 
1.) Find device in the lsusb output:
 
    $ lusb
    ...
    Bus 003 Device 003: ID 0040:073d  
    ...

2.) Ensure that the usbmon driver is loaded
 
    $ sudo modprobe usbmon
 
3.) Allow non-root access to your device's bus usbmon node:
 
    $ sudo chmod 644 /dev/usbmon3

    !!!WARNING!!!

    THIS WILL ALLOW NON-ROOT THE ABILITY TO SNIFF THE USB BUS

    !!!WARNING!!!

 
4.) Run tshark against the usb interface or against a packet capture:
 
    $ tshark -i usbmon3 -X lua_script:keysniff.lua
    $ tshark -X lua_script:keysniff.lua -r capture.pcap 
 
--]]


do 

    print("Wireshark KeySniffer")
    print("====================\n")    

    --checking operating system, package.config stores the directory seperator, '\\' is Windows
    if package.config:sub(1, 1) == "\\" then
        print("[*] Warning USB Capture on Windows requires USBCap")
        print("[*] This script will still work against a packet capture")
    
    elseif package.config:sub(1, 1) == "/" then
        --lets check that usbmon is enabled using lsmod
        local h = io.popen("lsmod")
        local hresult = h:read("*a")
    
        if string.find(hresult, "usbmon") == nil then
            print("[*] Warning, looks like usbmon isn't loaded, Live Capture won't work")
            print("[*] Load by running \"modprobe usbmon\"\n")
        end
    end

    --we want to capture usb data for each packet
    local usbdata = Field.new("usb.capdata")

    --the listener function, will create our tap
    local function init_listener()
        print("[*] Starting Sniffing...\n")  
  
        --only listen for usb packets
        local tap = Listener.new("usb")

        --called for every packet meeting the filter set for the Listener(), so usb packets
        function tap.packet(pinfo, tvb)

            --list from http://www.usb.org/developers/devclass_docs/Hut1_11.pdf
            local keys = "????abcdefghijklmnopqrstuvwxyz1234567890\n??\t -=[]\\?;??,./"
            --get the usb.capdata
            local data = usbdata()

            --make sure the packet actually has a usb.capdata field
            if data ~= nil then
                local keycodes = {}
                local i = 0

                --match on everything that is a hex byte %x and add it to the table
                --this works b/c data is in format %x:%x:%x:%x
                --it is effectively pythons split(':') function
                for v in string.gmatch(tostring(data), "%x+") do
                    i = i + 1
                    keycodes[i] = v
                end

                --make sure we got a keypress, which is the 3rd value 
                --this works on a table b/c we are using int key values
                if #keycodes < 3 then
                    return
                end
                
                --convert the hex key to decimal
                local code = tonumber(keycodes[3], 16) + 1
                --get the right key mapping
                local key = keys:sub(code, code)

                --as long as it isn't '?' lets print it to stdout
                if key ~= '?' then
                    io.write(key)
                    io.flush()                                        
                end
            end
        end
        
        --this is called when capture is reset
        function tap.reset()
            print("[*] Done Capturing")
        end

        --function called at the end of tshark run
        function tap.draw()
            print("\n\n[*] Done Processing")
        end
    end

    init_listener()

end
