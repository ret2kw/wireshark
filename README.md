wireshark
=========

wireshark scripts written using the [Lua API] (http://wiki.wireshark.org/Lua)


###keysniff###
This script uses usbmon (or usbpcap on windows) to act as a keylogger of sorts. Currently it doesn't take into account long presses so records multiple keypresses. Just needs some tweaking.


###login delta###
Uhhhhh yeah...so I had a weird requirement where I wanted to record how long it takes for a computer to process GPOs (which are pulled down over SMB/CIFS). So this script times how long it takes between a GPO being 'opened' and 'closed'. Mainly here for reference for some more advanced scripting, albiet useless and ugly ;) 
