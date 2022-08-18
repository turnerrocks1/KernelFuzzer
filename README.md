# fukkkkern
fukkkkernfuzzer is a Hybrid fuzzer between a smart fuzzer schematics and a majority dumb fuzzer.
The smart side of the fuzzer is the "logic" ~*which isn't 100% correct"*~.
The logic behind this fuzzer is it'll save corpus files "aka sample codes it the fuzzer sends to the kernel.
*That is yet to come* ~easy to implement
*Check code coverage normally you can do this by having a debug kernel or kernel that have san coverage* but that would recquire building
your own kernel which that isn't the aim of this project it's supposed to be noob friendlt :)*
*Maybe their is someway to hook console.app and filter for kernel messages to see what we are actually feeding to "kexts"?*
*That feature is yet to come as well*
*This works by using P0 code of finding the "type" number to open a IOKit service and going through the registry list and whichever number returns
successful is that "kexts" type number*
*My version of the fuzzer was inspired by one of the P0's members random bit flipper ConnectCallMethod fuzzer ~though I did alter majority of there stuff~*
*Once we have "kext" name and correct type number we pass it to the dumb fuzzer and the fuzzer connect to it sending "Interesting Int's" as arguments to the scalar method, and or scalar method struct*
This version aka version #2 was made overnight and it extremely sloppy and messy code...
I did have a version #3 which was near perfection and revised and not messy anymore but while running this fuzzer it burnt out my cpu and I had to send it to apple so they can fix it... Brand new M1 MacBook at that so please note to run this at your own risk... 
To follow up behind that I honestly don't know how this code burnt out my cpu but maybe it's because i implemented a "race condition" type setup to test for race condition's in the kernel in version #3 I think I created 2 or 3 threads to run the same code repeatedly in the kernel in hope's to "cause a crash / find a bug" looking back at it now I don't know how I would narrow down a corpus for a race condition case because whose not to say a crash isn't from a regular function call or rather from the "race condition kernel template itself?"

With that being said i'll have to redownload this version and clean it and rewrite it again because somehow I had version #3 flawlessly and I also implemented the ConnectCallAsyncMethod which was easy to do. 

The only bugs I found with version #2 was a DOS case which the fuzzer caused back to back after 3 reboots on macOS 12.3.1 haven't ranned it since apple forcefully updated my macbook to 12.5 during repair :(. The DOS case will be put in the showcase folder in this github repo if anybody interested in looking and seeing what it is or to double check to make sure I didn't overlook anything :).

Features:
If you wan't me to add features or implement new ideas please open an issue on this repo and i'll respond rather quickly :)
