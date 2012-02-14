=============
o USE-CASES o
=============

1. pinballspy.py
++++++++++++++++
[snip]
PS C:\users\rude-boi\CODE\injektors> python.exe .\patching\pinballspy.py
[+] Obtaining pinball PID ..
[+] OK.
[+] Searching for characteristic '☺0ï►ü· ╩Ü;' signature in pinball process memory ..
[+] OK (Found signature at 0x010196BA).
[+] Attaching to pinball process ..
[+] OK.
[+] Setting bp at 0x010196BE ..
[+] OK.
[+] Starting DEBUG_EVENT loop ..
[+] Current pinball score is 2000
[+] Current pinball score is 2500
[+] Current pinball score is 3000
[+] Current pinball score is 3500
[+] Current pinball score is 4250
[+] Current pinball score is 4750
[+] Current pinball score is 5250
[+] Current pinball score is 5750
[+] Current pinball score is 6500
[+] Current pinball score is 7000
[+] Current pinball score is 7500
[+] Current pinball score is 8000
[+] Current pinball score is 8500
[+] Current pinball score is 9000
[+] Current pinball score is 9750
[+] Current pinball score is 10500
[+] Current pinball score is 11000
[+] Current pinball score is 11500
[+] Current pinball score is 13500
[+] Current pinball score is 14000
[+] Current pinball score is 14500
[+] Current pinball score is 16500
[+] Current pinball score is 18500
[+] Current pinball score is 19000
[+] Current pinball score is 21000
[+] Current pinball score is 23000
[+] Current pinball score is 23500
[+] Current pinball score is 25500
[+] Current pinball score is 27500
[+] Current pinball score is 28000
[+] Current pinball score is 28500
[+] Current pinball score is 29000
[+] Current pinball score is 29500
[+] Current pinball score is 30000
[+] Current pinball score is 30500
[+] Current pinball score is 31000
[+] Current pinball score is 31500
[+] Current pinball score is 32000
[+] Current pinball score is 32500
[+] Current pinball score is 33000
[+] Current pinball score is 33500
[+] Current pinball score is 34000
[+] Current pinball score is 34500
[+] Current pinball score is 35000
[+] Current pinball score is 35500
[+] Current pinball score is 60500
[snip]

2. find_signature.py
++++++++++++++++++++
[snip]
PS C:\users\rude-boi\CODE\injektors> python.exe .\patching\find_signature.py ..\..\Desktop\Pinball.exe 81FA00CA9A3B
Searching for signature 81FA00CA9A3B in file ..\..\Desktop\Pinball.exe ..
Found signature at 0x010196BE
