from processing import *

test_string = "test"
my_bytes = test_string.encode('utf-8')  

if(sha256(my_bytes) == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"):
    print("working")
else:
    print("not working")