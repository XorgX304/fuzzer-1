import sys
f = open("list2.txt", "r")
i=0
for x in f:
  x = x[:-1]
  sys.stdout.write("vuln.bp_addresses["+str(i)+"]=0x"+x+";\n") 
  sys.stdout.flush()
  i=i+1

