import understand

# Open Database
db = understand.open("/home/nimashiri/test.udb")

for ent in sorted(db.ents(),key= lambda ent: ent.name()):
  print (ent.name(),"  [",ent.kindname(),"]",sep="",end="\n")