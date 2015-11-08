from xml.dom.minidom import Document, parse

doc = parse("../../../authorizedUsers.xml")

print doc.toprettyxml("    ", "    \n")
