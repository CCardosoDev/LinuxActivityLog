from xml.dom.minidom import Document, parse

doc = parse("../../../commandsLog.xml")

print doc.toprettyxml("    ", "    \n")
