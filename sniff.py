import sys
from scapy.all import *

if __name__ == "__main__":
	print("This isn't the main file, you shouldn't be running this")
	sys.exit(0)


class Sniffer:
	def __init__(self):
		self.instruction_seperator = " "
		self.value_seperator = ":"
		self.sniff_values = []
		self.sniff_attributes = ["IPv4", "IPv6", "MAC", "FilterIP", "BlackList"]
		init_values()
	
	def init_values(self):
		# These are the default settings of the program
		# IPv4
		self.sniff_values[self.sniff_attributes[0]] = True
	
	def validate_format(self, inp_format):
		
		if inp_format == "default":
			return True
		
		intstructions = inp_format.split(self.instruction_seperator)
		
		for instruction in instructions:
			
			instruction_parts = instruction.split(self.value_seperator)
			
			if not len(intruction_parts) == 2:
				return False
			
	
	def set_value(self, attribute, value):
		pass
