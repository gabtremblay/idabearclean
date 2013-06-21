# Renesas M16C IDA function discovery tool
#
#
__author__ = 'Gabriel'
import idc
import idautils


def search_functions():
    # For each segment
    for segment in idautils.Segments():
        # For each byte in the address range of the segment
        for byte_addr in range(segment, idc.SegEnd(segment)):
            # Fetch byte
            dis_text = idc.GetDisasm(byte_addr)
            peekahead_dis_text = idc.GetDisasm(byte_addr + 1)
            if "7Ch" in dis_text and "0F2h" in peekahead_dis_text:
                idc.MakeCode(byte_addr)
                idc.MakeFunction(byte_addr)

    print "End of file reached"


def search_strings():
    pass

# Start with functions
search_functions()
search_strings()