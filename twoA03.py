import sys,os

sys.path.append("..//ines_mapper//")
#import "../ines_mapper/ines_mapper.py"
import ines_mapper


addressing_modes = {
    "imp":0,
    "abs":2,
    "abx":2,
    "aby":2,

    "zp":1,
    "zpx":1,
    "zpy":1,

    "acc":1,

    "imm":1,

    "rel":1,

    "ind":2,
    "izx":1,
    "izy":1
}


class opcode:
    def __init__(self,mnemonic,mode,cycle_count,add_cycle):
        self.mnemonic = mnemonic
        self.addr_mode = mode
        self.cycle_count = cycle_count
        self.add_cycle = add_cycle


    def get_arg_size(self):
        return addressing_modes[self.addr_mode]

# quick hex() formatter
def hexd(n,pad=False,pad_count=2):
    out = hex(n).replace("0x","").upper()
    if pad: return out if n > 0x1*(16**(pad_count)) else ("0"*(pad_count-len(out)))+out
    return out

def parse_opcodes_from_file(opcode_file):
    opcode_filename = os.path.split(opcode_file)[-1] 
    print(f"Loading opcodes from: {opcode_filename}")
    op_sets = dict()
    with open(opcode_file,"r") as f:
        content = f.read().split("\n\n")
        i=0
        for byte_set in content:
            if byte_set == "": continue
            i+=1
            j=0

            new_set = [] 
            opcodes = byte_set.split("\n")
            for code in opcodes:
                if code == "": continue

                # wackier hack: remove trailing spaces (like a normal person)
                code = code.replace("  ","")
                if code[-1] == " ": code = code[:-1]

                op_args = code.replace("\n","").split(" ")

                try:
                    addr_mode = "imp"
                    cycle_count = 0
                    add_cycle = False
                    cycle_count = int(op_args[1])

                except ValueError:
                    # must be 2 args (3 bytes) so args[1] is an addr_mode
                    addr_mode = op_args[1]
                    if op_args[2][-1] == "*":
                        add_cycle = True
                        cycle_count = int(op_args[2][:-1])

                    else:
                        cycle_count = int(op_args[2])


                except IndexError:
                    # must be 0 args (1 byte) so there's nothing else in args[]
                    addr_mode = "imp"
                

                op = opcode(op_args[0],addr_mode,cycle_count,add_cycle)
                    

                new_set.append(op)
                j+=1
            op_sets[hexd(i-1)] = new_set
    return op_sets




def main(bin_file):
    bin_filename = os.path.split(bin_file)[-1]
    print(f"Starting disassembly [{bin_filename}]:")
    opcode_sets = parse_opcodes_from_file("raw_opcodes.txt")

    with open(bin_file,"rb") as f:
        data = f.read()

    #print(data)

    i=0
    #for i in range(len(data))
    cnt=0
    for _ in data:
        #print(i,cnt)
        if i > cnt:
            cnt += 1
            continue
        byte = data[i]
        byte = hexd(data[i])
        if data[i] < 0x10: byte = "0"+byte
        opcode_set_id = byte[0]
        opcode_id = byte[1]
 
        try:
            op = opcode_sets[opcode_set_id][int(opcode_id,16)]
        except:
            op = opcode("???","imp",0,False)

        arg_size = op.get_arg_size()
        args = []

        if arg_size > 0:
            arg_start = i+1
            arg_end = max(arg_start,arg_start+arg_size)
            args = data[arg_start:arg_end]

        print(hexd(i,pad=True,pad_count=4),end=" "*2)
        print(byte+"".join([hexd(b,pad=True) for b in args[::-1]]),end="\t")
        print(op.mnemonic, end="  ")
        for byte in args[::-1]:
            print(hexd(byte,pad=True),end=" ")

        """if arg_size != 0:
            if op.addr_mode == "imm":
                print("$#"+hexd(data[i+arg_size-1],pad=True),end=" ")
            else:
                for j in range(arg_size,0,-1):
                    try:
                        print(hexd(data[i+j],pad=True),end=" ")
                    except IndexError:
                        print("\nAccess Violation: ",i+j)
        """



        """for j in range(arg_size,0,-1):
            try:
                print(hexd(data[i+j],pad=True),end=" ")
            except IndexError:
                print(i,j,i+j,len(data))"""
        print()

        i += arg_size + 1
        cnt += 1       

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} [bin_file]")
        exit()

    bin_file = sys.argv[1]
    if not os.path.exists(bin_file):
        print(f"Error: bin file doesn't exist")
        exit()

    main(bin_file)

