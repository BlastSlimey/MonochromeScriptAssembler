
from os import PathLike
from enum import Enum


def get_file_as_bytes(f: PathLike | str) -> bytes:
    with open(f, "rb") as infile:
        base_rom_bytes = bytes(infile.read())
    return base_rom_bytes


def get_text_file(f: PathLike | str) -> str:
    with open(f, "rt") as infile:
        text = infile.read()
    return text


def get_text_file_lines(f: PathLike | str) -> list[str]:
    with open(f, "rt") as infile:
        text = infile.readlines()
    return text


debug_active = False
print_disassembly = False


def see_write(out, s, end="\n"):
    if print_disassembly:
        print(s, end=end)
    print(s, end=end, file=out)


def debug(s):
    if debug_active:
        print(s)


class ByteType(Enum):
    UNKNOWN = 0
    IGNORE = 1
    RAW = 2
    COMMAND_HEADER = 3
    COMMAND_TAIL = 4
    ACTION_HEADER = 5
    ACTION_TAIL = 6


def disassemble(f: PathLike | str, dest: PathLike | str):
    data = get_file_as_bytes(f)
    command_text = get_text_file_lines("commands.txt")
    action_text = get_text_file_lines("actions.txt")
    commands = {}
    actions = {}
    for line in command_text:
        c = line.split()
        commands[int(c[0], 16)] = c
        debug(f"Registered command {c}")
    for line in action_text:
        a = line.split()
        actions[int(a[0], 16)] = a
        debug(f"Registered action {a}")
    pointer = 0
    scripts = []
    while data[pointer:pointer+2] != b'\x13\xfd':
        if pointer in scripts:
            break
        scr_addr = 4 + pointer + int.from_bytes(data[pointer:pointer+4], "little")
        scripts.append(scr_addr)
        pointer += 4
        debug(f"Registered script {pointer//4-1} with address {scr_addr}")

    # structure analysis
    structure: list[ByteType] = [ByteType.UNKNOWN] * len(data)
    links: dict[int, str] = {}

    def fill_raw_action(addr: int, shift: int):
        debug(f"{'  '*shift}Filling raw action at {addr}")
        match structure[addr]:
            case ByteType.COMMAND_HEADER:
                structure[addr : addr + 4] = [ByteType.RAW] * 4
                down_command = int.from_bytes(data[addr:addr+2], "little")
                down_params_len = sum(int(par[0]) for par in commands[down_command][2:])
                structure[addr : addr + down_params_len + 2] = [ByteType.RAW] * (down_params_len+2)
            case ByteType.COMMAND_TAIL:
                down_addr = addr - 1
                while structure[down_addr] == ByteType.COMMAND_TAIL:
                    down_addr -= 1
                down_command = int.from_bytes(data[down_addr:down_addr+2], "little")
                down_params_len = sum(int(par[0]) for par in commands[down_command][2:])
                structure[down_addr : down_addr + down_params_len + 2] = [ByteType.RAW] * (down_params_len+2)
            case ByteType.ACTION_TAIL:
                down_addr = addr - 1
                while structure[down_addr] == ByteType.ACTION_TAIL:
                    down_addr -= 1
                structure[down_addr : down_addr + 4] = [ByteType.RAW] * 4
        structure[addr] = ByteType.RAW
        for next_addr in range(1, 4):
            match structure[next_addr]:
                case ByteType.COMMAND_HEADER:
                    down_command = int.from_bytes(data[next_addr:next_addr+2], "little")
                    down_params_len = sum(int(par[0]) for par in commands[down_command][2:])
                    structure[next_addr : next_addr + down_params_len + 2] = [ByteType.RAW] * (down_params_len+2)
                case ByteType.ACTION_HEADER:
                    structure[next_addr: next_addr + 4] = [ByteType.RAW] * 4
            structure[next_addr] = ByteType.RAW

    def fill_raw_command(addr: int, params_len: int, shift: int):
        debug(f"{'  '*shift}Filling raw command at {addr}")
        match structure[addr]:
            case ByteType.COMMAND_TAIL:
                down_addr = addr - 1
                while structure[down_addr] == ByteType.COMMAND_TAIL:
                    down_addr -= 1
                down_command = int.from_bytes(data[down_addr:down_addr+2], "little")
                down_params_len = sum(int(par[0]) for par in commands[down_command][2:])
                structure[down_addr:down_addr+down_params_len+2] = [ByteType.RAW] * (down_params_len+2)
            case ByteType.ACTION_HEADER:
                structure[addr:addr+4] = [ByteType.RAW] * 4
            case ByteType.ACTION_TAIL:
                down_addr = addr - 1
                while structure[down_addr] == ByteType.ACTION_TAIL:
                    down_addr -= 1
                structure[down_addr:down_addr+4] = [ByteType.RAW] * 4
        structure[addr] = ByteType.RAW
        for next_addr in range(addr+1, addr+params_len+2):
            match structure[next_addr]:
                case ByteType.COMMAND_HEADER:
                    down_command = int.from_bytes(data[next_addr:next_addr+2], "little")
                    down_params_len = sum(int(par[0]) for par in commands[down_command][2:])
                    structure[next_addr:next_addr+down_params_len+2] = [ByteType.RAW] * (down_params_len+2)
                case ByteType.ACTION_HEADER:
                    structure[next_addr:next_addr+4] = [ByteType.RAW] * 4
            structure[next_addr] = ByteType.RAW

    def walk_action(addr: int, shift: int):
        debug(f"{'  '*shift}Walk action at {addr}")
        while addr < len(data):
            if structure[addr] == ByteType.ACTION_HEADER:
                debug(f"{'  '*shift}Walk action found header at {addr}")
                return
            action = int.from_bytes(data[addr:addr+2], "little")
            if structure[addr] in (ByteType.RAW, ByteType.COMMAND_HEADER, ByteType.COMMAND_TAIL, ByteType.ACTION_TAIL):
                fill_raw_action(addr, shift)
            else:  # only UNKNOWN at this point
                for param_addr in range(addr+1, addr+4):
                    if structure[param_addr] in (ByteType.RAW, ByteType.COMMAND_HEADER, ByteType.ACTION_HEADER):
                        fill_raw_action(addr, shift)
                        break
            if structure[addr] == ByteType.UNKNOWN:
                structure[addr] = ByteType.ACTION_HEADER
                structure[addr+1:addr+4] = [ByteType.ACTION_TAIL] * 3
            if action == 0xfe:
                debug(f"{'  '*shift}EndAction at {addr}")
                return
            addr += 4

    def walk_command(addr: int, shift: int):
        try:
            debug(f"{'  '*shift}Walk command at {addr}")
            while addr < len(data):
                if structure[addr] == ByteType.COMMAND_HEADER:
                    debug(f"{'  '*shift}Walk command found header at {addr}")
                    return
                command = int.from_bytes(data[addr:addr+2], "little")
                params = commands[command][2:]
                params_len = sum(int(par[0]) for par in params)
                if structure[addr] in (ByteType.RAW, ByteType.COMMAND_TAIL, ByteType.ACTION_HEADER, ByteType.ACTION_TAIL):
                    fill_raw_command(addr, params_len, shift)
                else:  # only UNKNOWN at this point
                    for param_addr in range(addr+1, addr+params_len+2):
                        if structure[param_addr] in (ByteType.RAW, ByteType.COMMAND_HEADER, ByteType.ACTION_HEADER):
                            fill_raw_command(addr, params_len, shift)
                            break
                if structure[addr] == ByteType.UNKNOWN:
                    structure[addr] = ByteType.COMMAND_HEADER
                    structure[addr+1:addr+params_len+2] = [ByteType.COMMAND_TAIL] * (params_len+1)
                match command:
                    case 2:  # if vmhalt, return
                        debug(f"{'  '*shift}VMHalt at {addr}")
                        return
                    case 4:  # if vmcall, branch and add link
                        link_addr = addr + 2 + params_len + int.from_bytes(data[addr+2:addr+6], "little")
                        link_addr %= 0x100000000
                        if link_addr not in links:
                            links[link_addr] = f"sub{len(links)}"
                        debug(f"{'  '*shift}VMCall at {addr} to {link_addr}")
                        walk_command(link_addr, shift+1)
                    case 5:  # if vmreturn, return
                        debug(f"{'  '*shift}VMReturn at {addr}")
                        return
                    case 0x1e:  # if vmjump, jump and add link
                        link_addr = addr + 2 + params_len + int.from_bytes(data[addr+2:addr+6], "little")
                        link_addr %= 0x100000000
                        if link_addr not in links:
                            links[link_addr] = f"lbl{script_num}-{len(links)}"
                        debug(f"{'  '*shift}VMJump at {addr} to {link_addr}")
                        addr = link_addr
                        continue
                    case 0x1f:  # if vmjumpif, branch and add link
                        link_addr = addr + 2 + params_len + int.from_bytes(data[addr+3:addr+7], "little")
                        link_addr %= 0x100000000
                        if link_addr not in links:
                            links[link_addr] = f"lbl{script_num}-{len(links)}"
                        debug(f"{'  '*shift}VMJumpIf at {addr} to {link_addr}")
                        walk_command(link_addr, shift+1)
                    case 0x20:  # if vmcallif, branch and add link
                        link_addr = addr + 2 + params_len + int.from_bytes(data[addr+3:addr+7], "little")
                        link_addr %= 0x100000000
                        if link_addr not in links:
                            links[link_addr] = f"sub{len(links)}"
                        debug(f"{'  '*shift}VMCallIf at {addr} to {link_addr}")
                        walk_command(link_addr, shift+1)
                    case 0x64:  # if actorcmdexec, branch action and add link
                        link_addr = addr + 2 + params_len + int.from_bytes(data[addr+4:addr+8], "little")
                        link_addr %= 0x100000000
                        if link_addr not in links:
                            links[link_addr] = f"act{script_num}-{len(links)}"
                        debug(f"{'  '*shift}ActorCmdExec at {addr} to {link_addr}")
                        walk_action(link_addr, shift+1)
                    case 0x8c:  # if CallTrainerLose, return
                        debug(f"{'  '*shift}CallTrainerLose at {addr}")
                        return
                    case 0x17a:  # if CallWildLose, return
                        debug(f"{'  '*shift}CallWildLose at {addr}")
                        return
                addr += params_len + 2
        except Exception as e:
            raise Exception(e.args, f"Address {addr}")

    script_num = 0
    for script_addr in scripts:
        if script_addr not in links:
            links[script_addr] = f"scr{script_num}"
            debug(f"Registered link scr{script_num}")
        script_num += 1
        walk_command(script_addr, 1)

    pointer = len(scripts) * 4 + 2
    while pointer < len(data):
        if structure[pointer] != ByteType.UNKNOWN:
            pointer += 1
            continue
        search = pointer + 1
        zero = data[pointer] == 0
        while search < len(data) and structure[search] == ByteType.UNKNOWN:
            if data[search] != 0:
                zero = False
            search += 1
        if search >= len(data):
            structure[pointer:] = [ByteType.RAW] * (len(data) - pointer)
        elif structure[search] == ByteType.ACTION_HEADER and zero and search - pointer < 4:
            structure[pointer:search] = [ByteType.IGNORE] * (search - pointer)
        else:
            structure[pointer:search] = [ByteType.RAW] * (search - pointer)
        pointer = search+1

    with open(dest, "wt") as out:
        for script_num in range(len(scripts)):
            see_write(out, f"{script_num} {links[scripts[script_num]]}")
        pointer = len(scripts) * 4
        if data[pointer:pointer+2] == b'\x13\xfd':
            see_write(out, "# commands")
            pointer += 2
        else:
            see_write(out, "# no stop bytes\n# commands")
        while pointer < len(data):
            if pointer in links:
                if links[pointer][0:3] == "scr":
                    see_write(out, f"\n# {links[pointer]}")
                elif links[pointer][0:3] == "lbl":
                    see_write(out, f"\n   # {links[pointer]}")
                elif links[pointer][0:3] == "act":
                    see_write(out, f"\n   # {links[pointer]}")
                else:
                    see_write(out, f"\n# {links[pointer]}")
            match structure[pointer]:
                case ByteType.RAW:
                    see_write(out, f"    _{hex(data[pointer])}")
                    pointer += 1
                case ByteType.IGNORE:
                    pointer += 1
                case ByteType.COMMAND_HEADER:
                    comm_num = int.from_bytes(data[pointer:pointer+2], "little")
                    comm_def = commands[comm_num]
                    see_write(out, f"    {comm_def[1]}", "")
                    pointer += 2
                    if comm_num in (4, 0x1e):
                        value = int.from_bytes(data[pointer:pointer + 4], 'little')
                        see_write(out, f" {links[(value+pointer+4)%0x100000000]}")
                        pointer += 4
                    elif comm_num in (0x1f, 0x20):
                        cond = data[pointer]
                        value = int.from_bytes(data[pointer+1:pointer + 5], 'little')
                        see_write(out, f" {cond} {links[(value+pointer+5)%0x100000000]}")
                        pointer += 5
                    elif comm_num == 0x64:
                        actor = int.from_bytes(data[pointer:pointer+2], 'little')
                        value = int.from_bytes(data[pointer+2:pointer+6], 'little')
                        if actor in range(0x4000, 0x4200) or actor in range(0x8000, 0x8100):
                            see_write(out, f" {hex(actor)} {links[(value+pointer+6)%0x100000000]}")
                        else:
                            see_write(out, f" {actor} {links[(value+pointer+6)%0x100000000]}")
                        pointer += 6
                    else:
                        for param in comm_def[2:]:
                            length = int(param[0])
                            value = int.from_bytes(data[pointer:pointer+length], "little")
                            if value in range(0x4000, 0x4200) or value in range(0x8000, 0x8100) or value in range(0xFF00, 0x10000):
                                see_write(out, f" {hex(value)}", "")
                            else:
                                see_write(out, f" {value}", "")
                            pointer += length
                        see_write(out, "")
                case ByteType.ACTION_HEADER:
                    act_num = int.from_bytes(data[pointer:pointer+2], "little")
                    value = int.from_bytes(data[pointer+2:pointer+4], "little")
                    see_write(out, f"     {actions[act_num][1]} {value}")
                    pointer += 4


def assemble(f: PathLike | str, dest: PathLike | str):
    data = [line.split() for line in get_text_file_lines(f)]
    command_text = get_text_file_lines("commands.txt")
    action_text = get_text_file_lines("actions.txt")
    commands: dict[str, tuple[list[str], int]] = {}
    actions: dict[str, int] = {}
    for line in command_text:
        c = line.split()
        commands[c[1]] = (c[2:], int(c[0], 16))
        debug(f"Registered command {c}")
    for line in action_text:
        a = line.split()
        actions[a[1]] = int(a[0], 16)
        debug(f"Registered action {a}")

    links: dict[str, int] = {}
    assembly: bytearray = bytearray()
    # {calling address: label name}
    link_calls: dict[int, str] = {}

    # search "# command"
    for l in range(len(data)):
        words = data[l]
        if words == ["#", "commands"]:
            script_lines = data[:l]
            command_lines = data[l+1:]
            debug(f"# command at line {l}")
            break
    else:
        raise Exception("Missing '# commands'")
    # write script list
    stop_bytes = True
    if len(script_lines) > 0 and script_lines[-1] == ["#", "no", "stop", "bytes"]:
        stop_bytes = False
        script_lines.pop()
        debug(f"# no stop bytes at line {l}")
    for words in script_lines:
        if len(words) == 0:
            continue
        if len(words) < 2 or not words[0].isnumeric():
            raise Exception(f"Bad line in script list: {' '.join(words)}")
        script = int(words[0])
        link_calls[script*4] = words[1]
        debug(f"Script {script} calling {words[1]}")
        if len(assembly) < script*4+4:
            assembly.extend(bytes(script*4+4-len(assembly)))
    if stop_bytes:
        assembly.extend(b'\x13\xfd')
    # write command lines
    last_link = ""  # only used for actions right after a label
    for words in command_lines:
        if len(words) == 0:
            continue
        if words[0] == "#":
            if len(words) != 2:
                raise Exception(f"Bad label definition: {' '.join(words)}")
            links[words[1]] = len(assembly)
            last_link = words[1]
            debug(f"Link {words[1]} to {len(assembly)}")
        elif words[0].startswith("_"):
            raw = int(words[0][1:], 16)
            if raw > 0xff:
                raise Exception(f"Raw value out of bounds: {' '.join(words)}")
            assembly.append(raw)
            last_link = ""
            debug(f"Raw {raw}")
        elif words[0] in commands:
            given_param_count = len(words) - 1
            needed_param_count = len(commands[words[0]][0])
            if given_param_count != needed_param_count:
                raise Exception(f"Param count mismatch: {' '.join(words)}")
            command = commands[words[0]][1]
            param_lengths = [int(p[0]) for p in commands[words[0]][0]]
            assembly.extend(command.to_bytes(2, "little"))
            last_link = ""
            debug(f"Command {' '.join(words)}")
            for param_num in range(given_param_count):
                param_val = words[param_num+1]
                if param_val.isnumeric():
                    assembly.extend(int(param_val).to_bytes(param_lengths[param_num], "little"))
                elif param_val.startswith("0x"):
                    assembly.extend(int(param_val, 16).to_bytes(param_lengths[param_num], "little"))
                else:
                    link_calls[len(assembly)] = param_val
                    assembly.extend(b"\0\0\0\0")
                    debug(f"    Calling link {param_val}")
        elif words[0] in actions:
            if len(words) != 2:
                raise Exception(f"Bad action call: {' '.join(words)}")
            if last_link != "" and links[last_link] % 4 != 0:
                links[last_link] += (4 - (links[last_link] % 4))
            action = actions[words[0]]
            value = int(words[1])
            if len(assembly) % 4 != 0:
                assembly.extend(bytes(4 - (len(assembly) % 4)))
            assembly.extend(action.to_bytes(2, "little"))
            assembly.extend(value.to_bytes(2, "little"))
            last_link = ""
            debug(f"Action {' '.join(words)}")
        else:
            raise Exception(f"Unknown command: {' '.join(words)}")
    # fill link calls
    for addr, link_name in link_calls.items():
        if link_name not in links:
            raise Exception(f"Unknown label: {link_name}")
        jump = ((links[link_name]-addr-4) % 0x100000000)
        assembly[addr:addr+4] = jump.to_bytes(4, "little")
        debug(f"Linking param at address {hex(addr)} to {hex(links[link_name])}, jumping {hex(jump)}")
    with open(dest, "wb") as out:
        out.write(assembly)


if __name__ == "__main__":
    # debug_active = True
    # print_disassembly = True
    # for i in [852]:
    for i in [*range(0, 853, 2), *range(854, 899)]:
    # for i in [*range(154, 853, 2), *range(854, 899)]:
        if i < 10:
            ii = f"00{i}"
        elif i < 100:
            ii = f"0{i}"
        else:
            ii = str(i)
        try:
            original = f"assembled unknown/7_{ii}"
            text = f"disassembled/{ii}.asm"
            reassembled = f"reassembled/{ii}.bin"
            disassemble(original, text)
            assemble(text, reassembled)
            if get_file_as_bytes(original) == get_file_as_bytes(reassembled):
                print(f"{ii} original == disassembled")
            else:
                print(f"{ii} is not equal, that's bad!")
        except Exception as e:
            print(f"{ii} failed: {e.args}")
            # raise e
