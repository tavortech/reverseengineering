def load_mapping(filename):
    mapping = {}
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                content = line[1:-1]
                if ',' in content:
                    value_str, key_str = content.split(',', 1)
                    value = int(value_str.strip())
                    key = int(key_str.strip())
                    mapping[value] = key
    return mapping

if __name__ == "__main__":
    mapping = load_mapping('reverse_mapping.txt')
    input_string = input("Enter the mapped string: ")
    res = ""
    for char in input_string:
        value = ord(char)
        if value in mapping:
            res += chr(mapping[value])
        else:
            res += f"[{char}: No mapping found]"
    print(res)