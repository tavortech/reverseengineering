import subprocess
import os

exe_path = os.path.join(os.path.dirname(__file__), 'keygen.exe')

# Dictionary to store reverse mappings: {output_byte: input_byte}
reverse_map = {}

for i in range(256):
    char = bytes([i])
    try:
        result = subprocess.run(
            [exe_path, char.decode('latin1')],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        output = result.stdout
        if output:
            output_byte = output[0]  # Take the first byte of output
            reverse_map[output_byte] = i
    except Exception as e:
        continue

# Save as {output_byte, input_byte}
with open('reverse_mapping.txt', 'w') as f:
    for out_b, in_b in reverse_map.items():
        f.write(f'{{{out_b},{in_b}}}\n')