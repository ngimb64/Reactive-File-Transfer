from pwn import cyclic

size = 256
file_num = 1

# While the size of written data is less
# than or equals to 8X max buffer size #
while size <= 32768:
    with open(f'test_file{file_num}.txt', 'w', encoding='utf-8') as out_file:
        # Write current size as random data with pwn tools cyclic function #
        out_file.write(cyclic(size).decode())

    size = size * 2
    file_num += 1