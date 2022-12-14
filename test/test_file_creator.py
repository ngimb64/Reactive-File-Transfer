from pwn import cyclic

start_size = 256
file_num = 1

while start_size <= 4096:
    with open(f'test_file{file_num}.txt', 'w', encoding='utf-8') as out_file:
        out_file.write(cyclic(start_size - 5).decode())

    start_size = start_size * 2
    file_num += 1