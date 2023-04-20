import lists


def digitsMatching(value):
    return value % 0x100000000


def digitsMatching_100(value):
    return value % 0x100


def getSubKey(key, key_ptr, value_for_sub_key, num):
    t2 = lists.prim_list[num // 2]
    ctr = 0
    while ctr < value_for_sub_key:
        v0 = key[key_ptr]
        v0 = 2 * (v0 - 0x100) if v0 >= 0x80 else v0 * 2
        v1 = lists.prim_list[((0x100 // 2) + (v0 // 2))]
        v1 = digitsMatching(t2 * v1)
        v2 = v1 + 0x3ff
        v0 = v1 if v2 <= 0x80000000 else v2
        v1 = (v0 & ((1 << 0xa) - 1)) * 2
        t2 = lists.prim_list[v1 // 2]
        key_ptr += 1
        ctr += 1
    return t2.to_bytes(2, byteorder='little')


def getScrambleKey(key, ptr, value_for_sub_key):
    k1 = getSubKey(key, ptr, value_for_sub_key, 0x200)
    k2 = getSubKey(key, ptr, value_for_sub_key, 0x400)
    k3 = getSubKey(key, ptr, value_for_sub_key, 0x600)
    scramble_key = k1 + k2 + k3
    return scramble_key


def getMainKey(key):
    ptr = 0
    while ptr < 0x8:
        scramble_key = getScrambleKey(key, ptr, 2)
        k = int.from_bytes(scramble_key[0:2], byteorder='little').to_bytes(2, byteorder='big')
        key = key[:ptr] + k + key[ptr + 2:]
        ptr += 2
    return key


def getFinalKey(main_key, xor_key, id_final_key_func, sc):
    final_key = b'\x00' * 8
    for i in range(4):
        if sc[id_final_key_func][5][i] == 0:
            k1 = xor_key[sc[id_final_key_func][0][i]] ^ main_key[sc[id_final_key_func][1][i]]
        else:
            k1 = digitsMatching_100(xor_key[sc[id_final_key_func][0][i]] + main_key[sc[id_final_key_func][1][i]])
        ofs1 = sc[id_final_key_func][2][i]
        final_key = final_key[:ofs1] + k1.to_bytes(1, byteorder='little') + final_key[ofs1 + 1:]
        k2 = main_key[sc[id_final_key_func][3][i]]
        ofs2 = sc[id_final_key_func][4][i]
        final_key = final_key[:ofs2] + k2.to_bytes(1, byteorder='little') + final_key[ofs2 + 1:]
    return final_key


def setCompositeData(value_for_final_key, cvm_ptr, adr, main_key, b_in, b_out):
    ptr = 0
    for j in range(0x800 // 8):
        temp = (value_for_final_key << 0x14) & 0xffffffff
        value_for_final_key = digitsMatching(temp + value_for_final_key)
        value_for_final_key = value_for_final_key.to_bytes(4, byteorder='big')
        key = getScrambleKey(value_for_final_key, 0, 4)
        xor_key = key[3:4] + key[2:3] + key[5:6] + key[4:5]
        id_final_key_func = int.from_bytes(key[0:2], byteorder='little') % 9
        final_key = getFinalKey(main_key, xor_key, id_final_key_func, lists.sc_list)
        v2 = id_final_key_func + ptr
        for i in range(8):
            v1 = final_key[i]
            v0 = b_in[adr]
            v0 = v0 ^ v1
            b_out += v0.to_bytes(1, byteorder='little')
            v2 = digitsMatching(v2 * v1)
            adr += 1
        ptr += 0x8
        value_for_final_key = digitsMatching(v2 * cvm_ptr)
    return b_out, adr, cvm_ptr


def getKeyFromHdr(header_file):
    ptr1 = 0x25
    ptr2 = 0x20
    b_key = b''

    for i in range(4):
        header_file.seek(ptr1 + i)
        b_key += header_file.read(1)
        header_file.seek(ptr2 + i)
        b_key += header_file.read(1)
    return b_key


def makeCvmHdr(p_cvm, p_hdr):
    f1 = open(p_cvm, 'rb')
    f2 = open(p_hdr, 'wb')

    cvm_hdr = 0x1800
    f2.write(f1.read(cvm_hdr))
    f1.close()
    f2.close()


def unpackCvm(p_cvm, p_iso):
    f_cvm = open(p_cvm, 'rb')
    f_iso = open(p_iso, 'wb')

    cvm_hdr = 0x1800
    iso_start = 0x8000
    b_1_length = 0x2800
    ptr = 0

    # Create scramble key
    key_from_hdr = getKeyFromHdr(f_cvm)
    main_key = getMainKey(key_from_hdr)

    # b_0
    ptr += cvm_hdr
    f_cvm.seek(ptr)
    f_iso.write(f_cvm.read(iso_start))

    # b_1
    ptr += iso_start
    f_cvm.seek(ptr)
    b_1 = f_cvm.read(b_1_length)

    cvm_ptr = 0x10
    adr = 0
    b_out = b''
    while adr < len(b_1):
        value_for_final_key = main_key[5] * cvm_ptr
        (b_out, adr, cvm_ptr) = setCompositeData(value_for_final_key, cvm_ptr, adr, main_key, b_1, b_out)
        cvm_ptr += 1
    if b_out[0:8] == b'\x01CD001\x01\x00':
        b_2_length = int.from_bytes(b_out[0x202C:0x2030], byteorder='little') - 0x800
    else:
        raise ValueError('Conversion failed. The file may not be a supported CVM file.')

    # b_2
    ptr += b_1_length
    f_cvm.seek(ptr)

    # Patting b_2_length to be a multiple of 0x800
    length_differencial = (0x800 - (b_2_length % 0x800))
    b_2_length = b_2_length if length_differencial == 0x800 else b_2_length + length_differencial
    b_2 = f_cvm.read(b_2_length)

    adr = 0
    while adr < len(b_2):
        value_for_final_key = main_key[5] * cvm_ptr
        (b_out, adr, cvm_ptr) = setCompositeData(value_for_final_key, cvm_ptr, adr, main_key, b_2, b_out)
        cvm_ptr += 1

    f_iso.write(b_out)

    # b_3
    ptr += b_2_length
    f_cvm.seek(ptr)
    file_size = p_cvm.stat().st_size
    while ptr < file_size:
        f_cvm.seek(ptr)
        f_iso.write(f_cvm.read(0x800))
        ptr += 0x800

    f_cvm.close()
    f_iso.close()


def packCvm(p_iso, p_cvm, p_hdr):
    f_iso = open(p_iso, 'rb')
    f_hdr = open(p_hdr, 'rb')
    f_cvm = open(p_cvm, 'wb')

    sizeof_cvm_hdr = 0x1800
    iso_start = 0x8000

    # get iso header length
    f_iso.seek(iso_start + 0x202C)
    iso_length = int.from_bytes(f_iso.read(4), byteorder='little') + 0x2000

    # Create scramble key
    key_from_hdr = getKeyFromHdr(f_hdr)
    main_key = getMainKey(key_from_hdr)

    # cvmhdr
    if p_hdr.stat().st_size != sizeof_cvm_hdr:
        raise ValueError('不正なhdrです。')
    f_hdr.seek(0)
    f_cvm.write(f_hdr.read(sizeof_cvm_hdr))

    # zero patting
    zero_data = b'\x00' * 0x8000
    f_cvm.write(zero_data)

    # scramble data
    ptr = iso_start
    f_iso.seek(ptr)

    # Patting iso_length to be a multiple of 0x800
    length_differencial = (0x800 - (iso_length % 0x800))
    iso_length = iso_length if length_differencial == 0x800 else iso_length + length_differencial
    b_1 = f_iso.read(iso_length)

    cvm_ptr = 0x10
    adr = 0
    b_out = b''
    while adr < len(b_1):
        a0 = main_key[5] * cvm_ptr
        (b_out, adr, cvm_ptr) = setCompositeData(a0, cvm_ptr, adr, main_key, b_1, b_out)
        cvm_ptr += 1
    f_cvm.write(b_out)

    # file data
    ptr += iso_length
    f_iso.seek(ptr)
    file_size = p_iso.stat().st_size
    while ptr < file_size:
        f_iso.seek(ptr)
        f_cvm.write(f_iso.read(0x800))
        ptr += 0x800

    f_iso.close()
    f_hdr.close()
    f_cvm.close()
