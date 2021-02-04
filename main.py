from Crypto.Cipher import AES
import pandas as pd

my_data = {"MAC": [], "K": [], "GID": [], "DID": []}


def filter_mac(mac):
    '''
    :param mac: string: mac address
    :return: string: mac address without colon and uppercase
    '''
    a = "".join(str(mac).split(":"))
    a = a.upper()
    return a


def set_data(mac, constant):
    '''
    split the mac into oui and eui48l and add the constant in between
    :param mac: string: mac address
    :param constant: hex constant
    :return: string: string: eui48l + constant + oui, where oui equals to the first 6 digits os the MAC address and
            eui48l is the last 6 digits
    '''
    mac = filter_mac(mac)
    constant = filter_mac(constant)

    n = 6
    splitmac = [mac[i:i + n] for i in range(0, len(mac), n)]

    oui, eui48l = splitmac[0], splitmac[1]

    return str(eui48l + constant + oui)


def gid(mac):
    '''
    generate gid and did adress from mac
    :param mac: string: mac address
    :return: string: gid address
    '''
    mac = filter_mac(mac)
    return mac[4:]


def input_process():
    '''
    take care of the reading input files and generate the key
    :return: None
    '''
    # read the master key from file
    with open('MK.txt', 'r') as f:
        mk = f.read()
        f.close()
        mk_bytearray = bytearray.fromhex(mk)

    # read the constant from file
    with open('k.txt', 'r') as f:
        constant = f.read()
        f.close()

    # read the mac address from file
    with open('input.txt', 'r') as f:
        for line in f:
            # filter the unnecessary characters of the MAC
            mac_adress = filter_mac(line.rstrip())

            # save MAC, GID and DID to the dictionary
            my_data['MAC'].append(mac_adress)
            my_data['GID'].append(gid(mac_adress))
            my_data['DID'].append(gid(mac_adress))

            # set the mac and constant together, transform it into a byte array
            data = set_data(line, constant)
            data_bytearray = bytearray.fromhex(data)

            # create the cipher object and encrypt the data, generating the product key
            cipher = AES.new(mk_bytearray, AES.MODE_ECB)
            product_key = cipher.encrypt(data_bytearray)

            # save the product key to the dictionary
            my_data['K'].append(product_key.hex().upper())
        f.close()


def output_process():
    '''
    take care of writing the output files
    :return: None
    '''
    # create pandas data frame from the dictionary
    df = pd.DataFrame.from_dict(my_data)
    df.style.set_properties(align='right')

    # create data frames based on specific items
    df_k = df.to_string(index=False, header=False, columns=['K'])
    df_gid = df.to_string(index=False, header=False, columns=['GID'])
    df_did = df.to_string(index=False, header=False, columns=['DID'])
    df_mac_k = df.to_string(index=False, header=False, columns=['MAC', 'K'])
    df_mac_gid = df.to_string(index=False, header=False, columns=['MAC', 'GID'])
    df_mac_did = df.to_string(index=False, header=False, columns=['MAC', 'DID'])
    df_mac_k_gid_did = df.to_string(index=False, header=False, columns=['MAC', 'K', 'GID', 'DID'])

    # create a list containing the data frames and another containing its names
    df_list = [df_k, df_gid, df_did, df_mac_k, df_mac_gid, df_mac_did, df_mac_k_gid_did]
    df_namelist = ['df_k', 'df_gid', 'df_did', 'df_mac_k', 'df_mac_gid', 'df_mac_did', 'df_mac_k_gid_did']

    # create a file based on the data frame name and write the data in it.
    j = 0
    for i in df_namelist:
        with open(i + '.txt', 'a') as f:
            for line in df_list[j]:
                f.write(line)
            f.write('\n')
            f.close()
        j += 1


def run():
    input_process()
    output_process()


if __name__ == '__main__':
    run()
