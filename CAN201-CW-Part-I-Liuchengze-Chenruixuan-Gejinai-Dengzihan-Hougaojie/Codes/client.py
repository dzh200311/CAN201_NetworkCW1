from socket import *
import hashlib
import argparse
import json
import struct
from os.path import join, getsize
import time
import sys


# Const Value
OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_ERROR = 'SAVE', 'DELETE', 'GET', 'UPLOAD', 'DOWNLOAD', 'BYE', 'LOGIN', "ERROR"
TYPE_FILE, TYPE_DATA, TYPE_AUTH, DIR_EARTH = 'FILE', 'DATA', 'AUTH', 'EARTH'
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = 'operation', 'direction', 'type', 'username', 'password', 'token'
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = 'key', 'size', 'total_block', 'md5', 'block_size'
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'
DIR_REQUEST, DIR_RESPONSE = 'REQUEST', 'RESPONSE'


def make_packet(json_data, bin_data=None):
    """
    Make a packet following the STEP protocol.
    Any information or data for TCP transmission has to use this function to get the packet.
    :param json_data:
    :param bin_data:
    :return: The complete binary packet
    """

    j = json.dumps(dict(json_data), ensure_ascii=False)
    j_len = len(j)

    if bin_data is None:
        return struct.pack('!II', j_len, 0) + j.encode()
    else:
        return struct.pack('!II', j_len, len(bin_data)) + j.encode() + bin_data

def get_tcp_packet(conn):
    """
    Receive a complete TCP "packet" from a TCP stream and get the json data and binary data.
    :param conn: the TCP connection
    :return:
        json_data
        bin_data
    """
    bin_data = b''
    while len(bin_data) < 8:
        data_rec = conn.recv(8)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    data = bin_data[:8]
    bin_data = bin_data[8:]
    j_len, b_len = struct.unpack('!II', data)
    while len(bin_data) < j_len:
        data_rec = conn.recv(j_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    j_bin = bin_data[:j_len]

    try:
        json_data = json.loads(j_bin.decode())
    except Exception as ex:
        return None, None

    bin_data = bin_data[j_len:]
    while len(bin_data) < b_len:
        data_rec = conn.recv(b_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    return json_data, bin_data

def _argparse():
    """
    Gets arguments from the command line

    :return:
    An ArgumentParser object that holds information needed by the program
    """
    parse = argparse.ArgumentParser()
    parse.add_argument("-server_ip", "--server_ip", required=True, dest="ip", help="")
    parse.add_argument("-port", "--port", type= int, default='1379', required=False, dest="port", help="")
    parse.add_argument("-username", "--id", required=True, dest="username", help="")
    parse.add_argument("-file", "--f", required=True, dest="file_name", help="")
    return parse.parse_args()

def login_to_server(username, password):
    """
    Make the packet required for the login operation, which calls the 'make_packet 'function

    :param username:
    :param password:
    :return:
    A packet that can be sent directly over client socket

    """
    login_data = {
        FIELD_OPERATION: OP_LOGIN,
        FIELD_DIRECTION: DIR_REQUEST,
        FIELD_TYPE: TYPE_AUTH,
        FIELD_USERNAME: username,
        FIELD_PASSWORD: password
    }

    return make_packet(login_data)

def save_operation(token, file_size):
    """
    Make the packet required for the save operation, which calls the 'make_packet' function

    :param token:
    :param file_size:
    :return:
    A packet that can be sent directly over client socket

    """
    about_key = input("Whether to customize a key value (if not, it will be automatically generated randomly)Y/N： ")
    if about_key == 'Y' or about_key == 'y':
        set_file_key = input("Please enter a custom key value： ")

        save_packet = {
            FIELD_OPERATION: OP_SAVE,
            FIELD_DIRECTION: DIR_REQUEST,
            FIELD_TYPE: TYPE_FILE,
            FIELD_TOKEN: token,
            FIELD_SIZE: file_size,

            FIELD_KEY: set_file_key
        }
    else:
        save_packet = {
            FIELD_OPERATION: OP_SAVE,
            FIELD_DIRECTION: DIR_REQUEST,
            FIELD_TYPE: TYPE_FILE,
            FIELD_TOKEN: token,
            FIELD_SIZE: file_size
        }

    return make_packet(save_packet)

def upload_operation(token, key, index, total_block, send_file):
    """
    Make the packet required for the upload operation, which calls the 'make_packet' function

    :param token:
    :param key: key value returned by the server for uploading operations
    :param index: index number of the block that is currently being uploaded
    :param total_block:
    :param send_file: Files to upload
    :return:
    A packet that can be sent directly over client socket

    """
    upload_packet = {
        FIELD_OPERATION: OP_UPLOAD,
        FIELD_DIRECTION: DIR_REQUEST,
        FIELD_TYPE: TYPE_FILE,
        FIELD_KEY: key,
        FIELD_BLOCK_INDEX: index,
        FIELD_TOKEN: token
    }
    # max_block_size = 20480
    # Split the file into blocks
    if index != total_block - 1:
        final_file = send_file[20480*index:20480*(index+1)]

    else:
        final_file = send_file[20480*index:]
    return make_packet(upload_packet, final_file)

def update_progress_bar(i, total_block):
    progress = (i + 1) / total_block
    bar_length = 40
    progress_int = int(progress * bar_length)
    bar = "▋" * progress_int + " " * (bar_length - progress_int)
    sys.stdout.write("\rDownload progress: {:.1%} [{}] {}/{}".format(progress, bar, i+1, total_block))
    sys.stdout.flush()

def main():

    # Gets arguments from the command line
    parser = _argparse()
    server_ip = parser.ip
    server_port = parser.port
    username = parser.username
    file_name = parser.file_name

    # A password is automatically generated based on the username
    generate_password = hashlib.md5()
    generate_password.update(username.encode())
    password = generate_password.hexdigest()

    # Establish a TCP connection
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect((server_ip, server_port))

    """
     The login request is sent to the server, the returned token value will be stored, 
     and if no token value is returned, 
     an error message is printed and the program is waiting to confirm that the program exits
    """
    token: str
    clientSocket.send(login_to_server(username, password))
    msg_with_token = get_tcp_packet(clientSocket)

    if 'token' in msg_with_token[0].keys():
        token = msg_with_token[0]['token']
        print("Token:{}".format(token))
        print("The login is successful.")
        print("Currently, only the file upload function is available,so this operation will be performed automatically")
        # After the login is successful, the system automatically uploads files
        try:

            f = open(file_name, 'rb')
            send_file = f.read()
            f.close()
            file_size = getsize(file_name)

            """
             The save request is sent to the server, the returned upload plan will be stored,
             and if no upload plan is returned,
             an error message is printed and the program is waiting to confirm that the program exits
            """
            clientSocket.send(save_operation(token, file_size))
            upload_plan = get_tcp_packet(clientSocket)
            if upload_plan[0]['status'] == 200:
                # Gets the parameters required for the upload operation
                total_block = upload_plan[0]['total_block']
                key = upload_plan[0]['key']

                # Record the md5 value of the file to be uploaded
                check_md5_ = hashlib.md5()
                check_md5_.update(send_file)
                file_md5 = check_md5_.hexdigest()

                start = time.time()
                # The upload operation is performed in blocks
                for i in range(total_block):
                    """
                    The upload request is sent to he server, the returned status will be checked
                    """
                    clientSocket.send(upload_operation(token, key, i, total_block, send_file))
                    block_upload_msg = get_tcp_packet(clientSocket)

                    if block_upload_msg[0]['status'] == 200:

                        update_progress_bar(i, total_block)

                        if i == total_block - 1:
                            # Check file integrity
                            server_file_md5 = block_upload_msg[0]['md5']
                            key = block_upload_msg[0]['key']
                            if file_md5 == server_file_md5:
                                print()
                                print("By checking the md5, Congratulations on successfully uploading your file!")
                                print("MD5：" + server_file_md5)
                                print("File key: " + key)
                                end = time.time()
                                print("Upload time:" + str(end - start))
                                input("Press Enter to exit ")

                            else:
                                print()
                                print("File missing please upload again!")
                                input("Press Enter to exit ")
                    else:
                        print(block_upload_msg[0]['status_msg'])
                        input("Press Enter to exit ")

            else:

                print(upload_plan[0]['status_msg'])
                input("Press Enter to exit ")


        except FileNotFoundError:
            input("The file path is incorrect, press Enter to exit")

    else:
        input("Login failed.Press Enter to exit! ")

    clientSocket.close()
    return 0

if __name__ == '__main__':
    main()