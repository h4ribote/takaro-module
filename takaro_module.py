import requests
import json
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import hashlib
from string import ascii_lowercase, digits
from secrets import choice
import multiprocessing

ModuleVersion = "1.0"

multiprocessing.freeze_support()

def tkr_url(directory:str = ""):
    return "https://takaro.h4ribote.net/" + directory


class wallet:

    def generate():
        private_key = SigningKey.generate(curve=SECP256k1)
        hex_public_key = private_key.verifying_key.to_string().hex()
        private_key = private_key.to_string().hex()

        public_hash = hashlib.sha256(bytes.fromhex(hex_public_key)).hexdigest()

        address = decimal_to_base62(int(public_hash,16))

        return {"address":address,"private_key":private_key,"public_key":hex_public_key}
    
    def from_private(hex_private_key: str):
        private_key = SigningKey.from_string(bytes.fromhex(hex_private_key), curve=SECP256k1)
        hex_public_key = private_key.verifying_key.to_string().hex()

        public_hash = hashlib.sha256(bytes.fromhex(hex_public_key)).hexdigest()

        address = decimal_to_base62(int(public_hash,16))

        return {"address":address,"private_key":hex_private_key,"public_key":hex_public_key}

    def balance(address:str) -> list:
        response = requests.post(tkr_url("exploler/balance.php"), data={"address":address})
        data = json.loads(response.text)
        return data


class transaction:

    def post(variable:dict):
        post_data = {
            'transaction_id':variable['transaction_id'],
            'signature':variable['signature'],
            'public_key':variable['public_key'],
            'previous_hash':variable['previous_hash'],
            'source':variable['source'],
            'dest':variable['dest'],
            'amount':variable['amount'],
            'currency_id':variable['currency_id'],
            'fee_amount':variable['fee_amount'],
            'comment':variable['comment'],
            'nonce':variable['nonce'],
            'miner':variable['miner'],
            'miner_comment':variable['miner_comment'],
            'miner_public_key':variable['miner_public_key'],
            'miner_signature':variable['miner_signature'],
            'node_address':variable['node_address'],
            'node_signature':variable['node_signature']
        }

        response = requests.post(tkr_url("post/transaction.php"), data=post_data)

        data = (response.text)

        data = json.loads(data)

        return data
    
    def post2node(post_data:dict,node_url:str):

        response = requests.post(node_url, data=post_data)

        data = (response.text)

        data = json.loads(data)

        return data

    def create(wallet:dict,dest,amount:int,currency_id,fee_amount:int,comment,indent:int = 0):
        new_transaction = {
            "transaction_id":gen_transaction_id(indent),
            "source":wallet['address'],
            "dest":dest,
            "amount":int(amount),
            "currency_id":currency_id,
            "fee_amount":int(fee_amount),
            "comment":comment
        }

        
        data=new_transaction['transaction_id']+wallet['address']+dest+str(amount)+currency_id+str(fee_amount)+comment

        new_transaction['signature'] = sign_data(wallet['private_key'],data)
        new_transaction['public_key'] = wallet['public_key']

        return new_transaction


class multi_mine:
    def mining(target_data:dict,previous_hash:str,miner_wallet:dict,comment:str="mined with qash_client made by h4ribote",difficulty:int=6,num_processes:int=4):
        
        data1 = target_data['transaction_id'] + target_data['signature'] + previous_hash +\
        target_data['source'] + target_data['dest'] + str(target_data['amount']) + target_data['currency_id'] +\
        str(target_data['fee_amount']) + comment
        data2 = miner_wallet['address']

        found_nonce = multi_mine.parallel_thread(data1, data2, difficulty, num_processes)
        target_data['nonce'] = found_nonce
        target_data['miner'] = miner_wallet['address']
        target_data['previous_hash'] = previous_hash
        target_data['miner_comment'] = comment
        target_data['miner_public_key'] = miner_wallet['public_key']
        target_data['miner_signature'] = sign_data(miner_wallet['private_key'],(target_data['transaction_id']+comment))
        return target_data
    
    def parallel_thread(target_data1, target_data2, difficulty:int=6, num_processes:int=4):
        result_queue = multiprocessing.Queue()
        processes = []
        nonce_range = 2**32 // num_processes

        for i in range(num_processes):
            start_nonce = i * nonce_range
            end_nonce = (i + 1) * nonce_range if i != num_processes - 1 else 2**32
            process = multiprocessing.Process(target=multi_mine.find_nonce, args=(target_data1, target_data2, difficulty, start_nonce, end_nonce, result_queue))
            processes.append(process)
            process.start()

        for process in processes:
            process.join()

        while not result_queue.empty():
            result = result_queue.get()
            if result is not None:
                return result

        return None
    
    def find_nonce(target_data1, target_data2, difficulty, start_nonce, end_nonce, result_queue):
        nonce = start_nonce
        while nonce < end_nonce:
            data = f"{target_data1}{nonce}{target_data2}"
            hash_result = hashlib.sha256(data.encode('utf-8')).hexdigest()
            if hash_result.startswith('0' * difficulty):
                result_queue.put(nonce)
                return
            nonce += 1
        result_queue.put(None)


class mining:
    def mine(target_data:dict,previous_hash:str,miner_wallet:dict,comment:str="mined with tkrpy made by h4ribote",difficulty:int = 6):
        data1 = target_data['transaction_id'] + target_data['signature'] + previous_hash +\
        target_data['source'] + target_data['dest'] + str(target_data['amount']) + target_data['currency_id'] +\
        str(target_data['fee_amount']) + target_data['comment']
        data2 = miner_wallet['address']
        nonce = 0
        while True:
            data = f"{data1}{nonce}{data2}"
            hash_result = hashlib.sha256(data.encode('utf-8')).hexdigest()
            if hash_result.startswith('0' * difficulty):
                break
            nonce += 1
        target_data['nonce'] = nonce
        target_data['miner'] = miner_wallet['address']
        target_data['previous_hash'] = previous_hash
        target_data['miner_comment'] = comment
        target_data['miner_public_key'] = miner_wallet['public_key']
        target_data['miner_signature'] = sign_data(miner_wallet['private_key'],(target_data['transaction_id']+comment))
        return target_data


class node:
    def transaction_id(indent:int = 0):
        i = 0
        while i < 20:
            try:
                transaction_id_tmp = gen_transaction_id(indent)
                response = requests.post(tkr_url("exploler/transaction.php"), data={"transaction_id":transaction_id_tmp})
                data = json.loads(response.text)
                if not "error" in data:
                    return transaction_id_tmp
            except:
                i += 1
        raise Exception('Please check the server status')
    
    def verify_transaction(transaction:dict,node_wallet:dict):
        # Custom verify code here...
        verify = True
        if verify:
            signed_data = sign_data(node_wallet['private_key'],transaction['transaction_id'])
            return signed_data
        return False

    def post_transaction(transaction:dict,node_wallet:dict):
        try:
            signed_data = node.verify_transaction(transaction,node_wallet)
            if not signed_data:
                return {"error":"invalid transaction"}
            else:
                transaction['node_address'] = node_wallet['address']
                transaction['node_signature'] = signed_data
            
            response = requests.post(tkr_url("post/transaction.php"), data=transaction)
            data = json.loads(response.text)
            return data
        except Exception as e:
            return {"error":e}
    
    def get_previous_hash():

        response = requests.post(tkr_url("exploler/transaction.php"))
        data = json.loads(response.text)
        if "error" in data:
            return False
        else:
            previous_transaction = data[0]
            previous_data = ""
            for fdata in previous_transaction.values():
                previous_data += str(fdata)

            previous_hash = hashlib.sha256(previous_data.encode('utf-8')).hexdigest()

            return previous_hash
    
    def previous_hash_from_admin() -> str:
        response = requests.post(tkr_url("exploler/previous_hash.php"))
        data = json.loads(response.text)
        return str(data['hash'])
    


def sign_data(hex_private_key,data):
    private_key = SigningKey.from_string(bytes.fromhex(hex_private_key), curve=SECP256k1)

    signature = private_key.sign(hashlib.sha256(data.encode('utf-8')).digest())

    return signature.hex()


def decimal_to_base62(decimal:int):
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if decimal == 0:
        return alphabet[0]
    base62 = ""
    while decimal:
        decimal, remainder = divmod(decimal, 62)
        base62 = alphabet[remainder] + base62
    return base62

def gen_transaction_id(indent:int=0):
    if indent > 9:
        raise ValueError
    chars = ascii_lowercase + digits
    return str(indent) + ''.join(choice(chars) for x in range(24))


