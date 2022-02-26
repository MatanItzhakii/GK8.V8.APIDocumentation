import binascii
import time
from typing import Tuple, Union
import json
from Cryptodome.Cipher import AES
from Protocols.DepositAddressesManager import DepositAddressesManager
from Protocols.GetBulletinsResponse import GetBulletinsResponse
from Helpers.helpers import *
from Helpers.RequestManager import RequestManager
from Helpers.User import User
from tinyec import registry
from threading import Lock
from Gk8Crypto.AESCipher import AESCipher
from enum import Enum

mutex = Lock()
SYNC_API_COMMANDS = ["sendTransaction", "sendTransactionFromCashbox", "sendPayloadToBeSigned",
                     "sendConvertEth1ToEth2Transaction"]


class ApiClient(object):
    """
     * __init__
     * @param user The data of the user who wishes to use the API
     * @param thread_index The index of the thread to communicate with (for access token selection)
     * @param encrypted_api True in order to use encrypted communication with the server (default), false otherwise
     * @param request_timeout The timeout for server API requests (in seconds), or None for no timeout
    """

    def __init__(self, user: User, thread_index: int,
                 encrypted_api: bool = True, request_timeout: int = RequestManager.DEFAULT_REQUEST_TIMEOUT):
        self.user = user
        self.thread_index = thread_index
        self.encrypted_api = encrypted_api
        self.requestManager = RequestManager(user, self.thread_index, SYNC_API_COMMANDS,
                                             self.encrypted_api, request_timeout)
        self.xPubKeySignedByCold = None
        self.coinToCoinsResponseSignedByCold = None

    def get_user(self):
        return self.user

    """----------------------------------------- User from qr creation functions ------------------------------------"""
    """
     * fromQr
     * @param qr_location_or_value the location of the file containing the qr data or the data itself (with disregard to the checksum!)
     * @param force_ip_address other optional ip address to override the address in the qr
     * @return ApiClient object that can run api functions
    """

    @classmethod
    def fromQr(cls, qr_location_or_value: str = "example_qr.txt", force_ip_address: str = "", thread_index=0,
               encrypted_api=True):
        user = getInfoFromQr(qr_location_or_value, force_ip_address)
        return cls(user, thread_index, encrypted_api)

    """
     * getUserDataFromQrString
     * @param qrStringData qr string data from cold wallet
     * @return data about given user
    """

    @classmethod
    def getUserDataFromQrString(self, qrStringData):
        data = getAllInfoFromQr(qrStringData)
        print(
            "sharedsecret: " + data[0] + "\n" +
            "userprivatekey: " + data[1] + "\n" +
            "userpublickey: " + data[2] + "\n" +
            "serverip: " + binascii.unhexlify(data[3]).decode() + "\n" +
            "apikeys: " + data[4] + "\n" +
            "useridentifier: " + data[5] + "\n" +
            "username: " + str(base64.b16decode(data[6]).decode('utf_8')) + "\n" +
            "serveridentifier: " + data[7] + "\n" +
            "aesKey: " + data[8]
        )

    """---------------------------- End of user from qr creation functions ------------------------------------------"""

    """----------------------------------------- Api user creation functions ----------------------------------------"""
    """
     * decryptApiUserMessages
     * @param verifyingKey the DiffieHellman publicKey that was inserted to the cold wallet
     * @param ip the hot wallet ip
     * @return decrypted data to create the user
    """

    @staticmethod
    def decryptApiUserMessages(verifyingKey, ip, isProduction, requestTimeout=RequestManager.DEFAULT_REQUEST_TIMEOUT):
        apiSignKey, apiVerifingKey = getRemoteKeys(verifyingKey)
        jsonObj = {}
        jsonObj["PublicKey"] = verifyingKey
        response = RequestManager.send_unsecure(ip, "registerRemoteUser", jsonObj,
                                                encrypt_api=True, request_timeout=requestTimeout)
        encryptedData = response["EncryptedMessage"]["EncryptedData"]
        iv = response["EncryptedMessage"]["IV"]
        ColdPublicKey = response["ColdPublicKey"]
        Gk8Signature = response["Gk8Signature"]
        if isProduction is True:
            verifyingKeyHex = "6508310404ba6344cd140c46938e8d691fa5b70fe273b886232008dd5a6453e43e5c5ccdc29ae4ddc63b8a409b49a90d28ff217aa0c5d2b265ccc22b74b9cb2a"
        else:
            verifyingKeyHex = "e563d23bc24cf91ad18ca00a2855c554088f3cd963855c888901423b23c597aeeceb7f7b3213a5e442f1a7b05cb4e3617f7696a2b1052fe68ef1b173e98cc5dc"

        verifyingKey = ecdsa.VerifyingKey.from_string(bytes.fromhex(verifyingKeyHex),
                                                      curve=ecdsa.SECP256k1)
        try:
            if not verifyingKey.verify(bytes.fromhex(Gk8Signature[2:]), ColdPublicKey.encode(), hashfunc=hashlib.sha256,
                                       sigdecode=ecdsa.util.sigdecode_der):
                print("verification failed 1")
                return
        except ecdsa.keys.BadSignatureError:
            print("verification failed 2")
            return
            # Yay, it is signed by GK8!
        parts = ColdPublicKey.split("|")
        if len(parts) != 2:
            print("name format error")
            return
        publicKey, name = parts
        curve = registry.get_curve('secp256r1')
        myPrivateKeyInt = int.from_bytes(bytes.fromhex(apiSignKey), "big")
        coldPublicKeyInt = createPointSecp256r1(bytes.fromhex(publicKey))
        g_to_the_private1_to_the_private2 = (myPrivateKeyInt * coldPublicKeyInt)
        pre_shared_secret = g_to_the_private1_to_the_private2.x
        aes_key_big = sha256(pre_shared_secret.to_bytes(32, "big"))
        aes = AES.new(aes_key_big, AES.MODE_CBC, bytes.fromhex(iv))
        decrypted = aes.decrypt(bytes.fromhex(encryptedData)).decode("utf-8")
        decrypted = decrypted[:decrypted.rfind('\f')]  # clean padding
        return name, decrypted

    """
     * createRemoteUser
     * @param verifyingKey the DiffieHellman publicKey that was inserted to the cold wallet
     * @param ip the hot wallet ip
     * @return ApiClient object that can run api functions
    """

    @staticmethod
    def createRemoteUser(verifingKey, ip, isProduction, requestTimeout=RequestManager.DEFAULT_REQUEST_TIMEOUT):
        name, decrypted = ApiClient.decryptApiUserMessages(verifingKey, ip, isProduction, requestTimeout)
        dummyErrorDetection = "XB0sJI3RRJmgtbJLTOf7Yg=="
        return name, ApiClient.fromQr(decrypted + "," + dummyErrorDetection, ip)

    def encryptedMigrationString(self, ip):
        jsonObj = {}
        jsonObj["PublicKey"] = self.get_user_identifier()
        response = RequestManager.send_unsecure(ip, "encryptedMigrationString", jsonObj,
                                                encrypt_api=True, request_timeout=self.requestManager.request_timeout)
        encryptedData = response["EncryptedMessage"]["EncryptedData"]
        iv = response["EncryptedMessage"]["IV"]
        aes_cipher = AESCipher(self.user.get_user_aes_cold_key())
        return aes_cipher.decrypt(encryptedData, iv)

    """
     * generateApiKeysForApiUser
     * @param none
     * @return ECDSA key pair 
     """

    @staticmethod
    def generateKeys(curve=ecdsa.SECP256k1):
        # generate key pair
        signKeyObj = ecdsa.SigningKey.generate(curve)
        verifyingKeyObj = signKeyObj.get_verifying_key()
        return signKeyObj, verifyingKeyObj

    @staticmethod
    def generateKeysForRemoteUser():
        signKeyObj, verifyingKeyObj = ApiClient.generateKeys(ecdsa.NIST256p)
        encoder = base64.b16encode
        # decode the keys to utf-8 base 16
        signKey = encoder(signKeyObj.to_string()).decode("utf-8")
        verifyingKey = encoder(verifyingKeyObj.to_string()).decode("utf-8")
        verifyingKeyBase36WithChecksum = toBase36AndAddTwoWordsCheckSum(
            int.from_bytes(compress(verifyingKeyObj), byteorder='big'))
        print('Insert the key to cold wallet:' + '\n------------------------------------------------')
        print(verifyingKeyBase36WithChecksum + '\n------------------------------------------------')
        storeRemoteKeys(signKey, verifyingKey)  # stores key pair in file named apiKeys
        return signKey, verifyingKey, verifyingKeyBase36WithChecksum

    def set_server_ip(self, ip: str):
        print("setServerIP ApiClient", ip)
        self.user.set_server_ip(ip)
        # The timeout would remain the same as selected for the previous IP
        self.requestManager = RequestManager(self.user, self.thread_index, SYNC_API_COMMANDS,
                                             self.encrypted_api, self.requestManager.request_timeout)

    """
     * set_request_timeout
     * @param request_timeout The timeout for server API requests (in seconds), or None for no timeout
    """

    def set_request_timeout(self, request_timeout: int):
        self.requestManager.set_request_timeout(request_timeout)

    """-------------------------------------------- End of api user creation functions --------------------------------"""

    """-------------------------------------------- Api functions -----------------------------------------------------"""
    """
     * generateNewAccessToken
     * @param none
     * @return access token to connect the api
    """

    def generateNewAccessToken(self):
        token = self.requestManager.send_generate_access_token()
        return token

    def __getAndAssureXPubKeySignedByColdExist(self):
        if self.xPubKeySignedByCold is None:
            expected_signed_items = [["FunctionData", "XPubKeySignedByCold"]]
            response = self.requestManager.send_request_access_token_included("getXPubKeySignedByCold",
                                                                              {},
                                                                              expected_signed_items=expected_signed_items)
            self.xPubKeySignedByCold = response["FunctionData"]["XPubKeySignedByCold"]
        return self.xPubKeySignedByCold

    # You should force that only if you know a new EVM/ERC20 was added to the system
    def __getAndAssureGetCoinsResponseExist(self, force: bool, coin_symbol_to_force_if_not_exists: set = set()):
        assert isinstance(coin_symbol_to_force_if_not_exists, set)
        if force or self.coinToCoinsResponseSignedByCold is None or\
                not coin_symbol_to_force_if_not_exists.issubset(set(self.coinToCoinsResponseSignedByCold.keys())):
            self.getCoins()
        return self.coinToCoinsResponseSignedByCold

    def isServerEncrypted(self):
        try:
            get_version_response = self.getVersion()
            get_version_response_data = json.loads(get_version_response["Data"])["FunctionData"]
            encrypted_api = get_version_response_data["useEncryption"]
        except Exception as e:
            encrypted_api = True #backward competability
        return encrypted_api

    """
    ############################################################### EVM Smart Contracts  ###############################################################
       _______________                        |*\_/*|________
      |  ___________  |     .-.     .-.      ||_/-\_|______  |
      | |           | |    .****. .****.     | |           | |
      | |   0   0   | |    .*****.*****.     | |   0   0   | |
      | |     -     | |     .Contracts.      | |     -     | |
      | |   \___/   | |      .*******.       | |   \___/   | |
      | |___     ___| |       .*****.        | |___________| |
      |_____|\_/|_____|        .***.         |_______________|
        _|__|/ \|_|_.............*.............._|________|_
       / ********** \                          / ********** \
     /  ************  \                      /  ************  \
    --------------------                    --------------------
    This is an explanation on how to access smart contracts on the EVM networks secured by GK8's MPC
    This is very similar to sending a normal transaction except of:
    1. Instead of sending using the command sendTransaction use sendTransactionToEvmContractWithContractInfo or sendTransactionToEvmContractWithRawHex
        sendTransactionToEvmContractWithContractInfo is meant where you know the parameters you want to send to the function and the ABI 
        sendTransactionToEvmContractWithRawHex is meant where this data is already compiled to binary and ready to be sent 
        **** Notice that sending funds to the fallback function is done with sendTransaction.

    2. Transfer with amount 0 wei is allowed now as long as it sending to a smart contract

    3. When sending transaction to a smart contract low gas limit is forbidden, 21500 is tested, higher fee is recommended

    4. It is highly recommended to send transactions with flag ValidateTransaction so that the system can run eth_call and prevent wasting gas


    It is important to understand that all the things in GK8 system also applies on smart contracts. Limitation, Policies approvals and more.



    Please read the documentation on sendTransactionToEvmContractWithContractInfo or sendTransactionToEvmContractWithRawHex below for more details. 
    """

    """
    https://solidity.readthedocs.io/en/develop/abi-spec.html
    * sendTransactionToEvmContractWithRawHex
    * @param account_id The account ID wanted to use in this operation
    * @param contract_address String of the address of the contract to send to
    * @param amount the amount wanted to send with this transaction, in Wei
    * @param gas_price the gas_price we want to transfer with, in Wei
    * @param gas_limit the gas limit we want to transfer, in gas units - must be at least 21500, it is recommended to use getGasLimitSuggestedForTransactionToEvmContractWithRawHex
    * @param raw_data_in_hex binary data parsed and encoded already by the standard in the link above must start with 0x
    * @param validate_transaction if this is true, the MPC wallet will access the node (using eth_call) to check if this
    * transaction is likely to fail and will block the transaction if it is 
    * @param is_group_transaction if we wont send money from group balance default False
    * @param description free text for describing the transaction (will not be sent to the blockchain)
    * @param specificFromAddress Deposit address to send from and only can be used if the account is defined as an Endpoint account.     
    * @param max_priority_fee the max priority fee we want to tip the miner. Should be sent in EVM / ERC20 transactions
     *        that are EIP1559 type, otherwise should be None. (for more info, read https://metamask.io/1559/)
    * @param evm_coin_symbol the coin symbol of the EVM network on which the smart contract is deployed, for example: ETH, CELO, etc...          
    * @return Dict ready to be sent to the MPC by the function sendTransaction 
    
    example:
    
     * ETH: sendTransactionToEvmContractWithRawHex(1,"0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe","6000","50000000000",70000, "0x48656c6c6f2c20776f726c64210000000000000000000000000000000000000000",True,"false","example","0xe75fb554e433e03763a1560646ee22dcb74e5274b34c5ad644e7c0f619a7e1d0","ETH","1000000000")
    """



    def sendTransactionToEvmContractWithRawHex(self, account_id: int, contract_address: str, amount: str,
                                               gas_price: int, gas_limit: int,
                                               raw_data_in_hex: str, validate_transaction: bool = True,
                                               is_group_transaction: str = "false", description: str = "",
                                               specificFromAddress: str = None, evm_coin_symbol: str = "ETH",
                                               max_priority_fee=None):
        if gas_limit < 21500:
            raise Exception("Contract access with low gas limit is forbidden")
        if raw_data_in_hex == "" or raw_data_in_hex == "0x":
            raise Exception("Contract data cannot be empty")
        return self.__sendTransactionThatMightBeAContractAccess(account_id, evm_coin_symbol,
                                                                [[contract_address, amount]],
                                                                gas_price, gas_limit, is_group_transaction,
                                                                description, specificFromAddress,
                                                                ApiClient.__generateDataForContractFromRaw(
                                                                    raw_data_in_hex, validate_transaction),
                                                                max_priority_fee=max_priority_fee)

    sendTransactionToEthereumContractWithRawHex = sendTransactionToEvmContractWithRawHex

    def getGasLimitSuggestedForTransactionToEvmContractWithRawHex(self, account_id: int, contract_address: str,
                                                                  amount: str,
                                                                  gas_price: int, raw_data_in_hex: str,
                                                                  validate_transaction: bool = True,
                                                                  specificFromAddress: str = None,
                                                                  evm_coin_symbol: str = "ETH"):
        if raw_data_in_hex == "" or raw_data_in_hex == "0x":
            raise Exception("Contract data cannot be empty")
        return self.__getGasLimitSuggestedForTransactionThatMightBeAContractAccess(account_id, evm_coin_symbol,
                                                                                   [[contract_address, amount]],
                                                                                   gas_price, specificFromAddress,
                                                                                   ApiClient.__generateDataForContractFromRaw(
                                                                                       raw_data_in_hex,
                                                                                       validate_transaction))

    @staticmethod
    def __generateDataForContractFromRaw(raw_data_in_hex: str, validate_transaction: bool = True):
        if len(raw_data_in_hex) < 2 or raw_data_in_hex[:2] != "0x":
            raw_data_in_hex = "0x" + raw_data_in_hex
        return {"RawData": raw_data_in_hex, "validateTransaction": validate_transaction}

    """
    https://solidity.readthedocs.io/en/develop/abi-spec.html
    * sendTransactionToEvmContractWithContractInfo 
    * @param account_id The account ID wanted to use in this operation
    * @param contract_address String of the address of the contract to send to
    * @param amount the amount to send with this transaction, in Wei
    * @param gas_price the gas_price we want to transfer with, in wei
    * @param gas_limit the gas limit we want to transfer, in gas units - must be at least 21500
    * @param function_name string representing the function name to call, e.g. "foo" (with no params)
    * @param parameters_fields_types_and_values list of pairs of "type" and value for each parameter in the function (see below)
            e.g [["int","32432"],["bytes","0x1234567890"],["int8[3]",["-20","0","127"]],["string","got the idea, right?"]]
            * @subparam type string representing the parameters types, e.g. ["int32","uint256","string[]","bool"]
                    GK8 system supports all the types supported by solidity:
                    * uint<M>: unsigned integer type of M bits, 0 < M <= 256, M % 8 == 0. e.g. uint32, uint8, uint256. (uint is uint256)
                    * int<M>: signed integer type of M bits, 0 < M <= 256, M % 8 == 0.  e.g. int32, int8, int256. (int is int256)
                    * address
                    * bool
                    * bytes<M>: binary type of M bytes, 0 < M <= 32
                    * function: an address (20 bytes) followed by a function selector (4 bytes).
                    * <type>[M]: an array of constant size of any type, e.g. int[32], string[7], bytes3[2],.... 
                    * bytes: an unlimited collection of bytes
                    * string: string in UTF8
                    * <type>[]: a variable-length array of elements of the given type. e.g. int[], string[], bytes3[],....
                    * tuple: (T1,T2,...,Tn): tuple consisting of the types T1, …, Tn, n >= 0, e.g. (int,string,int[32])

                    IMPORTANT: you must spell the type name correctly! No redundant spaces, no Capitals, spelling it in a wrong way will cause the request to fail.

            * @subparam value representing the value of parameters in parameters_fields_types, e.g. ["12345678","34769874356980435879",[1.2,34,-1.2],["bl","cl","mkasdsa"],"True"]
                    Except than "function", "fixed length array", "variable-length array", "tuple", all the values must be given as strings, even ints.
                    Those 4 types are given as python lists containing in inner value in each cell. Some examples:
                    * uint<M>: any base 10 non negative number in range of M bits: "2131"  /  "12131"  /  "45678906543467890"  /  "0"
                    * int<M>:  any base 10 number in range of two's complement M bits: "2131"  /  "-2131"  /  "45678906543467890"  / "0"
                    * address: any EVM address, 0x + 40 hex chars "0xEDF9C138F990b4ed9b7cb83F6ad8fF76017572B9"   /   "0x0000C138F990B4ED9B7CB83F6AD8FF76017572B9", "0xedf9c138f990b4ed9b7cb83f6ad8ff76017572b9"
                    * bool:   "true" / "false"
                    * bytes<M>: given in hex with 0x prefix, must hold 2*M hex characters "0x00F9C138F990b4ed9b7c"   /   "0xEDF9C138F990B4ED9B7CB83F6AD8FF76017572B9"  /  "0xe9"
                    * function: a python list of length 2, holding address and one of "4 bytes digested function pointer e.g. 0x1234abcd" or "function declaration ready to be hashed, e.g. 'foo(int,string)'"
                                ["0xEDF9C138F990b4ed9b7cb83F6ad8fF76017572B9","0x1234abcd"]  /  ["0x0000C138F990B4ED9B7CB83F6AD8FF76017572B9","foo(int,string)"]
                    * <type>[M]: python list of <type>, e.g. 
                                         int[3]      -> ["2342","-32432","1"]
                                         bytes3[2]   -> ["0x232323","0x000011","0xabABcd"]
                                         bool[3]     -> ["True","True","False"]
                    * bytes: same as bytes<M>, must start with 0x and hold an even non negative count of hex digits
                    * string: "hello world!" / "שלום עולם!" / "Ethereum is so cool :)"
                    * <type>[]: same as <type>[M]
                    * tuple: (T1,T2,...,Tn):  python list of the types, e.g. 
                                        (int,string,bool[3]) -> ["-2133242","tuples are kind of redundant,right?", ["True","True","False"]]
                                        (int,string,(int, bool[3])) -> ["7","tuples are redundant", ["7",["True","True","False"]]]      
    * @param validate_transaction if this is true, the MPC wallet will access the node (using eth_call) 
                                    to check if this transaction is likely to fail and will block the transaction if it is 
    * @param is_group_transaction if we wont send money from group balance default False
    * @param description free text for describing the transaction (will not be sent to the blockchain)
    * @param specificFromAddress Deposit address to send from and only can be used if the account is defined as an Endpoint account
    * @param max_priority_fee the max priority fee we want to tip the miner. Should be sent in EVM / ERC20 transactions
     *        that are EIP1559 type, otherwise should be None. (for more info, read https://metamask.io/1559/)
    * @param evm_coin_symbol the coin symbol of the EVM network on which the smart contract is deployed, for example: ETH, CELO, etc...
    * @return Dict, e.g. {"FunctionName":"transfer",
                           "ParametersFieldsTypesAndValues":[["address","0xEDF9C138F990b4ed9b7cb83F6ad8fF76017572B9"], ["uint256","100000000000000000"]]} 
                           
    example:
    
     * ETH: sendTransactionToEvmContractWithRawHex(1,"0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe","6000","50000000000",70000, "transfer",[["address","0xEDF9C138F990b4ed9b7cb83F6ad8fF76017572B9"], ["uint256","100000000000000000"]],True,"false","transferExample","0xe75fb554e433e03763a1560646ee22dcb74e5274b34c5ad644e7c0f619a7e1d0","1000000000","ETH")
                           
    """

    def sendTransactionToEvmContractWithContractInfo(self, account_id: int, contract_address: str, amount: str,
                                                     gas_price: int, gas_limit: int,
                                                     function_name: str, parameters_fields_types_and_values: list,
                                                     validate_transaction: bool = True,
                                                     is_group_transaction: str = "false", description: str = "",
                                                     specificFromAddress: str = None, max_priority_fee=None,
                                                     evm_coin_symbol: str = "ETH"):
        if gas_limit < 21500:
            raise Exception("Contract access with low gas limit is forbidden")
        return self.__sendTransactionThatMightBeAContractAccess(account_id, evm_coin_symbol,
                                                                [[contract_address, amount]],
                                                                gas_price, gas_limit, is_group_transaction, description,
                                                                specificFromAddress,
                                                                ApiClient.__generateDataForContractFromInfo(
                                                                    function_name, parameters_fields_types_and_values,
                                                                    validate_transaction),
                                                                max_priority_fee=max_priority_fee)

    sendTransactionToEthereumContractWithContractInfo = sendTransactionToEvmContractWithContractInfo

    def getGasLimitSuggestedForTransactionToEvmContractWithContractInfo(self, account_id: int, contract_address: str,
                                                                        amount: str,
                                                                        gas_price: int, function_name: str,
                                                                        parameters_fields_types_and_values: list,
                                                                        validate_transaction: bool = True,
                                                                        evm_coin_symbol: str = "ETH"):
        return self.__getGasLimitSuggestedForTransactionThatMightBeAContractAccess(account_id, evm_coin_symbol,
                                                                                   [[contract_address, amount]],
                                                                                   gas_price, "",
                                                                                   ApiClient.__generateDataForContractFromInfo(
                                                                                       function_name,
                                                                                       parameters_fields_types_and_values,
                                                                                       validate_transaction))

    @staticmethod
    def __generateDataForContractFromInfo(function_name: str, parameters_fields_types_and_values: list,
                                          validate_transaction: bool = True):
        for [type, value] in parameters_fields_types_and_values:
            if not isinstance(type, str):
                raise Exception("all variables in parameters_fields_types must be strings")
        return {"FunctionName": function_name, "ParametersFieldsTypesAndValues": parameters_fields_types_and_values,
                "validateTransaction": validate_transaction}

    """
     * sendTransaction
     * @param account_id The account ID we want to use in this operation
     * @param coin_type Coin symbol we want to use in this operation
     * @param outputs List in all coins: [(destination_address:str,amount_to_transfer:int)] 
                           in XRP it is optional to add destination tag [(destination_address:str, amount_to_transfer:int, destination_tag:int)]
                           in XLM it is optional to add Memo [(destination_address:str, amount_to_transfer:int, StellarMemo:class)]
     * @param fee the fee/gas price/max fee/.... we want to transfer, depending on the coin 
     * @param gas_limit the gas limit we want to transfer need to be None unless ETH/ERC20/XTZ
     * @param is_group_transaction "true" if we want to send money from group balance, else "false", default false 
     * @param description free text for describing the transaction (will not be sent to the blockchain)
     * @param specificFromAddress Deposite address to send from and only can be used if the account is defined as an Endpoint account.
     * @param max_priority_fee the max priority fee we want to tip the miner. Should be sent in EVM / ERC20 transactions
     *        that are EIP1559 type, otherwise should be None. (for more info, read https://metamask.io/1559/)
     * @param max_storage the max storage for the transaction. Only relevant for XTZ.
                        1420 for non existing address in blockchain and 0 for existing address, to be on the safe side you may always use 1420
     * @return on success transactions array: [{'AmountToTransfer': '600','DestinationAddress': '3CSXFAJoWJqEXqV9LFjsbagreAt5PpGLzF'}]}
        ********** NOTE: success or failure in this api call does not necessarily means success or failure in the transaction itself
        ********** for example, the transaction may work by the response to the client can be lost in communication (if the internet is down for the client)
        ********** another example is that the transaction was approved here but failed in the signing process
        To know the status of the transaction you can access the function statusForTransaction.
        To get the token to send those functions you should call getCurrentToken one action BEFORE sendTransaction:
            myTokenToStoreInTheDb = user.getCurrentToken()
            sendTransaction(1,"BTC",[[address,547]],6,None)
            .....
            user.statusForTransaction(myTokenToStoreInTheDb,"BTC")
     examples:
      * BTC: sendTransaction(1,"BTC",[("bc1qx65xcxz6dfsge2g4eaerercslh83y66wrpm79r","6000"),("13eFhUc3ugSCd6C63cZrTQfHgkBzoMpzF4","10000000")],"100")
             
      * BCH: sendTransaction(1,"BCH",[("bitcoincash:qrsa3h493qk778en3xpwena5ndfndnmq6quvcdzwup","6000"),("13eFhUc3ugSCd6C63cZrTQfHgkBzoMpzF4","10000000")],"100")
      
      * ETH: sendTransaction(1,"ETH",[("f7DA48a6400a2A89a1901C58c5FA3546574B2CC2","6000")],"10000000000",21000, max_priority_fee="1000000000")

      * XRP: sendTransaction(1,"XRP",[("rHr5Aejv6MGW1Q3tGknsvTbR3fztZ9mH4x","5",1)],10,None)    
             sendTransaction(1,"XRP",[("rHr5Aejv6MGW1Q3tGknsvTbR3fztZ9mH4x","5")],10,None)   
             
      * XLM: sendTransaction(1,"XLM",[("GA3F24IKDWUMOOELZNI4B3HSOAOCNHC6ZFAOZ7RLHVDAQND25TJ2LOGF","5",StellarMemo(StellarMemo.StellarMemoType.Text,"My Memo") )],100) 
             sendTransaction(1,"XLM",[("GA3F24IKDWUMOOELZNI4B3HSOAOCNHC6ZFAOZ7RLHVDAQND25TJ2LOGF","5" )],100) 
      
      * XTZ: sendTRansaction(1,"XTZ",[("tz1ckGsovfBqqXyZSW3WfSRDTmLrnE65f2H3","6000")], "10000000000", 1, max_storage = 1420)
      
      * ADA sendTransaction(1,"ADA",[("addr_test1qrsvf3wv74sx5cy45esshqmxund2ag84rflmtk5qyxnydmc6plc97jjghl99ffzugjuaq6q4g8v73lnpru7wpk8730vs0t74mz","10000000")], "44") 
        
      # CELO is a non london fork evm  
      * CELO:  sendTransaction(1,"CELO",[("f7DA48a6400a2A89a1901C58c5FA3546574B2CC2","6000")],"10000000000",21000) 
      
      # CEL is celsius token based on ETH network
      * CEL: sendTransaction(1,"CEL",[("f7DA48a6400a2A89a1901C58c5FA3546574B2CC2","6000")],"10000000000",100000, max_priority_fee="1000000000")
    """

    def sendTransaction(self, account_id: int, coin_type: str, outputs: list, fee: int, gas_limit: int = None,
                        is_group_transaction: str = "false", description: str = "", specificFromAddress: str = None,
                        max_priority_fee=None, max_storage=None):#only for tezos
        return self.__sendTransactionThatMightBeAContractAccess(account_id, coin_type, outputs, fee, gas_limit,
                                                                is_group_transaction, description, specificFromAddress,
                                                                max_priority_fee=max_priority_fee,
                                                                max_storage=max_storage)

    """
     * getGasLimitSuggestedForTransaction
     * @param account_id The account ID we want to use in this operation
     * @param coin_type Coin symbol we want to use in this operation
     * @param outputs List in all coins: [(destination_address:str,amount_to_transfer:int)] 
                           in XLM it is optional to add Memo [(destination_address:str, amount_to_transfer:int, StellarMemo:class)]
     * @param fee the fee/gas price/max fee/.... we want to transfer, depending on the coin 
     * @param specificFromAddress Deposit address to send from, only can be used if the account is defined as an Endpoint account.
     * @param max_priority_fee the max priority fee we want to tip the miner. Should be sent in EVM / ERC20 transactions
     *        that are EIP1559 type, otherwise should be None. (for more info, read https://metamask.io/1559/)
       @return returns the suggested gas limit for the transaction as "GasLimitSuggested" in wei
     example:
          
    getGasLimitSuggestedForTransaction(1,"ETH",[("f7DA48a6400a2A89a1901C58c5FA3546574B2CC2","6000")],"10000000000", max_priority_fee="1000000000")
    """
    
    def getGasLimitSuggestedForTransaction(self, account_id: int, coin_type: str, outputs: list, fee: int,
                                           specificFromAddress: str = None, max_priority_fee=None):
        return self.__getGasLimitSuggestedForTransactionThatMightBeAContractAccess(account_id, coin_type, outputs, fee,
                                                                                   specificFromAddress,
                                                                                   max_priority_fee=max_priority_fee)

    class StellarMemo(object):

        class StellarMemoType(Enum):
            Text = 1
            Id = 2
            Hash = 3
            Return = 4

        def __init__(self, memoType: StellarMemoType, memoData: str):
            self.memoType = memoType
            self.memoData = memoData

    def getCoinFamilyAndEipType(self, coin_type: str):
        coin_family = None
        eip_type = None
        parent_evm = None
        coin = self.__getAndAssureGetCoinsResponseExist(False,{coin_type})[coin_type]
        coin_family = coin["CoinFamily"]
        if "EipType" in coin:
            eip_type = coin["EipType"]
            if coin_family == CoinFamily.ERC20.value:
                parent_evm = coin["ParentEvm"]

        return coin_family, eip_type, parent_evm

    """
    same as sendTransaction but can also accept data for smart contracts
        * @param data_for_contract only when sending to a contract, data to send to an EVM smart contract, recommended to be generated by generateDataForContractFromRaw or generateDataForContractFromRaw
        examples:
        * ETH: sendTransaction(1,"ETH",[(address,"5")],6000000000,100000,False,{"FunctionName":"transfer",
                                                    "ParametersFieldsTypesAndValues":[["address","0xEDF9C138F990b4ed9b7cb83F6ad8fF76017572B9"], ["uint256","100000000000000000"]],
                                                    "validateTransaction":True})


        * ETH: sendTransaction(1,"ETH",[(address,"0")],6000000000,100000,False,
                                                {"RawData":"0xa9059cbb000000000000000000000000edf9c138f990b4ed9b7cb83f6ad8ff76017572b9000000000000000000000000000000000000000000000000016345785d8a0000",
                                                    "validateTransaction":True})
    """

    def __sendTransactionThatMightBeAContractAccess(self, account_id: int, coin_type: str, outputs: list, fee: int,
                                                    gas_limit: int, is_group_transaction: str = "false",
                                                    description: str = "", specificFromAddress: str = None,
                                                    data_for_contract=None, max_priority_fee=None, max_storage=None):
        global mutex
        mutex.acquire()
        try:
            if len(description) > 1900:
                raise Exception("description max length is 1900")
            txs = []
            data: Union[Tuple[str, str], Tuple[str, str, int], Tuple[str, str, ApiClient.StellarMemo]]
            for data in outputs:
                if coin_type == "XRP" and len(data) > 2:
                    destination_address, amount_to_transfer, destination_tag = data
                    txs.append({"DestinationAddress": destination_address, "AmountToTransfer": str(amount_to_transfer),
                                "DestinationTag": destination_tag})
                elif coin_type == "XLM" and len(data) > 2:
                    destination_address, amount_to_transfer, memo = data
                    assert (isinstance(memo, ApiClient.StellarMemo))
                    txs.append({"DestinationAddress": destination_address, "AmountToTransfer": str(amount_to_transfer),
                                "Memo": memo.memoData, "MemoType": str(memo.memoType.name)})
                else:
                    destination_address, amount_to_transfer = data
                    txs.append({"DestinationAddress": destination_address, "AmountToTransfer": str(amount_to_transfer)})

            final_fee = {"Fee": fee}

            coin_family, eip_type, parent_evm = self.getCoinFamilyAndEipType(coin_type)
            if coin_family == CoinFamily.EVM.value or coin_family == CoinFamily.ERC20.value or coin_type == "XTZ":
                assert gas_limit is not None, "Gas limit can not be None"
                if coin_type == "XTZ":
                    assert gas_limit >= 1420, "Gas limit must be a number greater than 1420"
                    assert max_storage is not None, "Max storage can not be None"
                    final_fee = {"GasPrice": str(fee), "GasLimit": str(gas_limit),
                                 "StorageLimit": max_storage}
                else:
                    assert gas_limit >= 21000, "Gas limit must be a number greater than 21000"
                    final_fee = {"GasPrice": str(fee), "GasLimit": gas_limit}
                    if eip_type == EipType.Eip1559.value:
                        if coin_type != "ETH" and parent_evm != "ETH": #backward compatibility
                            assert max_priority_fee is not None, "Max priority fee can not be None"
                        if max_priority_fee is not None:
                            final_fee["MaxPriorityFee"] = str(max_priority_fee)
                    else:
                        assert max_priority_fee is None, "Max priority fee should be None"
            else:
                assert max_priority_fee is None, f"Max priority fee must be None for {coin_type} coin"
            request = {
                "AccountId": account_id,
                "CoinType": coin_type,
                "Fee": final_fee,
                "GroupTransaction": is_group_transaction,
                "Transactions": txs,
                "UserDescription": description,
            }
            if specificFromAddress is not None:
                request["SpecificFromAddress"] = specificFromAddress

            if data_for_contract is not None:
                request["DataForContract"] = data_for_contract
            return self.requestManager.send_request_access_token_included("sendTransaction", request)
        finally:
            mutex.release()

    def __getGasLimitSuggestedForTransactionThatMightBeAContractAccess(self, account_id: int, coin_type: str,
                                                                       outputs: list, fee: int,
                                                                       specificFromAddress: str = None,
                                                                       data_for_contract=None, max_priority_fee=None):
        assert coin_type != "BTC" and coin_type != "XRP" and coin_type != "BCH" and coin_type != "XLM" and coin_type != "ADA" and coin_type != "XTZ", "Available only for Ethereum-based coins "
        txs = []
        data: Tuple[str, str]
        for data in outputs:
            destination_address, amount_to_transfer = data
            txs.append(
                {"DestinationAddress": destination_address, "AmountToTransfer": str(amount_to_transfer)})

        if max_priority_fee is not None:
            final_fee = {"GasPrice": str(fee), "MaxPriorityFee": str(max_priority_fee)}
        else:
            final_fee = {"GasPrice": str(fee)}
        request = {
            "AccountId": account_id,
            "CoinType": coin_type,
            "Fee": final_fee,
            "Transactions": txs
        }
        if specificFromAddress is not None:
            request["SpecificFromAddress"] = specificFromAddress
        if data_for_contract is not None:
            request["DataForContract"] = data_for_contract
        return self.requestManager.send_request_access_token_included("getGasLimitSuggested", request)

    """
     * __evaluateSmartContractTransaction
     * evaluates a smart contract transaction by calling an eth call and returns the EthCallResponse in the response -
     * error message in case of eth call failure, and the return value of the eth call in case of eth call success.
     * @param from_address - the address where the transaction is sent from.
     * @param contract_address - the address of the contract to send from.
     * @param data_for_contract - the contract data contract as Json - may contain a function name in "FunctionName" field
     * and parameters types & values in "ParametersFieldsTypesAndValues field, or all the data parsed to bytes in "RawData" field.
     * @param gas_limit - the gas limit we want to transfer, in gas units - if None the gas limit will be the default value from the eth call.
     * @param gas_price - the gas price we want to transfer with, in Wei - if None the gas price will be the default value from the eth call.
     * @param amount - the amount to send with this transaction, in Wei - if None the amount will be the default value from the eth call.
     * @param evm_coin_symbol - the coin symbol of the EVM network on which the smart contract is deployed, for example: ETH, CELO, etc...
    """

    def __evaluateSmartContractTransaction(self, from_address: str, contract_address: str, data_for_contract: dict,
                                           gas_limit: int = None, gas_price: int = None, amount: int = None,
                                           evm_coin_symbol: str = "ETH"):
        request = {
            "FromAddress": from_address,
            "ContractAddress": contract_address,
        }
        request["EvmCoinSymbol"] = str(evm_coin_symbol)
        if gas_limit is not None:
            request["GasLimit"] = str(gas_limit)
        if gas_price is not None:
            request["GasPrice"] = str(gas_price)
        if amount is not None:
            request["Amount"] = str(amount)
        if data_for_contract is not None:
            request["DataForContract"] = data_for_contract

        return self.requestManager.send_request_access_token_included("evaluateSmartContractTransaction", request)

    """
     * https://solidity.readthedocs.io/en/develop/abi-spec.html
     * evaluateSmartContractTransactionWithContractInfo
     * evaluates a smart contract transaction with data for contract as function name & parameters fields types and values
     * by calling an eth call, and returns the EthCallResponse in the response - error message in case of eth call failure,
     * and the return value of the eth call in case of eth call success.
     * @param from_address - the address where the transaction is sent from.
     * @param contract_address - the address of the contract to send from.
     * @param function_name string representing the function name to call, e.g. "foo" (with no params).
     * @param parameters_fields_types_and_values list of pairs of "type" and value for each parameter in the function (see below)
            e.g [["int","32432"],["bytes","0x1234567890"],["int8[3]",["-20","0","127"]],["string","got the idea, right?"]
            * @subparam type string representing the parameters types, e.g. ["int32","uint256","string[]","bool"]
                    GK8 system supports all the types supported by solidity:
                    * uint<M>: unsigned integer type of M bits, 0 < M <= 256, M % 8 == 0. e.g. uint32, uint8, uint256. (uint is uint256)
                    * int<M>:  signed integer type of M bits, 0 < M <= 256, M % 8 == 0.  e.g. int32, int8, int256. (int is int256)
                    * address
                    * bool
                    * bytes<M>: binary type of M bytes, 0 < M <= 32
                    * function: an address (20 bytes) followed by a function selector (4 bytes)
                    * <type>[M]: an array of constant size of any type, e.g. int[32], string[7], bytes3[2],.... 
                    * bytes: an unlimited collection of bytes
                    * string: string in UTF8
                    * <type>[]: a variable-length array of elements of the given type. e.g. int[], string[], bytes3[],....
                    * tuple: (T1,T2,...,Tn): tuple consisting of the types T1, …, Tn, n >= 0, e.g. (int,string,int[32])

                    IMPORTANT: you must spell the type name correctly! No redundant spaces, no Capitals, spelling it in a wrong way will cause the request to fail.

            * @subparam value representing the value of parameters in parameters_fields_types, e.g. ["12345678","34769874356980435879",[1,34,-1],["bl","cl","mkasdsa"],"True"]
                    Except than "function", "fixed length array" "variable-length array", "tuple", all the values must be given as strings, even ints.
                    Those 4 types are given as python lists containing in inner value in each cell. Some examples:
                    * uint<M>: any base 10 non negative number in range of M bits: "2131"  /  "12131"  /  "45678906543467890"  /  "0"
                    * int<M>:  any base 10 number in range of two's complement M bits "2131"  /  "-2131"  /  "45678906543467890"  / "0"
                    * address: any EVM address, 0x + 40 hex chars "0xEDF9C138F990b4ed9b7cb83F6ad8fF76017572B9"   /   "0x0000C138F990B4ED9B7CB83F6AD8FF76017572B9"  /  "0xedf9c138f990b4ed9b7cb83f6ad8ff76017572b9"
                    * bool:   "true" / "false"
                    * bytes<M>: given in hex with 0x prefix, must hold 2*M hex characters "0x00F9C138F990b4ed9b7c"   /   "0xEDF9C138F990B4ED9B7CB83F6AD8FF76017572B9"  /  "0xe9"
                    * function: a python list of length 2, holding address and one of "4 bytes digested function pointer e.g. 0x1234abcd" or "function declaration ready to be hashed, e.g. 'foo(int,string)'"
                                ["0xEDF9C138F990b4ed9b7cb83F6ad8fF76017572B9","0x1234abcd"]  /  ["0x0000C138F990B4ED9B7CB83F6AD8FF76017572B9","foo(int,string)"]
                    * <type>[M]: python list of <type>, e.g. 
                                         int[3]      -> ["2342","-32432","1"]
                                         bytes3[2]   -> ["0x232323","0x000011","0xabABcd"]
                                         bool[3]     -> ["True","True","False"]
                    * bytes: same as bytes<M>, must start with 0x and hold an even non negative count of hex digits
                    * string: "hello world!" / "שלום עולם!" / "Ethereum is so cool :)"
                    * <type>[]: same as <type>[M]
                    * tuple: (T1,T2,...,Tn):  python list of the types, e.g. 
                                        (int,string,bool[3]) -> ["-2133242","tuples are kind of redundant,right?", ["True","True","False"]]
                                        (int,string,(int, bool[3])) -> ["7","tuples are redundant", ["7",["True","True","False"]]]      
     * @param gas_limit - the gas limit we want to transfer, in gas units - if None the gas limit will be the default value from the eth call.
     * @param gas_price - the gas price we want to transfer with, in Wei - if None the gas price will be the default value from the eth call.
     * @param amount - the amount to send with this transaction, in Wei - if None the amount will be the default value from the eth call.
     * @param evm_coin_symbol - the coin symbol of the EVM network on which the smart contract is deployed, for example: ETH, CELO, etc...
     
     * @return  returns ETHCallReturnValue if succeed else error.
     
     * example: 
     
     *evaluateSmartContractTransactionWithContractInfo("0xd38fcFD88C41F32E4711f3722375dD611b42A024","0x963d0aef2a6ba868b38cb032f2a81db145c467fb","transfer",[("0x6705ff69a6745ee35e2a7c3a0A8fb27698C7ea67","1")])
    """

    def evaluateSmartContractTransactionWithContractInfo(self, from_address: str, contract_address: str,
                                                         function_name: str,
                                                         parameters_fields_types_and_values: list,
                                                         gas_limit: int = None, gas_price: int = None,
                                                         amount: int = None, evm_coin_symbol: str = "ETH"):
        contract_data = {"FunctionName": function_name,
                         "ParametersFieldsTypesAndValues": parameters_fields_types_and_values}
        return self.__evaluateSmartContractTransaction(from_address, contract_address, contract_data, gas_limit,
                                                       gas_price, amount, evm_coin_symbol)

    """
     * https://solidity.readthedocs.io/en/develop/abi-spec.html
     * evaluateSmartContractTransactionWithContractInfo
     * evaluates a smart contract transaction with data for contract as raw data in hex, by calling an eth call and returns the
     * EthCallResponse in the response - error message in case of eth call failure, and the return value of the
     * eth call in case of eth call success.
     * @param from_address - the address where the transaction is sent from.
     * @param contract_address - the address of the contract to send from.
     * @param raw_data_in_hex binary data parsed and encoded already by the standard in the link above, must start with 0x.
     * @param gas_limit - the gas limit we want to transfer, in gas units - if None the gas limit will be the default value from the eth call.
     * @param gas_price - the gas price we want to transfer with, in Wei - if None the gas price will be the default value from the eth call.
     * @param amount - the amount to send with this transaction, in Wei - if None the amount will be the default value from the eth call.
     * @param evm_coin_symbol - the coin symbol of the EVM network on which the smart contract is deployed, for example: ETH, CELO, etc...
     * @return returns ETHCallReturnValue if succeed else error.
     
     example: 
     
     *evaluateSmartContractTransactionWithRawHex("0xd38fcFD88C41F32E4711f3722375dD611b42A024","0x963d0aef2a6ba868b38cb032f2a81db145c467fb","0xa9059cbb000000000000000000000000963d0aef2a6ba868b38cb032f2a81db145c467fb0000000000000000000000000000000000000000000000056bc75e2d63100000,
     600000,1000000000,0,"ETH")
    """

    def evaluateSmartContractTransactionWithRawHex(self, from_address: str, contract_address: str, raw_data_in_hex: str,
                                                   gas_limit: int = None, gas_price: int = None, amount: int = None,
                                                   evm_coin_symbol="ETH"):
        if len(raw_data_in_hex) < 2 or raw_data_in_hex[:2] != "0x":
            raw_data_in_hex = "0x" + raw_data_in_hex

        contract_data = {"RawData": raw_data_in_hex}

        return self.__evaluateSmartContractTransaction(from_address, contract_address, contract_data, gas_limit,
                                                       gas_price, amount, evm_coin_symbol)

    """
     * evaluateSmartContractTransactionWithoutDataForContract
     * evaluates a smart contract transaction without data for contract by calling an eth call and returns the
     * EthCallResponse in the response - error message in case of eth call failure, and the return value of the
     * eth call in case of eth call success.
     * @param from_address - the address where the transaction is sent from.
     * @param contract_address - the address of the contract to send from.
     * @param gas_limit - the gas limit we want to transfer, in gas units - if None the gas limit will be the default value from the eth call.
     * @param gas_price - the gas price we want to transfer with, in Wei - if None the gas price will be the default value from the eth call.
     * @param amount - the amount to send with this transaction, in Wei - if None the amount will be the default value from the eth call.
     * @param evm_coin_symbol - the coin symbol of the EVM network on which the smart contract is deployed, for example: ETH, CELO, etc...
     * @return returns ETHCallReturnValue if succeed else error.
     *example:
     
     *evaluateSmartContractTransactionWithoutDataForContract("0xd38fcFD88C41F32E4711f3722375dD611b42A024","0x963d0aef2a6ba868b38cb032f2a81db145c467fb","ETH")
    """

    def evaluateSmartContractTransactionWithoutDataForContract(self, from_address: str, contract_address: str,
                                                               gas_limit: int = None, gas_price: int = None,
                                                               amount: int = None, evm_coin_symbol="ETH"):
        return self.__evaluateSmartContractTransaction(from_address, contract_address, None, gas_limit, gas_price,
                                                       amount, evm_coin_symbol)

    """
     * getFundsForAddress
     * @param account_id the account to get funds to in this operation
     * @param address the address to get funds to in this operation
     * @param coinType The symbol of the coin used in this operation
     * @return funds for given address as "funds" in wei
     
     example:
     
     getFundsForAddress(1,"3Q9oEdmKU5w2p35gPrkBTkb2a9z44gLTAS","BTC")
    """

    def getFundsForAddress(self, account_id: int, address: str, coin_type: str):
        return self.requestManager.send_request_access_token_included("getFundsForAddress",
                                                                      {"AccountId": account_id, "Address": address,
                                                                       "CoinType": coin_type})

    """
     * sendPayloadToBeSigned - for Stellar transactions only
     * @param account_id the account that holds the address to send from
     * @param coin_type one of the coins BTC,ETH,BCH...
     * @param bytesToSign 64 hexadecimal chars to sign on without 0x
     * @param from_address the address to send transaction from
     * @param description free text for the transaction
    """

    def sendPayloadToBeSigned(self, account_id: int, coin_type: str, bytesToSign: str, from_address: str,
                              description: str = ""):
        request = {"AccountId": account_id,
                   "CoinType": coin_type,
                   "BytesToSign": bytesToSign,
                   "UserDescription": description}
        if from_address is not None:
            request["SpecificFromAddress"] = from_address

        return self.requestManager.send_request_access_token_included("sendPayloadToBeSigned", request)

    """
     * getConvertEth1ToEth2SigningRoot - Phase 1 of converting ETH1 to ETH2
     * @param account_id the account that holds the address to send from
     * @param validators_public_keys_hex list of validators public keys in hex (96 hex digits each)
       @return return the Data to sign in Hex, Validator key in Hex
     example:
     
     getConvertEth1ToEth2SigningRoot(1,"0xa00cc6e72f9b325d6c896a2fa0bc4ca2e8893aedffc5e2a6690ca6626dd97830f7147ab617690d40a0b245b85f21cfe7")
    """

    def getConvertEth1ToEth2SigningRoot(self, account_id: int, validators_public_keys_hex: list):
        return self.requestManager.send_request_access_token_included("getConvertEth1ToEth2SigningRoot",
                                                                      {"AccountId": account_id,
                                                                       "ValidatorsPublicKeysHex": validators_public_keys_hex})

    """
     * sendConvertEth1ToEth2Transaction - Phase 2 of converting ETH1 to ETH2
     * @param account_id the account that holds the address to send from
     * @param validator_public_key_hex - validator's public keys in hex (96 hex digits)
     * @param BlsSignatureHex - ETH2 Bonneh-Lynn-Shacham (BLS) signature in hex
     * @param gas_price the gas_price we want to transfer with, in Wei
     * @param gas_limit the gas limit we want to transfer, in gas units - must be at least 21500
     * @param max_priority_fee the max priority fee we want to tip the miner.
     * @param validate_transaction if this is true, the MPC wallet will access the node (using eth_call) to check if this
     * transaction is likely to fail and will block the transaction if it is 
     * @return return the Approval request status, Amount to Transfer, Destination Address
     
     example:
     
     sendConvertEth1ToEth2Transaction(1,"0xa00cc6e72f9b325d6c896a2fa0bc4ca2e8893aedffc5e2a6690ca6626dd97830f7147ab617690d40a0b245b85f21cfe7","0xb3411b20b150fbcd40ac01fc037925b95046387be9df15c24ade7a5df15edc5e8c717d4133648edf2bb66b9112829c76029f6410d8b240b7f18a3fe9b075f9f136aded9435aa92028acee19e81b073b4622a0f34da640c87dd6db5454d70cca7","100000000000","90000",max_priority_fee-1000000000,true)
    """

    def sendConvertEth1ToEth2Transaction(self, account_id: int, validator_public_key_hex: str, bls_signature_hex: str,
                                         gas_price: str, gas_limit: int, max_priority_fee=None,
                                         validate_transaction: bool = True):
        return self.requestManager.send_request_access_token_included("sendConvertEth1ToEth2Transaction",
                                                                      {"AccountId": account_id,
                                                                       "ValidatorPublicKeysHex": validator_public_key_hex,
                                                                       "BlsSignatureHex": bls_signature_hex,
                                                                       "Fee": {"GasPrice": str(gas_price),
                                                                               "GasLimit": gas_limit,
                                                                               "MaxPriorityFee": str(max_priority_fee)},
                                                                       "validateTransaction": validate_transaction})

    """
     * getTransactionData
     * This is a deprecated function, please use getTransactionsPage and searchTransaction instead.
    """

    def getTransactionData(self, account_id: int, coin_type: str, order_from_newest: str = "false"):
        return self.requestManager.send_request_access_token_included("getTransactionData",
                                                                      {"AccountId": account_id, "CoinType": coin_type,
                                                                       "StartIndex": 0, "EndIndex": 2147483647,
                                                                       "OrderFromNewest": order_from_newest})

    """
     * getSuggestedFee
     * @param coinType array of the coins to be query, send "ALL_COINS" in the array to query all coins.
     * @param useCache True if you want to use cache, False if you don't want to
     * @return suggested fee for given coins.
     
    example:
    
    getSuggestedFee("true", "BTC")
    """

    def getSuggestedFee(self, use_cache: str, coin_type: list):
        return self.requestManager.send_request_access_token_included("getSuggestedFee", {
            "UseCache": use_cache,
            "CoinType": coin_type
        })

    """
     * getConfirmations
     * @param coinType the coin to use in this operation
     * @return confirmations for given coin
     
     example:
     
     getConfirmations("BTC")
    """

    def getConfirmations(self, coin_type: str):
        return self.requestManager.send_request_access_token_included("getConfirmations",
                                                                      {"CoinType": coin_type})

    """
     * isSupportSendToMany
     * @param coinType the coin used in this operation
     * @return return true if given coin support to send transaction for number of address
     
     example:
     
     isSupportSendToMany("BTC")
    """

    def isSupportSendToMany(self, coin_type: str):
        return self.requestManager.send_request_access_token_included("isSupportSendToMany",
                                                                      {"CoinType": coin_type})

    """
     * statusForTransaction
     * @param access token given from send transaction request
     * @param coinType the coin used in this operation
     * @return status int for given token (if transaction sent/approved/ignored ...)
     
     example:
     
     statusForTransaction("7e023dba0c3d5a0dd7b79fffc10e1ac1eec221aa63361f07008e04f69e9600a3","BTC")
    """

    def statusForTransaction(self, token: str, coin_type: str):
        return self.requestManager.send_request_access_token_included("statusForTransaction",
                                                                      {"Token": token, "CoinType": coin_type})

    """
     * getSingleTransaction
     * @param access token given from send transaction request
     * @param coinType the coin used in this operation
     * @return all transaction data: (AccountId, Address, Amount, Approvers, Confirmations, From, IsGroupTransaction, Status)
     
     example:
     
     getSingleTransaction("7e023dba0c3d5a0dd7b79fffc10e1ac1eec221aa63361f07008e04f69e9600a3","BTC")
    """

    def getSingleTransaction(self, token: str, coin_type: str):
        return self.requestManager.send_request_access_token_included("getSingleTransaction",
                                                                      {"Token": token, "CoinType": coin_type})

    """
     * availableBalance
     * @param account_id in int the account id used in this operation
     * @param coinType the coin symbol used in this operation (ETH,BTC,etc...)
     * @return available balance in wallets for given account and coin symbol
     
     example:
     
     availableBalance(1,"BTC")
    """

    def availableBalance(self, account_id: int, coin_types: list):
        if isinstance(coin_types, list) is False:
            raise Exception("coin_types must be list")
        return self.requestManager.send_request_access_token_included("availableBalance",
                                                                      {"AccountId": account_id,
                                                                       "CoinsAndWallets": [{"CoinType": coin_type}
                                                                                           for coin_type in
                                                                                           coin_types]})

    """
     * getBulletins
     * @param decryptEncryptedAlerts whether to decrypt the encrypted messages for all the alerts
     *                                (does not decrypt by default)
     * @return all bulletins for current user (all notifications such as approve request/alerts)
     * AccountId - Id of the account the message comes from
     * AccountName - The name of the account
     * NotificationId - Id of this notification
     * Time - Time the notification was created
     * Title - Title of the message
     * UserId - Id of the user that created the operation
     * Message - Message contained in the alert
     
     - Bulletins
     * AccountId - Id of the account the message comes from
     * AccountName - The name of the account
     * Currency - Currency used in the transaction of this message
     * GroupTransaction - Is this a group transaction
     * Info - Information about the transaction
     
     - Outputs
     * Amount - Amount in crypto being sent to this address
     * Destination - Destination address
     
     - Status - Status of the transaction 
     * PENDING = 1         #pending approval
     * BEING_CANCELLED = 2 #canceled request
     * EXPIRED = 3         #expired request
     * APPROVED = 4        #enough approvers before expired
     * BEING_HANDLED = 5   #currently in handler
     * HANDLED = 6         #finished handling
     * CHECK_HANDLED = 7   #need to check status - if system shutdown while being handled
     
     * TxAccessToken - Access token used to create this transaction
     * EncryptedTxDataAndShares - Encrypted transaction data
     * Machine - Cold or MPC
     
     - Header:
     * CreationTime - Time this transaction was created
     * Creator - ID of the creator
     * CreatorName - Name of the transaction creator
     * ID: Id address of this message in string
     * Type - Type of this transaction
     
     - UserActions: 
     * Action - Action made by this approver
     * UserId - Id of the approver
    """

    def getBulletins(self, decrypt_encrypted_alerts: bool = False, decrypt_tx_data: bool = False):
        bulletins = self.requestManager.send_request_access_token_included("getBulletins",
                                                                           {"StartIndex": 0, "EndIndex": 2562456})
        return GetBulletinsResponse.getBulletins(bulletins, decrypt_encrypted_alerts, self.user, decrypt_tx_data)

    """
     * approveHotRequest
     * @param request_id id of send transaction request (get by using getBulletins)
     * @param request_creator_id id of the send transaction creator
     * @param request_creator_name id of the send transaction creator --DEPRECATED--
     * @param request_type int 0 mean TRANSACTION_REQUEST
     * @param coin_type one of the coins BTC,ETH,BCH...
     * @param account_id in int the account to send from
     * @param outputs list [{"Amount":"596","Destination":"3AXdTF1GxHVugRzrndCPSAQEBd2BqBhMde"}], List in all coins: [(destination_address:str,amount_to_transfer:int)] 
                           in XRP it is optional to add destination tag [(destination_address:str, amount_to_transfer:int, destination_tag:int)]
                           in XLM it is optional to add Memo [(destination_address:str, amount_to_transfer:int, StellarMemo:class)]
     * @param tx_access_token transaction request access token (get by using getBulletins)
     * @param approvers_list :[{"Action":0,"User":"87654321"},{"Action":0,"User":"3333"}]
     * @param specific_from_address string : "3AXdTF1GxHVugRzrndCPSAQEBd2BqBhMde"
     * @param data_for_contract - the contract data contract as Json - may contain a function name in "FunctionName" field
     * and parameters types & values in "ParametersFieldsTypesAndValues field, or all the data parsed to bytes in "RawData" field.
     * @param bytes_to_sign 64 hexadecimal chars to sign on without 0x for raw Stellar transactions
     * @param fee the fee we want to transfer
     * @param is_eth1_to_eth2_conversion - whether the transaction type is sendConvertEth1ToEth2Transaction
     * @return regular response if succeed else error
     
     example: 
     
     approveHotRequest("9e2626a39663f285fdfae2fc0b329baf","1111","1111 1111",1,"BTC",1,[("100000000","36t2WWRbzuw8Ft5o8GXBUzCc3ZEF84eMjm")],"a8c2b4da17998863be8c6270e65be24dec8e79eaea616a54a89184ec43379021",[("0","6666"),("3","2222")])
    """

    def approveHotRequest(self, request_id: str, request_creator_id: str, request_creator_name: str, request_type: int,
                          coin_type: str, account_id: int, outputs: list, tx_access_token: str, approvers_list: list,
                          specific_from_address: str = "", data_for_contract=None, bytes_to_sign: str = "", fee=None,
                          is_eth1_to_eth2_conversion=None):
        function_data = {
            "RequestId": request_id,
            "RequestType": request_type,
            "CoinType": coin_type,
            "AccountId": account_id,
            "RequestCreator": request_creator_id,
            "RequestCreatorName": request_creator_name,
            "Outputs": outputs,
            "TxAccessToken": tx_access_token,
            "ApproversList": approvers_list,
            "Fee": fee
        }
        if specific_from_address is not None:
            function_data["SpecificFromAddress"] = specific_from_address
        if data_for_contract is not None:
            function_data["DataForContract"] = data_for_contract
        if is_eth1_to_eth2_conversion is not None:
            function_data["IsEth1ToEth2Conversion"] = is_eth1_to_eth2_conversion
        if len(bytes_to_sign) > 0:
            function_data["BytesToSign"] = bytes_to_sign

        return self.requestManager.send_request_access_token_included("approveRequest", function_data)

    """
     * getColdTransactionBulletins
     * @param startIndex
     * @param endIndex
     * @param getPendingTxOnly
     * @return all cold transactions for current user
    """

    def getColdTransactionBulletins(self, startIndex: int = 0, endIndex: int = 4294967295,
                                    getPendingTxOnly: bool = False):
        bulletins = self.requestManager.send_request_access_token_included("getBulletins",
                                                                           {"StartIndex": startIndex,
                                                                            "EndIndex": endIndex})
        return GetBulletinsResponse.getColdTransactionBulletins(bulletins, self.user, getPendingTxOnly)

    """
     * approveColdRequest
     * @param request_id id of send transaction request (get it by using getBulletins)
     * @param request_creator_id id of the send transaction creator
     * @param request_creator_name id of the send transaction creator --DEPRECATED--
     * @param request_type int 0 mean TRANSACTION_REQUEST
     * @param outputs list [{"Amount":"596","Destination":"3AXdTF1GxHVugRzrndCPSAQEBd2BqBhMde"}], List in all coins: [(destination_address:str,amount_to_transfer:int)] 
                           in XRP it is optional to add destination tag [(destination_address:str, amount_to_transfer:int, destination_tag:int)]
                           in XLM it is optional to add Memo [(destination_address:str, amount_to_transfer:int, StellarMemo:class)]
     * @param txAccessToken transaction request access token (get it by using getBulletins)
     * @param approvers_list :[{"Action":0,"User":"87654321"},{"Action":1,"User":"3333"}] 
     * @param a_index answer index from getColdTransactionBulletins
     * @param a_share answer share from getColdTransactionBulletins
     * @param a_random answer random from getColdTransactionBulletins
     * @return regular response if succeed else error
     
     example:
     
     approveColdRequest("d4f7ec035593d02ef1cf318cac7afed7","1111","1111",1,[("6000000","3Q9oEdmKU5w2p35gPrkBTkb2a9z44gLTAS")],[("0","5555")],"1","0,277f2ccc055bf46f4b962cf4ab958b7fafc17179424afa96f1246da6851e85bdc67eaa0f00fb0d28631bf8a52815f799c61383165054bd8effe22958715f506bd1911cf90875b493476916b5f40052b23b95bd4f6adaf869313b6784e76074149a7f0200d94335c229cb0f673daa9d76ad3609da856de09c30e4266f59d69f988735eb4acdbd12de35a3d42552d2ef7efa8a748152c921d13c289c96cbfcec2aaa24ccc1e7a1e76bc09d2c06af5d4e4f920c99c52ddc460138e346f0a639e8da0921710596ee9f4db801f3573efd4f1232032861daa8df60c11608da4833889e8b07ec1ca1fe9b29ec5b735c28f716730faebd7f0f36c8c1a717d3806ce7f08a","07d55e6bf981304e094d72643445d003da1894ec0cf1b57b46136f105fd311d9af1f79266fdc1330daeb4314f9ba1c9124de0ff80514543edafc58bcab60e81d9aa34e8b2f3e70b6e6ed8da9106c90e5b976c4222c9ecf5dbc0ba00bc9c525cefc8f936f1823df4e7c233e7b2de442b3193c68aad70eec3cf095d929da90ef78")
    """

    def approveColdRequest(self, request_id: str, request_creator_id: str, request_creator_name: str, request_type: int,
                           outputs: list, approvers_list: list, a_index: str, a_share: str, a_random: str, fee=None):
        return self.requestManager.send_request_access_token_included("approveRequest",
                                                                      {
                                                                          "RequestId": request_id,
                                                                          "RequestType": request_type,
                                                                          "RequestCreator": request_creator_id,
                                                                          "RequestCreatorName": request_creator_name,
                                                                          "Outputs": outputs,
                                                                          "TxAccessToken": "",
                                                                          "ApproversList": approvers_list,
                                                                          "Answers": {"Index": a_index,
                                                                                      "Share": a_share,
                                                                                      "Random": a_random},
                                                                          "Fee": fee
                                                                      })

    """
     * ignoreRequest
     * @param request_id id of send transaction request
     * @return regular response if succeed else error
    """

    def ignoreRequest(self, request_id: str):
        return self.requestManager.send_request_access_token_included("ignoreRequest", {"RequestId": request_id})

    """
     * cancelHotTransactionRequest
     * @param request_id id of send transaction request (get by using getBulletins)
     * @return regular response "success" if succeed else error
     
     example:
     
     *cancelHotTransactionRequest("3528940ef786afe01de2be56ff4cdf3c")
    """

    def cancelHotTransactionRequest(self, request_id: str):
        return self.requestManager.send_request_access_token_included("cancelHotTransactionRequest",
                                                                      {"RequestId": request_id})

    """
     * getCommunityWithLastSeen
     * @param none
     * @return last seen message number of system cosigners including name, ID, and public key of the cosigners
    """

    def getCommunityWithLastSeen(self):
        return self.requestManager.send_request_access_token_included("getCommunityWithLastSeen")

    """
     * getCoins
     * @param none
     * @return list of all coin symbols in the system, and data about them: 
       - AddressRegex - The pattern used for this currency's addresses
       - AmountRegex - The pattern used for this currency's amount
       - Decimal - Number of decimals this currency works with
       - FeeDecimal - Number of decimals this currency uses for the fee
       - FeeRegex - The pattern used for this currency's fee
       - Name -  The name of this currency in string
       - Symbol - The symbol of this currency in string
       - Type - The type of this currency in string(for example - "Coin")
       - CoinFamily: (see helpers.CoinFamily)
         * 0 for Native coins (all the coins other than EVM coins and ERC20 tokens)
         * 1 for EVM (Ethereum Virtual Machine) coins - https://ethereum.org/en/developers/docs/evm/
         * 2 for ERC20 tokens
       - EipType (optional, appears only for EVM coins and ERC20 tokens - see helpers.EipType) - https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2718.md
       - ChainID (optional, appears only for EVM coin and ERC20 tokens) - the identifier of the EVM network - https://chainlist.org/
       - ParentEvm (optional, appears only for ERC20 tokens) - the symbol of the EVM Network on which the ERC20 token was deployed
       - Signature - Cold Wallet's signature for this operation in string
       - CoinPrice - Coin price as defined in the system
       - NodeStatus:
         * 0 Disabled
         * 1 Disconnected
         * 2 Unsynced
         * 3 Synced
         
    """

    def getCoins(self):
        response = self.requestManager.send_request_access_token_included("getCoins", expected_signed_items=[
            ["FunctionData", "Coins", "CoinDataSignedByCold"], ["FunctionData", "SelectedCurrencySignedByCold"]])
        if response is not None:
            self.coinToCoinsResponseSignedByCold = {coin["CoinSymbol"]: coin["CoinDataSignedByCold"] for coin in
                                                    response["FunctionData"]["Coins"]}
            return response

    """
     * getSystemPreferences
     * @param none
     * @return the permissions of all of the system users as "Status" in string(for example: "Admin, Account Manager, Multisig Approver etc...)
    """

    def getSystemPreferences(self):
        expected_signed_items_function = \
            lambda response: ([["FunctionData", "DescriptionOfAllSystemPreferencesSignedByCold"]]
                              if response["FunctionData"]["Status"] == "Admin" else [])
        return self.requestManager.send_request_access_token_included_with_dynamic_expected_signed_items("getSystemPreferences", expected_signed_items_function)

    """
     * getAccounts
     * @param none
     * @return all accounts in system and all coins data for account
      -AccountOwnersData:
      * ColdWalletApprovers - How many approvers for cold vault transactions
      * ColdWalletApproversAllowedRemote - How many remote approvers are allowed for cold vault transactions
      * HotWalletApprovers - How many approvers needed for MPC transactions
      * OwnersList - Array with the list of the owner(s)
      
      -Addresses
      * CoinSymbol - The symbol of the coin used in this operation
      * ColdAddress - Cold Wallet address for this crypto
      * HotAddress - MPC address for this crypto
      
      * Id - Id of this account
      * NickName - Name of this account
      * Time - Time when the Cold Wallet signed this message
      * isMultisigAccount - Is this a Multisig Account or not
      
      * Signature - Signature of this message in string
      
      -BalancesAndPriceForAccount:
      * CoinPrice - Value of this coin in FIAT
      * CoinSymbol - The symbol of the coin used in this operation
      * ColdFunds - Cold vault funds in crypto for this coin
      * HotFunds - MPC funds in crypto for this coin
      
      * isConnectedByUserGroup - Is the user in a group that has access to this account?
      * isOwnedByMe - Is the user running this command the Owner?
      * IsAccountEndpointAccount - Is the account an endpoint account?
      * IsStellarRawBytesTransactionAllowed - Is XLM raw bytes transaction allowed?
      
      * isUserMultisigApprover - Is the requesting user a Multisig approver?	

    """

    def getAccounts(self):
        return self.requestManager.send_request_access_token_included("getAccounts", expected_signed_items=[
            ["FunctionData", "Accounts", "AccountDataSignedByCold"]])

    """
     * getAllCashboxes
     * @param none
     * @return array containing all cashboxes associated with accounts that user can view
     - Cashboxes:
     * CashboxEthereumRealBalance - Amount of ETH if this is an ERC20 cashbox
     * CashboxRealBalance - The current balance in this cashbox
     * CashboxStatus - Status of the cashbox (Closed, Used, Created)
     
     - CashboxDataSignedByCold:
     * Signature - The signature from the Cold Vault
     
     - Data:
     * AccountId - The ID of the account of this cashbox
     * CashboxAddress - The address of this cashbox
     * CashboxContactName - The contact name of the address of this cashbox
     * CashboxCreationTime - The time this cashbox was created (Unix time)
     * CashboxId - The Id of this cashbox
     * CashboxName - The name of this cashbox
     * CurrencySymbol - The symbol of the currency
     * GasLimit - The GasLimit used in this cashboxes transactions (if valid)
     * Parts - The number of parts this cashbox was created with
     * Time - The time of this request
     * TotalAmount - The Total amount in crypto for this cashbox
     
     - CashboxDestinations:
     * Address - One of the destination addresses of this cashbox
     * DestinationIndex - The index of this destination address
     * DestinationName - The name of the contact of the destination address
     * Protected - Whether the transactions to this address requires a password or not (True/False)
     
     * FeeOptions - An array with the fee options for the cashbox transaction
     * UsersIds - An array with the ID of the users that have access to this cashbox
    """

    def getAllCashboxes(self):
        return self.requestManager.send_request_access_token_included("getAllCashboxes", expected_signed_items=[
            ["FunctionData", "Cashboxes", "CashboxDataSignedByCold"]])

    """
     * sendTransactionFromCashbox
     * @param cashbox_id - identifier for the cashbox to use in this operation
     * @param destination_index - identifier for the transaction destination starting from 0 (use getCashboxes to get the values beforehand)
     * @param parts_count - amount of parts to send from cashbox starting from 1
     * @param fee_index - identifier for the fee to pay starting from 0 (use getCashboxes to get the values beforehand)
     * @param passwords - list of passwords in case destination is protected with importance to the order
     * @return return approvalRequestStatus, AmountToTransfer, DestinationAddress
     
     example:
     
     sendTransactionFromCashbox(1,1,1,1,["LZ47MIRBQC"])
     
    """

    def sendTransactionFromCashbox(self, cashbox_id: int, destination_index: int, parts_count: int, fee_index: int,
                                   passwords: list = []):
        return self.requestManager.send_request_access_token_included("sendTransactionFromCashbox", {
            "CashboxId": cashbox_id,
            "DestinationIndex": destination_index,
            "PartsCount": parts_count,
            "FeeIndex": fee_index,
            "Passwords": passwords})

    """
     * closeCashbox
     * @param cashbox_id - identifier for the cashbox to close in this operation in int (can be seen in the Cashbox's "Show" tab)
     * @param fee_index - The index of the fee to be used in the transactions ("see getAllCashboxes for info about the indexes")
     * @return details of created transaction
      - Transaction:
      * AmountToTransfer - Amount that was transferred in the crypto's smallest units (satoshi, wei, drops,...)
      * DestinationAddress - The destination address that the amount was sent to
    """

    def closeCashbox(self, cashbox_id: int, fee_index: int):
        return self.requestManager.send_request_access_token_included("closeCashbox", {
            "CashboxId": cashbox_id,
            "FeeIndex": fee_index})

    """
     * getMultisigRequests
     * @param none
     * @return all accounts in system and all coins data for account
      - CoinSymbol - The symbol of the coin used in this operation (BTC,ETH,ADA etc...)
      - CurrencyTransactions - Array with the multisig requests for this currency in string
      * AccountId - ID of the account this transaction was sent from
      * AccountName - The name of the account this transaction was sent from
      * Amount - The amount in crypto that was sent in this transaction in wei
      * CreatorId - The ID of the creator of this transaction
      * CreatorName - The name of the creator of this transaction
      * DestinationAddress - The destination address of this transaction
      * Info - Extra information about this transaction
      * InputAmounts - Array with the input amount of each UTXO
      * RawTx - The raw transaction information
      * Status - The status of this transaction
      * Time - The time this operation took place in
      * TotalFee - The total fee this transaction used
      * TxId - The TxId of this transaction in string (get from transaction's page)
      * UserDescription - Description given to this operation


    """

    def getMultisigRequests(self):
        return self.requestManager.send_request_access_token_included("getMultisigRequests")

    """
     * sendMultisigSignedRequest
     * @param CoinSymbol The symbol of the coin used in this operation
     * @param coinType the coin used to
     * @param txid string representing the signed transaction id of this request
     * @param accountId in int the account to send money from
     * @param AccountId	the account id of the account to send funds from
     * @param signArray list of signatures for the specified transaction one per vin
     * @return Returns "Success" if succeeded else error
     
     example: 
     
     *sendMultisigSignedRequest("BTC","da9418ecc7f8a085d73ddde5bada5f392919a25dd22e908225f25ec6e32c7131",1,[("3BrKcMHXdRmy2ni2dk9UAD3qRkxjYs3oaN","36ZNvsHRNU1F8StrMwTvWBdj55WEc4WqAZ","3NZR6w4FqggSqnRB37PqqV9e5Wds61Q2Bo","36d21GgHPLU754i4LSY24BBPMDdfpR6chd")])
    """

    def sendMultisigSignedRequest(self, coinSymbol: str, txid: str, accountId: int, signArray: list):
        return self.requestManager.send_request_access_token_included("sendMultisigSignedRequest",
                                                                      {
                                                                          "CoinSymbol": coinSymbol,
                                                                          "Txid": txid,
                                                                          "AccountId": accountId,
                                                                          "SignsArray": signArray
                                                                      })

    """
     * getColdDefinitions
     * @param none
     * @return cold definitions data
     - GeneralInformation:
     * ProductVersion - the current version of the system
     * TimeDescription - the current local time
     * TimeSinceEpochInSeconds - the current linux epoch time
     
     - SystemPreferences:
     * AmountToSpendByColdTransactions - the max amount in FIAT to spend by a cold transaction
     * MaxFeeAsPercentageOfAutoTransactionAmount - the max fee to be spent by a balance transaction between the cold and the hot
     
     - Currencies:
     - HardLimits:
     - ColdHardLimitsForAllLayers:
     * Entity - the type of entity the limits are applied on (user/group)
     
     - Limits:
     - ColdHardLimitsForForeignDestinations:
     * Entity - the type of entity the limits are applied on (user/group)
     * Limits - a list of hourly/daily/weekly/monthly limits for this entity
     
     - RequiredApprovals
     * AdminManagers - the amount of admin managers required to approve the action
     * Admins - the amount of admins required to approve the action
     * CreateOrUpdateUser - the action which requires approval.
     
     - Accounts:
     * AccountId - ID of the account this transaction was sent from
     * AccountName - The name of the account this transaction was sent from
     * AccountOwners - a list of all the account owners for this account id
     
     - BalancingInformation:
     * ColdGeneralTransactionsApproversCount - the amount of cold general approvers for this account id
     * ColdRemoteTransactionsApproversCount - the max amount of remote transaction approvers out of the general approvers
     * HotTransactionsApproversCount - the amount of hot transaction approvers for this account id
     
     - ColdDefinitionsExport:
     * FrequencyTime - How much time it takes to export Cold Definitions to the MPC each time
     * IsAutoExportEnabled - Whether Auto Export Cold Definitions is enabled or not(True/False)
     
     - AuditExport:
     * FrequencyTime - How much time it takes to export the audits to the MPC each time
     * IsAutoExportEnabled - Whether audits auto export is enabled or not(True/False)
     
     - Signature: Signature from the Cold in string

    """

    def getColdDefinitions(self):
        return self.requestManager.send_request_access_token_included("getColdDefinitions")

    """
     * getContacts
     * @param none
     * @return Returns a list of the contacts from the Cold Wallet
     - ContactDataSignedByCold:
     * Address - Contact Address in string
     * Name - Contact Name
     * Symbol - The symbol of this contact's currency
     * Time - Time the message was signed by the Cold Wallet
     
     - Signature:
     * Cold Wallet Signature in string
    """

    def getContacts(self):
        return self.requestManager.send_request_access_token_included("getContacts", expected_signed_items=[
            ["FunctionData", "ContactDataSignedByCold"]])

    """
     * searchTransactions
     * @param include_output_transactions bool indicating if we want output transactions, true if you want to include Output Transactions
     * @param include_input_transactions bool indicating if we want input transactions, true if you want to include Input Transactions
     * @param currencies list of requested currencies, currencies used in this operation (BTC,ETH,BCH,XRP,etc)
     * @param accounts Accounts used in this operation string (optional)
     * @param creators Id of the creators of the transaction
     * @param user_description sub string insensitive to search in user description, Description of the transaction you want to fetch
     * @param start_date_time_in_milliseconds_since_epoch filter transactions from that time including
     * @param end_date_time_in_milliseconds_since_epoch The end date of the transactions (in unix Epoch time)
     * @param status_keys list of indices out of TransactionState enum (apiclient/Status/TransactionState.py),
     * representing the required transaction statuses.
     * e.g: [1,2,5] - all the transactions whose their status is FAILED_LIMITATIONS or FAILED_TECHNICAL or FAILED_NO_FUNDS
     *      [10,11] - all the transactions whose their status is CANCELED_GROUP_CHANGED or CANCELED_ACCOUNT_APRROVERS_CHANGED
     * @return amount of extracted transactions in system for given filters 
     - ExtractedTransactionsCount - Number of transactions that were valid for this search
    """

    def searchTransactions(self,
                           include_output_transactions: bool = None,
                           include_input_transactions: bool = None,
                           currencies: list = None,
                           accounts: list = None,
                           creators: list = None,
                           user_description: str = None,
                           start_date_time_in_milliseconds_since_epoch: int = None,
                           end_date_time_in_milliseconds_since_epoch: int = None,
                           status_keys: list = None,
                           limit_rows: int = None):
        requestJson = dict()
        if include_output_transactions is not None:
            requestJson["IncludeOutputTransactions"] = include_output_transactions
        if include_input_transactions is not None:
            requestJson["IncludeInputTransactions"] = include_input_transactions
        if currencies is not None:
            requestJson["Currencies"] = currencies
        if accounts is not None:
            requestJson["Accounts"] = accounts
        if creators is not None:
            requestJson["Creators"] = creators
        if user_description is not None:
            requestJson["UserDescription"] = user_description
        if start_date_time_in_milliseconds_since_epoch is not None:
            requestJson["StartDateTimeInMillisecondsSinceEpoch"] = start_date_time_in_milliseconds_since_epoch
        if end_date_time_in_milliseconds_since_epoch is not None:
            requestJson["EndDateTimeInMillisecondsSinceEpoch"] = end_date_time_in_milliseconds_since_epoch
        if status_keys is not None:
            requestJson["StatusKeys"] = status_keys
        if limit_rows is not None:
            requestJson["LimitRows"] = limit_rows
        return self.requestManager.send_request_access_token_included("searchTransactions", requestJson)

    """
     * getTransactionsPage
     * @param start_index start index to retrieve transactions
     * @param end_index end index to retrieve transactions
     * You can request up to 1000 transaction in one request
     * @return all transactions in system for given indices range 
     
     transactions Response:
-----------------------

there will be json with array field "Transactions",
each element in the array will have the following fields:

1."Account" - account name
2."Amount" - amount in smallest unit (as string)
3."Confirmations" - string representing amount of confirmations
4."Currency" - currency symbol string
5."Date" - string representing date and time
6."From" - string representing the source address
7."In/Out" - "In" or "Out" (representing output or input transaction)
8."Number" - serial number of the result
9."Status" - string representing status of the transaction
10."To" - string representing the destination address
11."TxId" - string representing the tx id or tx hash of the transaction
12."User Description" - string representing the description of the user (empty for input transactions)
13."ExtraData" - array of elements representing another data for the transaction
	structure:
	a."Key"
	b."Value"
	c."ExtraDataForKey" - array of elements representing inner extra data of structure
		c1."Key"
		c2."Value"
		
	the extra data will be different on all types and it will be detailed here.

note: some transactions will include more than one Transaction element,
for example, in bitcoin output transaction there will be Transaction element for every destination that will contain its destination data,
however the extra data will include data that represent the whole transaction.

explanation for extra data in output transactions:
----------------------------------------------------

1.Key: "In/Out"
  Value: "Out"
  ExtraDataForKey:[]
  
2.Key: "Date"
  Value: string representing date
  ExtraDataForKey:[]
  
3.Key: "Currency"
  Value: string representing currency : "<currency_name> (symbol: <currency_symbol>)"
  ExtraDataForKey:[]
  
4.Key: "Account"
  Value: string representing account : "<account_name> (id: <account_id>)"
  ExtraDataForKey:[]
  
5.Key: "User"
  Value: string representing user : "<user_name> (id: <user_id>)"
  ExtraDataForKey:[]
  
6.Key: "Group"
  Value: group name
  ExtraDataForKey:[]
  
7.Key: "Is Group Transaction"
  Value: "True" or "False"
  ExtraDataForKey:[]
  
8.Key: "Sources"
  Value: string representing amount of sources in the transaction
  ExtraDataForKey:[
	{
		Key: "Address of Source 1"
		Value: string of the address
	}
  
	{
		Key: "Contact Name of Source 1"
		Value: string of the contact name or "" if not exist
	}
	
	{
		Key: "Address of Source 2"
		Value: string of the address
	}
  
	{
		Key: "Contact Name of Source 2"
		Value: string of the contact name or "" if not exist
	}
	
	... will continue as 3,4 by the transaction
  ]
  
9.Key: "Amount to Destinations"
  Value: string representing sum of the money (in smallest unit) to all destinations
  ExtraDataForKey:[
	{
		Key: "Address of Destination 1"
		Value: string of the address
	}
  
	{
		Key: "Contact Name of Destination 1"
		Value: string of the contact name or "" if not exist
	}
	
	{
		Key: "Amount to Destination 1"
		Value: string of the amount money in smallest unit
	}
	
	{
		Key: "Address of Destination 2"
		Value: string of the address
	}
  
	{
		Key: "Contact Name of Destination 2"
		Value: string of the contact name or "" if not exist
	}
	
	{
		Key: "Amount to Destination 2"
		Value: string of the amount money in smallest unit
	}
	...will continue as 3,4 by the transaction
  ]
  
10.Key: "Total Out Amount"
  Value: string representing total out amount with fee in the transaction in smallest unit in one of the two variations:
		a."<amount> (with fee)" - in transaction case
		b."<amount> + fee" - in transaction request case (this is the state when transaction still not signed or not approved)
  ExtraDataForKey:[]
  
11.Key: "Machine"
  Value: "Cold" or "Hot" (transaction send from cold or from hot)
  ExtraDataForKey:[]
  
12.Key: "Status"
  Value: string representing status of the transaction, for example "Sent", "Failed"...
			in eth and erc20 and ripple transactions that are out of gas or out of balance they will be marked "Sent (X)"
  ExtraDataForKey:[]
  
13.Key: "Status Description"
  Value: string adding details for status of the transaction (mostly for failed reasons explanations)
  ExtraDataForKey:[]
  
//the following element will appear only on transactions waiting in queue or failed time out
14.Key: "Timeout At"
  Value: string representing date for the transaction to be fail on time out.
  ExtraDataForKey:[]
  
15.Key: "User Description"
   Value: string that user sent the transaction with.
   ExtraDataForKey:[]
   
//this element relevant only for sent transactions in ripple, eth and erc20
16.Key: "Nonce"
   Value: string that represent the transaction nonce
   ExtraDataForKey:[]
   
//this element relevant only for sent transactions in eth and erc20
17.Key: "Gas Price"
   Value: string that represent the fee amount of eth to gas unit in smallest unit
   ExtraDataForKey:[]
   
//this element relevant only for sent transactions in eth and erc20
18.Key: "Gas Limit"
   Value: string that represent the limit of gas units in sent transaction
   ExtraDataForKey:[]
   
//this element relevant only for sent transactions in ripple, eth and erc20
19.Key: "Out Of Gas / Balance"
   Value: "True" or "False"
   ExtraDataForKey:[]
   
//this element relevant only for sent transactions in bitcoin
20.Key: "Fee Per VByte"
   Value: string that represents the amount of satoshi per virtual byte in bitcoin transaction
   ExtraDataForKey:[]
   
//this element relevant only for sent transactions in bitcoincash
21.Key: "Fee Per Byte"
   Value: string that represents the amount of satoshi per byte in bitcoincash transaction
   ExtraDataForKey:[]
   
//this element relevant only for sent transactions in ripple bitcoin and bitcoincash
22.Key: "Total Fee"
   Value: string that represents the amount of fee to pay in smallest unit in current transaction
   ExtraDataForKey:[]
    
23.Key: "TxId"
   Value: string that represent the txid or txhash , empty for non sent transactions
   ExtraDataForKey:[]
   
//this element exist only in sent transactions
24.Key: "Raw Transaction"
   Value: string that represent the serialize of the transaction into bytes
   ExtraDataForKey:[]
  
25.Key: "Block Number"
   Value: string that represent the block number for the transaction to be included,  or "None" if the transaction is not in blockchain yet
   ExtraDataForKey:[]
   
26.Key: "Confirmations"
   Value: string that represent the amount of confirmations for transaction, or "0" if the transaction is not in blockchain yet, or "" if there is no node communication at the moment and the transaction is not in the blockchain
   ExtraDataForKey:[]
  
27.Key: "TxToken"
   Value: string that represent the id of the transaction in the db (represents also the access key that used to send this transaction)
   ExtraDataForKey:[]
  
  
  
  
  
  
explanation for extra data in bitcoin/bitcoincash input transactions:
-------------------------------------------------------------------------

in btc/bch input transactions we will have Transaction object for each output in the transaction that is our cold/hot or deposit address.

1.Key: "In/Out"
  Value: "In"
  ExtraDataForKey:[]
  
2.Key: "Date"
  Value: string representing date of the block closed that included the transaction
  ExtraDataForKey:[]
  
3.Key: "Currency"
  Value: string representing currency : "<currency_name> (symbol: <currency_symbol>)"
  ExtraDataForKey:[]
  
4.Key: "Account"
  Value: string representing account : "<account_name> (id: <account_id>)"
  ExtraDataForKey:[]
  
5.Key: "Sources"
  Value: string representing amount of sources in the transaction
  ExtraDataForKey:[
	{
		Key: "Address of Source 1"
		Value: string of the address
	}
  
	{
		Key: "Contact Name of Source 1"
		Value: string of the contact name or "" if not exist
	}
	
	{
		Key: "Address of Source 2"
		Value: string of the address
	}
  
	{
		Key: "Contact Name of Source 2"
		Value: string of the contact name or "" if not exist
	}
	
	... will continue as 3,4 by the transaction
  ]
  
6.Key: "Amount to Destinations"
  Value: string representing sum of the money (in smallest unit) to all destinations (include non our wallet destinations)
  ExtraDataForKey:[
	{
		Key: "Address of Destination 1"
		Value: string of the address
	}
  
	{
		Key: "Contact Name of Destination 1"
		Value: string of the contact name or "" if not exist
	}
	
	{
		Key: "Amount to Destination 1"
		Value: string of the amount money in smallest unit
	}
	
	//the following element will appear only if the output is our deposit address
	{
		Key: "Account of Destination 1"
		Value: string of the account id that the deposit address is assigned to
	}
	
	//the following element will appear only if the output is our deposit address
	{
		Key: "Deposit Address Index of Destination 1"
		Value: string of the deposit address index (inside account)
	}
	
	...will continue as 2,3,4 by the transaction
  ]
  
7.Key: "Total Out Amount"
  Value: string representing total out amount with fee in the transaction in smallest unit:"<amount> (with fee)"
  ExtraDataForKey:[]
  
8.Key: "Machine"
  Value: "Cold" for transactions to the cold or "Hot" for transactions to the hot or deposit addresses
  ExtraDataForKey:[]
  
9.Key: "Status"
  Value: "Input Transaction"
  ExtraDataForKey:[]
  
10.Key: "User Description"
  Value: "" (always empty string)
  ExtraDataForKey:[]
  
//this element relevant only for input transactions in bitcoin
11.Key: "Fee Per VByte"
   Value: string that represents the amount of satoshi per virtual byte in bitcoin transaction
   ExtraDataForKey:[]
   
//this element relevant only for input transactions in bitcoincash
12.Key: "Fee Per Byte"
   Value: string that represents the amount of satoshi per byte in bitcoincash transaction
   ExtraDataForKey:[]
   
13.Key: "Total Fee"
   Value: string that represents the amount of fee to pay in smallest unit in current transaction
   ExtraDataForKey:[]
    
14.Key: "TxId"
   Value: string that represent the txid
   ExtraDataForKey:[]
  
15.Key: "Block Number"
   Value: string that represent the block number for the input transaction
   ExtraDataForKey:[]
   
16.Key: "Confirmations"
   Value: string that represent the amount of confirmations for transaction,  or "" if there is no node communication at the moment
   ExtraDataForKey:[]
   
   
   
   
   
   
explanation for extra data in ripple input transactions:
-------------------------------------------------------------------------
  
1.Key: "In/Out"
  Value: "In"
  ExtraDataForKey:[]
  
2.Key: "Date"
  Value: string representing date of the block closed that included the transaction
  ExtraDataForKey:[]
  
3.Key: "Currency"
  Value: string representing currency : "Ripple (symbol: XRP)"
  ExtraDataForKey:[]
  
4.Key: "Account"
  Value: string representing account : "<account_name> (id: <account_id>)"
  ExtraDataForKey:[]
  
5.Key: "Sources"
  Value: string representing amount of sources in the transaction
  ExtraDataForKey:[
	{
		Key: "Address of Source 1"
		Value: string of the address
	}
  
	{
		Key: "Contact Name of Source 1"
		Value: string of the contact name or "" if not exist
	}
	
	{
		Key: "Address of Source 2"
		Value: string of the address
	}
  
	{
		Key: "Contact Name of Source 2"
		Value: string of the contact name or "" if not exist
	}
	
	... will continue as 3,4 by the transaction
  ]
  
6.Key: "Amount to Destinations"
  Value: string representing the money (in smallest unit) to destination
  ExtraDataForKey:[
	{
		Key: "Address of Destination 1"
		Value: string of the address (if destination includes destination tag it will be concatinating "<address>:<tag>")
	}
  
	{
		Key: "Contact Name of Destination 1"
		Value: string of the contact name or "" if not exist
	}
	
	{
		Key: "Amount to Destination 1"
		Value: string of the amount money in smallest unit
	}	
  ]
  
7.Key: "Total Out Amount"
  Value: string representing total out amount with fee in the transaction in smallest unit:"<amount> (with fee)"
  ExtraDataForKey:[]
  
8.Key: "Machine"
  Value: "Cold" for transactions to the cold or "Hot" for transactions to the hot
  ExtraDataForKey:[]
  
9.Key: "Status"
  Value: "Input Transaction"
  ExtraDataForKey:[]
  
10.Key: "User Description"
  Value: "" (always empty string)
  ExtraDataForKey:[]
  
11.Key: "Total Fee"
   Value: string that represents the amount of fee to pay in smallest unit in current transaction
   ExtraDataForKey:[]
    
12.Key: "TxId"
   Value: string that represent the tx hash
   ExtraDataForKey:[]
  
13.Key: "Block Number"
   Value: string that represent the block number for the input transaction
   ExtraDataForKey:[]
   
14.Key: "Confirmations"
   Value: string that represent the amount of confirmations for transaction,  or "" if there is no node communication at the moment
   ExtraDataForKey:[]
   
   
   
   
   
   
explanation for extra data in ethereum and erc20 input transactions:
-------------------------------------------------------------------------

1.Key: "In/Out"
  Value: "In"
  ExtraDataForKey:[]
  
2.Key: "Date"
  Value: string representing date of the block closed that included the transaction
  ExtraDataForKey:[]
  
3.Key: "Currency"
  Value: string representing currency : "<currency_name> (symbol: <currency_symbol>)"
  ExtraDataForKey:[]
  
4.Key: "Account"
  Value: string representing account : "<account_name> (id: <account_id>)"
  ExtraDataForKey:[]
  
5.Key: "Transaction Type"
  Value: one of the following "Ethereum Transaction", "Ethereum Internal Transaction", "ERC20 Token Transaction"
  ExtraDataForKey:[]

//the following element is relevant only for ethereum internal transactions  
6.Key: "Initiator"
  Value: string representing eth address of the initiator who made the transaction into the smart contract
  ExtraDataForKey:[]
  
7.Key: "Sources"
  Value: string representing amount of sources in the transaction
  ExtraDataForKey:[
	{
		Key: "Address of Source 1"
		Value: string of the address
	}
  
	{
		Key: "Contact Name of Source 1"
		Value: string of the contact name or "" if not exist
	}
	
	{
		Key: "Address of Source 2"
		Value: string of the address
	}
  
	{
		Key: "Contact Name of Source 2"
		Value: string of the contact name or "" if not exist
	}
	
	... will continue as 3,4 by the transaction
  ]
  
8.Key: "Amount to Destinations"
  Value: string representing the money (in smallest unit) to destination
  ExtraDataForKey:[
	{
		Key: "Address of Destination 1"
		Value: string of the address (if destination includes destination tag it will be concatinating "<address>:<tag>")
	}
  
	{
		Key: "Contact Name of Destination 1"
		Value: string of the contact name or "" if not exist
	}
	
	{
		Key: "Amount to Destination 1"
		Value: string of the amount money in smallest unit
	}	
	
	//the following element will appear only if the output is our deposit address
	{
		Key: "Account of Destination 1"
		Value: string of the account id that the deposit address is assigned to
	}
	
	//the following element will appear only if the output is our deposit address
	{
		Key: "Deposit Address Index of Destination 1"
		Value: string of the deposit address index (inside account)
	}
  ]
  
9.Key: "Machine"
  Value: "Cold" for transactions to the cold or "Hot" for transactions to the hot or deposit addresses
  ExtraDataForKey:[]
  
10.Key: "Status"
  Value: "Input Transaction"
  ExtraDataForKey:[]
  
11.Key: "User Description"
  Value: "" (always empty string)
  ExtraDataForKey:[]
  
12.Key: "Gas Price"
  Value: string representing the fee in smallest unit for single gas unit
  ExtraDataForKey:[]

//the following element is relevant for non internal eth transactions (only regular eth transactions and erc20 transactions)
13.Key: "Gas Limit"
  Value: string representing the limit for gas units in the transaction
  ExtraDataForKey:[]
  
//the following element is relevant for non internal eth transactions (only regular eth transactions and erc20 transactions)
14.Key: "Gas Used"
  Value: string representing the actual amount of gas units used in the transaction
  ExtraDataForKey:[]
  
//the following element is relevant for non internal eth transactions (only regular eth transactions and erc20 transactions)
15.Key: "Total Fee"
  Value: string representing the amount of fee payed in the transaction in smallest unit
  ExtraDataForKey:[]
  
16.Key: "TxId"
   Value: string that represent the tx hash
   ExtraDataForKey:[]
   
//the following element is relevant only for internal eth transactions
17.Key: "Trace Id"
  Value: string representing id for operation performed as part of actions in smart contract
  ExtraDataForKey:[]
  
18.Key: "Block Number"
   Value: string that represent the block number for the input transaction
   ExtraDataForKey:[]
   
19.Key: "Confirmations"
   Value: string that represent the amount of confirmations for transaction,  or "" if there is no node communication at the moment
   ExtraDataForKey:[]
   




explanation for extra data in stellar input transactions:   
-------------------------------------------------------------------------

1.Key: "In/Out"
  Value: "Out"
  ExtraDataForKey:[]
  
2.Key: "Date"
  Value: string representing date
  ExtraDataForKey:[]
  
3.Key: "Currency"
  Value: string representing currency : "<currency_name> (symbol: <currency_symbol>)"
  ExtraDataForKey:[]
  
4.Key: "Account"
  Value: string representing account : "<account_name> (id: <account_id>)"
  ExtraDataForKey:[]
  
5.Key: "User"
  Value: string representing user : "<user_name> (id: <user_id>)"
  ExtraDataForKey:[]
  
6.Key: "Group"
  Value: group name
  ExtraDataForKey:[]
  
7.Key: "Is Group Transaction"
  Value: "True" or "False"
  ExtraDataForKey:[]
  
8.Key: "OriginalOneUnitPrice"
  Value: Price of specific currency 
  ExtraDataForKey:[]

9.Key: "Transaction Version"
  Value: Version of the transaction
  ExtraDataForKey:[]  
  
10.Key: "Is Group Transaction"
  Value: "True" or "False"
  ExtraDataForKey:[]  

11.8.Key: "Sources"
  Value: string representing amount of sources in the transaction
  ExtraDataForKey:[
	{
		Key: "Address of Source 1"
		Value: string of the address
	}
  
	{
		Key: "Contact Name of Source 1"
		Value: string of the contact name or "" if not exist
	}
  
        {
		Key: "Amount to destination"
		Value: string of the contact name or "" if not exist
	}
	
12.Key: "Total Out Amount"
  Value: string representing total out amount with fee in the transaction in smallest unit:"<amount> (with fee)"
  ExtraDataForKey:[]
  
13.Key: "Machine"
  Value: "Cold" for transactions to the cold or "Hot" for transactions to the hot or deposit addresses
  ExtraDataForKey:[]
  
14.Key: "Status"
  Value: "Input Transaction"
  ExtraDataForKey:[]
  
15.Key: "User Description"
  Value: "" (always empty string)
  ExtraDataForKey:[]
  
16.Key: "Total Fee"
   Value: string that represents the amount of fee to pay in smallest unit in current transaction
   ExtraDataForKey:[]
    
17.Key: "TxId"
   Value: string that represent the txid
   ExtraDataForKey:[]
  
18.Key: "Block Number"
   Value: string that represent the block number for the input transaction
   ExtraDataForKey:[]
   
19.Key: "Confirmations"
   Value: string that represent the amount of confirmations for transaction,  or "" if there is no node communication at the moment
   ExtraDataForKey:[]
   
20.Key: "Nonce"
   Value: string represent the Nonce number
   ExtraDataForKey:[]
   
21.Key: "Declined by blockchain"
   Value: True or false whether declined by blockchain
   ExtraDataForKey:[]
   
22.Key: "Raw transaction"
   Value: string of the raw transaction address
   ExtraDataForKey:[]   
   
23.Key: "TxToken"
   Value: string that represent the tx token from cold
   ExtraDataForKey:[]   
   
   
   
   
explanation for extra data in cardano input transactions:   
-------------------------------------------------------------------------   

1.Key: "In/Out"
  Value: "Out"
  ExtraDataForKey:[]
  
2.Key: "Date"
  Value: string representing date
  ExtraDataForKey:[]
  
3.Key: "Currency"
  Value: string representing currency : "<currency_name> (symbol: <currency_symbol>)"
  ExtraDataForKey:[]
  
4.Key: "Account"
  Value: string representing account : "<account_name> (id: <account_id>)"
  ExtraDataForKey:[]
  
5.Key: "User"
  Value: string representing user : "<user_name> (id: <user_id>)"
  ExtraDataForKey:[]
  
6.Key: "Group"
  Value: group name
  ExtraDataForKey:[]
  
7.Key: "Is Group Transaction"
  Value: "True" or "False"
  ExtraDataForKey:[]
  
8.Key: "OriginalOneUnitPrice"
  Value: Price of specific currency 
  ExtraDataForKey:[]

9.Key: "Transaction Version"
  Value: Version of the transaction
  ExtraDataForKey:[]  
  
10.Key: "Is Group Transaction"
  Value: "True" or "False"
  ExtraDataForKey:[]  

11.8.Key: "Sources"
  Value: string representing amount of sources in the transaction
  ExtraDataForKey:[
	{
		Key: "Address of Source 1"
		Value: string of the address
	}
  
	{
		Key: "Contact Name of Source 1"
		Value: string of the contact name or "" if not exist
	}
  
        {
		Key: "Amount to destination"
		Value: string of the contact name or "" if not exist
	}
	{
		Key: "Address of Source 2"
		Value: string of the address
	}
  
	{
		Key: "Contact Name of Source 2"
		Value: string of the contact name or "" if not exist
	}
	
	... will continue as 3,4 by the transaction
  ]	
12.Key: "Total Out Amount"
  Value: string representing total out amount with fee in the transaction in smallest unit:"<amount> (with fee)"
  ExtraDataForKey:[]
  
13.Key: "Machine"
  Value: "Cold" for transactions to the cold or "Hot" for transactions to the hot or deposit addresses
  ExtraDataForKey:[]
  
14.Key: "Status"
  Value: "Input Transaction"
  ExtraDataForKey:[]
  
15.Key: "User Description"
  Value: "" (always empty string)
  ExtraDataForKey:[]
  
16.Key: "Total Fee"
   Value: string that represents the amount of fee to pay in smallest unit in current transaction
   ExtraDataForKey:[]
    
17.Key: "TxId"
   Value: string that represent the txid
   ExtraDataForKey:[]
  
18.Key: "Block Number"
   Value: string that represent the block number for the input transaction
   ExtraDataForKey:[]
   
19.Key: "Confirmations"
   Value: string that represent the amount of confirmations for transaction,  or "" if there is no node communication at the moment
   ExtraDataForKey:[]
   
20.Key: "Nonce"
   Value: string represent the Nonce number
   ExtraDataForKey:[]
   
21.Key: "Declined by blockchain"
   Value: True or false whether declined by blockchain
   ExtraDataForKey:[]
   
22.Key: "Raw transaction"
   Value: string of the raw transaction address
   ExtraDataForKey:[]   
   
23.Key: "TxToken"
   Value: string that represent the tx token from cold
   ExtraDataForKey:[]  
   
24.Key: "Staking operation"
   Value: string that represent which staking operation being performed
   ExtraDataForKey:[]     
   
25.Key: "Staking additional info"
   Value: string that represent the additional info such as pool ID
   ExtraDataForKey:[]     
   
26.Key: "Fee per VByte"
   Value: string that represent how much fee was taken in this operation
   ExtraDataForKey:[]     
   
   
   
   
   
explanation for extra data in Tezos input transactions:   
-------------------------------------------------------------------------    

1.Key: "In/Out"
  Value: "Out"
  ExtraDataForKey:[]
  
2.Key: "Date"
  Value: string representing date
  ExtraDataForKey:[]
  
3.Key: "Currency"
  Value: string representing currency : "<currency_name> (symbol: <currency_symbol>)"
  ExtraDataForKey:[]
  
4.Key: "Account"
  Value: string representing account : "<account_name> (id: <account_id>)"
  ExtraDataForKey:[]
  
5.Key: "Amount"
  Value: Amount that took place in this transaction 	
  ExtraDataForKey:[]   

6.Key: "Confirmations"
   Value: string that represent the amount of confirmations for transaction,  or "" if there is no node communication at the moment
   ExtraDataForKey:[]
   
7.Key: "From"
   Value: string that represent the sender address
   ExtraDataForKey:[]  
   
8.Key: "Status"
   Value: string that represent the status of the transaction
   ExtraDataForKey:[]  
   
9.Key: "To"
   Value: string that represent the reciever addres
   ExtraDataForKey:[]     
   
10.Key: "Sources"
  Value: string representing amount of sources in the transaction
  ExtraDataForKey:[
	{
		Key: "Address of Source 1"
		Value: string of the address
	}
  
	{
		Key: "Contact Name of Source 1"
		Value: string of the contact name or "" if not exist
	}
	
11.Key: "Block Number"
   Value: string that represent the block number for the input transaction
   ExtraDataForKey:[]
   
12.Key: "Total Fee"
   Value: string that represents the amount of fee to pay in smallest unit in current transaction
   ExtraDataForKey:[]
   
13.Key: "Machine"
  Value: "Cold" for transactions to the cold or "Hot" for transactions to the hot or deposit addresses
  ExtraDataForKey:[]
  
14.Key: "Total Out Amount"
  Value: string representing total out amount with fee in the transaction in smallest unit:"<amount> (with fee)"
  ExtraDataForKey:[]
  
15.Key: "Branch"
   Value: string that represent the branch address
   ExtraDataForKey:[]           	
   
   
   
   
explanation for extra data in CELO input transactions:   
-------------------------------------------------------------------------       

1.Key: "In/Out"
  Value: "Out"
  ExtraDataForKey:[]
  
2.Key: "Date"
  Value: string representing date
  ExtraDataForKey:[]
  
3.Key: "Currency"
  Value: string representing currency : "<currency_name> (symbol: <currency_symbol>)"
  ExtraDataForKey:[]
  
4.Key: "Account"
  Value: string representing account : "<account_name> (id: <account_id>)"
  ExtraDataForKey:[]
  
5.Key: "User"
  Value: string representing user : "<user_name> (id: <user_id>)"
  ExtraDataForKey:[]
  
6.Key: "Group"
  Value: group name
  ExtraDataForKey:[]
  
7.Key: "Is Group Transaction"
  Value: "True" or "False"
  ExtraDataForKey:[]
  
8.Key: "OriginalOneUnitPrice"
  Value: Price of specific currency 
  ExtraDataForKey:[]

9.Key: "Transaction Version"
  Value: Version of the transaction
  ExtraDataForKey:[]  
  
10.Key: "Is Group Transaction"
  Value: "True" or "False"
  ExtraDataForKey:[]  

11.8.Key: "Sources"
  Value: string representing amount of sources in the transaction
  ExtraDataForKey:[
	{
		Key: "Address of Source 1"
		Value: string of the address
	}
  
	{
		Key: "Contact Name of Source 1"
		Value: string of the contact name or "" if not exist
	}
  
        {
		Key: "Amount to destination"
		Value: string of the contact name or "" if not exist
	}
	
12.Key: "Total Out Amount"
  Value: string representing total out amount with fee in the transaction in smallest unit:"<amount> (with fee)"
  ExtraDataForKey:[]
  
13.Key: "Machine"
  Value: "Cold" for transactions to the cold or "Hot" for transactions to the hot or deposit addresses
  ExtraDataForKey:[]
  
14.Key: "Status"
  Value: "Input Transaction"
  ExtraDataForKey:[]
  
15.Key: "User Description"
  Value: "" (always empty string)
  ExtraDataForKey:[]
  
16.Key: "Total Fee"
   Value: string that represents the amount of fee to pay in smallest unit in current transaction
   ExtraDataForKey:[]
    
17.Key: "TxId"
   Value: string that represent the txid
   ExtraDataForKey:[]
  
18.Key: "Block Number"
   Value: string that represent the block number for the input transaction
   ExtraDataForKey:[]
   
19.Key: "Confirmations"
   Value: string that represent the amount of confirmations for transaction,  or "" if there is no node communication at the moment
   ExtraDataForKey:[]
   
20.Key: "Nonce"
   Value: string represent the Nonce number
   ExtraDataForKey:[]
   
21.Key: "Declined by blockchain"
   Value: True or false whether declined by blockchain
   ExtraDataForKey:[]
   
22.Key: "Raw transaction"
   Value: string of the raw transaction address
   ExtraDataForKey:[]   
   
23.Key: "TxToken"
   Value: string that represent the tx token from cold
   ExtraDataForKey:[]   
   
23-4.Key: "Gas Price"
   Value: string that represent the gas price set
   ExtraDataForKey:[]   
   
25.Key: "Gas Limit"
   Value: string that represent the gas limit set
   ExtraDataForKey:[]          
     
    """

    def getTransactionsPage(self, start_index: int, end_index: int):
        if start_index < 0:
            raise Exception("Negative start index")
        if end_index < 0:
            raise Exception("Negative end index")
        if end_index - start_index + 1 > 1000:
            raise Exception("You can request up to 1000 transactions in one Page")
        if end_index < start_index:
            raise Exception("Start index must be smaller or equal to End index")
        return self.requestManager.send_request_access_token_included("getTransactionsPage", {
            "StartIndex": start_index, "EndIndex": end_index})

    """
         * getTransactionByToken
         * @param transactionToken on transaction creation a token is being provided.
         * @param coin_type coin type of the transaction
         
         
         * @return data same as get transaction page but for a specific transaction (check getTransactionPage for more info)
         
        """

    def getTransactionByToken(self, transactionToken: str, coin_type: str):
        return self.requestManager.send_request_access_token_included("getTransactionByToken", {
            "TransactionToken": transactionToken, "CoinType": coin_type})

    """
     * retrieveAllHotUtxosForAccount
     * @param coin_type the coin symbol to retrieve hot utxos
     * @param account_id the account to query
     * @return all hot utxos in system for given currency and accountId 
     
     * AccountId - the id of the account
     * Amount - the amount in crypto in this transaction
     * CurrencySymbol - the symbol of the currency
     * HighestFeeInMergeTransaction - the highest fee to be spent in this merge transaction that contains this UTXO
     * MergeUtxosTransactionsRequestsIds - a list of merge request id's that contain this UTXO
     * Mergeable - returns true if can be merged, otherwise will return false
     * Spendable - the transaction id of this transaction
     * VoutIndex - The Vout (transaction output number) of this UTXO
     
     example:
     
     *retrieveAllHotUtxosForAccount("BTC",1)
    """

    def retrieveAllHotUtxosForAccount(self, coin_type: str, account_id: int):
        return self.requestManager.send_request_access_token_included("retrieveAllHotUtxosForAccount", {
            "CoinType": coin_type, "AccountId": account_id})

    """
     * retrieveSingleHotUtxoByTxIdAndVoutIndex
     * @param coin_type The symbol of the currency of this UTXO 
     * @param tx_id The TxID of this UTXO
     * @param vout_index The Vout (transaction output number) of this UTXO
     * @return hot utxo in system for given currency by txId and vout index 
     
     * AccountId - the id of the account
     * Amount - the amount in crypto in this transaction
     * CurrencySymbol - the symbol of the currency
     * HighestFeeInMergeTransaction - the highest fee to be spent in this merge transaction that contains this UTXO
     * MergeUtxosTransactionsRequestsIds - a list of merge request id's that contain this UTXO
     * Mergeable - returns true if can be merged, otherwise will return false
     * Spendable - the transaction id of this transaction
     * VoutIndex - The Vout (transaction output number) of this UTXO
     * TxId - the transaction id of this transaction
     
     example:
     
     *retrieveSingleHotUtxoByTxIdAndVoutIndex("BTC","6e3913dace62cdfc5812e3288701d3bc297db9bed49128af39afb78d14fdcf8c",1)
     
    """

    def retrieveSingleHotUtxoByTxIdAndVoutIndex(self, coin_type: str, tx_id: str, vout_index: int):
        return self.requestManager.send_request_access_token_included("retrieveSingleHotUtxoByTxIdAndVoutIndex",
                                                                      {"CoinType": coin_type, "TxId": tx_id,
                                                                       "VoutIndex": vout_index})

    """
     * searchMergeUtxosRequests
     * @param coin_type the coin to query merge utxos requests
     * @param account_id the account to query merge utxos requests
     * @param status_keys list of indices out of TransactionState enum (apiclient/Status/TransactionState.py),
     * representing the required transaction statuses.
     * e.g: [1,2,5] - all the transactions whose their status is FAILED_LIMITATIONS or FAILED_TECHNICAL or FAILED_NO_FUNDS
     *      [10,11] - all the transactions whose their status is CANCELED_GROUP_CHANGED or CANCELED_ACCOUNT_APRROVERS_CHANGED
     * @param type_filter list of types to filter
     * @return merge utxos requests in system for given filters as below:
     
     * AccountId - the id of the account
     * Date - The time/date the merge request was made in epoch time
     * Fee - The Fee used in the merge utxo request
     * CurrencySymbol - the symbol of the currency
     * MergeUtxosRequestId - The ID of this merge utxo request
     * MergeUtxosRequestType - The type of this merge utxo request
     * MergeUtxosRequestTypeKey - The type key of this merge utxo request (0 - Merge, 1 - Raise Fee, 2 - Override Fee)
     
     - MergeUtxosRequestOptions:
     * MaxAmountForUtxoToCollect - The max amount of the currency for a utxo to be merged within this request
     * MaxUtxosPerTransaction - The max amount of UTXOs per transaction to be merged within this request
     * MinAmountForUtxoToCollect - The min amount of UTXOs per transaction to be merged within this request
     
     - MergeUtxosTransactionsRequests:
     * BaseForMergeUtxosTransactionRequestId - The ID of the merge utxo request that was based on this request (if applicable)
     * BasedOnMergeUtxosTransactionRequestId - The ID of the merge utxo request this was based on this request (if applicable)
     * FailureDescription - Failure description in the case of failing
     * MergeUtxosRequestId - The ID of this merge utxo request
     * ReplaceableTransactionsChainCount - The number of times the merge utxo request was changed
     * Status - Status of this transaction
     * StatusKey - An integer representing the status of this transaction
     * TransactionSerialNumber - The Serial number of this transaction
     * TxId - The TxId of this transaction
     
     - UtxosIds:
     * TxId - The Id of this transaction
     * VoutIndex - The Vout (transaction output number) of this transaction
     
     
    """

    def searchMergeUtxosRequests(self,
                                 coin_type: str,
                                 account_id: int,
                                 status_keys: list = None,
                                 type_filter: list = None):
        requestJson = dict()
        requestJson["CoinType"] = coin_type
        requestJson["AccountId"] = account_id
        if status_keys is not None:
            requestJson["StatusKeys"] = status_keys
        if type_filter is not None:
            requestJson["MergeUtxosRequestTypeKeys"] = type_filter

        return self.requestManager.send_request_access_token_included("searchMergeUtxosRequests", requestJson)

    """
     * getMergeUtxosRequestById
     * @param merge_utxos_request_id The request id of this merge UTXO's
     * @return merge utxos request in system for given id as seen below:
     
     * AccountId - the id of the account
     * Date - The time/date the merge request was made in epoch time
     * Fee - The Fee used in the merge utxo request
     * CurrencySymbol - the symbol of the currency
     * MergeUtxosRequestId - The ID of this merge utxo request
     * MergeUtxosRequestType - The type of this merge utxo request
     * MergeUtxosRequestTypeKey - The type key of this merge utxo request (0 - Merge, 1 - Raise Fee, 2 - Override Fee)
     
     - MergeUtxosRequestOptions:
     * MaxAmountForUtxoToCollect - The max amount of the currency for a utxo to be merged within this request
     * MaxUtxosPerTransaction - The max amount of UTXOs per transaction to be merged within this request
     * MinAmountForUtxoToCollect - The min amount of UTXOs per transaction to be merged within this request
     
     - MergeUtxosTransactionsRequests:
     * BaseForMergeUtxosTransactionRequestId - The ID of the merge utxo request that was based on this request (if applicable)
     * BasedOnMergeUtxosTransactionRequestId - The ID of the merge utxo request this was based on this request (if applicable)
     * FailureDescription - Failure description in the case of failing
     * MergeUtxosRequestId - The ID of this merge utxo request
     * ReplaceableTransactionsChainCount - The number of times the merge utxo request was changed
     * Status - Status of this transaction
     * StatusKey - An integer representing the status of this transaction
     * TransactionSerialNumber - The Serial number of this transaction
     * TxId - The TxId of this transaction
     
     - UtxosIds:
     * TxId - The Id of this transaction
     * VoutIndex - The Vout (transaction output number) of this transaction
     
     
    """

    def getMergeUtxosRequestById(self, merge_utxos_request_id: str):
        return self.requestManager.send_request_access_token_included("getMergeUtxosRequestById", {
            "MergeUtxosRequestId": merge_utxos_request_id})

    """
     * mergeUtxos
     * @param coin_type The symbol of the coin used in this transaction
     * @param account_id the relevant account to merge utxos
     * @param min_amount the min amount for utxo to be collected in string
     * @param max_amount the max amount for utxo to be collected in wei, string
     * @param fee the fee to pay for each merge utxos transaction created (Use suggested fee pop up window)
     * @param max_utxos_per_transaction the max quantity of utxos to be included in same transaction
     * @return Merges separate utxos depending on the parameters
     
     * AccountId - the id of the account
     * Date - The time/date the merge request was made in epoch time
     * Fee - The Fee used in the merge utxo request
     * CurrencySymbol - the symbol of the currency
     * MergeUtxosRequestId - The ID of this merge utxo request
     * MergeUtxosRequestType - The type of this merge utxo request
     * MergeUtxosRequestTypeKey - The type key of this merge utxo request (0 - Merge, 1 - Raise Fee, 2 - Override Fee)
     
     - MergeUtxosRequestOptions:
     * MaxAmountForUtxoToCollect - The max amount of the currency for a utxo to be merged within this request
     * MaxUtxosPerTransaction - The max amount of UTXOs per transaction to be merged within this request
     * MinAmountForUtxoToCollect - The min amount of UTXOs per transaction to be merged within this request
     
     - MergeUtxosTransactionsRequests:
     * BaseForMergeUtxosTransactionRequestId - The ID of the merge utxo request that was based on this request (if applicable)
     * BasedOnMergeUtxosTransactionRequestId - The ID of the merge utxo request this was based on this request (if applicable)
     * FailureDescription - Failure description in the case of failing
     * MergeUtxosRequestId - The ID of this merge utxo request
     * ReplaceableTransactionsChainCount - The number of times the merge utxo request was changed
     * Status - Status of this transaction
     * StatusKey - An integer representing the status of this transaction
     * TransactionSerialNumber - The Serial number of this transaction
     * TxId - The TxId of this transaction
     
     - UtxosIds:
     * TxId - The Id of this transaction
     * VoutIndex - The Vout (transaction output number) of this transaction
      
     example:
     
     *mergeUtxos("BTC",1,"1","100000000",1,20)
     
    """

    def mergeUtxos(self, coin_type: str, account_id: int, min_amount: str, max_amount: str, fee: int,
                   max_utxos_per_transaction: int):
        return self.requestManager.send_request_access_token_included("mergeUtxos", {
            "CoinType": coin_type,
            "AccountId": account_id,
            "MinAmount": min_amount,
            "MaxAmount": max_amount,
            "Fee": fee,
            "MaxUtxosPerTransaction": max_utxos_per_transaction})

    """
     * raiseFeeForMergeUtxosTransactionRequest
     * @param merge_utxos_request_id The relevant merge utxos request id that contains transaction request to be raised
     * @param transaction_serial_number The relevant transaction serial number in the merge utxos request to be raised
     * @param fee the fee to pay for merge utxos transaction created
     * @param extend_replaceable_transactions_chain Boolean to indicate whether we allow to extend the length of replaceable transactions chain over regular max length 
     (should always be false, except if after discussing with gk8 support, you have been instructed to send true)
     * @return This action will resend the Merge UTXO's transaction with a higher fee
     
     * AccountId - the id of the account
     * Date - The time/date the merge request was made in epoch time
     * Fee - The Fee used in the merge utxo request
     * CurrencySymbol - the symbol of the currency
     * MergeUtxosRequestId - The ID of this merge utxo request
     * MergeUtxosRequestType - The type of this merge utxo request
     * MergeUtxosRequestTypeKey - The type key of this merge utxo request (0 - Merge, 1 - Raise Fee, 2 - Override Fee)
     
     - MergeUtxosRequestOptions:
     * MaxAmountForUtxoToCollect - The max amount of the currency for a utxo to be merged within this request
     * MaxUtxosPerTransaction - The max amount of UTXOs per transaction to be merged within this request
     * MinAmountForUtxoToCollect - The min amount of UTXOs per transaction to be merged within this request
     
     - MergeUtxosTransactionsRequests:
     * BaseForMergeUtxosTransactionRequestId - The ID of the merge utxo request that was based on this request (if applicable)
     * BasedOnMergeUtxosTransactionRequestId - The ID of the merge utxo request this was based on this request (if applicable)
     * FailureDescription - Failure description in the case of failing
     * MergeUtxosRequestId - The ID of this merge utxo request
     * ReplaceableTransactionsChainCount - The number of times the merge utxo request was changed
     * Status - Status of this transaction
     * StatusKey - An integer representing the status of this transaction
     * TransactionSerialNumber - The Serial number of this transaction
     * TxId - The TxId of this transaction
     
     - UtxosIds:
     * TxId - The Id of this transaction
     * VoutIndex - The Vout (transaction output number) of this transaction
     
     example:
      
    *raiseFeeForMergeUtxosTransactionRequest("5d2186175a18420c4b70491c19973dbc1ed70534ef0e2e76cf776ac14680bab2",1,2,false)
     
    """

    def raiseFeeForMergeUtxosTransactionRequest(self, merge_utxos_request_id: str, transaction_serial_number: int,
                                                fee: int, extend_replaceable_transactions_chain: bool = False):
        return self.requestManager.send_request_access_token_included("raiseFeeForMergeUtxosTransactionRequest", {
            "MergeUtxosRequestId": merge_utxos_request_id,
            "TransactionSerialNumber": transaction_serial_number,
            "Fee": fee,
            "ExtendReplaceableTransactionsChain": extend_replaceable_transactions_chain})

    """
     * overrideMergeUtxosTransactionRequest
     * @param merge_utxos_request_id The relevant merge utxos request id that contains transaction request to override
     * @param transaction_serial_number The relevant transaction serial number in the merge utxos request to override
     * @param fee the fee to pay for merge utxos transaction created
     * @param extend_replaceable_transactions_chain Boolean to indicate whether we allow to extend the length of replaceable transactions chain over regular max length 
     (should always be false, except if after discussing with gk8 support, you have been instructed to send true)
     * @return merge utxos request created 
     
     * AccountId - the id of the account
     * Date - The time/date the merge request was made in epoch time
     * Fee - The Fee used in the merge utxo request
     * CurrencySymbol - the symbol of the currency
     * MergeUtxosRequestId - The ID of this merge utxo request
     * MergeUtxosRequestType - The type of this merge utxo request
     * MergeUtxosRequestTypeKey - The type key of this merge utxo request (0 - Merge, 1 - Raise Fee, 2 - Override Fee)
     
     - MergeUtxosRequestOptions:
     * MaxAmountForUtxoToCollect - The max amount of the currency for a utxo to be merged within this request
     * MaxUtxosPerTransaction - The max amount of UTXOs per transaction to be merged within this request
     * MinAmountForUtxoToCollect - The min amount of UTXOs per transaction to be merged within this request
     
     - MergeUtxosTransactionsRequests:
     * BaseForMergeUtxosTransactionRequestId - The ID of the merge utxo request that was based on this request (if applicable)
     * BasedOnMergeUtxosTransactionRequestId - The ID of the merge utxo request this was based on this request (if applicable)
     * FailureDescription - Failure description in the case of failing
     * MergeUtxosRequestId - The ID of this merge utxo request
     * ReplaceableTransactionsChainCount - The number of times the merge utxo request was changed
     * Status - Status of this transaction
     * StatusKey - An integer representing the status of this transaction
     * TransactionSerialNumber - The Serial number of this transaction
     * TxId - The TxId of this transaction
     
     - UtxosIds:
     * TxId - The Id of this transaction
     * VoutIndex - The Vout (transaction output number) of this transaction
     
     example: 
     
     *overrideMergeUtxosTransactionRequest("09ff08c5028c85cbdb349a297ffc19b2c32b9a949ef0b6b57464efaf1467f001",1,7,true)
    """

    def overrideMergeUtxosTransactionRequest(self, merge_utxos_request_id: str, transaction_serial_number: int,
                                             fee: int, extend_replaceable_transactions_chain: bool = False):
        return self.requestManager.send_request_access_token_included("overrideMergeUtxosTransactionRequest", {
            "MergeUtxosRequestId": merge_utxos_request_id,
            "TransactionSerialNumber": transaction_serial_number,
            "Fee": fee,
            "ExtendReplaceableTransactionsChain": extend_replaceable_transactions_chain})

    """
     * updateCoinsPrices
     * @param data is json list "Data" : [{"CoinSymbol":"BTC","FiatPrice":"9000.30"}]
     * @return response the coin symbols that has been updated if the function succeeded.(example: BTC,ETH etc...)
    
     * UpdatedCoinsSymbols - The Symbols of the currencies that were updated
     
    """

    def updateCoinsPrices(self, data: list):
        return self.requestManager.send_request_access_token_included("updateCoinsPrices", {"Data": data})

    """
     * registerWebhook
     * @param webhook_url The webhook URL to be registered
     * @param type the type of webhook:
     *  0 - input transaction - notifying the user about incoming transactions into our system.
     *  1 - approve transaction - notifying the user about transactions that wait to his approval.
     * @param filter - a Json containing the filters by which you want to filter the data for the webhook.
     * - For input transaction webhook, the filter must contain the following fields: CoinSymbol, Machine, AccountId
     *   and MinAmount, for example:
     *       filter: {
     *           "CoinSymbol": "BTC",
     *           "Machine": "Hot",
     *           "AccountIds": ["1"],
     *           "MinAmount": "10000"
     *       }
     * - Approve transaction webhook does not require any filters, so you can choose not to send this parameter,
     *   or to send an empty Json
     * @return register status
     
     * Status - Success/Failed
     * WebhookId - The ID of the created webhook
     
     example:
     
     *registerWebhook("http://192.168.1.22:8027",0,{("BTC","1")})
    """

    def registerWebhook(self, webhook_url: str, type: int, filter: dict = {}):
        return self.requestManager.send_request_access_token_included("registerWebhook",
                                                                      {"WebhookUrl": webhook_url, "Type": type,
                                                                       "Filter": filter})

    """
     * unregisterWebhook
     * @param webhook_id the id of webhook (get from using registerWebhook)
     * @return Unregisters an existingwebhook and returns a success/failed status
     - Status (either success or failed)
     * Success
     * Failed
     
    """

    def unregisterWebhook(self, webhook_id: str):
        return self.requestManager.send_request_access_token_included("unregisterWebhook", {"WebhookId": webhook_id})

    """
     * getAllWebhooks
     * @param None
     * @return Returns an array containing all registered webhooks by user id
     * Status - The status of this webhook (0 for pending, 1 for working, 2 for error)
     * Type - The type of this webhook: 0 for input transaction, 1 for approve transaction request
     * WebhookId - The ID of this webhook
     * WebhookUrl - The URL of this webhook
     
     - Filter: For input transaction, a Json containing the filters of this webhook
     * CoinSymbol - The symbol of the coin used in this operation
     * MinAmount - The min amount used in this operation
     
    """

    def getAllWebhooks(self):
        return self.requestManager.send_request_access_token_included("getAllWebhooks")

    """
     * getColdCommunication
     * @param None
     * @return returns Cold’s available Txid’s
     
     * Amount - The amount in the transaction to be synced in the Cold Vault
     * Deposit code	- The code to be inserted in the deposit dialogue box of the Cold Vault
     * TxId - The ID of the transaction
     
     
    """

    def getColdCommunication(self):
        return self.requestManager.send_request_access_token_included("getColdCommunication")

    """
     * getLastSeenMessageNumber
     * @param None
     * @return Returns the "Last Seen" message number from the MPC
     - MessagesNumber: message from the Cold Vault to the MPC which indicates the commnucation status between both components
     
    """

    def getLastSeenMessageNumber(self):
        return self.requestManager.send_request_access_token_included("getLastSeenMessageNumber")

    """
     * getAudits
     * @param None
     * @return Returns a list of all audit entries
     
     * AccountId - The ID of the account involved in this action
     * Action - The audit entry
     * Description - A description of the audit entry
     * Machine - COLD or MPC
     * Time - The time the action was initiated
     * UserId - The ID of the user that initiated the action
     * UserNickname - The Login name of the user that initiated the action
     
     
    """

    def getAudits(self, filter=None):
        if filter is not None:
            return self.requestManager.send_request_access_token_included("getAudits", {"Filter": filter})
        return self.requestManager.send_request_access_token_included("getAudits")

    """
     * getNotifications
     * @param limit - maximum amount of latest messages
     * @return Returns an array with all the messages from newest to oldest by user id
     
     - Alerts:
     * AccountId - Id of the account the message comes from
     * AccountName - The name of the account
     * NotificationId - Id of this notification in string
     * Time - Time the notification was created
     * Title - Title of the message
     * UserId - Id of the user that created the operation
     * Message - Message contained in the alert
     * EncryptedMessage - Encrypted Message from the Cold if valid
    """

    def getNotifications(self, limit: int = 20):
        return self.requestManager.send_request_access_token_included("getNotifications", {"Limit": limit})

    """
     * get_user_identifier
     * @param none
     * @return user identifier as string
    """

    def get_user_identifier(self):
        return "04" + self.user.userPublicKey

    """
     * get_is_SSM
     * @param none
     * @return user identifier as string
    """

    def get_is_SSM(self):
        return self.user.isSSM == "SSM:true"

    @staticmethod
    def load_stored_user(user_public_key):
        user = User.load_user_data(user_public_key)
        return ApiClient(user, 0, encrypted_api=True)

    """
     * getAllUsers
     * @param None
     * @return response a Json containing all the users' data. Each user has:
     * - user data signed from the cold wallet:
     *  * data["IdWithoutProduct"] = user id chosen in creation in the cold vault
     *  * data["FirstName"] = user first name
     *  * data["LastName"] = user last name
     *  * data["NickName"] = user login name
     *  * data["CanLoginToCold"] = true or false, whether the user can login to the cold vault
     *  * data["Deactivated"] = true or false, whether the user is deactivated
     *  * data["CanOnlySendToHot"] =  true or false, whether the user can only send to the MPC when on the cold vault
     *  * data["AutomaticUser"] = deprecated, always false, ignore
     *  * data["HasAccessToColdDefinitions"] = true or false, whether the user can access to the ColdDefinitions api
     *  * data["IsMultisigApprover"] = true or false, whether the user is a multisig approver
     *  * data["FailedLogins"] = number of failed logins the user had since the last successful login
     *  * data["ApiAccessReactivationFromColdTimestamp"] = OPTIONAL FIELD! time in seconds since epoch indicating when the user was reactivated from cold
    """

    def getAllUsers(self):
        return self.requestManager.send_request_access_token_included("getAllUsers", expected_signed_items=[
            ["FunctionData", "Users", "UserDataSignedByCold"]])

    """
      * getMyData
      * @param None
      * @return response a Json containing this specific user data signed by cold (same format as getAllUsers)
      - MyDataSignedByCold:
      * ApiAccessReactivationFromColdTimestamp - The time in epoch the user API Access was reactivated from the Cold Vault
      * AutomaticUser - Deprecated, always false
      * CanLoginToCold - Whether the user can log-in to the Cold Vault or not (True/False)
      * CanOnlySendToHot - Whether the user can only send to the MPC or not while using the Cold
      * Deactivated - Whether the user is deactivated or not from the cold
      * FailedLogins - Number of failed login attempts by this user since the last successful login
      * FirstName - The first name of this user
      * HasAccessToColdDefinitions - Whether the user has access to the API function getColdDefinitions
      * IdWithoutProduct - User id chosen in creation in the cold vault
      * IsMultisigApprover - Whether the user is a Multisig approver
      * LastName - User's last name
      * NickName - User's login name
      * Time - Time when the Cold Wallet signed this message
      
     """

    def getMyData(self):
        return self.requestManager.send_request_access_token_included("getMyData", expected_signed_items=[
            ["FunctionData", "MyDataSignedByCold"]])

    """
      * getMyGroupLimitLayer
      * @param None
      * @return response a Json containing this specific user group limit layers data signed by cold
      - MyGroupLimitLayerSignedByCold:
      - ColdLimitLayersMapFromCurrencySymbolToVectorOfNameAndAddress: 
      * CurrencySymbolToVectorOfNameAndAddress - The name of the account and address of: BTC,ETH,BCH,XLM,XRP,ADA,XTZ
      * DestinationClassName - The name of the destination class
      
      * GroupId - The id of the group
      * GroupName - The name of the group
      
      - HotLimitLayersMapFromCurrencySymbolToVectorOfNameAndAddress:
      - CurrencySymbolToVectorOfNameAndAddress: The name of the account and address of: BTC,ETH,BCH,XLM,XRP,ADA,XTZ
      * DestinationClassName - The name of the destination class
      * TIme - The UTC time of the API call
      * Signature: signature created from the Cold
     """

    def getMyGroupLimitLayer(self):
        return self.requestManager.send_request_access_token_included("getMyGroupLimitLayer", expected_signed_items=[
            ["FunctionData", "MyGroupLimitLayerSignedByCold"]])

    """
    * deactivateUserApiAccess - only an admin can access this API function.
    * @param user_to_deactivate_id The ID of the user to have his API access deactivated
    * @param deactivation_start_time (optional argument) - The Start Time of the deactivation in UNIX time
    * The required format is the number of seconds since epoch (January 1, 1970, 00:00:00 at UTC) until the start time.
    * The default value for deactivation_start_time is the time-stamp of the request.
    * @return response a confirmation Json.
    - Status: The status of this operation (Success/Failed)
    """

    def deactivateUserApiAccess(self, user_to_deactivate_id: str,
                                deactivation_start_time: str = str(round(time.time()))):
        return self.requestManager.send_request_access_token_included("deactivateUserApiAccess",
                                                                      {"UserToDeactivateId": user_to_deactivate_id,
                                                                       "DeactivationStartTime": deactivation_start_time})

    """
     * reactivateUserApiAccess - only an admin can access this API function.
     * @param user_id The ID of the user to have his API access reactivated
     * @return response a confirmation Json. Reactivates a user API access
      - Status: The status of this operation (Success/Failed)
     
    """

    def reactivateUserApiAccess(self, user_to_reactivate_id: str):
        return self.requestManager.send_request_access_token_included("reactivateUserApiAccess",
                                                                      {"UserToReactivateId": user_to_reactivate_id})

    """
     * getVersion
     * @param None
     * @return {"Version": {"Major": 0,"Minor": 0,"Patch": 0,"Tweak": 0},"useEncryption": true}
    """

    def getVersion(self):
        json = {}
        return self.requestManager.send_unsecure_and_unEncrypted(self.user.serverIP, "getVersion", json, request_timeout=self.requestManager.request_timeout)

    """
     * getCapabilities
     * @param None
     * @return capabilities strings for this version 
     - Capabilities: Capabilities string for this version
     * Key - string of Key used in this operation
     * Value - Whether True or False for Value
     
     * Version - string of version number
     
    """

    def getCapabilities(self):
        return self.requestManager.send_request_access_token_included("getCapabilities")

    """
     * stellarTokens
     * @param account_id in int the account created the token
     * @return This function will return the available stellar tokens in the requested account id
     - StellarTokenSignedByCold:
     * AccountId - The id of the account
     * Anchor - The address of the anchor on the blockchain
     * Issuer - The address of the issuer on the blockchain
     * Name - The name of the token
     * Time - The time that the Cold vault signed this transaction
     
     * Siganture - Signature from the Cold Wallet for this message
    """

    def stellarTokens(self, account_id: int):
        return self.requestManager.send_request_access_token_included("stellarTokens",
                                                                      {"AccountId": account_id},
                                                                      expected_signed_items=[
                                                                          ["FunctionData", "StellarTokenSignedByCold"]])

    """
     * getStellarSetOptionsTransactions
     * @param account_id in int the account created the token
     * @return This function will return the stellar set options transactions of the requested account id
     - StellarSetOptionsTransactionSignedByCold:
     * AnchorAddress - The blockchain address of the anchor
     * ClearFlags - One or more flags (combined via bitwise OR) indicating which flags to clear.
     * Creator - The user that created the action in the Cold Vault
     * HighThreshold - Queries the threshold of the operation
     * HomeDomain - Queries the home domain of an account
     * Inflation - Queries the inflation destination of an account
     * LowThreshold - Queries the threshold of the operation
     * MasterWeight - The weight of the master key
     * MediumThreshold - Queries the threshold of the operation
     * Name - The name of the user
     * SetFlags - One or more flags (combined via bitwise-OR) indicating which flags to set
     * Signer - The signer of the transaction
     * Time - The time of the API call
     * TransactionXdr - xdr base 64 raw transaction to sign and send to the stellar node
     * m_accountId - The account id from which the transaction was initiated
     * m_time - The epoch time of the transaction
     
     * Signature - Signature from the Cold Wallet for this message
    """

    def getStellarSetOptionsTransactions(self, account_id: int):
        return self.requestManager.send_request_access_token_included("getStellarSetOptionsTransactions",
                                                                      {"AccountId": account_id},
                                                                      expected_signed_items=[["FunctionData",
                                                                                              "StellarSetOptionsTransactionSignedByCold"]])


    """
    * getConnectionStatus
    * @param None
    * @return Returns (1: Okay) or (2: Missing info) as the Status of the connection
    * Status - Integer number (1 or 2) with the status of the connection of the user
    * UserId - The ID of the user
    """

    def getConnectionStatus(self):
        return self.requestManager.send_request_access_token_included("getConnectionStatus")

    def verify_deposit_addresses(self, response, accountId):
        isCoinsCacheRefreshNeeded = False
        for wallet in response["FunctionData"]["Wallets"]:
            for activeCurrency in wallet["ActiveCurrencies"]:
                if activeCurrency["Currency"] not in self.__getAndAssureGetCoinsResponseExist(False):
                    isCoinsCacheRefreshNeeded = True
                    break
            if isCoinsCacheRefreshNeeded is True:
                break

        return DepositAddressesManager.verify_deposit_addresses(self.__getAndAssureXPubKeySignedByColdExist(),
                                                                self.__getAndAssureGetCoinsResponseExist(
                                                                    isCoinsCacheRefreshNeeded), response, accountId)

    """
     * createManyWallets
     * @param WalletIds unique wallet id per wallet provided from the client
     * @param walletNames wallet name to be connected to each wallet.
     * @param accountId Account ID used in this operation
     * @param coinSymbols list of symbols to active for the wallets.
     * @param isHidden set the wallets to be hidden (default true).
     * @return All created wallets with addresses of each wallet, active currencies and ishidden.
     
     * AccountID - Account's id
     
     - ActiveCurrencies: Active currencies in account
     * Address - Address of wallet
     * Currency - Coin type
     
     * Hidden - Whether true or false for Hidden
     * WalletDerivationIndex - Integer index of wallet derivation
     * WalletIds - Wallet ids in string
     * WalletName - Wallet's name in string
     
     example:
     
     *createManyWallets(["487"],["asd"],1,["BTC"],false)
    """

    def createManyWallets(self, walletIds: list, walletNames: list, accountId: int, coinSymbols: list,
                          isHidden: bool = True, verify: bool = True):
        assert 0 < len(walletIds) <= 1000 and 0 < len(
            walletNames) <= 1000, "Maximal number of wallets per request are 1000"
        assert len(walletIds) == len(walletNames), "Number of wallet ids must be equal to Wallet names"

        response = self.requestManager.send_request_access_token_included("createManyWallets",
                                                                      {"AccountId": accountId,
                                                                       "WalletIds": walletIds,
                                                                       "WalletNames": walletNames,
                                                                       "CoinSymbols": coinSymbols,
                                                                       "IsHidden": isHidden})
        if verify:
            return self.verify_deposit_addresses(response, accountId)
        else:
            return response

    """
     * addCurrenciesToWallets
     * @param Account ID used in this operation
     * @param WalletIds unique wallet id per wallet provided from the client
     * @param coinSymbols list of symbols to active for the wallets.
     * @return success on finish else error
     - Status: Returns Succeed or Failed
    """

    def addCurrenciesToWallets(self, accountId: int, walletIds: list, coinSymbols: list):
        return self.requestManager.send_request_access_token_included("addCurrenciesToWallets",
                                                                      {"AccountId": accountId,
                                                                       "WalletIds": walletIds,
                                                                       "CoinSymbols": coinSymbols})

    """
     * removeCurrenciesFromWallets
     * @param Account ID used in this operation
     * @param WalletIds unique wallet id per wallet provided from the client
     * @param coinSymbols list of symbols to active for the wallets.
     * @return success on finish else error
     - Status: Returns Succeed or Failed
     
    """

    def removeCurrenciesFromWallets(self, accountId: int, walletIds: list, coinSymbols: list):
        return self.requestManager.send_request_access_token_included("removeCurrenciesFromWallets",
                                                                      {"AccountId": accountId,
                                                                       "WalletIds": walletIds,
                                                                       "CoinSymbols": coinSymbols})

    """
     * getWallets
     * @param accountId - Account ID used in this operation
     * @param WalletIds unique wallet id per wallet provided from the client
     * @return return requested wallets with addresses of each wallet, active currencies and ishidden.
     
     - Wallets: requested wallets with addresses of each wallet, active currencies and ishidden
     * WalletDerivationIndex - Integer index of wallet derivation
     * AccountID - account Id used in the operation
     * ActiveCurrencies - Active currencies in account
     * Hidden - whether true or false for hidden
     * WalletId - wallet id number in string
     * WalletName - wallet name in string
     
     example:
     
     *getWallets(1,["487"])
     
    """

    def getWallets(self, accountId: int, walletIds: list, verify: bool = True):
        assert 0 < len(walletIds) <= 1000, "Maximal number of wallets per request are 1000"
        response = self.requestManager.send_request_access_token_included("getWallets",
                                                                          {"AccountId": accountId,
                                                                           "WalletIds": walletIds})
        if verify:
            return self.verify_deposit_addresses(response, accountId)
        else:
            return response

    """
     * getWalletsByRange
     * @param accountId The account ID used in this operation
     * @param startingIndex wallets index
     * @param amount number of wallets to collect from provided index
     * @param showHidden ui/sort boolean to set a ui flag
     * @return return all wallets in the account with addresses of each wallet, active currencies and ishidden.
     * AccountID - account's id in string
     
     - ActiveCurrencies: Active currencies in account
     * Address - Address of wallet in string
     * Currency - coin symbol used
     * Hidden - whether true or false for hidden
     * WalletDerivationIndex - Integer index of wallet derivation
     * WalletIds - Wallet ids in string
     * WalletName - wallet's name in string
     
     example:
     
     *getWalletsByRange(1,0,2,true)
     
    """

    def getWalletsByRange(self, accountId: int, startingIndex: int, amount: int, showHidden: bool = True,
                          verify: bool = True):
        assert amount <= 1000, "Maximal number of wallets per request are 1000"
        assert amount >= 0, "Amount must be a positive number greater than 0"
        response = self.requestManager.send_request_access_token_included("getWalletsByRange",
                                                                          {"AccountId": accountId,
                                                                           "StartingIndex": startingIndex,
                                                                           "Amount": amount,
                                                                           "ShowHidden": showHidden})
        if verify:
            # List all active currencies with deposit wallets
            active_currencies = set()
            for deposit_wallet_data in response["FunctionData"]["Wallets"]:
                active_currencies = active_currencies.union([active_currency["Currency"]
                                                             for active_currency in
                                                             deposit_wallet_data["ActiveCurrencies"]])
            return DepositAddressesManager.verify_deposit_addresses(self.__getAndAssureXPubKeySignedByColdExist(),
                                                                    self.__getAndAssureGetCoinsResponseExist(False,
                                                                                                             active_currencies),
                                                                    response, accountId)
        else:
            return response

    """
     * getWalletsBalances
     * @param accountId account id to use in the operation
     * @param WalletIds unique wallet id per wallet provided from the client
     * @param updateNow if to take the balances from the node(limited to 50 wallets) or from the database
     * @return return requested wallets with addresses and balance of each wallet.
     - WalletBalances:
     - Balances: array with the balance for each wallet (MPC/Cold)
     * Address - Address of wallet in string
     * Balance - available balance in wallet
     * Coin - coin symbols
     * UpdateTime - date and hour of update time
     * WalletId - wallet'sid in string
     * WalletName - wallet's name in string
    """

    def getWalletsBalances(self, accountId: int, walletIds: list, updateNow: bool = False):
        MAX_WALLETS_FROM_NODE = 50
        assert not updateNow or (
                    len(walletIds) <= MAX_WALLETS_FROM_NODE), f"Maximal number of wallets per request is {MAX_WALLETS_FROM_NODE} if updateNow is true."
        return self.requestManager.send_request_access_token_included("getWalletsBalances",
                                                                      {"AccountId": accountId,
                                                                       "WalletIds": walletIds,
                                                                       "UpdateNow": updateNow})

    """
     * getWalletsBalancesByRange
     * @param accountId account id to use in this operation
     * @param startingIndex wallets index
     * @param amount number of wallets to collect from provided index
     * @param updateNow if to take the balances from the node(limited to 50 wallets) or from the database
     * @return return requested wallets with addresses and balance of each wallet by range
     
     - WalletBalances:
     - Balances: array with the balance for each wallet (MPC/Cold)
     * Address - Address of wallet in string
     * Balance - available balance in wallet
     * Coin - coin symbols
     * UpdateTime - date and hour of update time
     * WalletId - wallet'sid in string
     * WalletName - wallet's name in string 
    """

    def getWalletsBalancesByRange(self, accountId: int, startingIndex: int, amount: int, showHidden: bool = True,
                                  updateNow: bool = False):
        MAX_WALLETS_FROM_NODE = 50
        MAX_WALLETS = 1000
        assert amount <= MAX_WALLETS, "Maximal number of wallets per request are 1000"
        assert (not updateNow or (
                    amount <= MAX_WALLETS_FROM_NODE)), "Maximal number of wallets per request is 50 if updateNow is true."
        return self.requestManager.send_request_access_token_included("getWalletsBalancesByRange",
                                                                      {"AccountId": accountId,
                                                                       "StartingIndex": startingIndex,
                                                                       "Amount": amount,
                                                                       "ShowHidden": showHidden,
                                                                       "UpdateNow": updateNow})

    """
     * setWalletsHidden
     * @param accountId Account ID used in this operati multiline key may not be an implicit key in "on
     * @param WalletIds unique wallet id per wallet provided from the client
     * @param setHidden set/unset the wallets to be hidden (default true).
     * @return return success on finish else error
     - Status: Status of setWalletsHidden request
    """

    def setWalletsHidden(self, accountId: int, walletIds: list, setHidden: bool = True):
        return self.requestManager.send_request_access_token_included("setWalletsHidden",
                                                                      {"AccountId": accountId,
                                                                       "WalletIds": walletIds,
                                                                       "SetHidden": setHidden})

    """
     * deactivateWallets - clear active currencies and set to hidden
     * @param accountId Account ID used in this operation
     * @param WalletIds unique wallet id per wallet provided from the client
     * @return return success on finish.
     
     - Status: Status of setWalletsHidden request
     
    """

    def deactivateWallets(self, accountId: int, walletIds: list):
        return self.requestManager.send_request_access_token_included("deactivateWallets",
                                                                      {"AccountId": accountId,
                                                                       "WalletIds": walletIds})

    """
     * setWalletName
     * @param accountId ccount ID used in this operation
     * @param WalletId unique wallet id provided from the client
     * @param newWalletName new wallet name to be connected requested wallet.
     * @return return success on finish else error
     
     - Status: Status of setWalletsHidden request
     
     example:
     
     *renameWallet(1,"55556666","Matan")
    """

    def renameWallet(self, accountId: int, walletId: str, newWalletName: str):
        return self.requestManager.send_request_access_token_included("renameWallet",
                                                                      {"AccountId": accountId,
                                                                       "WalletId": walletId,
                                                                       "WalletName": newWalletName})

    """
     * getStakingAvailableRewards
     * @param account_id Account ID used in this operation
     * @param coin_types array of symbols to use
     * @return available rewards per account, per currency 
     
     - addressesWithdrawals:
     * address - string of address used for withdrawal
     * availableRewards - The amount of currency available as reward
     
     - coin: coin symbol in string
    """

    def getStakingAvailableRewards(self, account_id: int, coin_types: list):
        return self.requestManager.send_request_access_token_included("getStakingAvailableRewards",
                                                                      {"AccountId": account_id,
                                                                       "CoinTypes": coin_types})

    """
     * getActiveDelegations
     * @param account_id Account ID to use in this operation
     * @param coin_types coin symbol to use in this operation
     * @return pool-ids per account currency. if None, not delegated.
     - addressesWithdrawals:
     * address - string of address used for withdrawal
     * availableRewards - The amount of currency available as reward
    """

    def getActiveDelegations(self, account_id: int, coin_types: list):
        return self.requestManager.send_request_access_token_included("getActiveDelegations",
                                                                      {"AccountId": account_id,
                                                                       "CoinTypes": coin_types})

    """
     * getPoolInfo
     * @param accountId account ID to use in this operation
     * @param ticker WalletDerivationIndex provided with the wallet.
     * @param pool_id Pool ID used in this operation
     * @return structure like the follow:
     {
        "pool_id": "pool1pu5jlj4q9w9jlxeu370a3c9myx47md5j5m2str0naunn2q3lkdy", ID of pool
        "hex": "0f292fcaa02b8b2f9b3c8f9fd8e0bb21abedb692a6d5058df3ef2735", HEX of pool
        "url": "https://GK8.com/mainnet.json", URL of pool
        "hash": "47c0c68cb57f4a5b4a87bad896fc274678e7aea98e200fa14a1cb40c0cab1d8c", has of pool
        "ticker": "GK8", ticker of pool
        "name": "Stake GK8", name of pool
        "description": "The best pool ever", description of pool
        "homepage": "https://GK8.com/" homepage of pool
    } 
    
    example:
    
    *getPoolInfo(1,"ADA","pool1y25deq9kldy9y9gfvrpw8zt05zsrfx84zjhugaxrx9ftvwdpua2")
    """

    def getPoolInfo(self, account_id: int, ticker: str = "", pool_id: str = ""):
        assert ticker != "" or pool_id != "", "Must insert Ticker or Pool ID"
        return self.requestManager.send_request_access_token_included("getPoolInfo",
                                                                      {"AccountId": account_id,
                                                                       "Ticker": ticker,
                                                                       "PoolId": pool_id})

    """
     * getMaxSpendableBalance
     * @param accountId account ID to use in this operation
     * @param coinSymbols list of symbols(just of utxo coins).
     * @return max spendable balance in inside tx and
     * max spendable balance in outside tx for each coin in coinSymbols.
     
     * Coin - coin type used
     * MaxSpendableBalanceInOutsideTx - The amount of maximum spendable balance out side Tx for wanted coin
     * MaxSpendableBalanceToCold - The amount of maximum spendable balance to Cold for wanted coin
     
    """

    def getMaxSpendableBalance(self, accountId: int, coinSymbols: list):
        return self.requestManager.send_request_access_token_included("getMaxSpendableBalance",
                                                                      {"AccountId": accountId,
                                                                       "CoinSymbols": coinSymbols})


"""---------------------------------- End of api funcs --------------------------------------------------------- """
