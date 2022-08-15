import os
from utils import *
from encData import encData
from time import sleep
from Crypto.Random import get_random_bytes
from ElGamal import *

img_path = str(os.path.dirname(os.path.abspath(__file__))) + '\\' + "test_data.jpg"

class Issuer():
    def __init__(self):
        super().__init__()
        self.addr = "0x12NBhaHX4KZJ42AMpZ4pixETMTcvqTpTQ8"
        self.pk = initialize_ElGamal()
        self.sk = self.pk.getPrivateKey()
        self.pkd = "04ef80333b7c8064ae3a302ce7a5d7265216918a9ff5d60a72534ec7bb926521181a4580a3a7f156b009d45f947a9613da8f8ce8c8536a0b0d59e516fb8c19fc12"

    def getAddress(self):
        return self.addr
    
    def getPubkey(self):
        return self.pk                                              # Issuer의 public key return

    def getPubkey_data(self):
        return self.pkd

    def issueDIDCredential(self, addr, attr):                       # addr: peer의 address / attr: issue하려는 attr
        r = list()                                                  # r, t는 다시 peer에게 보내야 하기에 list로 저장
        t = list()
        for a in attr:
            r.append(get_random_bytes(16))                          # random 뽑아서 r에 추가
            data = (addr, a, r[-1])                                 # 하나로 모아서
            t.append(hash(data))                                    # hash한 값을 t에 추가
        tx_msg = "Issue: " + "||".join(t)                           # Transaction 생성하기 위한 메세지 설정
        if (makeTransaction(self.getPubkey(), tx_msg)):             # makeTransaction 호출하여 생성되고 블록체인에 올렸다면
            print("[Issuer]: Issue success")
            return t, r                                             # 생성 성공 시 r, t return
        else:
            return "[Issuer]: Cannot issue credentials"             # 생성 실패 시 False return
        
    def revokeDIDCredential(self, addr, t):                         # addr: peer의 address / t: revoke하려는 attr의 hash 값
        tx_msg = "Revoke: " + "||".join(t)                          # Transaction 생성하기 위한 메세지 설정
        if (makeTransaction(self.getPubkey(), tx_msg)):             # makeTransaction 호출하여 생성되고 블록체인에 올렸다면
            print("[Issuer]: Revoke success")
            return True                                             # 생성 성공 시 True return
        else:
            print("[Issuer]: Cannot revoke credentials")
            return False                                            # 생성 실패 시 False return

class Peer():                                                       # 필요한 모듈 사용 시 넣기
    def __init__(self):                                             # 개인 key 생성도 같이 할까
        super().__init__()
        self.addr = "0x1JqFz5Q7iDdKPsMych_k9GsrPPMTqdpKJcn"
        self.pk_enc = initialize_ElGamal()
        self.sk = self.pk_enc.getPrivateKey()
        r = get_random_bytes(16)
        self.pk_own = hash(self.sk, r)

    def getAddress(self):
        return self.addr                                            # 주소(addr)을 return

    # =========================== [Code:    DID] =========================== 
    def requestDIDCredentialIssue(self, issuer: Issuer, attr):      # Issuer에게 credential issue 요청 전송
        return issuer.issueDIDCredential(self.getAddress(), attr)   # 비동기식이면 addr과 attr을 메세지 만들어서 issuer에게 보낸다의 형태로 해야 할 듯
        
    def requestDIDCredentialRevoke(self, issuer: Issuer, attr):
        r = list()                                                  # input의 attr vector를 DB로부터 찾아서
        t = list()                                                  # 저장할 r, t를 list로 정의
        with open('./DB.txt', 'r') as fd:                           # DB 열어서 (임시로 text로 정의)
            fd.seek(0)                                              # offset 첫 위치로 이동하여
            lines = fd.readlines()                                  # 줄 단위 리스트로 lines에 저장
            for i in range(len(attr)):                              # attr 개수만큼 찾아야 함
                for line in lines:                                  # 리스트가 ["attr t r\n", ...]의 형태로 저장되어 있음
                    temp = " ".join([line.rstrip()])                # 마지막의 개행 문자 삭제
                    data = temp.split()                             # 리스트의 각 요소를 attr t r로 분리
                    if attr[i] == data[0]:                          # 각 줄별로 attr 비교
                        t.append(data[1])                           # 맞을 시 해당 t 불러오기
                        r.append(data[2])                           # 맞을 시 해당 r 불러오기
                        break
        if issuer.revokeDIDCredential(self.getAddress(), t):        # Issuer에게 credential revoke 요청 전송 (비동기식)
            return t, r
        else:
            return False

    def storeDIDCredential(self, attr, t, r):                       # Local DB에 (attr, t, r)을 저장
        # await issuer.issueDIDCredential(self.getAddress(), attr)
        if (len(attr) != len(t)) | (len(attr) != len(r)):
            print("[Peer]\t: Failed to store credentials")
            return False                                            # error check
        try:
            with open('./DB.txt', 'a+') as fd:                      # DB 접근하여 (임시로 text로 정의; DB.txt가 없을 시 새로 생성)
                for i in range(len(attr)):                          # list로 저장
                    credlist = [attr[i], t[i], r[i]]                # attr, t, r을 하나의 리스트로 만들어서
                    credential = " ".join(map(str, credlist))       # 문자열로 바꾼 뒤
                    fd.write(credential)                            # DB에 저장
                    fd.write('\n')
                print("[Peer]\t: Store succeeded")
            return True                                             # true return
        except:                                                     # 위의 작성에서 오류 발생 시
            return False                                            # false return

    def deleteDIDCredential(self, attr, t, r):                      # Local DB에 (attr, t, r)을 삭제        <== O(cred * line)
        if (len(attr) != len(t)) | (len(attr) != len(r)):
            print("[Peer]\t: Failed to delete credentials")
            return False                                            # error check
        credential = list()                                         # 삭제할 attr, t, r을 저장할 list 정의
        for i in range(len(attr)):
            credlist = [attr[i], t[i], r[i]]                        # attr, t, r을 하나의 리스트로 만들어서
            credential.append(" ".join(map(str, credlist)))         # 문자열로 바꿈
        try:
            with open('./DB.txt', 'r+') as fd:                      # DB 접근하여 (임시로 text로 정의; DB.txt가 없을 시 수행 안함)
                for cred in credential:                             # credential의 요소에 대하여
                    fd.seek(0)                                      # file offset을 file의 맨 처음으로 이동
                    offset = 0                                      # 첫 줄의 시작 위치를 offset에 저장
                    lines = fd.readlines()                          # 줄 단위 list로 저장
                    for line in lines:                              # 리스트가 ["attr t r\n", ...]의 형태로 저장되어 있음
                        line_offset = offset                        # 현재 줄의 시작 위치를 offset에 저장하며 삭제할 부분을 가리킬 때 사용
                        offset += len(line)                         # 현재 줄의 마지막 위치를 offset에 저장하며 추후 삭제할 부분 이후의 내용 복구를 위해 사용
                        temp = " ".join([line.rstrip()])            # 마지막의 개행 문자 삭제
                        if cred == temp:                            # 만약 해당 attr t r이 맞다면
                            if line_offset != 0:                    # 최초 첫줄을 제외한 나머지는 개행 문자로 인하여
                                offset += 2                         # offset에 2를 더하여 다음 줄의 시작 위치로 이동
                            fd.seek(offset)                         # file offset을 삭제할 부분 이후의 시작 위치로 이동하여
                            temp2 = fd.read()                       # temp2에 저장한다
                            fd.seek(line_offset)                    # file offset을 삭제할 부분의 시작 위치로 이동하여
                            fd.write(temp2)                         # temp2로 덮어써서 해당 부분 삭제 및 이후 내용을 복구한다.
                            fd.truncate()                           # file 후처리
                            break
                print("[Peer]\t: Delete succeeded")
            return True                                             # true/false return
        except:
            return False
    
    def genProof(self, crs, x, w):                                  # statement x와 witness w를 가지고 proof pi 생성
        pi = [crs, x, w]                                            # proof 만들기   
        return pi
    
    def createDIDPresentation(self, crs, x, attr, r, pk):
        c = hash(pk, hash(self.getAddress(), attr, r))
        w = [c, attr, r, pk]
        pi_did = self.genProof(crs, x, w)
        return [x, pi_did]
    
    # =========================== [Code:   Data] =========================== 
    def createDataPresentation(self, crs, x, attr_data, r_data, pk_data, data_key, CT, data):
        data_id = hash(data)
        c = hash(pk_data, hash(data_id, attr_data, r_data, data))
        w = [data_id, c, attr_data, r_data, pk_data, data, data_key, CT]
        pi_data = self.genProof(crs, x, w)
        return [x, pi_data]

    def registerInfo(self, info, CT):
        if makeTransaction(self.pk_enc, info):
            print("============ [Test:  Transfer info to blockchain completed] ============")
        if self.send2server(CT):
            print("============== [Test:  Transfer data to sever completed] ===============")

    def getDataKey(self):                                           # 추후 consumer와의 거래가 만족스러울 경우 자신의 k를 보내야 하기 위해서
        return self.k                                               # k를 따로 구하는 것보단 이게 더 낫지 않을까

    def genInfo(self, attr, r, attr_data, r_data, pk_did, pk_data, data):
        # data_id = hash(data)                                      # createDataPresentation에서 생성하고
                                                                    # genProof를 통해 검증하는 것도 있으니 생략해도 괜찮을 듯
        self.k = get_random_bytes(16); h_k = hash(self.k)
        CT = self.encset(self.k, data); h_ct = hash(CT)
        
        # self.pk_enc = generate()                                    # ElGamal이라 가정 (init에서 생성)
        # self.pk_own = get_random_bytes(16)                          # aes encrypt라 가정
        pre_did = self.createDIDPresentation(1, 1, attr, r, pk_did)
        pre_data = self.createDataPresentation(1, 1, attr_data, r_data, pk_data, self.k, CT, data)
       
        info = "Register: " + " ".join(["pre_did", "pre_data", h_ct, h_k, " ".join(map(str, self.pk_enc.getPublicKey())), self.pk_own])
        return info, CT
    
    # 나중에 파일에서 불러서 처리할 것
    def send2server(self, CT):
        return True

    def encset(self, data_key, data):
        enc = encData(data_key, data)
        enc.enc()
        return enc.getCT()
    
    # =========================== [Code:  Trade] =========================== 
    def genTrade(self, ENA, info, fee, crs):                        # ENA : consumer의 암호화된 계좌
                                                                    # info : blockchain에서 읽어오는 정보
                                                                    # fee : consumer가 peer에게 지불할 금액
        # account = self.pk_own.decrypt(ENA)
        # account = account - fee
        # ENA_new = self.pk_own.encrypt(account)
        ENA_new = 1                                                 # ENA에서 fee만큼 빼내어 다시 암호화한 것을 ENA_new라 정의
        info_list = info.split()                                    # info를 가져와서
        h_k = info_list[-5]                                         # 차후 해당 key가 필요하다는 것을 표현하기 위해 info에서 h_k 가져오기
        pk_enc = [info_list[-4], info_list[-3], info_list[-2]]      # Peer의 pk_enc 가져오기
        pk_own = info_list[-1]                                      # Peer의 pk_own 가져오기
        r = get_random_bytes(16)                                    # 난수 뽑기
        c = hash(self.pk_enc, pk_own, fee, r, h_k)
        msg = [self.pk_enc.getPublicKey(), self.pk_own, fee, r, h_k]
        c1, c2 = encrypt(pk_enc, msg)
        x = (c, c1, c2, ENA, ENA_new)                               # statement
        w = (r, h_k, self.pk_enc, self.pk_own, fee)                 # witness
        pi = self.genProof(crs, x, w)                               # Trade하기 위해 필요한 정보들이 제대로 입력했음을 나타내는 증명 생성
        tx_msg = "Trade: " + " ".join(map(str, [c, c1, c2, pi]))
        return makeTransaction(self.pk_enc, tx_msg)

    def getTradeList(self):                                         # Trade List를 주지만, 사실 상 Transaction 다 알려주기
        try:
            with open("Transaction.txt", 'r+') as fd:               # Transaction.txt 파일에 올라가있다 가정
                temp = fd.readlines()
                CTList = [line.rstrip() for line in temp]
                return CTList
        except:
            return "[Peer]\t: Cannot read trade list"
    
    def scanTrade(self):                                            # Trade List를 보면서 만족스러운 금액이 있을 경우 ㄱㄱ
        CTList = self.getTradeList()                                # Trade List 가져오기
        for ct in CTList:
            temp = ct.split()                                       
            if temp[0] == "Trade:":
                msg = self.pk_enc.decrypt(temp[2], temp[3])         # 문제점: 평문의 길이가 너무 길어 잘림
                print(msg)
                item = msg.split()
                try:
                    if len(item) == 7:                              # 내 sk를 이용하여 제대로 복호화가 되는지 확인
                        fee = item[-3]                              # 금액 확인하고 거래할 것인지 결정
                        print(type(fee))
                        print("금액: ", fee)
                        while 1:
                            result = input("수락하시겠습니까?? (Y/N) ")
                            if result == 'Y' or result == 'y':
                                return fee, item
                            elif result == 'N' or result == 'n':
                                break
                            else:
                                print("올바른 언어를 입력하세요.")
                                continue
                except:
                    continue
        print("Doesn't exist list waiting for trade")
        return -1, -1

    def approveTrade(self, msg, pk_cons: ElGamal, k, crs):
        msg = msg.split()
        c = msg[1]; h_k = msg[-1]
        CTk = pk_cons.encrypt(k)
        x = (c, CTk)
        w = (h_k, k, pk_cons)
        pi = self.genProof(crs, x, w)
        tx_msg = "Approve: " + " ".join(map(str, [c, CTk, pi]))
        return makeTransaction(self.pk_enc, tx_msg)

def main():
    peer = Peer()
    issuer = Issuer()
    consumer = Peer()
    iattr = ["1997", "7", "31", "Incheon", "M"]
    print("============================ [Test:  Issue] ============================")
    it, ir = peer.requestDIDCredentialIssue(issuer, iattr)
    peer.storeDIDCredential(iattr, it, ir)
    sleep(2)
    print("\n============================ [Test: Revoke] ============================")
    rattr = ["7", "31"]
    rt, rr = peer.requestDIDCredentialRevoke(issuer, rattr)
    peer.deleteDIDCredential(rattr, rt, rr)
    
    print("\n=========================== [Test:  genInfo] ===========================")
    data = img_path; r_data = 1; attr_data = ["M"]; pattr = ["1997", "Incheon", "M"]; pr = [ir[0], ir[3], ir[4]] # 임시로 그냥 끌고 와서 사용
    info, CT = peer.genInfo(pattr, pr, attr_data, r_data, issuer.getPubkey(), issuer.getPubkey_data(), data)
    peer.registerInfo(info, CT)
    # info = "Register: " + " ".join(["pre_did", "pre_data", "h_ct", "h_k", " ".join(map(str, peer.pk_enc.getPublicKey())), peer.pk_own])
    
    print("\n============================ [Test:  Trade] ============================")
    fee = 10
    consumer.genTrade(2, info, fee, 1)
    fee, ct = peer.scanTrade()
    peer.approveTrade(ct, consumer.pk_enc, peer.getDataKey(), 1)

if __name__ == "__main__":
    main()