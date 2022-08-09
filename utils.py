import hashlib                                                      # 헤더 파일

def hash(*args):
    msg = str(0)
    for i in str(args):
        msg += str(i)
    result = hashlib.sha256(str(msg).encode()).hexdigest()
    # print("=======================")
    # print("transaction 생성 완료")
    # print("Hash: ", result)

    return result

def makeTransaction(pk, msg):                                       # peer, consumer, issuer 다 사용하기에 
    return True
                                                                    # 전역 함수로 설정하는게 맞지 않을까
    serealize()                                                     # serealize msg
    sign(pk, msg)                                                   # 메세지 sign하기
    send()                                                          # 블록체인에게 보내기



#     try:
#     if self.Issuer_pk == pk:
#         # attr형식이 맞는지 확인하는 함수 추가
#         r = 3 # random
#         tx = addr + attr + r # t
#         # sign 햇다고 가정
#         tx = hashlib.sha256(str(tx).encode('utf-8')).hexdigest()
#         if (trasnferTX(tx, msg)):
#             return [tx, r]
#     else:print("INVALID ISSUER ADDRESS")

# except:
#     print("INVALID TRANSACTION")