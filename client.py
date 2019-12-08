import socket
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import hashlib
from Crypto.Cipher import PKCS1_OAEP
import threading
from base64 import b64encode
import base64
import json
import time
from tkinter import *
import queue
from functools import partial
from tkinter import filedialog
import re
#
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
arrDataFile =[]
msgQueue = queue.Queue()
CurrentChatUsr = ""
x = 0 
y = 0
rowRight = 1
#hàm lấy tên file
def getfilename(key,client):
    filename =  filedialog.askopenfilename(initialdir = "/",title = "Select file",filetypes = (("all files","*.*"),("jpeg files","*.jpg")))
    print('link file : '+ filename)
    encrypt_file(key, client, filename)
#hàm mã hóa và gửi  file data
def encrypt_file(key, client, in_filename ):
    global CurrentChatUsr
    global myName
    global x
    global y
    global CurrentChatUsr
    global count
    global chatBox
    global rowRight
    #Tách lấy tên file
    string = in_filename.replace('\\','/')
    arr = string.split("/")
    namefile = arr[len(arr)-1]
    
    #Lấy thông tin gửi cho server    :  EncryFile-tên file- 
    dataName ="EncryFile-"+ namefile +"-"+CurrentChatUsr+"-"+ myName
    print('data :'+dataName)
    dataName = dataName.encode()
    #Đọc dữ liệu từ file và mã hóa
    with open(in_filename, 'rb') as f:
        data = f.read()
        key = key[:16].encode()
        cipher = AES.new(key, AES.MODE_CBC)
        
        ct_bytesName = cipher.encrypt(pad(dataName, AES.block_size))
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytesName).decode('utf-8')
        ct2 = b64encode(ct_bytes).decode('utf-8')

        dataEncryFile = json.dumps({'iv':iv, 'ciphertext':ct, 'ciphertext2':ct2}).encode()
        # dataEncryFile = json.dumps({'iv':iv, 'ciphertext2':ct2}).encode()
        client.send(dataEncryFile)    
        #Hiện thị tin nhắn bên phía người gửi file 
        displayMsg = myName + ": đã gửi file  " +namefile+"\n"
        position = str(x) + "." + str(y)
        x = x + 1
        chatBox.insert(position,displayMsg) 

#hàm gửi tin nhắn mã hóa
def sendeMsg(key,client,message):
    sendMsg = message.encode()
    key = key[:16].encode()
    aesEncrypt = AES.new(key,AES.MODE_CTR)
    ct_bytes = aesEncrypt.encrypt(sendMsg)
    nonce = b64encode(aesEncrypt.nonce).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    eMsg = json.dumps({'nonce':nonce, 'ciphertext':ct}).encode()
    client.send(eMsg)
#hàm nhận dữ liệu theo từng Buffer
def recvall(sock):
    BUFF_SIZE = 4096 # 4 KiB
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            # either 0 or end of data
            break
    return data

#hàm nhận tin nhắn mã hóa chạy để chat trong function chat và hiển thị tin nhắn mình nhận được
def recvdMsgTTK(key,client):
    key = key[:16].encode()
    while True:
        global x
        global y
        global CurrentChatUsr
        global count
        global chatBox
        global rowRight
        eMsg = recvall(client)
        eMsg = eMsg.decode()
        b64 = json.loads(eMsg)
        try:
            nonce = base64.b64decode(b64['nonce'])
            ct = base64.b64decode(b64['ciphertext'])
            aesDecrypt = AES.new(key,AES.MODE_CTR,nonce=nonce)
            dMsg = aesDecrypt.decrypt(ct).decode()
            print("New mess from client ",client ," : " , dMsg)
            if (dMsg == "Create new user successfully" or dMsg == "Login successfully" or dMsg == "Login failed" or dMsg == "Create new user failed" or (dMsg.startswith('[') and dMsg.endswith(']'))):
                msgQueue.put(dMsg)
                data = msgQueue.get().split(',')
                CreateListUsr(listbox_2,data)
            else :
                MsgArr = dMsg.split('-')
                chatMsg=""
                if (myName == MsgArr[1] and CurrentChatUsr == MsgArr[0]):
                    for i,m in enumerate(MsgArr):
                        if (i>1):
                            chatMsg = chatMsg + MsgArr[i] + " "
                    displayMsg = CurrentChatUsr + ": " + chatMsg + "\n"
                    position = str(x) + "." + str(y)
                    chatBox.insert(position,displayMsg)
                    x = x + 1
        except :
            # Giả mã file nhận đc
            print('da nhan dc file ma hoa')
            iv = b64decode(b64['iv'])
            ct = b64decode(b64['ciphertext'])
            ct2 = b64decode(b64['ciphertext2'])
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size) 
            pt2 = unpad(cipher.decrypt(ct2), AES.block_size)
            print("The message NameFile(string): ", pt.decode())
            arr = pt.decode().split('-')
            nameFile = arr[1]
            dataFile = pt2
            arrDataFile.append([nameFile,dataFile])
            pt =pt.decode() #pt gồm : Tên file -client hiện tại - Client gửi file
            print('Thông tin file nhận đc :'+pt)
            print("Luu du lieu data vao mang thanh cong")
            arrName = pt.split('-')

            #Hiện thị tin nhắn bên phía người nhận file
            displayMsg = arrName[2] + ": đã gửi file  " +arrName[0]+"\n"
            position = str(x) + "." + str(y)
            x = x + 1
            chatBox.insert(position,displayMsg)
            
            #save file
            
            fileButton= Button(rootsC, text=arrName[0], command=partial(saveFile,arrName[0],pt2), width=10 , justify=LEFT)
            fileButton.grid(row=rowRight,column=7)
            rowRight +=1
            
#hàm  save file
def saveFile(nameFile,data):
    print("file name :"+nameFile)
    file = filedialog.asksaveasfilename(initialdir = "/",initialfile=nameFile,title = "Select file",filetypes = (("all files","*.*"),("jpeg files","*.jpg")))
    f = open(file, 'wb')
    f.write(data)
    f.close()
#hàm nhận tin nhắn mã hóa chạy để check đăng nhập, đăng ký 
def recvdMsg(key,client,msgQueue):
    global x
    global y
    global CurrentChatUsr
    global count
    eMsg = client.recv(1024).decode()
    b64 = json.loads(eMsg)
    nonce = base64.b64decode(b64['nonce'])
    ct = base64.b64decode(b64['ciphertext'])
    key = key[:16].encode()
    aesDecrypt = AES.new(key,AES.MODE_CTR,nonce=nonce)
    dMsg = aesDecrypt.decrypt(ct).decode()
    print("New mess from client ",client ," : " , dMsg)
    if (dMsg == "Create new user successfully" or dMsg == "Login successfully" or dMsg == "Login failed" or dMsg == "Create new user failed" or (dMsg.startswith('[') and dMsg.endswith(']'))):
        msgQueue.put(dMsg)

#Khung đăng ký
def Signup(key,client):
	global pwordE
	global nameE

	global roots

	roots = Tk()
	roots.title('Signup')
	instruction = Label(roots, text='register')
	instruction.grid(row=0, column=0, sticky=E)

	nameL = Label(roots, text='New Username: ')
	pwordL = Label(roots,text='New Password: ')
	nameL.grid(row=1, column=0, sticky=W)
	pwordL.grid(row=2, column=0, sticky=W)

	nameE = Entry(roots)
	pwordE = Entry(roots, show='*')
	nameE.grid(row=1, column=1)
	pwordE.grid(row=2, column=1)

	signupButton = Button(roots, text='Signup', command=partial(FSSignup,key,client))
	signupButton.grid(columnspan=2, sticky=W)
	roots.mainloop()

#hàm để thực hiện đăng ký
def FSSignup(key,client):
    sendMsg = "signup-" + nameE.get() + "-" + pwordE.get()
    if (nameE.get() != "" and pwordE.get() != ""):
        regex = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
        if (regex.search(nameE.get()) == None and regex.search(pwordE.get()) == None) :
            threadSend = threading.Thread(target=sendeMsg,args=(key,client,sendMsg,))
            threadSend.start()
            threadSend.join()

            threadRecv = threading.Thread(target=recvdMsg,args=(key,client,msgQueue,))
            threadRecv.start()
            threadRecv.join()

            msg = msgQueue.get()
            if ( msg == "Create new user successfully" ):
                roots.destroy()
                Login(key,client)

            if ( msg == "Create new user failed" ):
                r = Tk()	
                r.title('D:')
                r.geometry('150x50')
                rlbl = Label(r, text='\n! Invalid Register')
                rlbl.pack()
                r.mainloop()            
        else :
            r = Tk()	
            r.title('D:')
            r.geometry('150x50')
            rlbl = Label(r, text='\n! Invalid Register')
            rlbl.pack()
            r.mainloop()
    else :
        r = Tk()	
        r.title('D:')
        r.geometry('150x50')
        rlbl = Label(r, text='\n! Invalid Register')
        rlbl.pack()
        r.mainloop()

#khung đăng nhập
def Login(key,client):
	global nameEL
	global pwordEL
	global rootA

	rootA = Tk()
	rootA.title('Login')

	instruction = Label(rootA, text='Login\n')
	instruction.grid(sticky=E)

	nameL = Label(rootA, text='Username: ')
	pwordL = Label(rootA, text='Password: ')
	nameL.grid(row=1, sticky=W)
	pwordL.grid(row=2, sticky=W)

	nameEL = Entry(rootA)
	pwordEL = Entry(rootA, show='*')
	nameEL.grid(row=1, column=1)
	pwordEL.grid(row=2, column=1)

	loginB = Button(rootA, text='submit', command=partial(CheckLogin,key,client))
	loginB.grid(columnspan=2, sticky=W)

	rmuser = Button(rootA, text='register', fg='red', command=partial(DelUser,key,client))
	rmuser.grid(columnspan=2, sticky=W)
	rootA.mainloop()

#Hàm để thực hiện đăng nhập
def CheckLogin(key,client):
    sendMsg = "login-" + nameEL.get() + "-" + pwordEL.get()
    if (nameEL.get()!= "" and pwordEL.get() != ""):
        regex = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
        if (regex.search(nameEL.get()) == None and regex.search(pwordEL.get()) == None) :
            threadSend = threading.Thread(target=sendeMsg,args=(key,client,sendMsg,))
            threadSend.start()
            threadSend.join()

            threadRecv = threading.Thread(target=recvdMsg,args=(key,client,msgQueue,))
            threadRecv.start()
            threadRecv.join()

            msg = msgQueue.get()
            if ( msg == "Login successfully" ):
                threadRecv = threading.Thread(target=recvdMsg,args=(key,client,msgQueue,))
                threadRecv.start()
                threadRecv.join()

                global myName
                myName = nameEL.get()

                rootA.destroy()
                data = msgQueue.get().split(',')
                chat(key,client,data)
            elif ( msg == "Login failed"):
                r = Tk()	
                r.title('D:')
                r.geometry('150x50')
                rlbl = Label(r, text='\n! Invalid Login')
                rlbl.pack()
                r.mainloop()	
        else :
            r = Tk()	
            r.title('D:')
            r.geometry('150x50')
            rlbl = Label(r, text='\n! Invalid Login')
            rlbl.pack()
            r.mainloop()
    else:
        r = Tk()	
        r.title('D:')
        r.geometry('150x50')
        rlbl = Label(r, text='\n! Invalid Login')
        rlbl.pack()
        r.mainloop()

#hàm chuyển đổi khung đăng ký đăng nhập
def DelUser(key,client):
	rootA.destroy()
	Signup(key,client)

#khung chat chính
def chat(key,client,data):
    global rootsC
    rootsC = Tk()
    rootsC.title('User : '+myName)

    searchButton= Button(rootsC, text='search', command='', width=10 , justify=LEFT)
    entry_1 = Entry(rootsC) 
    scrollbar_1 = Scrollbar(rootsC)
    global listbox_2
    listbox_2 = Listbox(rootsC, yscrollcommand=scrollbar_1.set, selectmode=SINGLE)
    # danh sách người dùng đang đăng nhập
    CreateListUsr(listbox_2,data)
    
    scrollbar_1.config(command=listbox_2.yview)

    entry_1.grid(row=0, column=6)
    searchButton.grid(row=0,column=7)

    listbox_2.grid(rowspan=4, columnspan=4, row=2, column=0)
    scrollbar_1.grid(rowspan=4, row=2, column=4, sticky=N+S)
    # phần hiển thị tin nhắn
    global chatBox
    chatBox=Text(rootsC,width = 40 , height = 20 , bd =2 , relief='solid')
    chatBox.grid(row=5, column =6)
    global CurrentChatUsr
    global x
    global y
    CurrentChatUsr = ""
    x = 0
    y = 0
    #phần nhập tin nhắn
    global chatF
    chatF=Entry(rootsC , font = ('courier', 15, 'bold'),width = 23)
    chatF.grid(rowspan=2,row=6, column=6, sticky=W )
    
    # nút gửi tin nhắn
    addButton1 = Button(rootsC, text='send', command=partial(MsgChat,key,client,chatF,chatBox,listbox_2), width=10)
    addButton1.grid(columnspan=2, row=7, column=6, sticky=E)
    
    #nút thêm file để gửi (Quý code)
    addButton2= Button(rootsC, text='add', command=partial(getfilename,key,client), width=10)
    addButton2.grid(columnspan=2, row=8, column=6, sticky=E)

    threading.Thread(target=recvdMsgTTK,args=(key,client)).start()        
    rootsC.after(2000, checSelectkUser, listbox_2)
    
    
    rootsC.mainloop()

#hàm kiểm tra người dùng đang chat hiện tại là ai
def checSelectkUser(listbox):
    global CurrentChatUsr
    global x
    global y
    if (listbox.get(ACTIVE)) :
        if (CurrentChatUsr == ""):
            CurrentChatUsr = listbox.get(ACTIVE)
            x = 1
            y = 0
        else:
            if (CurrentChatUsr != listbox.get(ACTIVE)):
                chatBox.delete("1.0",END)
                x = 1
                CurrentChatUsr = listbox.get(ACTIVE)
    rootsC.after(2000, checSelectkUser, listbox_2)

#hàm cập nhập danh sách người dùng đang onl
def CreateListUsr(listbox,data):
    listbox.delete(0,END)
    for i,name in enumerate(data):
        if (replaceUsrname(name) != myName):
            clientNum = "client_" + str(i)
            clientNum = StringVar(rootsC, name=replaceUsrname(name))
            #configuration
            listbox.insert(i, clientNum)

#hàm hiển thị lên khung chat tin nhắn mình gửi
def MsgChat(key,client,message,chatBox,listbox):
    
    global CurrentChatUsr
    global x
    global y
    
    if (listbox.get(ACTIVE)) :
        if (CurrentChatUsr == ""):
            CurrentChatUsr = listbox.get(ACTIVE)
            x = 1
            y = 0
        else:
            if (CurrentChatUsr != listbox.get(ACTIVE)):
                chatBox.delete("1.0",END)
                x = 1
    recvName = CurrentChatUsr
    sendMsg = myName + "-" + recvName + "-" + message.get()
    sendeMsg(key,client,sendMsg)
    displayMsg = myName + ": " + message.get() + "\n"
    position = str(x) + "." + str(y)
    
    chatBox.insert(position,displayMsg)
    message.delete(0, 'end')

    x = x + 1

#hàm xử lý tên
def replaceUsrname(data):
    data = data.replace('[','').replace('"','').replace(']','').replace(' ','')
    return data

#hàm main thực hiện kết nối trao đổi khóa
def main():
    serverAddress = "127.0.0.1"
    # serverAddress = "192.168.1.1"
    serverPort = 1600

    #Tạo public key và private key    
    random_generator = Random.new().read
    #Tạo key 1024 bit bởi random_generator 
    key = RSA.generate(1024,random_generator)
    #Tạo public key từ key
    public = key.publickey().exportKey(format='PEM',passphrase=None, pkcs=1)
    #hash public key 
    hash_object = hashlib.sha1(public)
    hex_digest = hash_object.hexdigest()
    
    #kết nối đến server
    client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    client.connect((serverAddress,serverPort))
    print("Connectd to sever")
    client.send(public)
    confirm = client.recv(1024)
    if confirm.decode() == "YES":
        client.send(hex_digest.encode())
    #connected msg
    msg = client.recv(1024)
    # dùng private key để giải mã lấy session key 
    decrypt = PKCS1_OAEP.new(key).decrypt(msg)
    #hashing sha1
    en_object = hashlib.sha1(decrypt)
    en_digest = en_object.hexdigest()
    print(en_digest)
    if (en_digest): 
        Login(en_digest,client)
        client.close()

if __name__ == "__main__":
    main()

