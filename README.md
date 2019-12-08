"# network_security" 
How to use:
1. Install python 3
2. Install pycryptodome : pip install pycryptodome
3. Install mysql
4. Vào mysql : tạo csdl anm, tạo người quản lý riêng cho csdl này (tên đăng nhập và mật khẩu tùy chọn)

sửa đoạn code này để kết nối sql:

mydb = mysql.connector.connect(host='localhost',database='anm',user='',password='',port='')

-user : tên đăng nhập

-password : mật khẩu

-port : cổng của mysql (mặc định 3306)

5. Tạo bảng CSDL customers gồm 3 trường id(khóa chính), name, password
6. Launch server (nếu thiếu thư viện thì tự cài thêm)
7. Launch client
