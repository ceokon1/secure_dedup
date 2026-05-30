# Luồng đổi mật khẩu

Project này đã triển khai sẵn cơ chế đổi mật khẩu mà không cần mã hóa lại các file của người dùng.

## Thứ thực sự thay đổi

- Người dùng vẫn giữ nguyên `URK` (`User Root Key`).
- Mật khẩu cũ chỉ được dùng để suy ra `KEK` cũ.
- Client dùng `KEK` cũ để giải mã `URK` đang được lưu trên server.
- Client suy ra `KEK` mới từ mật khẩu mới.
- Client mã hóa lại chính `URK` cũ bằng `KEK` mới.
- Server chỉ cập nhật 4 trường:
  - `password_hash`
  - `enc_urk_b64`
  - `enc_urk_nonce_b64`
  - `kek_salt_b64`

## Thứ không thay đổi

- Không đổi dữ liệu trong bảng `files`.
- Không đổi dữ liệu trong bảng `user_files`.
- Không đổi `wrapped_kf_b64`.
- Không đổi ciphertext đang lưu trên MinIO.

Điều này làm được vì quyền truy cập file được neo vào `URK`, không neo trực tiếp vào mật khẩu đăng nhập.

## Ý nghĩa bảo mật

- Đổi mật khẩu có chi phí thấp vì không phải mã hóa lại toàn bộ file.
- Server vẫn không biết `URK` dạng plaintext.
- Sau khi đổi mật khẩu, thông tin đăng nhập cũ không còn dùng được.
- Các file hiện có vẫn truy cập được vì `URK` bên dưới không đổi.

## Luồng chi tiết

1. Người dùng nhập `current_password` và `new_password` trên CLI.
2. CLI gọi `GET /auth/me/bootstrap` để lấy `enc_urk_b64`, `enc_urk_nonce_b64`, `kek_salt_b64`.
3. CLI suy ra `KEK` cũ từ `current_password`.
4. CLI dùng `KEK` cũ để giải mã `URK`.
5. CLI sinh `salt` mới và suy ra `KEK` mới từ `new_password`.
6. CLI mã hóa lại chính `URK` đó bằng `KEK` mới.
7. CLI gọi `POST /auth/change-password` với:
   - `current_password`
   - `new_password`
   - `enc_urk_b64` mới
   - `enc_urk_nonce_b64` mới
   - `kek_salt_b64` mới
8. Server kiểm tra mật khẩu cũ có đúng không.
9. Nếu hợp lệ, server cập nhật `password_hash` và bộ bootstrap mới của `URK`.
10. Các file và ciphertext giữ nguyên, chỉ thay đổi cách khôi phục `URK` từ mật khẩu mới.

## Tham chiếu mã nguồn

- Luồng CLI: [client_cli/commands/change_password.py](D:/tai_lieu/mmhcs/Secure-Deduplicated-Cloud-Storage-main/client_cli/commands/change_password.py:27)
- Mở khóa `URK`: [client_cli/crypto/root_key.py](D:/tai_lieu/mmhcs/Secure-Deduplicated-Cloud-Storage-main/client_cli/crypto/root_key.py:38)
- Suy ra `KEK`: [client_cli/crypto/password_kdf.py](D:/tai_lieu/mmhcs/Secure-Deduplicated-Cloud-Storage-main/client_cli/crypto/password_kdf.py:28)
- API đổi mật khẩu: [api/routers/auth.py](D:/tai_lieu/mmhcs/Secure-Deduplicated-Cloud-Storage-main/api/routers/auth.py:40)
- Xử lý phía server: [api/services/auth_service.py](D:/tai_lieu/mmhcs/Secure-Deduplicated-Cloud-Storage-main/api/services/auth_service.py:66)
- Cập nhật DB: [api/repositories/user_repo.py](D:/tai_lieu/mmhcs/Secure-Deduplicated-Cloud-Storage-main/api/repositories/user_repo.py:34)
- Test tích hợp: [tests/integration/test_auth_and_health.py](D:/tai_lieu/mmhcs/Secure-Deduplicated-Cloud-Storage-main/tests/integration/test_auth_and_health.py:37)

## Mermaid

Xem sơ đồ tại [diagrams/change-password-sequence.mmd](D:/tai_lieu/mmhcs/Secure-Deduplicated-Cloud-Storage-main/diagrams/change-password-sequence.mmd).
