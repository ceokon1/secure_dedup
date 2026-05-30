# README: Hướng dẫn test tính năng đổi mật khẩu

Tài liệu này hướng dẫn test thủ công và test tự động cho tính năng `change-password` trong project **Secure Deduplicated Cloud Storage**.

Mục tiêu chính của test không chỉ là kiểm tra đăng nhập bằng mật khẩu mới, mà còn phải chứng minh rằng:

- File upload trước khi đổi mật khẩu vẫn download và giải mã được sau khi đổi mật khẩu.
- Mật khẩu cũ không còn đăng nhập được.
- Mật khẩu mới đăng nhập được.
- `URK` của user không đổi về mặt logic, chỉ được re-wrap bằng `KEK` mới.
- Bảng `files`, bảng `user_files` và ciphertext trên MinIO không bị tạo lại chỉ vì đổi mật khẩu.

---

## 1. Ý nghĩa của tính năng đổi mật khẩu

Trong project này, mật khẩu không mã hóa trực tiếp file.

Luồng khóa đúng là:

```text
password + kek_salt
        |
        v
Argon2id derive KEK
        |
        v
KEK mở encrypted URK
        |
        v
URK unwrap file_key K
        |
        v
K derive K_enc để giải mã file
```

Khi đổi mật khẩu, client làm như sau:

```text
1. Dùng mật khẩu cũ để derive old_KEK.
2. Dùng old_KEK để decrypt URK hiện tại.
3. Sinh salt mới.
4. Dùng mật khẩu mới để derive new_KEK.
5. Encrypt lại chính URK cũ bằng new_KEK.
6. Gửi encrypted URK mới lên server.
```

Vì `URK` bên dưới không đổi, các wrapped file key trong `user_files` vẫn dùng được. Do đó, không cần mã hóa lại file, không cần upload lại object lên MinIO, và không cần update các bản ghi file ownership.

---

## 2. Checklist cần đạt

Tính năng đổi mật khẩu được coi là pass khi đạt đủ các điều kiện sau:

```text
[OK] Register user thành công.
[OK] Login bằng mật khẩu cũ thành công.
[OK] Upload file bằng mật khẩu cũ thành công.
[OK] Download file trước khi đổi mật khẩu thành công.
[OK] File download trước khi đổi giống file gốc.
[OK] Đổi mật khẩu thành công.
[OK] Login bằng mật khẩu cũ bị từ chối.
[OK] Login bằng mật khẩu mới thành công.
[OK] Download file đã upload trước đó bằng mật khẩu mới thành công.
[OK] File download sau khi đổi giống file gốc.
[OK] Số row trong files không đổi do change-password.
[OK] Số row trong user_files không đổi do change-password.
[OK] Sai current_password bị reject.
[OK] new_password trùng current_password bị reject.
```

---

## 3. Chuẩn bị môi trường

### 3.1. Vào thư mục project

```bash
cd Secure-Deduplicated-Cloud-Storage-main
```

### 3.2. Tạo file `.env` nếu chưa có

```bash
cp .env.example .env
```

### 3.3. Cấu hình MinIO endpoint đúng theo cách chạy CLI

Đây là phần rất quan trọng vì project dùng presigned URL: API trả URL upload/download, sau đó CLI tự PUT/GET ciphertext trực tiếp với MinIO.

Có 2 mode chạy CLI.

#### Mode A: Chạy CLI ngoài Docker, trên host hoặc WSL

Ví dụ command dạng:

```bash
python -m client_cli.main ...
```

Khi đó `.env` nên để:

```env
MINIO_ENDPOINT=minio:9000
MINIO_PUBLIC_ENDPOINT=localhost:9000
MINIO_SECURE=false
MINIO_PUBLIC_SECURE=false
```

Ý nghĩa:

```text
MINIO_ENDPOINT=minio:9000
  API container dùng endpoint này để nói chuyện nội bộ với MinIO.

MINIO_PUBLIC_ENDPOINT=localhost:9000
  CLI chạy ngoài Docker dùng endpoint này để upload/download qua presigned URL.
```

#### Mode B: Chạy CLI bên trong container `api`

Ví dụ command dạng:

```bash
docker compose exec api python -m client_cli.main ...
```

Khi đó API nên sinh presigned URL dùng host Docker network:

```env
MINIO_ENDPOINT=minio:9000
MINIO_PUBLIC_ENDPOINT=minio:9000
MINIO_SECURE=false
MINIO_PUBLIC_SECURE=false
```

Hoặc không sửa `.env`, dùng biến override khi chạy CLI trong container:

```bash
docker compose exec -e SECURE_DEDUP_PRESIGNED_URL_BASE=http://minio:9000 api \
  python -m client_cli.main ...
```

Nếu chạy ngoài host/WSL mà API đang trả URL `http://minio:9000/...`, bạn có thể override tạm như sau:

```bash
export SECURE_DEDUP_PRESIGNED_URL_BASE=http://localhost:9000
```

Tuy nhiên cách khuyên dùng khi chạy CLI ngoài host vẫn là cấu hình:

```env
MINIO_PUBLIC_ENDPOINT=localhost:9000
```

### 3.4. Recreate API sau khi sửa `.env`

Chỉ sửa `.env` chưa đủ nếu container đang chạy. Cần recreate để API đọc lại cấu hình:

```bash
docker compose up -d --force-recreate api worker
```

Kiểm tra cấu hình thật trong container API:

```bash
docker compose exec api sh -lc 'echo MINIO_ENDPOINT=$MINIO_ENDPOINT && echo MINIO_PUBLIC_ENDPOINT=$MINIO_PUBLIC_ENDPOINT'
```

Với CLI ngoài host/WSL, kỳ vọng:

```text
MINIO_ENDPOINT=minio:9000
MINIO_PUBLIC_ENDPOINT=localhost:9000
```

Với CLI trong container, kỳ vọng:

```text
MINIO_ENDPOINT=minio:9000
MINIO_PUBLIC_ENDPOINT=minio:9000
```

### 3.5. Khởi động toàn bộ hệ thống

```bash
docker compose up --build -d
```

Kiểm tra các service:

```bash
docker compose ps
```

Kiểm tra API:

```bash
curl http://localhost:8000/health
```

Kỳ vọng:

```json
{"status":"ok"}
```

Kiểm tra MinIO từ host/WSL nếu chạy CLI ngoài Docker:

```bash
curl http://localhost:9000/minio/health/live
```

Kỳ vọng:

```text
OK
```

---

## 4. Cài dependency CLI nếu chạy ngoài Docker

Nếu bạn chạy:

```bash
python -m client_cli.main ...
```

thì venv trên host/WSL cần có dependency.

Tạo venv nếu chưa có:

```bash
python -m venv .venv
source .venv/bin/activate
```

Cài dependency client:

```bash
python -m pip install -r requirements-client.txt
```

Hoặc cài full dependency dev/test:

```bash
python -m pip install -r requirements-dev.txt
```

Kiểm tra nhanh:

```bash
python - <<'PY'
import httpx
import cryptography
import nacl
import argon2
print("client deps OK")
PY
```

Kỳ vọng:

```text
client deps OK
```

Nếu gặp lỗi:

```text
ModuleNotFoundError: No module named 'httpx'
```

thì nguyên nhân là venv chưa cài dependency. Chạy lại:

```bash
python -m pip install -r requirements-client.txt
```

---

## 5. Test nhanh bằng pytest

Chạy toàn bộ test:

```bash
pytest -q
```

Chạy riêng test đổi mật khẩu:

```bash
pytest -q tests/integration/test_auth_and_health.py::test_change_password_rewraps_same_root_key
```

Kỳ vọng:

```text
1 passed
```

Test này kiểm tra logic quan trọng:

```text
- Register user.
- Login bằng mật khẩu cũ.
- Bootstrap mở được root_key.
- Re-wrap root_key bằng mật khẩu mới.
- Gọi /auth/change-password.
- Login bằng mật khẩu cũ fail.
- Login bằng mật khẩu mới success.
- Bootstrap sau đổi mật khẩu vẫn decrypt ra đúng root_key cũ.
```

Lưu ý: pytest dùng fake MinIO/SQLite trong test fixture nên không thay thế hoàn toàn test end-to-end với Docker + MinIO thật.

---

## 6. Test end-to-end bằng CLI ngoài host/WSL

Phần này giống cách bạn đang test:

```bash
python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file ./dattq-session.json \
  ...
```

### 6.1. Khai báo biến test

Bạn có thể dùng email cố định hoặc email theo timestamp để tránh trùng user.

```bash
EMAIL="dattq-change-$(date +%s)@example.com"
OLD_PASSWORD="dattq123"
NEW_PASSWORD="dattq1234"
SESSION="./dattq-session.json"
NEW_SESSION="./dattq-new-session.json"
OLD_FAIL_SESSION="./dattq-old-fail-session.json"
SAMPLE="sample1.txt"
BEFORE="before.txt"
AFTER="after.txt"
```

Tạo file test:

```bash
printf 'hello before password change\n' > "$SAMPLE"
cat "$SAMPLE"
```

Kỳ vọng:

```text
hello before password change
```

### 6.2. Register user

```bash
python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file "$SESSION" \
  register "$EMAIL" \
  --password "$OLD_PASSWORD"
```

CLI vẫn sẽ hỏi:

```text
Confirm password:
```

Nhập lại đúng mật khẩu cũ:

```text
dattq123
```

Kỳ vọng:

```text
Registration successful.
user_id: ...
Run the login command next.
```

Nếu email đã tồn tại, đổi `EMAIL` hoặc dùng email timestamp như trên.

### 6.3. Login bằng mật khẩu cũ

```bash
python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file "$SESSION" \
  login "$EMAIL" \
  --password "$OLD_PASSWORD"
```

Kỳ vọng:

```text
Login successful. Session saved locally.
session_file: dattq-session.json
```

### 6.4. Upload file trước khi đổi mật khẩu

```bash
UPLOAD_LOG="$(mktemp)"
python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file "$SESSION" \
  upload "$SAMPLE" \
  --password "$OLD_PASSWORD" | tee "$UPLOAD_LOG"
```

Kỳ vọng:

```text
Upload successful.
file_id: <FILE_ID>
tag: ...
file_size: ... bytes
ciphertext_size: ... bytes
```

Lấy `file_id` tự động:

```bash
FILE_ID="$(awk '/^file_id:/ {print $2; exit}' "$UPLOAD_LOG")"
echo "$FILE_ID"
```

Nếu biến rỗng, copy thủ công giá trị sau dòng:

```text
file_id: ...
```

Ví dụ:

```bash
FILE_ID="346540a7-6771-459d-8248-2b49420d2086"
```

### 6.5. Download thử trước khi đổi mật khẩu

```bash
python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file "$SESSION" \
  download "$FILE_ID" \
  --password "$OLD_PASSWORD" \
  --output "$BEFORE"
```

Kỳ vọng:

```text
Download and decryption successful.
saved_to: .../before.txt
size: ... bytes
```

So sánh file gốc với file download trước khi đổi:

```bash
cmp -s "$SAMPLE" "$BEFORE" && echo OK_BEFORE_CHANGE || echo FAIL_BEFORE_CHANGE
```

Kỳ vọng:

```text
OK_BEFORE_CHANGE
```

### 6.6. Ghi lại số row trước khi đổi mật khẩu

Bước này dùng để chứng minh đổi mật khẩu không làm thay đổi object/file ownership.

```bash
docker compose exec postgres psql -U postgres -d secure_dedup -c "select count(*) as files_count from files;"
docker compose exec postgres psql -U postgres -d secure_dedup -c "select count(*) as user_files_count from user_files;"
```

Ghi lại kết quả trước khi đổi mật khẩu.

Xem rút gọn key material của user trước khi đổi. Không in full secret ra log:

```bash
docker compose exec postgres psql -U postgres -d secure_dedup -c "select email, left(password_hash, 24) as password_hash_prefix, left(enc_urk_b64, 24) as enc_urk_prefix, left(enc_urk_nonce_b64, 24) as nonce_prefix, left(kek_salt_b64, 24) as salt_prefix from users where email='$EMAIL';"
```

Sau khi đổi mật khẩu, `password_hash_prefix`, `enc_urk_prefix`, `nonce_prefix`, `salt_prefix` nên thay đổi. Nhưng row trong `files` và `user_files` không nên thay đổi chỉ vì đổi mật khẩu.

### 6.7. Đổi mật khẩu

```bash
python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file "$SESSION" \
  change-password \
  --current-password "$OLD_PASSWORD" \
  --new-password "$NEW_PASSWORD"
```

CLI vẫn sẽ hỏi confirm:

```text
Confirm new password:
```

Nhập:

```text
dattq1234
```

Kỳ vọng:

```text
Password changed successfully.
Your saved session token is still valid, but future logins now require the new password.
```

Lưu ý: project hiện tại chưa revoke JWT cũ ngay sau khi đổi mật khẩu. Vì vậy session token cũ có thể vẫn còn hiệu lực cho tới khi hết hạn. Nhưng các thao tác cần mở `URK` phải dùng mật khẩu mới.

### 6.8. Login bằng mật khẩu cũ phải fail

```bash
python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file "$OLD_FAIL_SESSION" \
  login "$EMAIL" \
  --password "$OLD_PASSWORD" \
  && echo FAIL_OLD_PASSWORD_STILL_WORKS \
  || echo OK_OLD_PASSWORD_REJECTED
```

Kỳ vọng:

```text
OK_OLD_PASSWORD_REJECTED
```

Có thể CLI in thêm lỗi dạng:

```text
Invalid email or password
```

Đó là kết quả đúng cho case này.

### 6.9. Login bằng mật khẩu mới phải success

```bash
python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file "$NEW_SESSION" \
  login "$EMAIL" \
  --password "$NEW_PASSWORD"
```

Kỳ vọng:

```text
Login successful. Session saved locally.
session_file: dattq-new-session.json
```

### 6.10. Download lại file cũ bằng mật khẩu mới

```bash
python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file "$NEW_SESSION" \
  download "$FILE_ID" \
  --password "$NEW_PASSWORD" \
  --output "$AFTER"
```

Kỳ vọng:

```text
Download and decryption successful.
saved_to: .../after.txt
size: ... bytes
```

So sánh file gốc với file download sau khi đổi:

```bash
cmp -s "$SAMPLE" "$AFTER" && echo OK_AFTER_CHANGE || echo FAIL_AFTER_CHANGE
```

Kỳ vọng:

```text
OK_AFTER_CHANGE
```

Đây là kết quả quan trọng nhất. Nó chứng minh file upload bằng mật khẩu cũ vẫn decrypt được sau khi đổi sang mật khẩu mới.

### 6.11. Kiểm tra lại DB sau khi đổi mật khẩu

Kiểm tra số row:

```bash
docker compose exec postgres psql -U postgres -d secure_dedup -c "select count(*) as files_count from files;"
docker compose exec postgres psql -U postgres -d secure_dedup -c "select count(*) as user_files_count from user_files;"
```

Kỳ vọng:

```text
files_count không đổi so với trước change-password
user_files_count không đổi so với trước change-password
```

Kiểm tra key material user đã thay đổi:

```bash
docker compose exec postgres psql -U postgres -d secure_dedup -c "select email, left(password_hash, 24) as password_hash_prefix, left(enc_urk_b64, 24) as enc_urk_prefix, left(enc_urk_nonce_b64, 24) as nonce_prefix, left(kek_salt_b64, 24) as salt_prefix from users where email='$EMAIL';"
```

Kỳ vọng:

```text
password_hash_prefix thay đổi
enc_urk_prefix thay đổi
nonce_prefix thay đổi
salt_prefix thay đổi
```

Không cần và không nên in toàn bộ secret/material ra log.

---

## 7. Test end-to-end bằng CLI trong container API

Nếu bạn muốn chạy CLI trong container `api`, dùng mode này.

### 7.1. Cấu hình endpoint

Có 2 cách.

Cách 1: `.env` để:

```env
MINIO_ENDPOINT=minio:9000
MINIO_PUBLIC_ENDPOINT=minio:9000
```

Sau đó recreate:

```bash
docker compose up -d --force-recreate api worker
```

Cách 2: giữ `.env` cho host/WSL nhưng override mỗi lần chạy CLI trong container:

```bash
-e SECURE_DEDUP_PRESIGNED_URL_BASE=http://minio:9000
```

### 7.2. Tạo file trong container

```bash
docker compose exec api sh -lc "printf 'hello before password change\n' > /tmp/sample1.txt"
```

### 7.3. Register và login

```bash
docker compose exec -e SECURE_DEDUP_PRESIGNED_URL_BASE=http://minio:9000 api \
  python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file /tmp/dattq-session.json \
  register dattq-container@example.com
```

Nhập password và confirm password, ví dụ:

```text
dattq123
dattq123
```

Login:

```bash
docker compose exec -e SECURE_DEDUP_PRESIGNED_URL_BASE=http://minio:9000 api \
  python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file /tmp/dattq-session.json \
  login dattq-container@example.com \
  --password dattq123
```

### 7.4. Upload, đổi mật khẩu, download lại

Upload:

```bash
docker compose exec -e SECURE_DEDUP_PRESIGNED_URL_BASE=http://minio:9000 api \
  python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file /tmp/dattq-session.json \
  upload /tmp/sample1.txt \
  --password dattq123
```

Ghi lại `file_id`.

Đổi mật khẩu:

```bash
docker compose exec -e SECURE_DEDUP_PRESIGNED_URL_BASE=http://minio:9000 api \
  python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file /tmp/dattq-session.json \
  change-password \
  --current-password dattq123 \
  --new-password dattq1234
```

Nhập confirm:

```text
dattq1234
```

Login session mới:

```bash
docker compose exec -e SECURE_DEDUP_PRESIGNED_URL_BASE=http://minio:9000 api \
  python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file /tmp/dattq-new-session.json \
  login dattq-container@example.com \
  --password dattq1234
```

Download lại:

```bash
docker compose exec -e SECURE_DEDUP_PRESIGNED_URL_BASE=http://minio:9000 api \
  python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file /tmp/dattq-new-session.json \
  download <FILE_ID> \
  --password dattq1234 \
  --output /tmp/after.txt
```

So sánh:

```bash
docker compose exec api sh -lc "cmp -s /tmp/sample1.txt /tmp/after.txt && echo OK_AFTER_CHANGE || echo FAIL_AFTER_CHANGE"
```

Kỳ vọng:

```text
OK_AFTER_CHANGE
```

---

## 8. Test các case lỗi quan trọng

### 8.1. Sai current password trên CLI

Dùng session hợp lệ nhưng nhập sai mật khẩu hiện tại:

```bash
python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file "$NEW_SESSION" \
  change-password \
  --current-password WrongPassword123 \
  --new-password dattq9999
```

Nhập confirm:

```text
dattq9999
```

Kỳ vọng: command fail. Thường client sẽ fail trước khi gọi update thành công vì không mở được `URK` bằng mật khẩu sai.

Sau đó kiểm tra mật khẩu hiện tại vẫn là mật khẩu mới cũ, ví dụ `dattq1234`:

```bash
python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file ./check-session.json \
  login "$EMAIL" \
  --password "$NEW_PASSWORD"
```

Kỳ vọng login thành công.

### 8.2. Server reject sai current_password

Case này gọi thẳng API để chắc chắn backend có kiểm tra `current_password`. Script dùng bootstrap hiện tại nhưng cố tình gửi `current_password` sai. Server phải trả `401` trước khi update DB.

```bash
python - <<'PY'
import json
import httpx

SESSION_FILE = "./dattq-new-session.json"
BASE_URL = "http://localhost:8000"

with open(SESSION_FILE, "r", encoding="utf-8") as f:
    session = json.load(f)

headers = {"Authorization": f"Bearer {session['access_token']}"}

with httpx.Client(base_url=BASE_URL) as client:
    bootstrap = client.get("/auth/me/bootstrap", headers=headers).json()
    response = client.post(
        "/auth/change-password",
        headers=headers,
        json={
            "current_password": "WrongPassword123",
            "new_password": "ShouldNotWork123",
            "enc_urk_b64": bootstrap["enc_urk_b64"],
            "enc_urk_nonce_b64": bootstrap["enc_urk_nonce_b64"],
            "kek_salt_b64": bootstrap["kek_salt_b64"],
        },
    )
    print(response.status_code)
    print(response.text)
PY
```

Kỳ vọng:

```text
401
{"detail":"Current password is incorrect"}
```

### 8.3. Mật khẩu mới trùng mật khẩu hiện tại

```bash
python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file "$NEW_SESSION" \
  change-password \
  --current-password "$NEW_PASSWORD" \
  --new-password "$NEW_PASSWORD"
```

Kỳ vọng CLI reject:

```text
New password must be different from the current password
```

### 8.4. Mật khẩu mới quá ngắn

```bash
python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file "$NEW_SESSION" \
  change-password \
  --current-password "$NEW_PASSWORD" \
  --new-password short
```

Nhập confirm:

```text
short
```

Kỳ vọng backend trả lỗi do `new_password` không đạt `min_length=8` hoặc password policy.

### 8.5. Không nên test invalid base64 trên account chính

Hiện tại schema `ChangePasswordRequest` yêu cầu các field sau là string:

```text
enc_urk_b64
enc_urk_nonce_b64
kek_salt_b64
```

Nếu project của bạn chưa bổ sung validator base64/nonce length/salt length chặt chẽ, không nên test payload rác trên account chính. Nếu backend chấp nhận payload sai, account có thể bị hỏng bootstrap material và không mở được `URK` nữa.

Chỉ test invalid base64 khi:

```text
- dùng account phụ để test phá,
- hoặc đã bổ sung validator rõ ràng,
- hoặc đã có cách reset DB/môi trường.
```

## 9. Một kịch bản test mẫu đã pass

Ví dụ bạn đã chạy:

```bash
python -m client_cli.main \
  --api-base-url http://localhost:8000 \
  --session-file ./dattq-session.json \
  download 346540a7-6771-459d-8248-2b49420d2086 \
  --password dattq1234 \
  --output after.txt
```

Output:

```text
Download and decryption successful.
saved_to: .../after.txt
size: 29 bytes
```

Sau đó so sánh đúng file:

```bash
cmp -s sample1.txt after.txt && echo OK_AFTER_CHANGE
```

Output:

```text
OK_AFTER_CHANGE
```

Kết luận của case này:

```text
File được upload trước khi đổi mật khẩu vẫn download và decrypt đúng bằng mật khẩu mới.
Tính năng change-password đạt yêu cầu end-to-end quan trọng nhất.
```

---

## 10. Kết luận

Khi test đổi mật khẩu, không chỉ kiểm tra message `Password changed successfully`. Cần kiểm tra đầy đủ 3 lớp:

```text
1. Auth layer:
   - old password fail,
   - new password success.

2. Crypto/key layer:
   - bootstrap bằng mật khẩu mới mở được cùng URK logic,
   - file key cũ vẫn unwrap được.

3. Storage/dedup layer:
   - file upload trước khi đổi vẫn download được,
   - files/user_files/object storage không bị tạo lại chỉ vì đổi password.
```

Nếu lệnh cuối cùng trả:

```text
OK_AFTER_CHANGE
```

thì luồng đổi mật khẩu đã pass ở mức end-to-end.