# Demo kiểm chứng Relay Signature Attack cho Proof of Ownership

Tài liệu này dùng cho project `Secure-Deduplicated-Cloud-Storage` trong môi trường lab/local do bạn sở hữu. Mục tiêu là kiểm chứng cơ chế Proof of Ownership hiện tại trước các biến thể relay chữ ký.

## 1. Kết luận nhanh sau khi rà source

Project hiện tại không bị replay chữ ký đơn giản theo kiểu: Alice ký challenge của Alice rồi Mallory đem chữ ký đó đi claim. Lý do là message PoW đang được bind với `context`, `user_id`, `tag_hex`, `nonce_b64`; server khi claim sẽ tự dựng lại message bằng `user_id` lấy từ JWT của người đang claim.

Tuy nhiên, vẫn nên kiểm thử biến thể mạnh hơn: **chosen-message relay / signing-oracle relay**. Trong biến thể này, attacker tạo challenge cho chính tài khoản attacker, rồi lừa hoặc ép một client đang có file ký đúng message của attacker. Khi đó chữ ký hợp lệ với `pk_PoW` của file, nên server có thể chấp nhận claim.

Tác động cần phân biệt rõ:

- Nếu attacker chỉ có chữ ký relay nhưng **không có file key K**, attacker có thể tạo ownership giả và nhận download metadata/presigned URL, nhưng không giải mã được ciphertext vì `wrapped_kf_b64` không chứa đúng K.
- Nếu attacker có cả chữ ký hợp lệ và K, hoặc một bản K đã được wrap đúng cho URK của attacker, attacker giải mã được file. Đây không còn là relay chữ ký thuần túy mà là compromised-client/key-exfiltration/full-proof-bundle relay.

## 2. Luồng PoW hiện tại trong project

Luồng claim hiện tại:

```text
POST /files/challenge { tag_hex }
  server tạo challenge theo user_id từ JWT + tag_hex
  trả nonce_b64 + context="pow-claim-v1"

client ký JSON canonical:
{
  "context": context,
  "nonce_b64": nonce_b64,
  "tag_hex": tag_hex,
  "user_id": current_user_id
}

POST /files/claim
  server lấy user_id từ JWT
  server lấy latest active challenge của user_id + tag_hex
  server dựng lại message
  server verify signature bằng files.pk_pow_b64
  nếu hợp lệ thì INSERT user_files
```

Các file liên quan trong source:

```text
api/services/challenge_service.py
api/services/claim_service.py
api/crypto/verify.py
client_cli/crypto/pow_sign.py
client_cli/commands/upload.py
```

## 3. Cài PoC test vào project

Copy file test vào thư mục test của project:

```bash
cp /mnt/data/test_relay_signature_attack.py \
  tests/integration/test_relay_signature_attack.py
```

Nếu bạn đang ở máy thật/WSL thì đường dẫn `/mnt/data/...` chỉ tồn tại trong sandbox ChatGPT. Bạn có thể tải file đính kèm rồi copy vào project.

Chạy test:

```bash
pytest -q tests/integration/test_relay_signature_attack.py
```

Kỳ vọng:

```text
3 passed
```

## 4. Ý nghĩa 3 test

### Test 1: `test_plain_replay_of_victim_signature_is_rejected`

Mô phỏng:

```text
Alice có file và ký challenge của Alice.
Mallory tạo challenge của Mallory.
Mallory dùng chữ ký của Alice để claim.
```

Kết quả mong muốn:

```text
HTTP 401 Invalid proof-of-ownership signature
```

Nếu test này pass, hệ thống đang chống được replay cơ bản nhờ bind chữ ký với `user_id` và `nonce`.

### Test 2: `test_chosen_message_signature_relay_can_create_bogus_ownership`

Mô phỏng:

```text
Mallory tạo challenge cho Mallory.
Mallory chuyển message đó cho Alice/Victim signing oracle.
Alice ký đúng message chứa user_id của Mallory.
Mallory gửi chữ ký lên /files/claim.
```

Kết quả hiện tại có thể là:

```text
/files/claim trả 200
Mallory xuất hiện trong /files
Mallory gọi được /files/download/init
Nhưng Mallory không decrypt được file nếu chỉ có signature mà không có K
```

Đây là điểm quan trọng: server không thể xác minh `wrapped_kf_b64` có thật sự là K đúng hay không, vì server không được biết K. Do đó, nếu chỉ relay chữ ký, hệ thống có thể bị ownership pollution nhưng chưa lộ plaintext.

### Test 3: `test_full_proof_bundle_relay_gives_real_access_if_file_key_is_also_relayed`

Mô phỏng mạnh hơn:

```text
Victim-side helper/malware không chỉ ký challenge mà còn để lộ K
hoặc tạo wrapped K hợp lệ cho attacker.
```

Kết quả:

```text
Mallory claim thành công
Mallory unwrap được K
Mallory decrypt được ciphertext
```

Đây là compromised-client model. Nó chứng minh ranh giới tin cậy: client không được cung cấp API ký tùy ý hoặc API xuất K/wrap K tùy ý cho request không rõ nguồn gốc.

## 5. Demo live trên API local

Copy script live vào root project:

```bash
cp /mnt/data/poc_relay_signature_live.py ./poc_relay_signature_live.py
chmod +x ./poc_relay_signature_live.py
```

Chuẩn bị môi trường local:

```bash
docker compose up -d --build
curl http://localhost:8000/health
curl http://localhost:9000/minio/health/live
```

Nếu chạy script ngoài Docker/WSL, `.env` nên có:

```env
MINIO_ENDPOINT=minio:9000
MINIO_PUBLIC_ENDPOINT=localhost:9000
MINIO_SECURE=false
MINIO_PUBLIC_SECURE=false
```

Sau khi sửa `.env`, recreate API:

```bash
docker compose up -d --force-recreate api worker
```

Chạy PoC:

```bash
python ./poc_relay_signature_live.py \
  --api-base-url http://localhost:8000 \
  --file ./relay-secret-demo.txt
```

Kỳ vọng output gồm các ý chính:

```text
[3] Naive replay ... should fail
    OK: naive replay rejected: HTTP 401 ...

[4] Chosen-message relay ...
    Claim accepted: ...
    OK: attacker is listed as owner, but decrypt fails without real K
```

Chạy thêm biến thể full bundle:

```bash
python ./poc_relay_signature_live.py \
  --api-base-url http://localhost:8000 \
  --file ./relay-secret-demo.txt \
  --full-bundle
```

Kỳ vọng thêm:

```text
[5] Stronger full-bundle relay ...
    CONFIRMED: full bundle relay decrypts successfully
```

## 6. Kiểm tra bằng database sau PoC

Xem ownership:

```bash
docker compose exec postgres psql -U postgres -d secure_dedup -c \
"select u.email, f.tag_hex, uf.file_id, left(uf.wrapped_kf_b64, 20) as wk_prefix from user_files uf join users u on u.id=uf.user_id join files f on f.id=uf.file_id order by u.email;"
```

Kỳ vọng thấy victim và attacker đều có dòng `user_files` cho cùng `file_id` trong test chosen-message relay.

## 7. Cách vá/hardening nên làm

### 7.1 Không expose signing oracle ở client

Client chỉ được ký khi chính lệnh upload/claim local đã tự tính file hash, OPRF, file key, tag và challenge từ phiên người dùng hiện tại. Không tạo endpoint/plugin/helper kiểu:

```text
sign_any_pow_message(message_json)
```

hoặc:

```text
wrap_any_file_key_for_request(...)
```

Nếu có UI, phải hiển thị rõ:

```text
Bạn đang chứng minh sở hữu file <tag> cho tài khoản <email/user_id> trên origin <api-base-url>
```

### 7.2 Bind chữ ký với thêm thông tin nguồn phiên

Hiện tại đã bind `context`, `user_id`, `tag_hex`, `nonce_b64`. Có thể mở rộng message thành:

```json
{
  "context": "pow-claim-v2",
  "api_origin": "http://localhost:8000",
  "aud": "secure-dedup-api",
  "challenge_id": "...",
  "user_id": "...",
  "user_email_hash": "...",
  "tag_hex": "...",
  "nonce_b64": "...",
  "issued_at": "...",
  "expires_at": "..."
}
```

Lợi ích: giảm nhầm lẫn cross-origin/cross-service và dễ audit hơn. `challenge_id` cũng giúp verify đúng challenge cụ thể thay vì “latest active challenge”.

### 7.3 Challenge nên có ID và one-time semantics rõ hơn

Thay response:

```json
{
  "nonce_b64": "...",
  "context": "pow-claim-v1"
}
```

bằng:

```json
{
  "challenge_id": "uuid",
  "nonce_b64": "...",
  "context": "pow-claim-v2",
  "expires_at": "..."
}
```

Claim request gửi lại `challenge_id`; server verify đúng challenge đó, lock row `FOR UPDATE`, reject nếu đã dùng/hết hạn.

### 7.4 Audit log cho PoW relay indicators

Ghi log an toàn, không log secret:

```text
challenge_id, user_id, tag_hex, created_at, used_at, client_ip, user_agent,
claim_result, signature_valid, already_owned
```

Cảnh báo nếu:

```text
nhiều challenge cùng tag trong thời gian ngắn
nhiều claim fail 401
một IP tạo challenge cho nhiều tài khoản
claim thành công nhưng sau đó download/decrypt phía client fail nhiều lần
```

### 7.5 Rate limit endpoint nhạy cảm

Áp rate limit cho:

```text
POST /files/check
POST /files/challenge
POST /files/claim
```

Điều này cũng phù hợp với threat model dedup vì endpoint check/challenge có thể trở thành file-confirmation oracle.

## 8. Kết luận kiểm chứng

Bảng kết quả kỳ vọng với project hiện tại:

| Biến thể | Kết quả mong muốn | Ý nghĩa |
|---|---:|---|
| Replay chữ ký Alice cho Mallory | 401 | Đang được chặn nhờ bind `user_id` + `nonce` |
| Mallory có signature trên đúng challenge của Mallory | 200 claim | Signing-oracle relay có thể tạo ownership |
| Chỉ có signature, không có K | Không decrypt được | Chưa phá confidentiality |
| Có signature + K/wrapped K hợp lệ | Decrypt được | Compromised client/key exfiltration |

Kết luận: phần server PoW hiện tại chống được replay cơ bản, nhưng an toàn cuối cùng phụ thuộc mạnh vào việc client không trở thành signing oracle/key-wrapping oracle cho attacker. Nên bổ sung test này vào regression suite để tránh các lần sửa sau vô tình làm yếu binding của chữ ký.
