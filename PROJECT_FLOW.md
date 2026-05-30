# Secure Dedup Project Flow

Tài liệu này chia hệ thống thành 3 luồng riêng để dễ đọc: xác thực người dùng, upload, và download.

## 1. Luồng đăng ký, đăng nhập và thao tác người dùng

```mermaid
flowchart TD
    User["Người dùng"] --> CLI["Python CLI"]

    CLI --> Register["Đăng ký tài khoản"]
    Register --> GenURK["Tạo user root key"]
    GenURK --> DeriveKEK["Derive KEK từ mật khẩu"]
    DeriveKEK --> WrapURK["Mã hóa user root key"]
    WrapURK --> AuthRegister["POST /auth/register"]
    AuthRegister --> UsersDB[("users")]

    CLI --> Login["Đăng nhập"]
    Login --> AuthLogin["POST /auth/login"]
    AuthLogin --> UsersDB
    AuthLogin --> JWT["JWT access token"]
    JWT --> SessionFile["Lưu session local"]

    CLI --> Bootstrap["Lấy bootstrap"]
    Bootstrap --> AuthBootstrap["GET /auth/me/bootstrap"]
    AuthBootstrap --> UsersDB
    AuthBootstrap --> UnlockURK["Giải mã user root key bằng mật khẩu"]

    CLI --> ListFiles["Liệt kê file"]
    ListFiles --> APIList["GET /files"]
    APIList --> UserFilesDB[("user_files")]
    APIList --> DecryptNames["CLI giải mã display name"]

    CLI --> ChangePassword["Đổi mật khẩu"]
    ChangePassword --> RewrapURK["Re-wrap user root key bằng KEK mới"]
    RewrapURK --> AuthChange["POST /auth/change-password"]
    AuthChange --> UsersDB

    CLI --> DeleteOwnedFile["Xóa file đã sở hữu"]
    DeleteOwnedFile --> APIDelete["DELETE /files/{file_id}"]
    APIDelete --> UserFilesDB

    CLI -.-> NCLI["Note: CLI entry<br/>client_cli/main.py<br/>build_parser()"]
    Register -.-> NRegister["Note: register command<br/>client_cli/commands/register.py<br/>handle()"]
    GenURK -.-> NRootKey["Note: user root key<br/>client_cli/crypto/root_key.py<br/>generate_root_key(), encrypt_root_key()"]
    DeriveKEK -.-> NKDF["Note: KEK từ password<br/>client_cli/crypto/password_kdf.py<br/>derive_kek()"]
    AuthRegister -.-> NAuthRegister["Note: register API<br/>api/routers/auth.py register()<br/>api/services/auth_service.py AuthService.register()"]
    Login -.-> NLogin["Note: login command<br/>client_cli/commands/login.py<br/>handle()"]
    AuthLogin -.-> NAuthLogin["Note: login API + JWT<br/>AuthService.login()<br/>api/integrations/jwt_manager.py"]
    SessionFile -.-> NSession["Note: local session<br/>client_cli/session/token_store.py<br/>TokenStore"]
    Bootstrap -.-> NBootstrap["Note: bootstrap API<br/>api/routers/auth.py bootstrap()<br/>AuthService.bootstrap()"]
    UnlockURK -.-> NUnlock["Note: unlock root key<br/>client_cli/crypto/root_key.py<br/>unlock_root_key_from_bootstrap()"]
    ListFiles -.-> NList["Note: list files<br/>api/routers/files.py list_files()<br/>FileQueryService.list_owned_files()"]
    APIDelete -.-> NDelete["Note: delete ownership<br/>api/routers/files.py delete_file()<br/>DeleteService.delete_owned_file()"]
    UsersDB -.-> NUserDB["Note: user data<br/>api/models/user.py User<br/>api/repositories/user_repo.py UserRepository"]

    classDef note fill:#fff7ed,stroke:#f97316,color:#7c2d12;
    class NCLI,NRegister,NRootKey,NKDF,NAuthRegister,NLogin,NAuthLogin,NSession,NBootstrap,NUnlock,NList,NDelete,NUserDB note;
```

## 2. Luồng hệ thống upload

```mermaid
flowchart TD
    User["Người dùng chọn file M cần upload"] --> Hash["Tính hash của file<br/>h = Hash(M)"]
    Hash --> Blind["Làm mù hash<br/>h' = h * r"]
    Blind --> OPRFReq["Yêu cầu key server ký<br/>/oprf/sign?token=h'"]

    OPRFReq --> ObliviousNote["Quá trình OPRF là oblivious<br/>server không biết h hay M"]
    OPRFReq --> BlindSign["Server ký mù bằng khóa bí mật d<br/>s' = SignBlind(h', d)"]
    KeyServerNote["Key server nên được tách riêng, harden<br/>và rate-limit mạnh để biến brute-force<br/>offline thành online"] -.-> BlindSign
    BlindSign --> ReturnBlindSig["Trả s' cho client"]

    ReturnBlindSig --> Unblind["Client gỡ mù hash<br/>s = s' / r"]
    Unblind --> FileKey["Tạo khóa K<br/>K = SHA256(s)"]
    FileKey --> KDF["Dùng KDF/HKDF để tách<br/>các nhánh khóa độc lập"]

    KDF --> EncKey["K_enc = HKDF(K,<br/>info='File-Encryption-AES-GCM')<br/>Dùng mã hóa file M bằng AES-GCM"]
    KDF --> PowSeed["Seed_PoW = HKDF(K,<br/>info='Ed25519-PoW-Seed')<br/>Dùng làm hạt giống sinh khóa PoW"]
    PowSeed --> PowKey["sk_PoW, pk_PoW = Ed25519(Seed_PoW)"]
    PowKey --> Tag["Tag = SHA256(pk_PoW)"]

    FileKey --> WrapKey["Tạo wrapped key<br/>WK = Encrypt(K_user, K)"]
    KUserNote["K_user là khóa gốc của user<br/>dùng để wrap K"] -.-> WrapKey

    Tag --> ApiCheck["Client gửi API Check Tag lên server"]
    ApiCheck --> TagLookup["metadata database tra cứu Tag"]

    subgraph MetadataDB["metadata database"]
        FilesTable["files<br/>Tag (primary)<br/>Object_URI<br/>pk_PoW"]
        UserFilesTable["user_files<br/>File_ID (primary)<br/>User_ID<br/>Tag<br/>Wrapped_Key (WK)"]
        UserFilesTable -->|"Tag"| FilesTable
    end

    TagLookup --> FilesTable
    FilesTable --> Exists{"Tag tồn tại?"}

    subgraph CaseExists["Trường hợp 1: Tag tồn tại"]
        ExistsYes["tồn tại"] --> Nonce["Server gửi nonce ngắn hạn cho client"]
        Nonce --> SignPoW["Client tính chữ ký<br/>sigma = Ed25519-Sign(sk_PoW,<br/>Context || Tag || User_ID || nonce)"]
        SignPoW --> ClaimReq["Client gửi server<br/>User_ID, Tag, WK, sigma"]
        ClaimReq --> LoadPk["Server truy vấn pk_PoW từ DB theo Tag"]
        LoadPk --> Verify["Verify(pk_PoW, Payload, sigma)"]
        Verify -->|"hợp lệ"| AddWK["Thêm WK vào user_files"]
        AddWK --> UserFilesTable
    end

    subgraph CaseMissing["Trường hợp 2: Tag không tồn tại"]
        ExistsNo["không tồn tại"] --> EncryptFile["Mã hóa file M<br/>C = AES-GCM(K_enc, M, nonce_aes)"]
        EncryptFile --> UploadCloud["Đẩy file C lên cloud<br/>cloud trả về Object_URL"]
        UploadCloud --> SaveReq["Gửi lên DB server<br/>User_ID, Tag, pk_PoW, WK, Object_URL"]
        SaveReq --> TagCheck["Tag_check = SHA256(pk_PoW)"]
        TagCheck --> CompareTag["So sánh Tag_check với Tag"]
        CompareTag -->|"trùng khớp"| InsertFile["Thêm bản ghi mới vào files"]
        CompareTag -->|"trùng khớp"| InsertUserFile["Thêm WK vào user_files"]
        InsertFile --> FilesTable
        InsertUserFile --> UserFilesTable
    end

    Exists -->|"Có"| ExistsYes
    Exists -->|"Không"| ExistsNo
    PowKey --> SignPoW
    EncKey --> EncryptFile
    WrapKey --> ClaimReq
    WrapKey --> SaveReq

    TagRisk["Lưu ý: chỉ trả lời rõ 'tồn tại/không tồn tại'<br/>có thể tạo oracle xác nhận file.<br/>Nên cân nhắc response đồng nhất hoặc rate-limit."] -.-> ApiCheck

    classDef client fill:#3f8f10,stroke:#79c143,color:#ffffff;
    classDef server fill:#1689c7,stroke:#75c7ef,color:#ffffff;
    classDef data fill:#64748b,stroke:#cbd5e1,color:#ffffff;
    classDef warning fill:#111827,stroke:#f59e0b,color:#ffffff;
    classDef decision fill:#334155,stroke:#cbd5e1,color:#ffffff;

    class User,Hash,Blind,OPRFReq,Unblind,FileKey,KDF,EncKey,PowSeed,PowKey,Tag,WrapKey,ApiCheck,SignPoW,ClaimReq,EncryptFile,UploadCloud,SaveReq client;
    class BlindSign,ReturnBlindSig,Nonce,LoadPk,Verify,AddWK,TagCheck,CompareTag,InsertFile,InsertUserFile server;
    class FilesTable,UserFilesTable,TagLookup data;
    class ObliviousNote,KeyServerNote,KUserNote,TagRisk warning;
    class Exists decision;
    style MetadataDB fill:#0f172a,stroke:#94a3b8,color:#e2e8f0;
    style CaseExists fill:#111827,stroke:#94a3b8,color:#e5e7eb;
    style CaseMissing fill:#111827,stroke:#94a3b8,color:#e5e7eb;
```

### Các điểm thiếu/cần làm rõ trong flow upload

- `K_user` chưa được sinh/khôi phục trong flow hình. Cần có bước đăng nhập hoặc bootstrap để giải mã user root key trước khi tạo `WK = Encrypt(K_user, K)`.
- Endpoint OPRF `/oprf/sign` là thiết kế mục tiêu. Code hiện tại vẫn dùng mock OPRF local, chưa có OPRF server thật.
- Nonce ở nhánh claim cần TTL ngắn, chỉ dùng một lần, và phải gắn với `User_ID`, `Tag`, `context`.
- Flow hình chưa thể hiện xác thực request bằng JWT/session.
- Flow hình chưa có encrypted display name theo từng user, trong khi project hiện tại có `enc_display_name_b64` và `display_name_nonce_b64`.
- Flow hình đơn giản hóa upload cloud thành một bước. Project hiện tại nên có `upload/init`, presigned PUT, rồi `upload/complete`.
- Server cần kiểm tra object đã tồn tại sau khi upload; tốt hơn nữa là kiểm tra size/hash ciphertext so với manifest.
- Cần ghi rõ `sk_PoW` không được lưu lâu dài; client nên derive tạm trong RAM rồi xóa sau khi ký.
- Cần quy định TTL/quyền truy cập cho `Object_URL` hoặc dùng presigned URL thay vì URL vật lý lâu dài.
- Schema trong hình đơn giản hóa DB. Code hiện tại dùng `files.id` làm primary key, `tag_hex` unique, và `user_files.file_id` trỏ sang `files.id`.
- Cần xử lý race condition khi hai client cùng upload một Tag chưa tồn tại.
- Cần tránh file confirmation oracle: response của check/claim nên được rate-limit và thiết kế để không dễ xác nhận người khác có file hay không.

## 3. Luồng hệ thống download

```mermaid
flowchart TD
    User["Người dùng"] --> CLI["CLI download file_id"]

    CLI --> Bootstrap["GET /auth/me/bootstrap"]
    Bootstrap --> UsersDB[("users")]
    Bootstrap --> UnlockURK["Giải mã user root key bằng mật khẩu"]

    CLI --> DownloadInit["POST /files/download/init"]
    DownloadInit --> UserFilesDB[("user_files")]
    DownloadInit -->|"Kiểm tra user sở hữu file"| FilesDB[("files")]
    DownloadInit -->|"Kiểm tra object tồn tại"| MinIO[("MinIO")]

    DownloadInit --> Response["Trả manifest + wrapped file key + encrypted name + presigned GET URL"]
    Response --> CLI

    CLI --> UnwrapFileKey["Unwrap file key bằng user root key"]
    UnwrapFileKey --> DeriveEncKey["Derive AES-GCM key"]

    CLI -->|"GET ciphertext"| MinIO
    MinIO --> Ciphertext["Ciphertext"]
    Ciphertext --> Decrypt["Giải mã và kiểm tra manifest"]
    DeriveEncKey --> Decrypt

    Response --> DecryptName["Giải mã display name"]
    DecryptName --> OutputPath["Chọn tên file output"]
    Decrypt --> SaveFile["Ghi plaintext ra máy người dùng"]
    OutputPath --> SaveFile
    SaveFile --> User

    CLI -.-> NDownloadCLI["Note: download command<br/>client_cli/commands/download.py<br/>handle()"]
    Bootstrap -.-> NBootstrapDL["Note: bootstrap call<br/>client_cli/api/http_client.py APIClient.get_bootstrap()<br/>api/routers/auth.py bootstrap()"]
    UnlockURK -.-> NUnlockDL["Note: unlock root key<br/>client_cli/crypto/root_key.py<br/>unlock_root_key_from_bootstrap()"]
    DownloadInit -.-> NDownloadInit["Note: download init API<br/>api/routers/downloads.py init_download()<br/>DownloadService.init_download()"]
    UserFilesDB -.-> NOwnership["Note: ownership lookup<br/>api/repositories/user_file_repo.py<br/>get_by_user_and_file()"]
    FilesDB -.-> NFileLookup["Note: file lookup<br/>api/repositories/file_repo.py<br/>get_by_id()"]
    Response -.-> NResponse["Note: response fields<br/>manifest, wrapped_kf_b64, wk_nonce_b64,<br/>encrypted display name, presigned GET URL"]
    UnwrapFileKey -.-> NUnwrap["Note: unwrap file key<br/>client_cli/crypto/key_wrap.py<br/>unwrap_file_key()"]
    DeriveEncKey -.-> NDeriveDL["Note: derive AES-GCM key<br/>client_cli/crypto/file_keys.py<br/>derive_encryption_key()"]
    MinIO -.-> NDownloadStorage["Note: download object<br/>client_cli/api/http_client.py download_presigned_bytes()<br/>api/services/storage_service.py create_download_url()"]
    Decrypt -.-> NDecrypt["Note: decrypt + verify manifest<br/>client_cli/crypto/file_encrypt.py<br/>decrypt_ciphertext()"]
    DecryptName -.-> NDecryptName["Note: private display name<br/>client_cli/crypto/private_metadata.py<br/>decrypt_display_name()"]
    SaveFile -.-> NSave["Note: write output<br/>client_cli/commands/download.py<br/>end of handle()"]

    classDef note fill:#fff7ed,stroke:#f97316,color:#7c2d12;
    class NDownloadCLI,NBootstrapDL,NUnlockDL,NDownloadInit,NOwnership,NFileLookup,NResponse,NUnwrap,NDeriveDL,NDownloadStorage,NDecrypt,NDecryptName,NSave note;
```

## Bảng dữ liệu chính

- `users`: tài khoản, password hash, encrypted user root key.
- `files`: metadata file dùng chung, định danh bởi `tag_hex`.
- `user_files`: quyền sở hữu theo từng user, wrapped file key, encrypted display name.
- `upload_sessions`: phiên upload tạm thời giữa init và complete.
- `pow_challenges`: challenge ngắn hạn để claim file đã tồn tại.
- `MinIO`: chỉ lưu ciphertext object.
## 4. Luồng đổi mật khẩu

```mermaid
sequenceDiagram
    participant U as User
    participant C as CLI
    participant A as API
    participant D as DB

    U->>C: Nhap mat khau hien tai va mat khau moi
    C->>A: GET /auth/me/bootstrap (Bearer JWT)
    A->>D: Lay enc_urk, nonce, salt cua user
    D-->>A: Bootstrap material
    A-->>C: enc_urk_b64, enc_urk_nonce_b64, kek_salt_b64

    C->>C: Derive KEK cu tu mat khau hien tai
    C->>C: Giai ma URK bang KEK cu
    C->>C: Derive KEK moi tu mat khau moi
    C->>C: Ma hoa lai chinh URK bang KEK moi

    C->>A: POST /auth/change-password
    A->>D: Verify current password hash
    A->>D: Update password_hash
    A->>D: Update enc_urk_b64, nonce, salt moi
    D-->>A: Commit thanh cong
    A-->>C: Password changed successfully

    Note over C,D: File ciphertext, files, user_files va wrapped file key khong thay doi.
```

### Ý nghĩa của luồng đổi mật khẩu

- Hệ thống không mã hóa lại toàn bộ file khi đổi mật khẩu.
- Thứ được giữ nguyên là `URK` (`user root key`), vì đây mới là khóa gốc để mở các wrapped file key.
- Mật khẩu chỉ dùng để suy ra `KEK` nhằm bảo vệ `URK`.
- Khi đổi mật khẩu, client mở `URK` bằng `KEK` cũ rồi mã hóa lại cùng `URK` đó bằng `KEK` mới.
- Server chỉ cập nhật `password_hash` và bộ bootstrap mới của `URK`.
- Nhờ vậy chi phí đổi mật khẩu thấp, không phải đụng tới ciphertext đã lưu trên MinIO.
