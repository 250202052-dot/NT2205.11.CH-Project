# Schema và privacy validator

Profile metadata mở rộng: allowlist thêm `packet_metadata` và `tls_extensions`; [validate_extended_metadata.py](validate_extended_metadata.py) kiểm tra numeric/bool/vector và missingness. Validator log chính tự gọi module này. Bảng companion trong `extended/` được kiểm tra bằng `scripts/dataset_tools.py extended --validate <extended_directory>`, không dùng schema baseline. Hướng dẫn: [EXTENDED_METADATA.md](../../report/EXTENDED_METADATA.md).

`zeek_metadata_allowlist.json` là schema `metadata-crypto-v1` cho sáu stream Zeek. `validate_zeek_metadata.py` từ chối stream/field ngoài allowlist, SSH banner chưa lọc và custom SHA256 sai định dạng. Chạy `python data/schemas/validate_zeek_metadata.py`; feature builder chạy kiểm tra này trước khi join logs. Regression test: `python tests/test_zeek_metadata.py`.

Final dataset: thêm `--dataset <run_directory>` để đối chiếu labeled CSV/Parquet với project columns/types/versions, kiểm tra provenance, banner/metadata tokens và secret markers. Labeler tự gọi validator này sau export và ghi `privacy_validation.json`. Regression test: `python tests/test_custom_dataset.py`.

Validator phải từ chối HTTP path/header/body raw values, SSH username/password/commands/content, file contents, decrypted payload, credentials, private keys và session secrets trước khi training. Final feature store cần pseudonymous host IDs; CSV hiện tại còn raw lab IP và chưa phải training artifact hoàn chỉnh.
