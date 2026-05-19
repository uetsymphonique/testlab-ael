# Skill: Dev CLI Execution Constraints

File này mô tả **môi trường development đang dùng để soạn, kiểm tra, hoặc hỗ trợ viết procedures trong repo**.

Đây **không phải** mô tả môi trường thực thi của bài test, victim host, attack host, hay lab target. Khi viết `Procedures` trong emulation plan, không được suy ra rằng một tool có sẵn trên máy test chỉ vì nó có hoặc không có trong file này. Capability của lab phải lấy từ `resources/setup/`, nội dung Phase, hoặc tài liệu setup cụ thể của plan.

## Có thể dùng trong môi trường dev hiện tại

### Code interpreter

- Go qua `go.exe`
- Python virtual environment tại `D:\vcs\ael\venv\`

### Command execution

- PowerShell
- `cmd`

## Chưa dùng trực tiếp được trong môi trường dev hiện tại

- Visual Studio Build Tools — đã cài nhưng chỉ dùng được trong Developer Command Prompt của Visual Studio
- `g++` — chưa được cài
