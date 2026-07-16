import os
import re
import sys

def replace_pr_info(directory):
    # Regex tìm chính xác từ "pr_info" độc lập
    pattern = re.compile(r'\bpr_info\b')
    changed_files = 0
    total_replacements = 0

    print(f"Đang quét thư mục: {directory}...")

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.c') or file.endswith('.h'):
                file_path = os.path.join(root, file)
                
                # Đọc nội dung file
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Kiểm tra xem có chứa pr_info không
                if pattern.search(content):
                    # Thay thế
                    new_content, count = pattern.subn('pr_debug', content)
                    
                    # Ghi lại vào file
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    
                    print(f"✔ Đã sửa: {file_path} ({count} vị trí)")
                    changed_files += 1
                    total_replacements += count

    print("-" * 50)
    print(f"Hoàn thành! Đã sửa {total_replacements} dòng pr_info trong {changed_files} file.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Sử dụng: python3 mute_logs.py <đường_dẫn_thư_mục>")
        sys.exit(1)
        
    target_dir = sys.argv[1]
    if os.path.exists(target_dir):
        replace_pr_info(target_dir)
    else:
        print("Đường dẫn thư mục không tồn tại!")
