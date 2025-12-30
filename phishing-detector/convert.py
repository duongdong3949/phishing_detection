import csv
import json
import os

input_file = 'majestic_million.csv'
output_file = 'ruleset.json'

CHROME_MAX_STATIC_RULES = 300000 

def convert_csv_to_json():
    if not os.path.exists(input_file):
        print(f"Lỗi: Không tìm thấy file {input_file}")
        return

    with open(input_file, 'r', encoding='utf-8') as f:
        total_rows_in_file = sum(1 for line in f) - 1
    
    count_to_process = min(total_rows_in_file, CHROME_MAX_STATIC_RULES)
    
    print(f"--- Thông tin file ---")
    print(f"Tổng số dòng trong CSV: {total_rows_in_file}")
    print(f"Số quy tắc sẽ tạo: {count_to_process} (Giới hạn trình duyệt: 300,000)")
    print(f"-----------------------")

    rules = []
    
    try:
        with open(input_file, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader) 
            
            for i, row in enumerate(reader):
                if i >= count_to_process:
                    break
                
                if len(row) > 2:
                    domain = row[2].strip()
                    if domain:
                        rules.append({
                            "id": i + 10,
                            "priority": 3,
                            "action": { "type": "allow" },
                            "condition": { 
                                "urlFilter": f"||{domain}^", 
                                "resourceTypes": ["main_frame"] 
                            }
                        })
                
                if (i + 1) % 50000 == 0:
                    print(f"Đã xử lý: {i + 1} dòng...")

        print(f"Đang ghi file {output_file} (dung lượng lớn, vui lòng đợi)...")
        with open(output_file, 'w', encoding='utf-8') as json_file:
            json.dump(rules, json_file) 
            
        print(f"--- Hoàn thành ---")
        print(f"Đã tạo thành công {len(rules)} quy tắc.")
        print(f"Lưu ý: File JSON này có thể nặng khoảng 40-50MB.")

    except Exception as e:
        print(f"Đã xảy ra lỗi: {e}")

if __name__ == "__main__":
    convert_csv_to_json()