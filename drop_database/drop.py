import asyncio
import os
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

DB_NAMES = ["server_status_db"]

async def delete_database_completely():
    print(f"[*] Đang kết nối tới server...")
    client = AsyncIOMotorClient(MONGO_URI)
    
    db_list = await client.list_database_names()
    for DB_NAME in DB_NAMES:
        if DB_NAME in db_list:
            print(f"[WARN] Đang tiến hành XÓA VĨNH VIỄN database: '{DB_NAME}'")
            print("       Hành động này không thể hoàn tác!")
            
            await client.drop_database(DB_NAME)
            
            print(f"[OK] Đã xóa thành công database '{DB_NAME}'.")
        else:
            print(f"[INFO] Không tìm thấy database tên '{DB_NAME}'. Có thể đã xóa rồi.")

    client.close()

if __name__ == "__main__":
    asyncio.run(delete_database_completely())