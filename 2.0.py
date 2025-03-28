import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
import os
import bcrypt
from cryptography.fernet import Fernet
import logging
from datetime import datetime
import shutil
import keyring
from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import sessionmaker, declarative_base
import requests
import time

# 替换为你的 OpenRouter API 密钥
OPENROUTER_API_KEY = 'your_api_key'
OPENROUTER_API_URL = 'your_api_url'

# 加密密钥管理
service_id = "chatbot_service"
username = "chatbot_user"
key = keyring.get_password(service_id, username)
if not key:
    key = Fernet.generate_key()
    keyring.set_password(service_id, username, key.decode())
cipher_suite = Fernet(key)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("chatbot.log"), logging.StreamHandler()]
)

# 定义常量
INPUT_PLACEHOLDER = "请输入消息..."


def generate_response(prompt):
    headers = {
        'Authorization': f'Bearer {OPENROUTER_API_KEY}',
        'Content-Type': 'application/json'
    }

    data = {
        'model': 'deepseek-ai/DeepSeek-R1-Distill-Qwen-7B',  # 或其他可用的模型
        'messages': [{'role': 'user', 'content': prompt}],
        'max_tokens': 100,  # 控制生成回复的长度
    }

    response = requests.post(OPENROUTER_API_URL, headers=headers, json=data)

    if response.status_code == 200:
        reply = response.json()['choices'][0]['message']['content']
        return reply
    else:
        return f"错误: {response.status_code} - {response.text}"


LOG_FILE_NAME = "对话记录_{}.txt"
HISTORY_HEADER = "\n--- 聊天历史记录 ---\n"
NO_RECORD_MSG = "当前没有聊天记录可查看。"

# 用户数据库路径（固定路径）
USER_DB_DIR = r"C:\Users\Administrator\AppData\AI database\聊天机器人\用户"
os.makedirs(USER_DB_DIR, exist_ok=True)
USER_DB_FILE = os.path.join(USER_DB_DIR, "users.db")

# 检查文件是否存在且损坏
if os.path.exists(USER_DB_FILE):
    try:
        # 尝试打开文件以检查是否损坏
        with open(USER_DB_FILE, 'rb') as f:
            f.read(100)  # 读取少量数据进行检查
    except Exception as e:
        print(f"文件损坏，将删除并重新创建: {e}")
        os.remove(USER_DB_FILE)

MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 20
MIN_PASSWORD_LENGTH = 6

# 密码验证函数
def validate_credentials(username, password):
    if len(username) < MIN_USERNAME_LENGTH or len(username) > MAX_USERNAME_LENGTH:
        return False, f"用户名长度应在 {MIN_USERNAME_LENGTH}-{MAX_USERNAME_LENGTH} 之间"
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"密码长度至少需要 {MIN_PASSWORD_LENGTH} 位"
    return True, ""

# 创建数据库引擎
engine = create_engine(f'sqlite:///{USER_DB_FILE}')
Base = declarative_base()

# 定义用户表结构
class User(Base):
    __tablename__ = 'users'
    username = Column(String, primary_key=True)
    password_hash = Column(String)

# 创建表
Base.metadata.create_all(engine)

# 用户数据库管理（修复后的版本）
def load_user_db():
    try:
        Session = sessionmaker(bind=engine)
        session = Session()
        users = session.query(User).all()
        user_db = {user.username: user.password_hash for user in users}
        session.close()
        return user_db
    except Exception as e:
        logging.error(f"加载用户数据库失败: {e}")
        return {}

def save_user_db(user_db):
    try:
        Session = sessionmaker(bind=engine)
        session = Session()
        for username, encrypted_hash in user_db.items():
            user = session.query(User).filter(User.username == username).first()
            if user:
                user.password_hash = encrypted_hash
            else:
                new_user = User(username=username, password_hash=encrypted_hash)
                session.add(new_user)
        session.commit()
        session.close()
    except Exception as e:
        logging.error(f"保存用户数据库失败: {e}")

user_db = load_user_db()

class ResponseManager:
    def __init__(self):
        self.responses = {
            "你好": "你好呀！有什么问题都可以问我。",
            "再见": "再见啦，祝你生活愉快！",
            "今天天气怎么样": "我还没办法获取实时天气呢，你可以查看天气预报软件。"
        }

    def get_response(self, user_input):
        return self.responses.get(user_input, "我不太理解你的问题，可以换一种说法吗？")


class ChatBotApp:
    def __init__(self, root):
        self.root = root
        self.root.title("liha智能助手")
        self.root.geometry("800x600")
        self.root.configure(bg="#F0F0F0")
        self.setup_style()
        self.create_widgets()
        self.response_manager = ResponseManager()
        self.show_login_dialog()

    def handle_input(self):
        user_input = self.input_box.get().strip()
        if user_input:
            bot_response = generate_response(user_input)
            self.update_chat_box(user_input, bot_response)
            self.save_chat_log(user_input, bot_response)
            self.input_box.delete(0, tk.END)
            self.restore_placeholder(None)

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("default")

        # 定义不同主题的样式
        self.themes = {
            "default": {
                "bg": "#F0F0F0",
                "fg": "#333",
                "button_bg": "#4CAF50",
                "button_fg": "white",
                "button_active_bg": "#45a049",
                "button_disabled_bg": "#cccccc",
                "button_disabled_fg": "#888",
                "entry_bg": "white",
                "entry_fg": "#333",
                "scrollbar_bg": "#DDD",
                "scrollbar_trough": "#EEE"
            },
            "dark": {
                "bg": "#212121",
                "fg": "#FFFFFF",
                "button_bg": "#2196F3",
                "button_fg": "white",
                "button_active_bg": "#1E88E5",
                "button_disabled_bg": "#757575",
                "button_disabled_fg": "#BDBDBD",
                "entry_bg": "#424242",
                "entry_fg": "#FFFFFF",
                "scrollbar_bg": "#616161",
                "scrollbar_trough": "#424242"
            }
        }
        self.switch_theme("default")

    def switch_theme(self, theme):
        style = ttk.Style()
        # 不再使用 theme_use，直接配置样式
        style.configure("TLabel", background=self.themes[theme]["bg"], foreground=self.themes[theme]["fg"], font=("微软雅黑", 10))
        style.configure("TButton",
                        background=self.themes[theme]["button_bg"],
                        foreground=self.themes[theme]["button_fg"],
                        font=("微软雅黑", 10),
                        padding=8,
                        relief="flat")
        style.map("TButton",
                  background=[("active", self.themes[theme]["button_active_bg"]), ("disabled", self.themes[theme]["button_disabled_bg"])],
                  foreground=[("disabled", self.themes[theme]["button_disabled_fg"])])
        style.configure("TEntry",
                        fieldbackground=self.themes[theme]["entry_bg"],
                        foreground=self.themes[theme]["entry_fg"],
                        relief="solid",
                        borderwidth=1,
                        font=("微软雅黑", 10))
        style.configure("TScrollbar", background=self.themes[theme]["scrollbar_bg"], troughcolor=self.themes[theme]["scrollbar_trough"])
        style.configure("TFrame", background=self.themes[theme]["bg"])
        self.root.configure(bg=self.themes[theme]["bg"])

    def create_widgets(self):
        # 聊天容器
        chat_frame = ttk.Frame(self.root, padding=10)
        chat_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 聊天记录
        self.chat_box = scrolledtext.ScrolledText(
            chat_frame,
            width=60,
            height=20,
            wrap=tk.WORD,
            bg="white",
            fg="#333",
            font=("微软雅黑", 10),
            borderwidth=1,
            relief="solid"
        )
        self.chat_box.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.chat_box.tag_config("user", foreground="#4CAF50")
        self.chat_box.tag_config("bot", foreground="#2196F3")

        # 输入容器
        input_frame = ttk.Frame(self.root, padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=5)

        # 输入框
        self.input_box = ttk.Entry(
            input_frame,
            width=50,
            style="TEntry"
        )
        self.input_box.insert(0, INPUT_PLACEHOLDER)
        self.input_box.bind("<FocusIn>", self.clear_placeholder)
        self.input_box.bind("<FocusOut>", self.restore_placeholder)
        self.input_box.pack(side=tk.LEFT, padx=5)

        # 发送按钮
        self.send_button = ttk.Button(
            input_frame,
            text="发送",
            command=self.handle_input,
            style="TButton"
        )
        self.send_button.pack(side=tk.LEFT, padx=5)
        self.send_button.state(['disabled'])

        # 功能按钮容器
        func_frame = ttk.Frame(self.root, padding=10)
        func_frame.pack(fill=tk.X, padx=10, pady=5)

        # 功能按钮
        self.history_button = ttk.Button(
            func_frame,
            text="历史记录",
            command=self.show_history_dialog,
            style="TButton"
        )
        self.history_button.pack(side=tk.LEFT, padx=5)
        self.history_button.state(['disabled'])

        self.feedback_button = ttk.Button(
            func_frame,
            text="反馈",
            command=self.show_feedback_dialog,
            style="TButton"
        )
        self.feedback_button.pack(side=tk.LEFT, padx=5)
        self.feedback_button.state(['disabled'])

        self.backup_button = ttk.Button(
            func_frame,
            text="备份",
            command=self.backup_chat_log,
            style="TButton"
        )
        self.backup_button.pack(side=tk.LEFT, padx=5)
        self.backup_button.state(['disabled'])

        self.restore_button = ttk.Button(
            func_frame,
            text="恢复",
            command=self.show_restore_dialog,
            style="TButton"
        )
        self.restore_button.pack(side=tk.LEFT, padx=5)
        self.restore_button.state(['disabled'])

        # 主题切换按钮
        self.theme_button = ttk.Button(
            func_frame,
            text="切换主题",
            command=lambda: self.switch_theme("dark" if self.themes["default"]["bg"] == self.root.cget("bg") else "default"),
            style="TButton"
        )
        self.theme_button.pack(side=tk.LEFT, padx=5)
        self.theme_button.state(['!disabled'])

    def clear_placeholder(self, event):
        if self.input_box.get() == INPUT_PLACEHOLDER:
            self.input_box.delete(0, tk.END)
            self.input_box.config(foreground="#333")

    def restore_placeholder(self, event):
        if not self.input_box.get():
            self.input_box.insert(0, INPUT_PLACEHOLDER)
            self.input_box.config(foreground="#888")

    def save_chat_log(self, user_input, bot_response):
        today = datetime.now().strftime("%Y-%m-%d")
        log_file = os.path.join(USER_DB_DIR, LOG_FILE_NAME.format(today))
        with open(log_file, 'a', encoding='utf-8') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            encrypted_user_input = cipher_suite.encrypt(user_input.encode()).decode()
            encrypted_bot_response = cipher_suite.encrypt(bot_response.encode()).decode()
            f.write(f"[{timestamp}] 用户: {encrypted_user_input}\n")
            f.write(f"[{timestamp}] 机器人: {encrypted_bot_response}\n")
        logging.info(f"保存聊天记录: {user_input} -> {bot_response}")

    def update_chat_box(self, user_input, bot_response):
        self.chat_box.insert(tk.END, f"你: {user_input}\n", "user")
        self.chat_box.insert(tk.END, f"豆包: {bot_response}\n", "bot")
        self.chat_box.see(tk.END)

    def show_history_dialog(self):
        history_dialog = tk.Toplevel(self.root)
        history_dialog.title("查看历史记录")
        history_dialog.geometry("600x400")
        history_dialog.configure(bg=self.root.cget("bg"))

        ttk.Label(history_dialog, text="开始时间 (YYYY-MM-DD HH:MM:SS)").place(x=20, y=20)
        start_time_entry = ttk.Entry(history_dialog)
        start_time_entry.place(x=20, y=40, width=200)

        ttk.Label(history_dialog, text="结束时间 (YYYY-MM-DD HH:MM:SS)").place(x=240, y=20)
        end_time_entry = ttk.Entry(history_dialog)
        end_time_entry.place(x=240, y=40, width=200)

        ttk.Label(history_dialog, text="搜索关键词:").place(x=20, y=70)
        search_entry = ttk.Entry(history_dialog, width=50)
        search_entry.place(x=20, y=90)

        history_text = scrolledtext.ScrolledText(
            history_dialog,
            width=70,
            height=15,
            wrap=tk.WORD,
            bg="white",
            fg="#333",
            font=("微软雅黑", 10),
            borderwidth=1,
            relief="solid"
        )
        history_text.place(x=20, y=120, width=560, height=250)

        def view_history():
            try:
                start = datetime.strptime(start_time_entry.get(), "%Y-%m-%d %H:%M:%S")
                end = datetime.strptime(end_time_entry.get(), "%Y-%m-%d %H:%M:%S")
                history = HISTORY_HEADER
                log_dir = USER_DB_DIR
                for filename in os.listdir(log_dir):
                    if filename.startswith("对话记录_") and filename.endswith(".txt"):
                        try:
                            date_str = filename.split("_")[1].split(".")[0]
                            file_date = datetime.strptime(date_str, "%Y-%m-%d")
                            if start.date() <= file_date <= end.date():
                                with open(os.path.join(log_dir, filename), 'r', encoding='utf-8') as f:
                                    for line in f.readlines():
                                        parts = line.strip().split(": ", 1)
                                        if len(parts) == 2:
                                            role, content = parts
                                            decrypted_content = cipher_suite.decrypt(content.encode()).decode()
                                            history += f"{role}: {decrypted_content}\n"
                        except:
                            continue
                history_text.delete(1.0, tk.END)
                history_text.insert(tk.END, history if history else NO_RECORD_MSG)
            except ValueError:
                messagebox.showerror("错误", "请输入正确的时间格式 (YYYY-MM-DD HH:MM:SS)")
            except Exception as e:
                messagebox.showerror("错误", f"发生错误: {str(e)}")

        def search_history():
            search_term = search_entry.get()
            history = ""
            try:
                start = datetime.strptime(start_time_entry.get(), "%Y-%m-%d %H:%M:%S")
                end = datetime.strptime(end_time_entry.get(), "%Y-%m-%d %H:%M:%S")
                log_dir = USER_DB_DIR
                for filename in os.listdir(log_dir):
                    if filename.startswith("对话记录_") and filename.endswith(".txt"):
                        try:
                            date_str = filename.split("_")[1].split(".")[0]
                            file_date = datetime.strptime(date_str, "%Y-%m-%d")
                            if start.date() <= file_date <= end.date():
                                with open(os.path.join(log_dir, filename), 'r', encoding='utf-8') as f:
                                    for line in f.readlines():
                                        parts = line.strip().split(": ", 1)
                                        if len(parts) == 2:
                                            role, content = parts
                                            decrypted_content = cipher_suite.decrypt(content.encode()).decode()
                                            if search_term in decrypted_content:
                                                history += f"{role}: {decrypted_content}\n"
                        except:
                            continue
                history_text.delete(1.0, tk.END)
                history_text.insert(tk.END, history if history else "未找到匹配的记录")
            except ValueError:
                messagebox.showerror("错误", "请输入正确的时间格式 (YYYY-MM-DD HH:MM:SS)")
            except Exception as e:
                messagebox.showerror("错误", f"发生错误: {str(e)}")

        def export_history():
            export_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
                title="选择导出路径"
            )
            if export_path:
                try:
                    history = ""
                    start = datetime.strptime(start_time_entry.get(), "%Y-%m-%d %H:%M:%S")
                    end = datetime.strptime(end_time_entry.get(), "%Y-%m-%d %H:%M:%S")
                    log_dir = USER_DB_DIR
                    for filename in os.listdir(log_dir):
                        if filename.startswith("对话记录_") and filename.endswith(".txt"):
                            try:
                                date_str = filename.split("_")[1].split(".")[0]
                                file_date = datetime.strptime(date_str, "%Y-%m-%d")
                                if start.date() <= file_date <= end.date():
                                    with open(os.path.join(log_dir, filename), 'r', encoding='utf-8') as f:
                                        for line in f.readlines():
                                            parts = line.strip().split(": ", 1)
                                            if len(parts) == 2:
                                                role, content = parts
                                                decrypted_content = cipher_suite.decrypt(content.encode()).decode()
                                                history += f"{role}: {decrypted_content}\n"
                            except:
                                continue
                    with open(export_path, 'w', encoding='utf-8') as f:
                        f.write(history)
                    messagebox.showinfo("导出成功", f"聊天记录已导出到 {export_path}")
                except Exception as e:
                    messagebox.showerror("导出失败", f"导出时发生错误: {str(e)}")

        ttk.Button(
            history_dialog,
            text="查看",
            command=view_history,
            style="TButton"
        ).place(x=20, y=330, width=100)

        ttk.Button(
            history_dialog,
            text="搜索",
            command=search_history,
            style="TButton"
        ).place(x=140, y=330, width=100)

        ttk.Button(
            history_dialog,
            text="导出",
            command=export_history,
            style="TButton"
        ).place(x=260, y=330, width=100)

    def show_feedback_dialog(self):
        feedback_dialog = tk.Toplevel(self.root)
        feedback_dialog.title("反馈")
        feedback_dialog.geometry("400x200")
        feedback_dialog.configure(bg=self.root.cget("bg"))

        ttk.Label(feedback_dialog, text="请输入你的反馈:").place(x=20, y=20)
        feedback_entry = ttk.Entry(feedback_dialog, width=50)
        feedback_entry.place(x=20, y=40, height=100)

        def submit_feedback():
            feedback = feedback_entry.get().strip()
            if feedback:
                with open(os.path.join(USER_DB_DIR, "feedback.txt"), 'a', encoding='utf-8') as f:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    f.write(f"[{timestamp}] {feedback}\n")
                messagebox.showinfo("感谢", "反馈已提交，感谢你的支持！")
                feedback_dialog.destroy()
            else:
                messagebox.showerror("错误", "请输入反馈内容。")

        ttk.Button(
            feedback_dialog,
            text="提交",
            command=submit_feedback,
            style="TButton"
        ).place(x=20, y=150, width=100)

    def backup_chat_log(self):
        max_retries = 3
        retry_delay = 1
        for attempt in range(max_retries):
            try:
                backup_path = filedialog.asksaveasfilename(
                    defaultextension=".zip",
                    filetypes=[("ZIP档案", "*.zip"), ("所有文件", "*.*")],
                    title="选择备份路径"
                )
                if backup_path:
                    log_dir = USER_DB_DIR
                    shutil.make_archive(backup_path.replace(".zip", ""), 'zip', log_dir)
                    messagebox.showinfo("备份成功", f"聊天记录已备份到 {backup_path}")
                    logging.info(f"成功备份到: {backup_path}")
                    break
            except Exception as e:
                if attempt < max_retries - 1:
                    messagebox.showwarning("备份失败", f"备份时发生错误: {str(e)}，将在 {retry_delay} 秒后重试...")
                    time.sleep(retry_delay)
                else:
                    messagebox.showerror("备份失败", f"备份时发生错误: {str(e)}，已达到最大重试次数。")

    def show_restore_dialog(self):
        restore_dialog = tk.Toplevel(self.root)
        restore_dialog.title("恢复聊天记录")
        restore_dialog.geometry("400x100")
        restore_dialog.configure(bg=self.root.cget("bg"))

        ttk.Label(restore_dialog, text="选择备份文件:").place(x=20, y=20)
        backup_path_entry = ttk.Entry(restore_dialog, width=50)
        backup_path_entry.place(x=20, y=40)

        def restore_chat():
            backup_path = backup_path_entry.get()
            if backup_path:
                log_dir = USER_DB_DIR
                try:
                    shutil.unpack_archive(backup_path, log_dir)
                    messagebox.showinfo("恢复成功", "聊天记录已恢复。")
                    logging.info(f"成功恢复自: {backup_path}")
                except Exception as e:
                    messagebox.showerror("恢复失败", f"恢复时发生错误: {str(e)}")

        ttk.Button(
            restore_dialog,
            text="浏览",
            command=lambda: backup_path_entry.insert(0, filedialog.askopenfilename()),
            style="TButton"
        ).place(x=300, y=40, width=80)

        ttk.Button(
            restore_dialog,
            text="恢复",
            command=restore_chat,
            style="TButton"
        ).place(x=20, y=70, width=100)

    def show_login_dialog(self):
        login_dialog = tk.Toplevel(self.root)
        login_dialog.title("登录/注册")
        login_dialog.geometry("300x200")
        login_dialog.configure(bg=self.root.cget("bg"))
        login_dialog.transient(self.root)

        ttk.Label(login_dialog, text="用户名:").place(x=20, y=20)
        username_entry = ttk.Entry(login_dialog)
        username_entry.place(x=20, y=40, width=260)

        ttk.Label(login_dialog, text="密码:").place(x=20, y=70)
        password_entry = ttk.Entry(login_dialog, show="*")
        password_entry.place(x=20, y=90, width=260)

        def handle_login():
            username = username_entry.get()
            password = password_entry.get()

            Session = sessionmaker(bind=engine)
            session = Session()
            user = session.query(User).filter(User.username == username).first()
            if user:
                encrypted_hash = user.password_hash.encode('utf-8')
                try:
                    if bcrypt.checkpw(password.encode('utf-8'), encrypted_hash):
                        messagebox.showinfo("登录成功", "欢迎回来！")
                        login_dialog.destroy()
                        self.enable_buttons()
                        logging.info(f"用户 {username} 登录成功")
                    else:
                        messagebox.showerror("登录失败", "密码错误")
                except ValueError as e:
                    logging.error(f"密码验证失败: {e}")
                    messagebox.showerror("登录失败", "密码哈希值损坏")
            else:
                messagebox.showerror("登录失败", "用户不存在")
            session.close()

        def handle_register():
            username = username_entry.get()
            password = password_entry.get()
            valid, msg = validate_credentials(username, password)
            if not valid:
                messagebox.showerror("注册失败", msg)
                return

            Session = sessionmaker(bind=engine)
            session = Session()
            existing_user = session.query(User).filter(User.username == username).first()
            if existing_user:
                messagebox.showerror("注册失败", "用户名已存在")
                session.close()
                return

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            new_user = User(username=username, password_hash=hashed_password.decode('utf-8'))
            session.add(new_user)
            session.commit()
            session.close()
            messagebox.showinfo("注册成功", "注册成功，请登录")
            logging.info(f"新用户注册: {username}")

        ttk.Button(
            login_dialog,
            text="登录",
            command=handle_login,
            style="TButton"
        ).place(x=20, y=130, width=120)

        ttk.Button(
            login_dialog,
            text="注册",
            command=handle_register,
            style="TButton"
        ).place(x=160, y=130, width=120)

    def enable_buttons(self):
        self.send_button.state(['!disabled'])
        self.history_button.state(['!disabled'])
        self.feedback_button.state(['!disabled'])
        self.backup_button.state(['!disabled'])
        self.restore_button.state(['!disabled'])


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatBotApp(root)
    root.mainloop()
    
