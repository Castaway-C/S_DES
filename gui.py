import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
from sdes_core import encrypt, decrypt
from ascii_processor import encrypt_ascii, decrypt_ascii
from brute_force import brute_force_crack
from closed_test import closed_test


class SDesGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("S-DES 加密算法工具")
        self.root.geometry("850x650")
        self.root.minsize(800, 600)

        self.BG_COLOR = "#f7f9fa"
        self.CARD_COLOR = "#ffffff"
        self.TEXT_COLOR = "#34495e"
        self.PRIMARY_COLOR = "#3498db"
        self.SECONDARY_COLOR = "#5dade2"
        self.TITLE_COLOR = "#2c3e50"
        self.BORDER_COLOR = "#e0e0e0"
        self.DISABLED_COLOR = "#bdc3c7"

        self.FONT_NORMAL = ("Segoe UI", 10)
        self.FONT_BOLD = ("Segoe UI", 10, "bold")
        self.FONT_TITLE = ("Segoe UI", 20, "bold")
        self.FONT_SECTION = ("Segoe UI", 13, "bold")

        self.root.configure(bg=self.BG_COLOR)
        self.setup_styles()

        self.main_frame = ttk.Frame(root, padding="10 10 10 10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.create_title()
        self.create_tabs()
        self.init_basic_tab()
        self.init_ascii_tab()
        self.init_brute_tab()
        self.init_test_tab()

        self.is_processing = False

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')

        # 全局样式
        style.configure(".",
                        background=self.BG_COLOR,
                        foreground=self.TEXT_COLOR,
                        font=self.FONT_NORMAL)

        # 主框架样式
        style.configure("TFrame", background=self.BG_COLOR)

        # 标题样式
        style.configure("Title.TLabel",
                        font=self.FONT_TITLE,
                        foreground=self.TITLE_COLOR,
                        background=self.BG_COLOR)

        # 选项卡样式
        style.configure("TNotebook", background=self.BG_COLOR, borderwidth=0)
        style.configure("TNotebook.Tab",
                        font=self.FONT_BOLD,
                        padding=(15, 8),
                        foreground=self.TEXT_COLOR,
                        background="#e4e6e8",
                        borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", self.CARD_COLOR), ("active", self.SECONDARY_COLOR)],
                  foreground=[("selected", self.PRIMARY_COLOR), ("active", "white")])

        # 容器样式
        style.configure("Card.TFrame",
                        background=self.CARD_COLOR,
                        relief="solid",
                        borderwidth=1,
                        bordercolor=self.BORDER_COLOR)

        # 卡片内部标题
        style.configure("Section.TLabel",
                        font=self.FONT_SECTION,
                        foreground=self.PRIMARY_COLOR,
                        background=self.CARD_COLOR)

        # 按钮样式
        style.configure("TButton",
                        font=self.FONT_BOLD,
                        padding=(12, 6),
                        relief="flat",
                        borderwidth=0,
                        background=self.PRIMARY_COLOR,
                        foreground="white")
        style.map("TButton",
                  background=[("active", self.SECONDARY_COLOR), ("disabled", self.DISABLED_COLOR)])

        # 输入框样式
        style.configure("TEntry",
                        borderwidth=1,
                        relief="solid",
                        bordercolor=self.BORDER_COLOR,
                        padding=(8, 6),
                        fieldbackground=self.CARD_COLOR)
        style.map("TEntry", bordercolor=[("focus", self.PRIMARY_COLOR)])

        # 进度条样式
        style.configure("TProgressbar",
                        thickness=10,
                        background=self.PRIMARY_COLOR,
                        troughcolor="#ecf0f1",
                        borderwidth=0)

    def create_title(self):
        title_frame = ttk.Frame(self.main_frame, style="TFrame")
        title_frame.pack(fill=tk.X, pady=(5, 15), padx=10)

        ttk.Label(title_frame, text="S-DES 加密算法工具", style="Title.TLabel").pack(anchor=tk.W)

        ttk.Separator(self.main_frame).pack(fill=tk.X, padx=10)

    def create_tabs(self):
        tab_container = ttk.Frame(self.main_frame)
        tab_container.pack(fill=tk.BOTH, expand=True, pady=(15, 0))

        self.tab_control = ttk.Notebook(tab_container)

        self.basic_tab = ttk.Frame(self.tab_control, padding=20)
        self.ascii_tab = ttk.Frame(self.tab_control, padding=20)
        self.brute_tab = ttk.Frame(self.tab_control, padding=20)
        self.test_tab = ttk.Frame(self.tab_control, padding=20)

        self.tab_control.add(self.basic_tab, text="  基础加解密  ")
        self.tab_control.add(self.ascii_tab, text="  字符串处理  ")
        self.tab_control.add(self.brute_tab, text="  暴力破解  ")
        self.tab_control.add(self.test_tab, text="  算法分析  ")

        self.tab_control.pack(fill=tk.BOTH, expand=True)

    def init_basic_tab(self):
        card = ttk.Frame(self.basic_tab, style="Card.TFrame", padding=25)
        card.pack(fill=tk.BOTH, expand=True)

        ttk.Label(card, text="二进制数据加解密", style="Section.TLabel").grid(
            row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 20))

        ttk.Label(card, text="8位输入 (二进制):", background=self.CARD_COLOR).grid(
            row=1, column=0, padx=5, pady=10, sticky=tk.W)
        self.basic_input = ttk.Entry(card, width=40)
        self.basic_input.grid(row=1, column=1, padx=5, pady=10, sticky=tk.EW)

        ttk.Label(card, text="10位密钥 (二进制):", background=self.CARD_COLOR).grid(
            row=2, column=0, padx=5, pady=10, sticky=tk.W)
        self.basic_key = ttk.Entry(card, width=40)
        self.basic_key.grid(row=2, column=1, padx=5, pady=10, sticky=tk.EW)

        ttk.Label(card, text="输出结果:", background=self.CARD_COLOR).grid(
            row=3, column=0, padx=5, pady=10, sticky=tk.W)
        self.basic_output_var = tk.StringVar()
        self.basic_output = ttk.Entry(
            card, textvariable=self.basic_output_var, state="readonly", width=40)
        self.basic_output.grid(row=3, column=1, padx=5, pady=10, sticky=tk.EW)

        btn_frame = ttk.Frame(card, style="Card.TFrame")
        btn_frame.grid(row=4, column=0, columnspan=2, pady=25)

        ttk.Button(btn_frame, text="加密", command=self.basic_encrypt,
                   width=15).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="解密", command=self.basic_decrypt,
                   width=15).pack(side=tk.LEFT, padx=10)

        ttk.Separator(card).grid(row=5, column=0, columnspan=2, sticky=tk.EW, pady=15)

        note_frame = ttk.Frame(card, style="Card.TFrame")

        card.columnconfigure(1, weight=1)

    def init_ascii_tab(self):
        card = ttk.Frame(self.ascii_tab, style="Card.TFrame", padding=25)
        card.pack(fill=tk.BOTH, expand=True)
        card.columnconfigure(1, weight=1)

        ttk.Label(card, text="ASCII字符串加解密", style="Section.TLabel").grid(
            row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 20))

        ttk.Label(card, text="输入文本:", background=self.CARD_COLOR).grid(
            row=1, column=0, padx=5, pady=10, sticky=tk.NW)
        self.ascii_input = scrolledtext.ScrolledText(card, width=40, height=7, relief="solid", bd=1)
        self.ascii_input.grid(row=1, column=1, padx=5, pady=10, sticky=tk.NSEW)

        ttk.Label(card, text="10位密钥 (二进制):", background=self.CARD_COLOR).grid(
            row=2, column=0, padx=5, pady=10, sticky=tk.W)
        self.ascii_key = ttk.Entry(card, width=40)
        self.ascii_key.grid(row=2, column=1, padx=5, pady=10, sticky=tk.W)

        ttk.Label(card, text="输出结果:", background=self.CARD_COLOR).grid(
            row=3, column=0, padx=5, pady=10, sticky=tk.NW)
        self.ascii_output = scrolledtext.ScrolledText(card, width=40, height=7, state="disabled", relief="solid", bd=1)
        self.ascii_output.grid(row=3, column=1, padx=5, pady=10, sticky=tk.NSEW)

        btn_frame = ttk.Frame(card, style="Card.TFrame")
        btn_frame.grid(row=4, column=0, columnspan=2, pady=25)

        ttk.Button(btn_frame, text="加密字符串", command=self.ascii_encrypt,
                   width=15).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="解密字符串", command=self.ascii_decrypt,
                   width=15).pack(side=tk.LEFT, padx=10)

        card.rowconfigure(1, weight=1)
        card.rowconfigure(3, weight=1)

    def init_brute_tab(self):
        card = ttk.Frame(self.brute_tab, style="Card.TFrame", padding=25)
        card.pack(fill=tk.BOTH, expand=True)

        ttk.Label(card, text="密钥暴力破解", style="Section.TLabel").grid(
            row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 20))

        input_container = ttk.Frame(card, style="Card.TFrame")
        input_container.grid(row=1, column=0, sticky=tk.EW, pady=10)
        input_container.columnconfigure(1, weight=1)

        ttk.Label(input_container, text="破解模式:", background=self.CARD_COLOR).grid(row=0, column=0, sticky=tk.W,
                                                                                      padx=5)
        self.brute_mode = tk.StringVar(value="binary")
        mode_combobox = ttk.Combobox(input_container, textvariable=self.brute_mode,
                                     values=["binary", "ascii"], state="readonly", width=12)
        mode_combobox.grid(row=0, column=1, sticky=tk.W, padx=5)
        mode_combobox.bind("<<ComboboxSelected>>", self.update_brute_inputs)

        self.brute_input_frame = ttk.Frame(card, style="Card.TFrame")
        self.brute_input_frame.grid(row=2, column=0, sticky=tk.EW, pady=10)

        self.binary_inputs = ttk.Frame(self.brute_input_frame, style="Card.TFrame")
        self.binary_inputs.columnconfigure(1, weight=1)
        ttk.Label(self.binary_inputs, text="已知明文 (8位二进制):", background=self.CARD_COLOR).grid(row=0, column=0,
                                                                                                     padx=5, pady=5,
                                                                                                     sticky=tk.W)
        self.brute_plaintext_bin = ttk.Entry(self.binary_inputs, width=30)
        self.brute_plaintext_bin.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Label(self.binary_inputs, text="对应密文 (8位二进制):", background=self.CARD_COLOR).grid(row=1, column=0,
                                                                                                     padx=5, pady=5,
                                                                                                     sticky=tk.W)
        self.brute_ciphertext_bin = ttk.Entry(self.binary_inputs, width=30)
        self.brute_ciphertext_bin.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)

        self.ascii_inputs = ttk.Frame(self.brute_input_frame, style="Card.TFrame")
        self.ascii_inputs.columnconfigure(1, weight=1)
        self.ascii_inputs.rowconfigure(0, weight=1)
        self.ascii_inputs.rowconfigure(1, weight=1)
        ttk.Label(self.ascii_inputs, text="已知明文 (ASCII):", background=self.CARD_COLOR).grid(row=0, column=0, padx=5,
                                                                                                pady=5, sticky=tk.NW)
        self.brute_plaintext_ascii = scrolledtext.ScrolledText(self.ascii_inputs, width=30, height=4, relief="solid",
                                                               bd=1)
        self.brute_plaintext_ascii.grid(row=0, column=1, padx=5, pady=5, sticky=tk.NSEW)
        ttk.Label(self.ascii_inputs, text="对应密文 (ASCII):", background=self.CARD_COLOR).grid(row=1, column=0, padx=5,
                                                                                                pady=5, sticky=tk.NW)
        self.brute_ciphertext_ascii = scrolledtext.ScrolledText(self.ascii_inputs, width=30, height=4, relief="solid",
                                                                bd=1)
        self.brute_ciphertext_ascii.grid(row=1, column=1, padx=5, pady=5, sticky=tk.NSEW)

        self.update_brute_inputs(None)

        btn_frame = ttk.Frame(card, style="Card.TFrame")
        btn_frame.grid(row=3, column=0, pady=20)
        ttk.Button(btn_frame, text="开始暴力破解", command=self.start_brute_force).pack()

        self.brute_progress = ttk.Progressbar(card, orient="horizontal", length=100, mode="determinate")
        self.brute_progress.grid(row=4, column=0, padx=5, pady=10, sticky=tk.EW)

        result_frame = ttk.Frame(card, style="Card.TFrame")
        result_frame.grid(row=5, column=0, sticky=tk.NSEW, pady=(10, 0))
        ttk.Label(result_frame, text="破解结果:", background=self.CARD_COLOR, font=self.FONT_BOLD).pack(anchor=tk.W,
                                                                                                        pady=(0, 5))
        self.brute_result = scrolledtext.ScrolledText(result_frame, width=60, height=8, relief="solid", bd=1)
        self.brute_result.pack(fill=tk.BOTH, expand=True)

        card.rowconfigure(5, weight=1)
        card.columnconfigure(0, weight=1)

    def update_brute_inputs(self, event):
        self.binary_inputs.pack_forget()
        self.ascii_inputs.pack_forget()

        if self.brute_mode.get() == "binary":
            self.binary_inputs.pack(fill=tk.BOTH, expand=True)
        else:
            self.ascii_inputs.pack(fill=tk.BOTH, expand=True)

    def init_test_tab(self):
        card = ttk.Frame(self.test_tab, style="Card.TFrame", padding=25)
        card.pack(fill=tk.BOTH, expand=True)

        ttk.Label(card, text="S-DES算法特性分析", style="Section.TLabel").grid(
            row=0, column=0, sticky=tk.W, pady=(0, 20))

        test_note = "本功能将检测S-DES是否存在密钥碰撞特性，并对其进行展示和统计。"
        ttk.Label(card, text=test_note, justify=tk.LEFT, background=self.CARD_COLOR).grid(
            row=1, column=0, sticky=tk.W, pady=10)

        # 输入要分析的明文
        input_frame = ttk.Frame(card, style="Card.TFrame")
        input_frame.grid(row=2, column=0, sticky=tk.W, pady=(15, 0))
        ttk.Label(input_frame, text="8位明文 (二进制):", background=self.CARD_COLOR).pack(side=tk.LEFT, padx=(0, 10))
        self.test_plaintext_entry = ttk.Entry(input_frame, width=20)
        self.test_plaintext_entry.pack(side=tk.LEFT)
        self.test_plaintext_entry.insert(0, '')

        btn_frame = ttk.Frame(card, style="Card.TFrame")
        btn_frame.grid(row=3, column=0, pady=20)
        ttk.Button(btn_frame, text="开始算法分析", command=self.start_closed_test).pack()

        self.test_progress = ttk.Progressbar(card, orient="horizontal", length=100, mode="determinate")
        self.test_progress.grid(row=4, column=0, pady=10, sticky=tk.EW)

        result_frame = ttk.Frame(card, style="Card.TFrame")
        result_frame.grid(row=5, column=0, sticky=tk.NSEW, pady=(10, 0))
        ttk.Label(result_frame, text="分析结果:", background=self.CARD_COLOR, font=self.FONT_BOLD).pack(anchor=tk.W,
                                                                                                        pady=(0, 5))
        self.test_result = scrolledtext.ScrolledText(result_frame, width=60, height=10, relief="solid", bd=1)
        self.test_result.pack(fill=tk.BOTH, expand=True)

        card.rowconfigure(5, weight=1)
        card.columnconfigure(0, weight=1)

    def start_brute_force(self):
        if self.is_processing:
            messagebox.showinfo("提示", "正在处理中，请稍候...")
            return
        mode = self.brute_mode.get()
        if mode == "binary":
            plaintext = self.brute_plaintext_bin.get().strip()
            ciphertext = self.brute_ciphertext_bin.get().strip()
            if len(plaintext) != 8 or not all(c in "01" for c in plaintext):
                messagebox.showerror("输入错误", "请输入8位二进制数作为明文！")
                return
            if len(ciphertext) != 8 or not all(c in "01" for c in ciphertext):
                messagebox.showerror("输入错误", "请输入8位二进制数作为密文！")
                return
        else:
            plaintext = self.brute_plaintext_ascii.get("1.0", tk.END).strip()
            ciphertext = self.brute_ciphertext_ascii.get("1.0", tk.END).strip()
            if not plaintext or not ciphertext:
                messagebox.showerror("输入错误", "明文和密文均不能为空！")
                return
            if len(plaintext) != len(ciphertext):
                messagebox.showerror("输入错误", "明文和密文的长度必须相同！")
                return

        self.is_processing = True
        self.brute_progress["value"] = 0
        self.brute_result.delete(1.0, tk.END)
        self.brute_result.insert(tk.END, f"开始{('二进制' if mode == 'binary' else 'ASCII字符串')}暴力破解...\n\n")

        def update_progress(progress):
            self.brute_progress["value"] = progress
            self.root.update_idletasks()

        def on_complete():
            self.is_processing = False
            self.brute_progress["value"] = 100

        thread = threading.Thread(target=self.run_brute_force,
                                  args=(mode, plaintext, ciphertext, update_progress, on_complete))
        thread.daemon = True
        thread.start()

    def run_brute_force(self, mode, plaintext, ciphertext, progress_callback, complete_callback):
        try:
            brute_force_crack(mode, plaintext, ciphertext, self.brute_result, progress_callback)
        finally:
            complete_callback()

    def basic_encrypt(self):
        input_text = self.basic_input.get().strip()
        key = self.basic_key.get().strip()
        if len(input_text) != 8 or not all(c in "01" for c in input_text):
            messagebox.showerror("输入错误", "请输入8位二进制数作为输入！")
            return
        if len(key) != 10 or not all(c in "01" for c in key):
            messagebox.showerror("输入错误", "请输入10位二进制数作为密钥！")
            return
        try:
            result = encrypt(input_text, key)
            self.basic_output_var.set(result)
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")

    def basic_decrypt(self):
        input_text = self.basic_input.get().strip()
        key = self.basic_key.get().strip()
        if len(input_text) != 8 or not all(c in "01" for c in input_text):
            messagebox.showerror("输入错误", "请输入8位二进制数作为输入！")
            return
        if len(key) != 10 or not all(c in "01" for c in key):
            messagebox.showerror("输入错误", "请输入10位二进制数作为密钥！")
            return
        try:
            result = decrypt(input_text, key)
            self.basic_output_var.set(result)
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")

    def ascii_encrypt(self):
        text = self.ascii_input.get("1.0", tk.END).strip()
        key = self.ascii_key.get().strip()
        if not text:
            messagebox.showerror("输入错误", "请输入要加密的文本！")
            return
        if len(key) != 10 or not all(c in "01" for c in key):
            messagebox.showerror("输入错误", "请输入10位二进制数作为密钥！")
            return
        try:
            result = encrypt_ascii(text, key)
            self.ascii_output.config(state="normal")
            self.ascii_output.delete("1.0", tk.END)
            self.ascii_output.insert("1.0", result)
            self.ascii_output.config(state="disabled")
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")

    def ascii_decrypt(self):
        text = self.ascii_input.get("1.0", tk.END).strip()
        key = self.ascii_key.get().strip()
        if not text:
            messagebox.showerror("输入错误", "请输入要解密的文本！")
            return
        if len(key) != 10 or not all(c in "01" for c in key):
            messagebox.showerror("输入错误", "请输入10位二进制数作为密钥！")
            return
        try:
            result = decrypt_ascii(text, key)
            self.ascii_output.config(state="normal")
            self.ascii_output.delete("1.0", tk.END)
            self.ascii_output.insert("1.0", result)
            self.ascii_output.config(state="disabled")
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")

    def start_closed_test(self):
        if self.is_processing:
            messagebox.showinfo("提示", "正在处理中，请稍候...")
            return

        plaintext = self.test_plaintext_entry.get().strip()
        if len(plaintext) != 8 or not all(c in "01" for c in plaintext):
            messagebox.showerror("输入错误", "请输入8位二进制数作为要分析的明文！")
            return

        self.is_processing = True
        self.test_progress["value"] = 0
        self.test_result.delete(1.0, tk.END)
        self.test_result.insert(tk.END, "开始算法分析...\n\n")

        def update_progress(progress):
            self.test_progress["value"] = progress
            self.root.update_idletasks()

        def on_complete():
            self.is_processing = False
            self.test_progress["value"] = 100

        thread = threading.Thread(target=self.run_closed_test,
                                  args=(plaintext, update_progress, on_complete))
        thread.daemon = True
        thread.start()

    def run_closed_test(self, plaintext, progress_callback, complete_callback):
        try:
            closed_test(plaintext, self.test_result, progress_callback)
        finally:
            complete_callback()
            self.root.after(0, lambda: self.test_result.insert(tk.END, "\n分析完成！"))