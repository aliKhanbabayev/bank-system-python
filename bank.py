import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime
from typing import Optional

DATA_FILE = "bank_data.json"


# ─── Helpers ──────────────────────────────────────────────────────────────────

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt,
                        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${dk.hex()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_hex, hash_hex = stored.split("$")
        if algo != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex),
                            n=int(n), r=int(r), p=int(p), dklen=len(hash_hex) // 2)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk.hex(), hash_hex)

def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _load() -> dict:
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "customers": {},
        "accounts": {},
        "transactions": [],
        "loans": {},
        "employees": {},
        "cards": {},
    }

def _save(db: dict):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

def _gen_id(prefix: str = "") -> str:
    import uuid
    return prefix + str(uuid.uuid4().int)[:8].upper()


# ─── Auth ─────────────────────────────────────────────────────────────────────

class Auth:
    current: Optional[dict] = None

    @classmethod
    def login(cls, db: dict, username: str, password: str) -> bool:
        emp = db["employees"].get(username)
        if emp and emp.get("active") and verify_password(password, emp["password"]):
            cls.current = emp
            return True
        return False

    @classmethod
    def logout(cls):
        cls.current = None

    @classmethod
    def require(cls, role: str = None):
        if not cls.current:
            raise PermissionError("Sisteme giriş edilməyib.")
        if role and cls.current.get("role") != role:
            raise PermissionError(f"'{role}' səlahiyyəti tələb olunur.")


# ─── Employee ─────────────────────────────────────────────────────────────────

def create_default_admin(db: dict) -> Optional[str]:
    """İlk işə salınmada admin yaradır və təsadüfi şifrəni qaytarır.
    Admin artıq varsa None qaytarır."""
    if "admin" in db["employees"]:
        return None
    password = secrets.token_urlsafe(12)
    db["employees"]["admin"] = {
        "id": "EMP000001",
        "name": "Admin",
        "surname": "Sistem",
        "role": "admin",
        "username": "admin",
        "password": hash_password(password),
        "active": True,
        "created_at": _now(),
    }
    return password

def add_employee(db: dict, name: str, surname: str, role: str,
                 username: str, password: str) -> dict:
    Auth.require("admin")
    if username in db["employees"]:
        raise ValueError(f"'{username}' artıq mövcuddur.")
    emp = {
        "id": _gen_id("EMP"),
        "name": name,
        "surname": surname,
        "role": role,
        "username": username,
        "password": hash_password(password),
        "active": True,
        "created_at": _now(),
    }
    db["employees"][username] = emp
    _save(db)
    return emp


# ─── Customer ─────────────────────────────────────────────────────────────────

def add_customer(db: dict, name: str, surname: str, fin: str,
                 phone: str, email: str, address: str) -> dict:
    Auth.require()
    for c in db["customers"].values():
        if c["fin"] == fin:
            raise ValueError(f"FIN {fin} artıq qeydiyyatdadır.")
    cid = _gen_id("C")
    customer = {
        "id": cid,
        "name": name,
        "surname": surname,
        "fin": fin,
        "phone": phone,
        "email": email,
        "address": address,
        "active": True,
        "created_at": _now(),
    }
    db["customers"][cid] = customer
    _save(db)
    return customer

def get_customer(db: dict, cid: str) -> dict:
    c = db["customers"].get(cid)
    if not c:
        raise KeyError(f"Müştəri tapılmadı: {cid}")
    return c

def search_customers(db: dict, query: str) -> list:
    q = query.lower()
    return [
        c for c in db["customers"].values()
        if q in (c["name"] + " " + c["surname"]).lower()
        or q in c["fin"].lower()
        or q in c["phone"]
    ]


# ─── Account ─────────────────────────────────────────────────────────────────

def open_account(db: dict, customer_id: str, account_type: str,
                 currency: str = "AZN", interest_rate: float = 0.0,
                 initial_deposit: float = 0.0) -> dict:
    Auth.require()
    get_customer(db, customer_id)
    acc_no = "AZ" + str(abs(hash(customer_id + _now())))[:14]
    account = {
        "account_number": acc_no,
        "customer_id": customer_id,
        "type": account_type,
        "currency": currency,
        "balance": 0.0,
        "interest_rate": interest_rate,
        "active": True,
        "created_at": _now(),
    }
    db["accounts"][acc_no] = account
    if initial_deposit > 0:
        account["balance"] = initial_deposit
        _record_txn(db, acc_no, "Mədaxil", initial_deposit, "İlk depozit", initial_deposit)
    _save(db)
    return account

def get_account(db: dict, account_number: str) -> dict:
    acc = db["accounts"].get(account_number)
    if not acc:
        raise KeyError(f"Hesab tapılmadı: {account_number}")
    if not acc["active"]:
        raise ValueError(f"Hesab aktiv deyil: {account_number}")
    return acc

def close_account(db: dict, account_number: str):
    Auth.require()
    acc = get_account(db, account_number)
    if acc["balance"] != 0:
        raise ValueError("Hesabı bağlamaq üçün balans sıfır olmalıdır.")
    acc["active"] = False
    _save(db)


# ─── Transactions ─────────────────────────────────────────────────────────────

def _record_txn(db: dict, account_number: str, txn_type: str, amount: float,
                description: str, balance_after: float, to_account: str = None):
    txn = {
        "id": _gen_id("TXN"),
        "account_number": account_number,
        "type": txn_type,
        "amount": amount,
        "description": description,
        "to_account": to_account,
        "balance_after": balance_after,
        "timestamp": _now(),
    }
    db["transactions"].append(txn)

def deposit(db: dict, account_number: str, amount: float, description: str = "Mədaxil") -> dict:
    Auth.require()
    if amount <= 0:
        raise ValueError("Məbləğ müsbət olmalıdır.")
    acc = get_account(db, account_number)
    acc["balance"] += amount
    _record_txn(db, account_number, "Mədaxil", amount, description, acc["balance"])
    _save(db)
    return acc

def withdraw(db: dict, account_number: str, amount: float, description: str = "Məxaric") -> dict:
    Auth.require()
    if amount <= 0:
        raise ValueError("Məbləğ müsbət olmalıdır.")
    acc = get_account(db, account_number)
    if acc["balance"] < amount:
        raise ValueError(f"Balans kifayət deyil. Cari: {acc['balance']:.2f} {acc['currency']}")
    acc["balance"] -= amount
    _record_txn(db, account_number, "Məxaric", amount, description, acc["balance"])
    _save(db)
    return acc

def transfer(db: dict, from_acc: str, to_acc: str, amount: float,
             description: str = "Köçürmə"):
    Auth.require()
    if amount <= 0:
        raise ValueError("Məbləğ müsbət olmalıdır.")
    src = get_account(db, from_acc)
    dst = get_account(db, to_acc)
    if src["balance"] < amount:
        raise ValueError(f"Balans kifayət deyil. Cari: {src['balance']:.2f}")
    now = _now()
    src["balance"] -= amount
    dst["balance"] += amount
    _record_txn(db, from_acc, "Köçürmə", amount, f"{description} → {to_acc}", src["balance"], to_acc)
    _record_txn(db, to_acc, "Köçürmə", amount, f"{description} ← {from_acc}", dst["balance"])
    _save(db)

def get_statement(db: dict, account_number: str,
                  start_date: str = None, end_date: str = None) -> list:
    Auth.require()
    get_account(db, account_number)
    result = [t for t in db["transactions"] if t["account_number"] == account_number]
    if start_date:
        result = [t for t in result if t["timestamp"] >= start_date]
    if end_date:
        result = [t for t in result if t["timestamp"] <= end_date]
    return result


# ─── Loan ─────────────────────────────────────────────────────────────────────

def _monthly_payment(principal: float, annual_rate: float, months: int) -> float:
    r = annual_rate / 100 / 12
    if r == 0:
        return round(principal / months, 2)
    payment = principal * (r * (1 + r) ** months) / ((1 + r) ** months - 1)
    return round(payment, 2)

def apply_loan(db: dict, customer_id: str, amount: float, interest_rate: float,
               term_months: int, purpose: str) -> dict:
    Auth.require()
    get_customer(db, customer_id)
    lid = _gen_id("LN")
    monthly = _monthly_payment(amount, interest_rate, term_months)
    loan = {
        "id": lid,
        "customer_id": customer_id,
        "amount": amount,
        "interest_rate": interest_rate,
        "term_months": term_months,
        "purpose": purpose,
        "monthly_payment": monthly,
        "remaining_balance": amount,
        "status": "gözləyir",
        "approved_by": None,
        "created_at": _now(),
    }
    db["loans"][lid] = loan
    _save(db)
    return loan

def approve_loan(db: dict, loan_id: str, account_number: str) -> dict:
    Auth.require()
    loan = db["loans"].get(loan_id)
    if not loan:
        raise KeyError(f"Kredit tapılmadı: {loan_id}")
    if loan["status"] != "gözləyir":
        raise ValueError(f"Kredit artıq '{loan['status']}' statusundadır.")
    acc = get_account(db, account_number)
    if acc["customer_id"] != loan["customer_id"]:
        raise ValueError("Hesab müştəriyə aid deyil.")
    acc["balance"] += loan["amount"]
    loan["status"] = "aktiv"
    loan["approved_by"] = Auth.current["username"]
    _record_txn(db, account_number, "Kredit verilişi", loan["amount"],
                f"Kredit [{loan_id}]", acc["balance"])
    _save(db)
    return loan

def reject_loan(db: dict, loan_id: str) -> dict:
    Auth.require()
    loan = db["loans"].get(loan_id)
    if not loan:
        raise KeyError(f"Kredit tapılmadı: {loan_id}")
    if loan["status"] != "gözləyir":
        raise ValueError(f"Kredit artıq '{loan['status']}' statusundadır.")
    loan["status"] = "rədd edilib"
    loan["approved_by"] = Auth.current["username"]
    _save(db)
    return loan

def make_loan_payment(db: dict, loan_id: str, account_number: str) -> dict:
    Auth.require()
    loan = db["loans"].get(loan_id)
    if not loan or loan["status"] != "aktiv":
        raise ValueError("Aktiv kredit tapılmadı.")
    acc = get_account(db, account_number)
    payment = min(loan["monthly_payment"], loan["remaining_balance"])
    if acc["balance"] < payment:
        raise ValueError(f"Balans kifayət deyil. Lazımi: {payment:.2f}")
    acc["balance"] -= payment
    loan["remaining_balance"] = round(loan["remaining_balance"] - payment, 2)
    if loan["remaining_balance"] <= 0.01:
        loan["remaining_balance"] = 0
        loan["status"] = "bağlanıb"
    _record_txn(db, account_number, "Kredit ödənişi", payment,
                f"Kredit ödənişi [{loan_id}]", acc["balance"])
    _save(db)
    return loan


# ─── Reports ─────────────────────────────────────────────────────────────────

def bank_report(db: dict) -> dict:
    Auth.require()
    total_balance = sum(a["balance"] for a in db["accounts"].values() if a["active"])
    total_loan_debt = sum(
        l["remaining_balance"] for l in db["loans"].values() if l["status"] == "aktiv"
    )
    return {
        "bank_name": "AzərBank İdarəetmə Sistemi",
        "generated_at": _now(),
        "total_customers": len(db["customers"]),
        "total_accounts": len([a for a in db["accounts"].values() if a["active"]]),
        "total_balance_azn": round(total_balance, 2),
        "total_loans": len([l for l in db["loans"].values() if l["status"] == "aktiv"]),
        "total_loan_debt_azn": round(total_loan_debt, 2),
        "total_transactions": len(db["transactions"]),
    }

def customer_summary(db: dict, customer_id: str) -> dict:
    Auth.require()
    customer = get_customer(db, customer_id)
    accounts = [a for a in db["accounts"].values() if a["customer_id"] == customer_id]
    loans = [l for l in db["loans"].values() if l["customer_id"] == customer_id]
    return {
        "customer": customer,
        "accounts": accounts,
        "total_balance": round(sum(a["balance"] for a in accounts if a["active"]), 2),
        "loans": loans,
        "total_loan_debt": round(
            sum(l["remaining_balance"] for l in loans if l["status"] == "aktiv"), 2
        ),
    }


# ─── CLI Interface ────────────────────────────────────────────────────────────

def print_header(title: str):
    print(f"\n{'─'*40}")
    print(f"  {title}")
    print(f"{'─'*40}")

def print_menu(options: dict):
    for key, label in options.items():
        print(f"  {key}. {label}")

def customer_menu(db: dict):
    while True:
        print_header("MÜŞTƏRİ İDARƏETMƏSİ")
        print_menu({"1": "Müştəri əlavə et", "2": "Müştəri axtar",
                    "3": "Müştəri xülasəsi", "0": "Geri"})
        c = input("Seçim: ").strip()
        if c == "1":
            name = input("Ad: ").strip()
            surname = input("Soyad: ").strip()
            fin = input("FIN: ").strip()
            phone = input("Telefon: ").strip()
            email = input("Email: ").strip()
            address = input("Ünvan: ").strip()
            cust = add_customer(db, name, surname, fin, phone, email, address)
            print(f"Müştəri əlavə edildi. ID: {cust['id']}")
        elif c == "2":
            q = input("Axtarış (ad/FIN/telefon): ").strip()
            results = search_customers(db, q)
            if not results:
                print("Nəticə tapılmadı.")
            for r in results:
                print(f"  [{r['id']}] {r['name']} {r['surname']} | FIN: {r['fin']} | Tel: {r['phone']}")
        elif c == "3":
            cid = input("Müştəri ID: ").strip()
            s = customer_summary(db, cid)
            c_info = s["customer"]
            print(f"\n  Ad: {c_info['name']} {c_info['surname']}")
            print(f"  FIN: {c_info['fin']} | Tel: {c_info['phone']}")
            print(f"  Ümumi balans: {s['total_balance']:.2f} AZN")
            print(f"  Kredit borcu: {s['total_loan_debt']:.2f} AZN")
            for a in s["accounts"]:
                print(f"    Hesab: {a['account_number']} | {a['type']} | {a['balance']:.2f} {a['currency']}")
        elif c == "0":
            break

def account_menu(db: dict):
    while True:
        print_header("HESAB İDARƏETMƏSİ")
        print_menu({"1": "Hesab aç", "2": "Hesab bağla", "3": "Balansa bax",
                    "4": "Mədaxil", "5": "Məxaric", "6": "Köçürmə",
                    "7": "Hesab çıxarışı", "0": "Geri"})
        c = input("Seçim: ").strip()
        if c == "1":
            cid = input("Müştəri ID: ").strip()
            print("Hesab növü: 1-Cari  2-Əmanət  3-Kredit")
            t_map = {"1": "Cari Hesab", "2": "Əmanət Hesabı", "3": "Kredit Hesabı"}
            t = t_map.get(input("Növ: ").strip(), "Cari Hesab")
            currency = input("Valyuta (AZN/USD/EUR) [AZN]: ").strip() or "AZN"
            rate = float(input("Faiz dərəcəsi [0]: ").strip() or 0)
            dep = float(input("İlk depozit [0]: ").strip() or 0)
            acc = open_account(db, cid, t, currency, rate, dep)
            print(f"Hesab açıldı: {acc['account_number']}")
        elif c == "2":
            acc_no = input("Hesab nömrəsi: ").strip()
            close_account(db, acc_no)
            print("Hesab bağlandı.")
        elif c == "3":
            acc_no = input("Hesab nömrəsi: ").strip()
            acc = get_account(db, acc_no)
            print(f"Balans: {acc['balance']:.2f} {acc['currency']}")
        elif c == "4":
            acc_no = input("Hesab nömrəsi: ").strip()
            amount = float(input("Məbləğ: ").strip())
            desc = input("Açıqlama [Mədaxil]: ").strip() or "Mədaxil"
            acc = deposit(db, acc_no, amount, desc)
            print(f"Mədaxil edildi. Yeni balans: {acc['balance']:.2f}")
        elif c == "5":
            acc_no = input("Hesab nömrəsi: ").strip()
            amount = float(input("Məbləğ: ").strip())
            desc = input("Açıqlama [Məxaric]: ").strip() or "Məxaric"
            acc = withdraw(db, acc_no, amount, desc)
            print(f"Məxaric edildi. Yeni balans: {acc['balance']:.2f}")
        elif c == "6":
            from_acc = input("Göndərən hesab: ").strip()
            to_acc = input("Alan hesab: ").strip()
            amount = float(input("Məbləğ: ").strip())
            transfer(db, from_acc, to_acc, amount)
            print("Köçürmə tamamlandı.")
        elif c == "7":
            acc_no = input("Hesab nömrəsi: ").strip()
            txns = get_statement(db, acc_no)
            if not txns:
                print("Əməliyyat yoxdur.")
            for t in txns[-20:]:
                sign = "+" if t["type"] in ("Mədaxil", "Kredit verilişi") else "-"
                print(f"  {t['timestamp']}  {t['type']:<20} {sign}{t['amount']:.2f} AZN  Son: {t['balance_after']:.2f}")
        elif c == "0":
            break

def loan_menu(db: dict):
    while True:
        print_header("KREDİT İDARƏETMƏSİ")
        print_menu({"1": "Kredit müraciəti", "2": "Krediti təsdiqlə",
                    "3": "Krediti rədd et", "4": "Kredit ödənişi",
                    "5": "Kredit siyahısı", "0": "Geri"})
        c = input("Seçim: ").strip()
        if c == "1":
            cid = input("Müştəri ID: ").strip()
            amount = float(input("Kredit məbləği: ").strip())
            rate = float(input("İllik faiz (%): ").strip())
            months = int(input("Müddət (ay): ").strip())
            purpose = input("Məqsəd: ").strip()
            loan = apply_loan(db, cid, amount, rate, months, purpose)
            print(f"Müraciət qəbul edildi. ID: {loan['id']} | Aylıq ödəniş: {loan['monthly_payment']:.2f} AZN")
        elif c == "2":
            lid = input("Kredit ID: ").strip()
            acc_no = input("Hesab nömrəsi (köçürmə üçün): ").strip()
            loan = approve_loan(db, lid, acc_no)
            print(f"Kredit təsdiqləndi. Status: {loan['status']}")
        elif c == "3":
            lid = input("Kredit ID: ").strip()
            loan = reject_loan(db, lid)
            print(f"Kredit rədd edildi.")
        elif c == "4":
            lid = input("Kredit ID: ").strip()
            acc_no = input("Ödəniş hesabı: ").strip()
            loan = make_loan_payment(db, lid, acc_no)
            print(f"Ödəniş qəbul edildi. Qalıq: {loan['remaining_balance']:.2f} AZN | Status: {loan['status']}")
        elif c == "5":
            for l in db["loans"].values():
                cust = db["customers"].get(l["customer_id"], {})
                name = cust.get("name", "?") + " " + cust.get("surname", "")
                print(f"  [{l['id']}] {name} | {l['amount']:.2f} AZN | {l['status']} | Qalıq: {l['remaining_balance']:.2f}")
        elif c == "0":
            break

def report_menu(db: dict):
    print_header("BANK HESABATI")
    r = bank_report(db)
    print(f"  Bank: {r['bank_name']}")
    print(f"  Tarix: {r['generated_at']}")
    print(f"  Müştərilər: {r['total_customers']}")
    print(f"  Hesablar: {r['total_accounts']}")
    print(f"  Ümumi Balans: {r['total_balance_azn']:.2f} AZN")
    print(f"  Aktiv Kreditlər: {r['total_loans']}")
    print(f"  Kredit Borcu: {r['total_loan_debt_azn']:.2f} AZN")
    print(f"  Əməliyyatlar: {r['total_transactions']}")

def employee_menu(db: dict):
    while True:
        print_header("İŞÇİ İDARƏETMƏSİ")
        print_menu({"1": "İşçi əlavə et", "2": "İşçi siyahısı", "0": "Geri"})
        c = input("Seçim: ").strip()
        if c == "1":
            name = input("Ad: ").strip()
            surname = input("Soyad: ").strip()
            role = input("Rol (admin/cashier/manager): ").strip()
            username = input("İstifadəçi adı: ").strip()
            password = input("Şifrə: ").strip()
            emp = add_employee(db, name, surname, role, username, password)
            print(f"İşçi əlavə edildi. ID: {emp['id']}")
        elif c == "2":
            for e in db["employees"].values():
                status = "Aktiv" if e["active"] else "Deaktiv"
                print(f"  [{e['id']}] {e['name']} {e['surname']} | {e['role']} | {e['username']} | {status}")
        elif c == "0":
            break


def main():
    db = _load()
    admin_password = create_default_admin(db)
    _save(db)
    if admin_password:
        print("=" * 50)
        print("İlk işə salınma: 'admin' hesabı yaradıldı.")
        print(f"  İstifadəçi adı: admin")
        print(f"  Şifrə (yalnız indi göstərilir): {admin_password}")
        print("Bu şifrəni saxlayın, təkrar göstərilməyəcək.")
        print("=" * 50)

    print("╔══════════════════════════════════╗")
    print("║   BANK DAXİLİ İDARƏETMƏ SİSTEMİ  ║")
    print("╚══════════════════════════════════╝")

    username = input("İstifadəçi adı: ").strip()
    password = input("Şifrə: ").strip()

    if not Auth.login(db, username, password):
        print("Giriş uğursuz oldu!")
        return

    print(f"\nXoş gəldiniz, {Auth.current['name']} {Auth.current['surname']}!")

    while True:
        print_header("ƏSAS MENYU")
        print_menu({
            "1": "Müştəri İdarəetməsi",
            "2": "Hesab İdarəetməsi",
            "3": "Kredit İdarəetməsi",
            "4": "Bank Hesabatı",
            "5": "İşçi İdarəetməsi (Admin)",
            "0": "Çıxış",
        })
        c = input("Seçim: ").strip()
        try:
            if c == "1":
                customer_menu(db)
            elif c == "2":
                account_menu(db)
            elif c == "3":
                loan_menu(db)
            elif c == "4":
                report_menu(db)
            elif c == "5":
                employee_menu(db)
            elif c == "0":
                Auth.logout()
                print("Sistemdən çıxıldı.")
                break
            else:
                print("Yanlış seçim!")
        except (PermissionError, ValueError, KeyError) as e:
            print(f"XƏTA: {e}")


if __name__ == "__main__":
    main()
