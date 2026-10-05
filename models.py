from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import uuid


class AccountType(Enum):
    CHECKING = "Cari Hesab"
    SAVINGS = "Əmanət Hesabı"
    LOAN = "Kredit Hesabı"


class TransactionType(Enum):
    DEPOSIT = "Mədaxil"
    WITHDRAWAL = "Məxaric"
    TRANSFER = "Köçürmə"
    LOAN_PAYMENT = "Kredit Ödənişi"
    INTEREST = "Faiz"


class LoanStatus(Enum):
    PENDING = "Gözləyir"
    APPROVED = "Təsdiqlənib"
    REJECTED = "Rədd edilib"
    ACTIVE = "Aktiv"
    CLOSED = "Bağlanıb"


@dataclass
class Customer:
    name: str
    surname: str
    fin: str
    phone: str
    email: str
    address: str
    customer_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8].upper())
    created_at: datetime = field(default_factory=datetime.now)
    is_active: bool = True

    @property
    def full_name(self):
        return f"{self.name} {self.surname}"


@dataclass
class Account:
    customer_id: str
    account_type: AccountType
    currency: str = "AZN"
    balance: float = 0.0
    account_number: str = field(default_factory=lambda: "AZ" + str(uuid.uuid4().int)[:14])
    created_at: datetime = field(default_factory=datetime.now)
    is_active: bool = True
    interest_rate: float = 0.0


@dataclass
class Transaction:
    account_number: str
    transaction_type: TransactionType
    amount: float
    description: str = ""
    to_account: Optional[str] = None
    transaction_id: str = field(default_factory=lambda: "TXN" + str(uuid.uuid4().int)[:10])
    timestamp: datetime = field(default_factory=datetime.now)
    balance_after: float = 0.0


@dataclass
class Loan:
    customer_id: str
    amount: float
    interest_rate: float
    term_months: int
    purpose: str
    loan_id: str = field(default_factory=lambda: "LN" + str(uuid.uuid4().int)[:8])
    status: LoanStatus = LoanStatus.PENDING
    approved_by: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    monthly_payment: float = 0.0
    remaining_balance: float = 0.0

    def calculate_monthly_payment(self):
        r = self.interest_rate / 100 / 12
        n = self.term_months
        if r == 0:
            return self.amount / n
        payment = self.amount * (r * (1 + r) ** n) / ((1 + r) ** n - 1)
        self.monthly_payment = round(payment, 2)
        self.remaining_balance = self.amount
        return self.monthly_payment


@dataclass
class Employee:
    name: str
    surname: str
    role: str
    username: str
    password_hash: str
    employee_id: str = field(default_factory=lambda: "EMP" + str(uuid.uuid4().int)[:6])
    created_at: datetime = field(default_factory=datetime.now)
    is_active: bool = True
