# Bank System

Python ilə yazılmış, terminal əsaslı sadə bank idarəetmə sistemi. Verilənlər lokal JSON faylında saxlanır. Layihə təhsil məqsədlidir, real maliyyə əməliyyatları üçün nəzərdə tutulmayıb.

## Xüsusiyyətlər

- **Müştərilər:** qeydiyyat, axtarış, xülasə
- **Hesablar:** cari, əmanət və kredit hesabı açmaq/bağlamaq
- **Əməliyyatlar:** mədaxil, məxaric, köçürmə, hesab çıxarışı
- **Kreditlər:** müraciət, təsdiq/rədd, aylıq ödəniş hesablaması və ödəniş
- **Hesabatlar:** bank üzrə ümumi hesabat
- **İşçilər və rollar:** giriş sistemi, `admin` səlahiyyəti tələb edən əməliyyatlar
- Şifrələr `hashlib.scrypt` ilə (təsadüfi duz, N=2^14, r=8, p=1) hash-lənir və sabit vaxtlı müqayisə ilə yoxlanılır

## Tələblər

- Python 3.9+
- Xarici paket tələb olunmur (yalnız standart kitabxana)

## İşə salmaq

```bash
python bank.py
```

İlk işə salınmada `bank_data.json` yaradılır və `admin` istifadəçisi əlavə olunur. Admin şifrəsi **təsadüfi yaradılır və ekrana yalnız bir dəfə çıxarılır**. Onu dərhal saxlayın, təkrar göstərilmir və faylda yalnız hash şəklində durur. Şifrəni itirsəniz, `bank_data.json` faylını silib sistemi yenidən başladın (bütün qeydlər silinəcək) və ya admin qeydini əl ilə yenidən yaradın.

Koda yazılmış standart şifrə yoxdur.

## Struktur

```
bank_system/
├── bank.py          # əsas məntiq və terminal menyuları
├── models.py        # dataclass və enum modelləri
└── .gitignore
```

## Məlumatların saxlanması

`bank_data.json` müştəri, hesab və işçi qeydlərini (şifrə hash-ləri daxil) saxlayır. Bu fayl `.gitignore`-a əlavə edilib və repoya düşməməlidir.

## Məhdudiyyətlər

- Şifrə hash-ləri `scrypt` formatındadır (`scrypt$N$r$p$duz$hash`). Köhnə SHA-256 hash-ləri dəstəklənmir, belə qeydlər üçün şifrə yenidən təyin olunmalıdır.
- Şifrə sıfırlama və hesab kilidləmə (uğursuz cəhdlərə qarşı) funksiyası yoxdur.
- JSON faylı eyni anda çoxlu istifadəçini dəstəkləmir.
- Avtomatik testlər yoxdur.

## Lisenziya

[MIT Lisenziyası](LICENSE) © 2026 Ali Xanbabayev
