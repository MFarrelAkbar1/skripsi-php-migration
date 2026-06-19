# Persiapan Sidang — Pertanyaan Teknis & Jawaban

**Judul:** Migrasi Otomatis Kode PHP Legacy ke PHP 8.x Menggunakan LLM Lokal dengan Kerangka Keamanan ISO/IEC 27001:2022

---

## A. Rekomendasi Model

---

**Q: Qwen2.5-Coder direkomendasikan, tapi Format Compliance Rate (FCR)-nya 0% di Kondisi A maupun B. Gimana bisa direkomendasikan kalau tidak patuh format sama sekali?**

FCR dan SVR (Syntax Validity Rate) adalah dua dimensi yang independen dan sengaja tidak digabung. FCR mengukur apakah model menulis tiga elemen sekaligus: penjelasan, blok kode PHP, dan baris `CONFIDENCE: [0-100]`. Qwen tidak pernah menulis baris `CONFIDENCE:` sehingga FCR = 0%. Tapi justru di sisi SVR — metrik primer yang diverifikasi secara objektif dengan `php -l` — Qwen konsisten menghasilkan kode PHP yang valid sintaksis di 100% percobaan, baik Kondisi A maupun B.

Bandingkan dengan CodeLlama: FCR 100% (paling patuh format) tapi SVR hanya 27,3% di Kondisi A dan 39,4% di Kondisi B — artinya lebih dari separuh kode yang dihasilkannya tidak lolos `php -l`. Model yang "disiplin mengikuti format" justru lebih sering menghasilkan kode rusak. Oleh karena itu rekomendasi didasarkan pada SVR, bukan FCR, karena SVR mencerminkan kegunaan praktis: kode yang dapat dieksekusi.

---

**Q: Kenapa Qwen confidence score-nya 0,00 terus? Apakah model tidak yakin dengan outputnya sendiri?**

Confidence score 0,00 pada Qwen bukan berarti model tidak yakin. Angka itu muncul karena Qwen tidak pernah menuliskan baris `CONFIDENCE: [angka]` dalam responnya — baik dalam bentuk tag XML, angka desimal, persentase, maupun frasa seperti "confident" atau "not sure". Keenam pola regex ekstraksi di `_extract_confidence()` tidak menemukan pola apapun, sehingga sistem mengembalikan nilai default 0,0.

Ini konsisten dengan gaya respons Qwen yang mengabaikan instruksi format sambil tetap mengerjakan tugas utama: menghasilkan penjelasan kerentanan dan blok kode PHP yang valid. Justru CodeLlama yang melaporkan confidence rata-rata 0,91 (Kondisi A) tapi 72,7% kodenya tidak lolos `php -l`. Ini membuktikan bahwa confidence score self-reported tidak berkorelasi dengan kualitas kode pada model berukuran kecil-menengah — dan menjadi alasan kenapa confidence score ditetapkan sebagai metrik **sekunder** sejak desain metodologi.

---

**Q: DeepSeek Coder FCR naik drastis dari 15% ke 61% di Kondisi B. Tapi kenapa extraction rate malah turun dari 9% ke 3%? Bukankah kontradiktif?**

Ini memang paradoks yang menarik dan dibahas eksplisit dalam skripsi. Strategi Kondisi B untuk DeepSeek adalah memperpendek dan menyederhanakan instruksi agar model lebih fokus mengikuti format. Hasilnya: model lebih sering menuliskan baris `CONFIDENCE:` (FCR naik), tapi instruksi yang lebih singkat ternyata mengurangi dorongan untuk menghasilkan blok kode PHP secara lengkap (extraction rate turun). Ada trade-off antara kepatuhan format dan kemampuan menghasilkan kode dalam satu prompt — sesuatu yang tidak bisa dioptimasi keduanya secara bersamaan pada model ukuran ini.

---

**Q: Mistral di Kondisi B malah lebih buruk — FCR turun dari 6% ke 0% padahal diberi contoh few-shot. Kenapa?**

Ini konsisten dengan temuan literatur yang dikutip (Akuthota et al., 2023): teknik prompt engineering yang efektif untuk model besar tidak selalu bisa langsung diterapkan ke model kecil-menengah. Contoh few-shot yang diberikan pada Mistral justru mengalihkan model dari mengerjakan tugas aslinya — model lebih fokus meniru struktur contoh daripada memahami dan menjawab pertanyaan keamanan. Fenomena ini disebut "distraction" di literatur prompt engineering untuk small LLM.

---

## B. Hasil Angka Spesifik

---

**Q: Kenapa Rector CR FT UGM 97,6% sementara DTI 91,7%? Padahal file DTI lebih banyak (326 vs 245)?**

Perbedaan 5,9 poin persentase hampir seluruhnya disebabkan oleh jumlah file yang **di-skip**, bukan yang gagal. FT UGM hanya 4 file di-skip (1,6%), sedangkan DTI ada 25 file di-skip (7,7%). File yang di-skip bukan kegagalan — melainkan file yang sudah kompatibel dengan PHP 8.3 atau tidak mengandung pola yang perlu ditransformasi Rector. File yang benar-benar gagal dikonversi sama persis: 2 file di masing-masing dataset (`captcha_helper.php` dan `form_helper.php`) akibat bug `FiberNodeScopeResolver` pada versi Rector yang digunakan — bukan dari kode sumber FT UGM atau DTI.

---

**Q: Dua file gagal dikonversi karena bug Rector. Kenapa tidak diganti versi Rector yang tidak ada bug-nya?**

Bug `FiberNodeScopeResolver` adalah bug pada versi Rector yang digunakan saat eksperimen. Penggunaan versi spesifik dicatat untuk reproducibility. Opsi mengganti versi dipertimbangkan, tapi karena: (1) hanya 2 dari 245/326 file yang terdampak, (2) kedua file adalah helper framework CodeIgniter yang jarang dimodifikasi, dan (3) file tersebut tetap disalin ke `output/` sebagai kode asli — pipeline tetap berjalan tanpa kehilangan data. Ini juga menjadi poin keterbatasan yang dicatat di Bab IV dan rekomendasi pengembangan lanjutan.

---

**Q: PHPStan menghasilkan 2.790 error di FT UGM dan 2.354 di DTI. Tapi FT UGM filenya lebih sedikit (245 vs 326). Kenapa errornya justru lebih banyak?**

Paradoks ini disebabkan oleh dependensi pihak ketiga FT UGM yang tidak diinstal secara penuh di lingkungan analisis. PHPStan tidak bisa me-resolve kelas-kelas seperti `PhpOffice\PhpSpreadsheet` dan `Dotenv\Dotenv` — setiap penggunaan kelas ini menghasilkan error `Class not found`. DTI tidak memiliki `composer.json` sehingga tidak ada dependensi eksternal yang menyebabkan cascade error seperti ini. Selain itu, ~354 error FT UGM dan ~318 error DTI adalah noise dari arsitektur dinamis CodeIgniter 3 (magic property `$this->db`, `$this->load`, dan helper function yang diinjeksi runtime).

---

**Q: Semgrep hanya menemukan 11 temuan di FT UGM padahal ada 245 file PHP. Apakah itu tidak terlalu sedikit?**

11 temuan adalah seluruh populasi temuan, bukan sample. Dan pola ini sebenarnya informatif: seluruh 11 temuan terlokalisasi di **satu file** saja — `system/core/Output.php` milik framework CodeIgniter 3, bukan kode aplikasi custom. Artinya kode aplikasi custom FT UGM di direktori `application/` tidak menghasilkan temuan Semgrep sama sekali. Hal yang sama terjadi di DTI. Ini menunjukkan bahwa kerentanan yang terdeteksi bukan dari kesalahan programmer aplikasi, melainkan dari kode framework lama. Kerentanannya: 1 SQL Injection (baris 768, `$_SERVER['QUERY_STRING']` langsung dipakai dalam konstruksi cache path tanpa sanitasi) dan 10 SSRF (nama file dari input user di operasi filesystem).

---

**Q: ΔF = 0 artinya Rector tidak memperbaiki kerentanan. Apakah ini kegagalan pipeline?**

Tidak, dan ini penting. ΔF = 0 adalah **hasil yang diharapkan** dan dikonfirmasi eksplisit. Rector bekerja berbasis AST (Abstract Syntax Tree) — ia mengubah sintaks, bukan logika program. Kerentanan SQL Injection dan SSRF yang ditemukan Semgrep memerlukan perbaikan semantik (sanitasi input, validasi path), yang berada di luar kapabilitas transformasi sintaksis otomatis. Yang penting: ΔF = 0 juga berarti konversi Rector **tidak memperkenalkan kerentanan baru** — konfirmasi yang kritis untuk migrasi otomatis berskala besar.

---

**Q: Similarity score validasi sampling 10% adalah 0,9214. Dari mana angka itu dan apa maknanya?**

Dihitung menggunakan algoritma Ratcliff/Obershelp via `difflib.SequenceMatcher` dengan formula 2M/T, di mana M = jumlah baris yang cocok dan T = total baris kedua versi. Sampel 24 file dipilih acak (seed=42) dari file valid yang lolos `php -l`. Dari 24 file, 12 dari `application/` dibandingkan dengan konversi referensi yang dibuat manual + LLM enterprise sebagai proxy konversi ideal. Skor 0,9214 dengan 11 dari 12 file berada di rentang 0,90-1,00 menunjukkan konversi Rector sangat dekat dengan konversi manual ideal. Satu file (0,70-0,80) memiliki perbedaan gaya penulisan (spasi, urutan atribut), bukan kesalahan konversi.

---

**Q: Kenapa pakai LLM enterprise (eksternal) sebagai referensi validasi padahal prinsipnya data harus lokal?**

Ini adalah trade-off yang disadari dan didokumentasikan secara transparan di Bab IV. Penggunaan model eksternal hanya terjadi **sekali** dalam prosedur evaluasi peneliti (bukan bagian dari pipeline produksi), tidak melibatkan pengiriman kode sumber secara utuh, dan dilakukan untuk menjaga independensi evaluator — model yang sama dengan yang ada di pipeline tidak bisa dijadikan penilai karena akan menghasilkan bias penilaian mandiri. Skripsi juga mencatat bahwa idealnya diganti dengan penilai lokal untuk sepenuhnya konsisten dengan prinsip kerahasiaan data.

---

## C. Desain Sistem & Metodologi

---

**Q: Kenapa AI Engine hanya menerima input dari Semgrep pre-scan (prioritas 1-5), bukan PHPStan? Bukankah PHPStan juga menemukan masalah?**

Ada dua alasan. Pertama, temuan PHPStan mayoritas adalah type errors dan technical debt yang membutuhkan refactoring mendalam — bukan perbaikan yang bisa dihasilkan AI secara snippet per snippet. Kedua, PHPStan menghasilkan ribuan temuan (2.790 di FT UGM) yang sebagian besar adalah noise dari arsitektur CodeIgniter 3 — mengirim semua ini ke AI Engine akan menghabiskan waktu inferensi untuk false positive. Semgrep pre-scan menghasilkan temuan kerentanan keamanan yang spesifik (SQL Injection, SSRF, XSS, dll.) yang lebih cocok untuk rekomendasi perbaikan berbasis AI.

---

**Q: Kenapa temperature dibuat 0,1? Dan kenapa tidak di-seed?**

Temperature 0,1 dipilih untuk meminimalkan variasi acak antar percobaan — setiap model dijalankan 3 kali per temuan (33 run per model, 165 total) sehingga perbedaan antar run mencerminkan variabilitas model yang sebenarnya, bukan noise acak. Ollama tidak menyediakan pengaturan seed inferensi yang konsisten untuk seluruh model yang diuji, sehingga variasi kecil antar run tetap dimungkinkan — ini dicatat sebagai keterbatasan eksperimental. Kondisi C menguji temperature 0,3-0,7 pada Qwen dan hasilnya SVR tetap 100% di semua nilai, artinya kualitas kode Qwen stabil terhadap perubahan temperature.

---

**Q: Kenapa potongan kode yang dikirim ke model dibatasi 2.000 karakter saja?**

Untuk menjaga ukuran prompt dalam batas context window default Ollama dan menghindari pemotongan respons akibat token overflow. Konsekuensinya: untuk file PHP panjang, model hanya menerima konteks parsial. Ini menjadi keterbatasan yang dicatat — terlihat dari temuan SQL Injection di `Output.php` baris 768 yang mendapat confidence 0% di DTI karena potongan kode yang dikirim tidak menyertakan konteks yang cukup untuk menganalisis konstruksi internal framework. Kondisi C menguji context window 4000 dan 8000: extraction rate naik dari 97% ke 100%, tapi secara keseluruhan perbedaannya marginal.

---

**Q: Kenapa pemetaan ISO menggunakan keyword matching berbasis rule, bukan AI?**

Tiga alasan: (1) **Deterministik** — temuan yang sama selalu menghasilkan pemetaan yang sama tanpa variasi antar inferensi, (2) **Dapat diaudit** — seluruh logika pemetaan tersimpan dalam kode Python `iso_mapper.py` yang bisa diperiksa baris per baris, (3) **Tidak memerlukan koneksi eksternal** — konsisten dengan persyaratan privasi data. Pendekatan berbasis AI untuk pemetaan ISO akan menghasilkan output yang bisa berubah antar inferensi, mempersulit audit kepatuhan. ISO 27001 adalah standar audit — hasilnya harus dapat direproduksi.

---

**Q: Mengapa target PHP 8.3, bukan 8.4 atau 8.5?**

Eksperimen PHP 8.5 dilakukan dan hasilnya adalah kegagalan. Rector dengan ruleset `UP_TO_PHP_85` yang masih eksperimental menerapkan transformasi terlalu agresif pada kode framework CodeIgniter 3 — menyebabkan syntax error di `CodeIgniter.php`, `Output.php`, dan `Security.php`. Akibatnya PHPStan menghasilkan 6.137 error (cascade false positive karena kelas induk CI3 tidak bisa di-resolve). PHP 8.4 lebih feasible tapi masih memerlukan perbaikan manual pada pola dynamic property CodeIgniter 3 yang dihapus di PHP 8.4. PHP 8.3 adalah target paling realistis untuk CodeIgniter 3.x dengan ruleset Rector yang sudah matang dan validasi 100% syntax validity.

---

**Q: Apakah pipeline bisa dipakai untuk codebase PHP selain CodeIgniter?**

Secara teknis ya, karena Rector dan Semgrep tidak bergantung pada framework tertentu. Tapi hasil penelitian ini hanya divalidasi pada dua aplikasi berbasis CodeIgniter 3.x, sehingga tingkat generalisasi ke framework lain (Laravel, Symfony, dll.) atau aplikasi PHP non-framework belum teruji. Ini adalah salah satu keterbatasan yang dicatat dan menjadi arah penelitian lanjutan. Arsitektur modular pipeline memudahkan penggantian komponen jika diperlukan.

---

## D. Pertanyaan Kritis Penguji

---

**Q: Validitas sintaks 100% setelah konversi — apakah itu benar-benar menjamin kode berfungsi dengan benar?**

Tidak, dan ini disebutkan eksplisit sebagai keterbatasan. `php -l` hanya memeriksa kebenaran sintaksis (parse error), bukan kebenaran semantik. Kode yang lolos `php -l` bisa saja: (1) mengandung logic bug yang tidak terlihat secara statis, (2) mengandung kerentanan keamanan yang tidak tertangani, atau (3) menghasilkan output berbeda dari kode asli meski sintaksnya valid. Pengujian fungsional (dynamic testing) tidak termasuk dalam scope penelitian ini — scope-nya adalah static analysis. Ini adalah batasan yang disadari dan disebutkan sejak Bab III.

---

**Q: Semua kerentanan yang ditemukan Semgrep berasal dari Output.php milik framework CI3, bukan kode aplikasi custom. Lalu apa gunanya pipeline untuk kode aplikasi FT UGM dan DTI?**

Poin ini memang perlu dijawab dengan jujur. Untuk deteksi kerentanan Semgrep, hasilnya memang terbatas pada framework — ini mencerminkan kondisi aktual dataset: kode aplikasi custom FT UGM dan DTI ternyata tidak mengandung pola kerentanan yang terdeteksi ruleset Semgrep yang digunakan. Nilai tambah pipeline untuk kode aplikasi custom tetap ada melalui dua komponen lain: (1) **Rector** berhasil memodernisasi sintaks PHP lama ke PHP 8.3 di 239/299 file aplikasi custom, dan (2) **PHPStan** mengekspos 2.790/2.354 potensi masalah kompatibilitas tipe yang tidak akan terdeteksi sebelum deployment ke PHP 8.3. Temuan PHPStan inilah yang lebih relevan secara praktis untuk kode aplikasi.

---

**Q: Mengapa eksperimen LLM hanya menggunakan 11 temuan dari satu file (Output.php)? Apakah itu representatif?**

Ini adalah keterbatasan dataset, bukan pilihan metodologis. 11 temuan adalah seluruh populasi temuan Semgrep pre-scan FT UGM — tidak ada subsetting. Dari 11 temuan itu, 10 adalah SSRF dari pola kode yang berulang di Output.php, sehingga eksperimen LLM pada dasarnya menguji respons model terhadap dua jenis kerentanan (SQL Injection dan SSRF) dengan variasi konteks terbatas. Keterbatasan ini didiskusikan di Bab IV dan menjadi alasan untuk tidak terlalu over-generalisasi kesimpulan komparasi model di luar konteks ini.

---

**Q: Confidence score CodeLlama sangat tinggi (0,91) tapi SVR hanya 27-39%. Apa implikasi temuan ini?**

Ini adalah temuan kritis penelitian. CodeLlama "sangat yakin" dengan jawabannya padahal lebih dari separuh kodenya tidak lolos validasi sintaks dasar. Ini menunjukkan bahwa model LLM berukuran kecil-menengah umumnya tidak terkalibrasi dengan baik dalam menilai output mereka sendiri — konsisten dengan literatur yang dikutip (Akuthota et al., 2023; Li et al., 2025 IRIS). Implikasi praktis: sistem yang mengandalkan confidence score self-reported untuk memfilter output AI akan mengambil keputusan yang keliru. Inilah mengapa confidence score ditetapkan sebagai metrik sekunder dan SVR sebagai metrik primer.

---

**Q: Pipeline ini sudah ada di GitHub. Apakah kode sumber FT UGM dan DTI tidak ikut ter-push?**

Tidak. Sesuai prinsip privasi data yang ditetapkan sejak desain sistem: direktori `input/` yang berisi kode sumber FT UGM dan DTI tidak pernah dipush ke repository. Yang ada di repository hanya kode pipeline Python, sample file testing di `tests/sample_php74/`, dan laporan dummy. Ini konsisten dengan persyaratan kerahasiaan data dari kedua institusi. Seluruh AI inference juga berjalan lokal via Ollama — tidak ada kode yang dikirim ke API eksternal selama proses pipeline produksi.

---

*Revisi terakhir: berdasarkan hasil aktual Bab III, IV, V skripsi.*
