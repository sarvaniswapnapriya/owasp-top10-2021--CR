import matplotlib.pyplot as plt

# Dane
categories = [
    "Broken Access Control", "Cryptographic Failures", "Injection", "Insecure Design", 
    "Security Misconfiguration", "Vulnerable and Outdated Components", 
    "Identification and Authentication Failures", "Software and Data Integrity Failures", 
    "Security Logging and Monitoring Failures", "Server-Side Request Forgery (SSRF)"
]
frequencies = [94, 83, 67, 55, 60, 53, 51, 47, 44, 39]

# Wykres
plt.figure(figsize=(12, 8))
bars = plt.barh(categories, frequencies, color='skyblue')
plt.xlabel('Percentage of Applications Affected')
plt.title('OWASP Top 10 Vulnerabilities 2021')
plt.gca().invert_yaxis()  # Odwróć oś Y, aby ranking był od 1 do 10

# Dodaj wartości procentowe do słupków
for bar in bars:
    plt.text(bar.get_width() - 5, bar.get_y() + bar.get_height()/2, f'{bar.get_width()}%', va='center', color='black', fontweight='bold')

plt.subplots_adjust(left=0.3, right=0.95, top=0.9, bottom=0.1)  # Dostosowanie marginesów
plt.show()
