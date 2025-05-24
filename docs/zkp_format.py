import random
from hashlib import sha256
from typing import List, Tuple
from sympy import isprime

def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a

def lcm(a: int, b: int) -> int:
    return abs(a * b) // gcd(a, b)

def L(x: int, n: int) -> int:
    return (x - 1) // n

def modinv(a: int, m: int) -> int:
    return pow(a, -1, m)

# def generate_keys(p: int, q: int) -> Tuple[int, int, int]:
#     n = p * q
#     lambda_val = lcm(p - 1, q - 1)
#     g = n + 1  # Стандартное значение для упрощения вычислений
#     return n, lambda_val, g

def encrypt(m: int, r: int, g: int, n: int) -> int:
    return (pow(g, m, n**2) * pow(r, n, n**2)) % n**2

def decrypt(c: int, g: int, lambda_val: int, n: int) -> int:
    numerator = L(pow(c, lambda_val, n**2), n)
    denominator = L(pow(g, lambda_val, n**2), n)
    return (numerator * modinv(denominator, n)) % n

def compute_digest(values: List[int]) -> int:
    h = sha256()
    for val in values:
        h.update(str(val).encode())
    return int(h.hexdigest(), 16)

def generate_keys(bit_length=512):
    # 1. Выбираем два больших простых числа p и q
    def get_prime(bits):
        while True:
            p = random.getrandbits(bits)
            if isprime(p):
                return p
    p = get_prime(bit_length // 2)
    q = get_prime(bit_length // 2)

    print(p)
    print(q)
    
    # 2. Вычисляем n = p * q и функцию Эйлера phi = (p-1)*(q-1)
    n = p * q
    lambda_val = lcm(p-1, q-1)
    
    # 3. Выбираем g (обычно g = n + 1)
    g = n + 1
    
    # 4. Убеждаемся, что gcd(L(g^phi mod n²), n) = 1, где L(u) = (u - 1)/n
    # Для g = n + 1 это условие выполняется автоматически
    public_key = (n, g)
    private_key = (lambda_val, n)
    return public_key, private_key

class CorrectMessageProof:
    def __init__(self, e_vec: List[int], z_vec: List[int], a_vec: List[int], 
                 ciphertext: int, valid_messages: List[int], n: int):
        self.e_vec = e_vec
        self.z_vec = z_vec
        self.a_vec = a_vec
        self.ciphertext = ciphertext
        self.valid_messages = valid_messages
        self.n = n
        self.nn = n * n

    @classmethod
    def prove(cls, n: int, valid_messages: List[int], message_to_encrypt: int) -> 'CorrectMessageProof':
        nn = n * n
        num_of_messages = len(valid_messages)
        
        # Генерация случайного r и шифрование сообщения
        while True:
            r = random.randint(2, n - 1)
            if gcd(r, n) == 1:
                break
                
        g = n + 1  # Стандартное значение g для Paillier
        ciphertext = encrypt(message_to_encrypt, r, g, n)
        
        # Вычисление u_i для каждого допустимого сообщения
        ui_vec = []
        for m in valid_messages:
            gm = pow(g, m, nn)
            gm_inv = modinv(gm, nn)
            ui = (ciphertext * gm_inv) % nn
            ui_vec.append(ui)
        
        # Генерация случайных e_j и z_j для всех сообщений, кроме истинного
        B = 256  # Параметр безопасности
        ei_vec = [random.getrandbits(B) for _ in range(num_of_messages - 1)]
        zi_vec = [random.randint(2, n - 1) for _ in range(num_of_messages - 1)]
        
        # Генерация случайного w
        w = random.randint(2, n - 1)
        
        # Находим индекс истинного сообщения
        true_index = valid_messages.index(message_to_encrypt)
        
        # Вычисляем a_i для каждого сообщения
        ai_vec = []
        j = 0
        for i in range(num_of_messages):
            if i == true_index:
                ai = pow(w, n, nn)
            else:
                zi_n = pow(zi_vec[j], n, nn)
                ui_ei = pow(ui_vec[i], ei_vec[j], nn)
                ui_ei_inv = modinv(ui_ei, nn)
                ai = (zi_n * ui_ei_inv) % nn
                j += 1
            ai_vec.append(ai)
        
        
        # Вычисляем challenge (chal)
        two_to_B = 2 ** B
        chal = compute_digest(ai_vec) % two_to_B
        
        # Вычисляем e_i для истинного сообщения
        ei_sum = sum(ei_vec) % two_to_B
        ei = (chal - ei_sum) % two_to_B
        
        # Вычисляем z_i для истинного сообщения
        ri_ei = pow(r, ei, n)
        zi = (w * ri_ei) % n
        
        # Собираем полные векторы e_vec и z_vec
        e_vec = []
        z_vec = []
        j = 0
        for i in range(num_of_messages):
            if i == true_index:
                e_vec.append(ei)
                z_vec.append(zi)
            else:
                e_vec.append(ei_vec[j])
                z_vec.append(zi_vec[j])
                j += 1
        
        return cls(e_vec, z_vec, ai_vec, ciphertext, valid_messages.copy(), n)
    
    def verify(self) -> bool:
        num_of_messages = len(self.valid_messages)
        nn = self.n * self.n
        B = 256
        two_to_B = 2 ** B
        
        # Проверка суммы e_i
        chal = compute_digest(self.a_vec) % two_to_B
        ei_sum = sum(self.e_vec) % two_to_B
        if chal != ei_sum:
            return False
        
        # Вычисление u_i для каждого допустимого сообщения
        ui_vec = []
        for m in self.valid_messages:
            gm = pow(g, m, nn)
            gm_inv = modinv(gm, nn)
            ui = (self.ciphertext * gm_inv) % nn
            ui_vec.append(ui)
        
        # Проверка каждого уравнения z_i^n ≡ a_i * u_i^e_i mod n²
        for i in range(num_of_messages):
            zi_n = pow(self.z_vec[i], self.n, nn)
            ui_ei = pow(ui_vec[i], self.e_vec[i], nn)
            right_side = (self.a_vec[i] * ui_ei) % nn
            if zi_n != right_side:
                return False
        
        return True

# Пример использования
if __name__ == "__main__":
    # Генерация ключейaVec

    public_key, private_key = generate_keys(bit_length = 2048)
    n = public_key[0]
    g = public_key[1]

    lambda_val = private_key[0]

    print("------N------")
    print(n)
    print("-------------")
    print("------G------")
    print(g)
    print("-------------")
    print("------LAMBDA------")
    print(lambda_val)
    print("-------------")


    # p = 838382000974237847921957342377847823774311
    # q = 113011
    # n, lambda_val, g = generate_keys(p, q)
    
    # Варианты голосов (должны быть уникальными и достаточно большими)
    vote_variants = [2**(30*i) for i in range(4)]
    
    # Тестовые голоса (должны быть из vote_variants)
    votes = [2**(30*1), 2**(30*1), 2**(30*1), 2**(30*1), 2**(30*1)]
    
    # Проверка, что все голоса из допустимых вариантов
    # for vote in votes:
    #     assert vote in vote_variants, f"Голос {vote} не входит в допустимые варианты"
    
    # Процесс голосования с доказательствами
    encrypted_votes = []
    proofs = []
    
    for m in votes:
        # Генерация доказательства
        proof = CorrectMessageProof.prove(n, vote_variants, m)
        proofs.append(proof)
        
        # Проверка доказательства (это будет делать получатель)
        assert proof.verify(), "Доказательство не прошло проверку"
        
        # Сохраняем зашифрованный голос
        encrypted_votes.append(proof.ciphertext)

        print(proof.ciphertext)
    
    # Проверка всех бюллетеней перед подсчетом
    print("Проверка всех бюллетеней перед подсчетом:")
    for i, proof in enumerate(proofs):
        if not proof.verify():
            print(f"Бюллетень {i} не прошел проверку!")
        else:
            print(f"Бюллетень {i} корректен")


    # Подсчет голосов (гомоморфное сложение)

    # decsum=0
    # it = iter(encrypted_votes)
    
    # for i, j in zip(it, it):
    #     encc = (i * j) % (n**2)
    #     dec = decrypt(encc, g, lambda_val, n)
    #     print(f"Расшифрованная сумма: {dec}, bin: {bin(dec)}")
    #     decsum += dec
    
    # print(f"Итоговый результат: {decsum}, bin: {bin(decsum)}")

    encc = 1
    
    for i in encrypted_votes:
        encc = (encc*i)%(n**2)

    decsum = decrypt(encc, g, lambda_val, n)
    print(encc)
    print(f"Итоговый результат: {decsum}, bin: {bin(decsum)}")
