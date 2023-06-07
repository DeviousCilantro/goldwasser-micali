use std::io;
use std::io::Write;
use num_primes::Generator;
use rug::Integer;
use ring::rand::{SystemRandom, SecureRandom};

fn generate_keypair() -> ((Integer, Integer), (Integer, Integer)) {
    let n;
    let mut p;
    let mut q;
    loop {
        p = Integer::from_str_radix(&Generator::safe_prime(512).to_string(), 10).unwrap();
        q = Integer::from_str_radix(&Generator::safe_prime(512).to_string(), 10).unwrap();
        if ((p.clone() - Integer::from(3)) % Integer::from(4) == 0) && ((q.clone() - Integer::from(3)) % Integer::from(4) == 0) {
            n = p.clone() * q.clone();
            break;
        };
    };
    let x = n.clone() - Integer::from(1);
    ((x, n), (p, q))
}

fn random_integer(rng: &SystemRandom, range: Integer) -> Integer {
    loop {
        let mut bytes = vec![0; ((range.significant_bits() + 7) / 8) as usize];
        rng.fill(&mut bytes).unwrap();
        let num = Integer::from_digits(&bytes, rug::integer::Order::Lsf);
        if num < range {
            return num;
        }
    }
}

fn encrypt_plaintext(plaintext: &Integer, pk: (Integer, Integer)) -> Vec<Integer> {
    let rand = SystemRandom::new();
    let (x, n) = pk;
    let mut ciphertext: Vec<Integer> = Vec::new();
    let bit_string = format!("{plaintext:b}");
    for bit in bit_string.chars() {
        let mut yi;
        loop {
            yi = random_integer(&rand, n.clone());
            if yi.clone().gcd(&n) == 1 {
                break;
            }
        }
        if bit.to_digit(2).unwrap() == 1 {
            ciphertext.push(yi.clone().secure_pow_mod(&Integer::from(2), &n));
        } else if bit.to_digit(2).unwrap() == 0 {
            ciphertext.push(((yi.clone().secure_pow_mod(&Integer::from(2), &n)) * x.clone()) % n.clone());
        }
        
    }
    ciphertext
}

fn decrypt_ciphertext(ciphertext: Vec<Integer>, sk: (Integer, Integer)) -> Integer {
    let (p, q) = sk;
    let mut m: Vec<u8> = Vec::new();
    for c in ciphertext {
        if (c.clone().secure_pow_mod(&((p.clone() - Integer::from(1)) / Integer::from(2)), &p) == 1) && (c.secure_pow_mod(&((q.clone() - Integer::from(1)) / Integer::from(2)), &q) == 1) {
            m.push(1);
        } else {
            m.push(0);
        }
    }
    let bit_string = m.iter()
        .map(|&bit| bit.to_string())
        .collect::<String>();
    
    Integer::from_str_radix(&bit_string, 2).unwrap()
}

fn main() {
    print!("Enter a string: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = input.trim();
    let (pk, sk) = generate_keypair();
    let input_plaintext = Integer::from_str_radix(&hex::encode(input), 16).unwrap();
    let ciphertext = encrypt_plaintext(&input_plaintext, pk);
    let mut encoded_ciphertext = Vec::new();
    for element in ciphertext.clone() {
        encoded_ciphertext.push(base64::encode(element.to_string()));
    }
    println!("Encrypted ciphertext: {:?}", &encoded_ciphertext);
    let output_plaintext = decrypt_ciphertext(ciphertext, sk);
    assert_eq!(input_plaintext, output_plaintext, "Correctness not verified.");
    let output_plaintext = format!("{:X}", &output_plaintext);
    println!("Decrypted plaintext: {}",  String::from_utf8(hex::decode(output_plaintext).unwrap()).unwrap());
    println!("Correctness verified.");
}
