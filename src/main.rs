use std::collections::HashSet;
use std::io::{self, Write};

/// --- HELPER FUNCTIONS ---

// Reads user input easily
fn input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap();
    buf.trim().to_string()
}

// Cleans text: uppercase only, no spaces or punctuation
fn sanitize(s: &str) -> String {
    s.to_ascii_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect()
}

// Extended Euclidean Algorithm for Modular Inverse (Used in Hill and RSA)
fn mod_inverse(a: i64, m: i64) -> Option<i64> {
    let (mut t, mut newt) = (0i64, 1i64);
    let (mut r, mut newr) = (m, a);
    while newr != 0 {
        let q = r / newr;
        let temp_t = t - q * newt;
        t = newt;
        newt = temp_t;
        let temp_r = r - q * newr;
        r = newr;
        newr = temp_r;
    }
    if r > 1 { return None; }
    if t < 0 { t += m; }
    Some(t)
}

// Modular Exponentiation: (base^exp) % modulo (Used in RSA and Diffie-Hellman)
fn mod_pow(mut base: i64, mut exp: i64, modulo: i64) -> i64 {
    let mut res = 1;
    base %= modulo;
    while exp > 0 {
        if exp % 2 == 1 { res = (res * base) % modulo; }
        base = (base * base) % modulo;
        exp /= 2;
    }
    res
}

/// --- 1. VIGENERE CIPHER ---
fn vigenere(text: &str, key: &str, encrypt: bool) -> String {
    let text = sanitize(text);
    let key = sanitize(key);
    let key_chars: Vec<char> = key.chars().collect();
    let mut result = String::new();

    for (i, c) in text.chars().enumerate() {
        let shift = (key_chars[i % key_chars.len()] as i16) - 65;
        let shift = if encrypt { shift } else { -shift };
        let mut new_c = ((c as i16 - 65 + shift) % 26) + 65;
        if new_c < 65 { new_c += 26; }
        result.push(new_c as u8 as char);
    }
    result
}

/// --- 2. RAIL FENCE CIPHER ---
fn rail_fence_encrypt(text: &str, rails: usize) -> String {
    let text = text.replace(" ", "");
    if rails == 1 { return text; }
    let mut fence: Vec<String> = vec![String::new(); rails];
    let mut rail = 0;
    let mut down = false;

    for c in text.chars() {
        fence[rail].push(c);
        if rail == 0 || rail == rails - 1 { down = !down; }
        rail = if down { rail + 1 } else { rail - 1 };
    }
    fence.join("")
}

fn rail_fence_decrypt(text: &str, rails: usize) -> String {
    let text = text.replace(" ", "");
    if rails == 1 { return text; }
    let mut lengths = vec![0; rails];
    let (mut rail, mut down) = (0, false);
    
    // Calculate lengths of each rail
    for _ in 0..text.len() {
        lengths[rail] += 1;
        if rail == 0 || rail == rails - 1 { down = !down; }
        rail = if down { rail + 1 } else { rail - 1 };
    }

    let mut fences = vec![vec![]; rails];
    let mut chars = text.chars();
    for r in 0..rails {
        for _ in 0..lengths[r] { fences[r].push(chars.next().unwrap()); }
    }

    let mut result = String::new();
    let mut pointers = vec![0; rails];
    rail = 0; down = false;
    for _ in 0..text.len() {
        result.push(fences[rail][pointers[rail]]);
        pointers[rail] += 1;
        if rail == 0 || rail == rails - 1 { down = !down; }
        rail = if down { rail + 1 } else { rail - 1 };
    }
    result
}

/// --- 3. COLUMNAR TRANSPOSITION ---
fn columnar_cipher(text: &str, key: &str, encrypt: bool) -> String {
    let text = text.replace(" ", "");
    let cols = key.len();
    let rows = (text.len() + cols - 1) / cols;
    
    let mut key_order: Vec<(usize, char)> = key.chars().enumerate().collect();
    key_order.sort_by_key(|&(_, c)| c);

    let mut res = String::new();

    if encrypt {
        let mut grid = vec![vec!['X'; cols]; rows];
        for (i, c) in text.chars().enumerate() { grid[i / cols][i % cols] = c; }
        for &(col_idx, _) in &key_order {
            for row in 0..rows { res.push(grid[row][col_idx]); }
        }
    } else {
        let mut grid = vec![vec![' '; cols]; rows];
        let mut chars = text.chars();
        for &(col_idx, _) in &key_order {
            for row in 0..rows { grid[row][col_idx] = chars.next().unwrap(); }
        }
        for row in 0..rows {
            for col in 0..cols { res.push(grid[row][col]); }
        }
    }
    res
}

/// --- 4. PLAYFAIR CIPHER ---
fn playfair(text: &str, key: &str, encrypt: bool) -> String {
    // 1. Build Matrix
    let mut matrix = Vec::new();
    let mut seen = HashSet::new();
    let clean_key = sanitize(key).replace("J", "I");
    for c in clean_key.chars().chain("ABCDEFGHIKLMNOPQRSTUVWXYZ".chars()) {
        if !seen.contains(&c) {
            seen.insert(c);
            matrix.push(c);
        }
    }

    // 2. Prepare text (digraphs)
    let text = sanitize(text).replace("J", "I");
    let mut prepared = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c1) = chars.next() {
        prepared.push(c1);
        if let Some(&c2) = chars.peek() {
            if c1 == c2 { prepared.push('X'); } 
            else { prepared.push(chars.next().unwrap()); }
        } else {
            prepared.push('X'); // Pad odd length
        }
    }

    // 3. Process
    let mut res = String::new();
    let shift = if encrypt { 1 } else { 4 }; // +4 mod 5 is same as -1 mod 5
    for chunk in prepared.chunks(2) {
        let (a, b) = (chunk[0], chunk[1]);
        let pos_a = matrix.iter().position(|&x| x == a).unwrap();
        let pos_b = matrix.iter().position(|&x| x == b).unwrap();
        let (r1, c1) = (pos_a / 5, pos_a % 5);
        let (r2, c2) = (pos_b / 5, pos_b % 5);

        if r1 == r2 { // Same Row
            res.push(matrix[r1 * 5 + (c1 + shift) % 5]);
            res.push(matrix[r2 * 5 + (c2 + shift) % 5]);
        } else if c1 == c2 { // Same Column
            res.push(matrix[((r1 + shift) % 5) * 5 + c1]);
            res.push(matrix[((r2 + shift) % 5) * 5 + c2]);
        } else { // Rectangle
            res.push(matrix[r1 * 5 + c2]);
            res.push(matrix[r2 * 5 + c1]);
        }
    }
    res
}

/// --- 5. HILL CIPHER (2x2) ---
fn hill_cipher(text: &str, matrix: [i64; 4], encrypt: bool) -> String {
    let mut text_chars: Vec<char> = sanitize(text).chars().collect();
    if text_chars.len() % 2 != 0 { text_chars.push('X'); }

    let [a, b, c, d] = matrix;
    let det = ((a * d - b * c) % 26 + 26) % 26; // Ensure positive mod

    let mut work_matrix = [a, b, c, d];

    if !encrypt {
        let det_inv = mod_inverse(det, 26).expect("Key Error: Determinant has no inverse mod 26!");
        let inv_a = (d * det_inv % 26 + 26) % 26;
        let inv_b = (-b * det_inv % 26 + 26) % 26;
        let inv_c = (-c * det_inv % 26 + 26) % 26;
        let inv_d = (a * det_inv % 26 + 26) % 26;
        work_matrix = [inv_a, inv_b, inv_c, inv_d];
    }

    let [wa, wb, wc, wd] = work_matrix;
    let mut res = String::new();

    for chunk in text_chars.chunks(2) {
        let x = (chunk[0] as i64) - 65;
        let y = (chunk[1] as i64) - 65;
        let out_x = (wa * x + wb * y) % 26;
        let out_y = (wc * x + wd * y) % 26;
        res.push((out_x as u8 + 65) as char);
        res.push((out_y as u8 + 65) as char);
    }
    res
}

/// --- MAIN CLI MENU ---
fn main() {
    loop {
        println!("\n=== Cryptography Study Toolkit ===");
        println!("1. Vigenère Cipher");
        println!("2. Rail Fence Transposition");
        println!("3. Columnar Transposition");
        println!("4. Playfair Cipher");
        println!("5. Hill Cipher (2x2)");
        println!("6. RSA Algorithm (Textbook)");
        println!("7. Diffie-Hellman Key Exchange");
        println!("8. Exit");
        
        let choice = input("Select an option (1-8): ");
        
        match choice.as_str() {
            "1" => {
                let text = input("Enter text: ");
                let key = input("Enter key string: ");
                println!("Encrypted: {}", vigenere(&text, &key, true));
                println!("Decrypted: {}", vigenere(&vigenere(&text, &key, true), &key, false));
            }
            "2" => {
                let text = input("Enter text: ");
                let rails: usize = input("Enter number of rails: ").parse().unwrap_or(2);
                let enc = rail_fence_encrypt(&text, rails);
                println!("Encrypted: {}", enc);
                println!("Decrypted: {}", rail_fence_decrypt(&enc, rails));
            }
            "3" => {
                let text = input("Enter text: ");
                let key = input("Enter key string (e.g., HACK): ");
                let enc = columnar_cipher(&text, &key, true);
                println!("Encrypted: {}", enc);
                println!("Decrypted: {}", columnar_cipher(&enc, &key, false));
            }
            "4" => {
                let text = input("Enter text: ");
                let key = input("Enter key: ");
                let enc = playfair(&text, &key, true);
                println!("Encrypted: {}", enc);
                println!("Decrypted: {}", playfair(&enc, &key, false));
            }
            "5" => {
                println!("Enter 2x2 matrix key integers (A, B, C, D) [e.g. 3, 3, 2, 5]: ");
                let a: i64 = input("A: ").parse().unwrap_or(3);
                let b: i64 = input("B: ").parse().unwrap_or(3);
                let c: i64 = input("C: ").parse().unwrap_or(2);
                let d: i64 = input("D: ").parse().unwrap_or(5);
                let text = input("Enter text: ");
                let enc = hill_cipher(&text, [a, b, c, d], true);
                println!("Encrypted: {}", enc);
                println!("Decrypted: {}", hill_cipher(&enc, [a, b, c, d], false));
            }
            "6" => {
                println!("-- RSA Keygen --");
                let p: i64 = input("Enter prime p (e.g., 61): ").parse().unwrap();
                let q: i64 = input("Enter prime q (e.g., 53): ").parse().unwrap();
                let e: i64 = input("Enter public exponent e (e.g., 17): ").parse().unwrap();
                
                let n = p * q;
                let phi = (p - 1) * (q - 1);
                let d = mod_inverse(e, phi).expect("e and phi are not coprime!");
                
                println!("\nPublic Key: (n: {}, e: {})", n, e);
                println!("Private Key: (d: {})", d);
                
                let m: i64 = input("Enter integer message to encrypt (m < n): ").parse().unwrap();
                let c = mod_pow(m, e, n);
                println!("Encrypted Ciphertext: {}", c);
                let decrypted_m = mod_pow(c, d, n);
                println!("Decrypted Message: {}", decrypted_m);
            }
            "7" => {
                println!("-- Diffie-Hellman --");
                let p: i64 = input("Enter public prime modulo p (e.g., 23): ").parse().unwrap();
                let g: i64 = input("Enter public base g (e.g., 5): ").parse().unwrap();
                let a_priv: i64 = input("Alice's private secret a (e.g., 4): ").parse().unwrap();
                let b_priv: i64 = input("Bob's private secret b (e.g., 3): ").parse().unwrap();
                
                let a_pub = mod_pow(g, a_priv, p);
                let b_pub = mod_pow(g, b_priv, p);
                
                println!("\nAlice sends Public Key A: {}", a_pub);
                println!("Bob sends Public Key B: {}", b_pub);
                
                let alice_shared = mod_pow(b_pub, a_priv, p);
                let bob_shared = mod_pow(a_pub, b_priv, p);
                
                println!("Alice computes Shared Secret: {}", alice_shared);
                println!("Bob computes Shared Secret: {}", bob_shared);
            }
            "8" => {
                println!("Happy encrypting! Goodbye.");
                break;
            }
            _ => println!("Invalid selection, try again."),
        }
    }
}