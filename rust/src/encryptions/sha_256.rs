fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

fn pad_message(message: &[u8]) -> Vec<u8> {
    let mut padded_message = Vec::from(message);

    // append '1'
    padded_message.push(0x80);

    // compute number of '0's for appending
    let message_len_bits = message.len() * 8;
    let mut zero_pad_len = (512 - (message_len_bits + 1 + 64) % 512) / 8;

    // append '0's
    while zero_pad_len > 0 {
        padded_message.push(0);
        zero_pad_len -= 1;
    }

    // append length info
    let message_len_bits = message_len_bits as u64;
    for i in 0..8 {
        padded_message.push((message_len_bits >> (56 - 8 * i)) as u8);
    }

    padded_message
}

fn process_block(block: &[u8], hash: &mut [u32; 8]) {
    let mut w = [0u32; 64];

    // initialize
    for i in 0..16 {
        w[i] = (u32::from(block[i * 4]) << 24)
            | (u32::from(block[i * 4 + 1]) << 16)
            | (u32::from(block[i * 4 + 2]) << 8)
            | u32::from(block[i * 4 + 3]);
    }
    for i in 16..64 {
        let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }

    let mut a = hash[0];
    let mut b = hash[1];
    let mut c = hash[2];
    let mut d = hash[3];
    let mut e = hash[4];
    let mut f = hash[5];
    let mut g = hash[6];
    let mut h = hash[7];

    for i in 0..64 {
        let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        let ch = (e & f) ^ (!e & g);
        let tmp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let tmp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(tmp1);
        d = c;
        c = b;
        b = a;
        a = tmp1.wrapping_add(tmp2); 
    }

    hash[0] = hash[0].wrapping_add(a);
    hash[1] = hash[1].wrapping_add(b);
    hash[2] = hash[2].wrapping_add(c);
    hash[3] = hash[3].wrapping_add(d);
    hash[4] = hash[4].wrapping_add(e);
    hash[5] = hash[5].wrapping_add(f);
    hash[6] = hash[6].wrapping_add(g);
    hash[7] = hash[7].wrapping_add(h);
}

pub fn sha256(message: &[u8]) -> [u8; 32] {
    // initialize hash value
    let mut hash = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // fill message
    let padded_message = pad_message(message);

    // process each chunk
    for block in padded_message.chunks(64) {
        process_block(block, &mut hash);
    }

    // switch u32 to u8
    let mut result = [0u8; 32];
    for (i, chunk) in hash.iter().enumerate() {
        result[i * 4] = (chunk >> 24) as u8;
        result[i * 4 + 1] = (chunk >> 16) as u8;
        result[i * 4 + 2] = (chunk >> 8) as u8;
        result[i * 4 + 3] = *chunk as u8;
    }

    result
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];


pub fn print_hash(hash: &[u8]) {
    for byte in hash {
        print!("{:02x}", byte);
    }
    println!();
}