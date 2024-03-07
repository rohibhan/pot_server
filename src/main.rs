use k256::ecdsa::{
    signature::Signer, signature::Verifier, RecoveryId, Signature, SigningKey, VerifyingKey,
};
use k256::Secp256k1;
use rand_core::OsRng;
use std::env;

fn main() {
    let mut message: String = String::from("Hello, World");
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 {
        message = args[1].clone();
    }

    println!("Message: {}", message);

    let mut msg = message.as_bytes();

    //Private Key -- which is called as signing key
    let signing_key = SigningKey::random(&mut OsRng);
    let sk = signing_key.to_bytes();
    println!("\nSigning Key : {:x?}", hex::encode(sk));

    //Message to create signature with private key which is signed with private key
    let signature: Signature = signing_key.sign(msg);
    let signature_bytes: &[u8] = &signature.to_bytes();
    println!("\nSignature key: {:x?}", hex::encode(signature_bytes));

    //Public key - which is called as verifying key derived from signing key
    let verify_key = VerifyingKey::from(&signing_key);
    // Serialize with `::to_encoded_point()`
    let vk = verify_key.to_encoded_point(true);
    println!("\nVerifying key: {:x?}", hex::encode(vk));

    let rtn = verify_key.verify(msg, &signature).is_ok();

    if rtn == true {
        println!("\nMessage '{0}' signature correct", message);
    } else {
        println!("\nMessage '{0}' signature incorrect", message);
    }

    msg = "hello".as_bytes();

    let rtn = verify_key.verify(msg, &signature).is_ok();

    if rtn == true {
        println!("\nWith 'hello', message signature correct");
    } else {
        println!("\nWith 'hello', message signature incorrect");
    }
}
